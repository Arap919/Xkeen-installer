#!/opt/bin/python3
"""Refresh only installer-owned Xray configurations; never print source data."""
import copy
import fcntl
import json
import hashlib
import os
import pathlib
import ssl
import subprocess
import tempfile
import urllib.parse
import urllib.request

LIMIT = 2 * 1024 * 1024
BASE = __XRAY_BASE__
ROOT = pathlib.Path('/opt/etc/xkeen-subscriptions')
TARGET = pathlib.Path('/opt/etc/xray/configs/00-installer.json')
PROTOCOLS = {'vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http'}


def valid_url(raw):
    u = urllib.parse.urlsplit(raw)
    return len(raw) <= 8192 and u.scheme == 'https' and bool(u.hostname) and not u.username and not u.password and not u.fragment and not any(c in raw for c in '\r\n\0')


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not valid_url(newurl):
            raise ValueError('redirect rejected')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def merge(sources):
    proxies = []
    for data in sources:
        docs = json.loads(data)
        if not isinstance(docs, list):
            docs = [docs]
        before = len(proxies)
        for doc in docs:
            if not isinstance(doc, dict) or not isinstance(doc.get('outbounds'), list):
                raise ValueError('configuration rejected')
            for out in doc['outbounds']:
                if not isinstance(out, dict):
                    raise ValueError('outbound rejected')
                if out.get('protocol') not in PROTOCOLS:
                    continue
                if not isinstance(out.get('settings'), dict) or 'proxySettings' in out:
                    raise ValueError('settings rejected')
                if 'dialerProxy' in out.get('streamSettings', {}).get('sockopt', {}):
                    raise ValueError('dependent proxy rejected')
                out['tag'] = 'subscription-node-%d' % (len(proxies) + 1)
                proxies.append(out)
        if before == len(proxies):
            raise ValueError('no suitable proxy')
    if not proxies:
        raise ValueError('no suitable proxy')
    result = copy.deepcopy(BASE)
    result['outbounds'] = [proxies[0]] + [o for o in result['outbounds'] if o.get('tag') != 'blocked-until-configured'] + proxies[1:]
    for rule in result['routing']['rules']:
        if rule.get('outboundTag') == 'blocked-until-configured':
            rule['outboundTag'] = 'subscription-node-1'
    data = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode()
    if len(data) > LIMIT:
        raise ValueError('configuration too large')
    return data


def owned(data, expected_hash):
    return hashlib.sha256(data).hexdigest() == expected_hash


def run(command):
    env = dict(os.environ, XRAY_LOCATION_ASSET='/opt/etc/xray/dat')
    try:
        return subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _xray_state(require_running):
    try:
        init = pathlib.Path('/opt/etc/init.d/S05xkeen').read_bytes()
    except OSError:
        return False
    if init.count(b'name_client="xray"') != 1 or init.count(b'name_client="') != 1:
        return False
    found = False
    for item in pathlib.Path('/proc').glob('[0-9]*/exe'):
        try:
            exe = os.readlink(item)
        except OSError:
            continue
        if exe in ('/opt/sbin/mihomo', '/opt/bin/mihomo'):
            return False
        if exe == '/opt/sbin/xray':
            found = True
    return found or not require_running


def xray_active():
    return _xray_state(True)


def may_restart_xray():
    return _xray_state(False)


def atomic(path, data):
    fd, name = tempfile.mkstemp(prefix='.subscription-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def update():
    os.umask(0o077)
    with open(ROOT / 'update.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if TARGET.is_symlink() or not TARGET.is_file():
            raise ValueError('unsafe target')
        old = TARGET.read_bytes()
        source_file = ROOT / 'sources.json'
        if source_file.is_symlink() or source_file.stat().st_mode & 0o077:
            raise ValueError('unsafe sources')
        source_old = source_file.read_bytes()
        metadata = json.loads(source_old)
        if len(old) > LIMIT or not owned(old, metadata.get('config_sha256')):
            raise ValueError('configuration ownership changed')
        sources = metadata.get('urls')
        if not isinstance(sources, list) or not 1 <= len(sources) <= 10 or not all(isinstance(u, str) and valid_url(u) for u in sources):
            raise ValueError('sources rejected')
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), HTTPSRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
        docs = []
        for raw in sources:
            with opener.open(urllib.request.Request(raw, headers={'Accept': 'application/json'}), timeout=15) as response:
                data = response.read(LIMIT + 1)
                if response.status != 200 or len(data) > LIMIT:
                    raise ValueError('response rejected')
                docs.append(data)
        data = merge(docs)
        if json.loads(data) == json.loads(old):
            return
        with tempfile.TemporaryDirectory(prefix='.subscription-', dir=TARGET.parent.parent) as stage:
            stage = pathlib.Path(stage)
            # Validate the complete confdir with only the managed file substituted.
            for item in TARGET.parent.iterdir():
                if item.is_symlink() or not item.is_file():
                    raise ValueError('unsafe configuration directory')
                if item.suffix == '.json':
                    (stage / item.name).write_bytes(data if item == TARGET else item.read_bytes())
            if not run(['/opt/sbin/xray', 'run', '-test', '-confdir', str(stage)]):
                raise ValueError('validation failed')
        if TARGET.read_bytes() != old or source_file.read_bytes() != source_old:
            raise ValueError('configuration changed concurrently')
        active = xray_active()
        try:
            atomic(TARGET, data)
            metadata['config_sha256'] = hashlib.sha256(data).hexdigest()
            atomic(source_file, (json.dumps(metadata) + '\n').encode())
            if active and may_restart_xray() and (not run(['/opt/etc/init.d/S05xkeen', 'restart', 'on']) or not xray_active()):
                raise ValueError('restart failed')
        except BaseException:
            atomic(TARGET, old)
            atomic(source_file, source_old)
            if active and may_restart_xray():
                run(['/opt/etc/init.d/S05xkeen', 'restart', 'on'])
            raise


if __name__ == '__main__':
    try:
        # Bound even a peer that sends bytes indefinitely without an idle timeout.
        import signal
        signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
        signal.alarm(240)
        update()
    except Exception:
        raise SystemExit(1)
