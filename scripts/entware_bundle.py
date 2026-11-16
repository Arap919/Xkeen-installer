#!/usr/bin/env python3
"""Prepare reviewable Entware locks and authenticated offline package repositories.

This maintainer tool never installs packages. Resolve produces a candidate lock;
fetch consumes an explicitly supplied reviewed lock and never refreshes metadata.
"""
import argparse
import hashlib
import json
import pathlib
import re
import ssl
import urllib.parse
import urllib.request

FEEDS = {'arm64': 'aarch64-k3.10', 'mips': 'mipssf-k3.4', 'mipsel': 'mipselsf-k3.4'}
ROOTS = ('libgcc libc libpthread librt entware-release findutils grep ldconfig locales opkg '
         'zoneinfo-asia zoneinfo-europe opt-ndmsv2 dropbear poorbox busybox '
         'curl jq ip-full iptables ipset ca-bundle coreutils-uname coreutils-nohup '
         'conntrack cron python3 ca-certificates python3-yaml wget-ssl').split()
NAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9+_.-]*\Z')
FILENAME = re.compile(r'[a-zA-Z0-9][a-zA-Z0-9+_.~-]*\.ipk\Z')
DEPENDENCY = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9+_.-]*)(?:\s+\((?:>=|<=|=|>>|<<|>|<)\s+[^()\s]+\))?\Z')


def secure_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname != 'bin.entware.net'
            or parsed.username is not None or parsed.password is not None
            or parsed.port not in (None, 443) or parsed.fragment or parsed.query
            or not parsed.path.startswith('/') or '..' in parsed.path.split('/')):
        raise ValueError('Only official certificate-validated Entware HTTPS URLs are permitted')
    return url


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        secure_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit):
    secure_url(url)
    context = ssl.create_default_context()
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname or context.cert_store_stats()['x509_ca'] == 0:
        raise ValueError('Certificate verification and trusted CA material are required')
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context), HTTPSRedirect())
    with opener.open(url, timeout=20) as response:
        if response.status != 200:
            raise ValueError('Entware download failed')
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Entware download exceeds size limit')
        return data


def parse_index(data, origin):
    secure_url(origin)
    if len(data) > 16 << 20 or b'\x00' in data:
        raise ValueError('Invalid package index')
    records = {}
    for block in data.decode('utf-8').replace('\r\n', '\n').strip().split('\n\n'):
        fields = {}
        last = None
        for line in block.splitlines():
            if line.startswith((' ', '\t')):
                if last is None:
                    raise ValueError('Orphan index continuation')
                fields[last] += '\n' + line
                continue
            key, separator, value = line.partition(':')
            if not separator or not key or key in fields:
                raise ValueError('Duplicate or malformed package field')
            fields[key] = value.strip()
            last = key
        required = ('Package', 'Version', 'Architecture', 'Filename', 'Size', 'SHA256sum')
        if any(not fields.get(key) for key in required):
            raise ValueError('Missing authenticated package metadata')
        name = fields['Package']
        if not NAME.fullmatch(name) or name in records or not FILENAME.fullmatch(fields['Filename']):
            raise ValueError('Duplicate package or unsafe package filename')
        if not re.fullmatch(r'[0-9]+', fields['Size']) or not 0 < int(fields['Size']) <= 64 << 20 or not re.fullmatch(r'[a-f0-9]{64}', fields['SHA256sum']):
            raise ValueError('Missing or invalid package digest/size')
        records[name] = {'name': name, 'version': fields['Version'], 'architecture': fields['Architecture'],
                         'depends': fields.get('Depends', ''), 'filename': fields['Filename'],
                         'size': int(fields['Size']), 'sha256': fields['SHA256sum'],
                         'url': origin.rstrip('/') + '/' + fields['Filename'], 'stanza': block + '\n\n'}
    return records


def closure(records, roots):
    selected = {}

    def visit(name):
        if name in selected:
            return
        if name not in records:
            raise ValueError('Missing dependency: ' + name)
        record = records[name]
        selected[name] = record
        for dependency in record['depends'].split(','):
            if not dependency.strip():
                continue
            match = DEPENDENCY.fullmatch(dependency.strip())
            if not match:
                raise ValueError('Unsupported dependency expression: ' + dependency)
            visit(match.group(1))

    for name in roots:
        visit(name)
    return [selected[name] for name in sorted(selected)]


def verify(record, data):
    if len(data) != record['size'] or hashlib.sha256(data).hexdigest() != record['sha256']:
        raise ValueError('Package bytes do not match reviewed metadata: ' + record['name'])


def validate_lock(lock):
    if lock.get('format') != 1 or lock.get('arch') not in FEEDS or not lock.get('roots') or not lock.get('packages'):
        raise ValueError('Invalid reviewed lock')
    records = {}
    for record in lock['packages']:
        secure_url(record['url'])
        if record['name'] in records:
            raise ValueError('Duplicate locked package')
        origin = record['url'].rsplit('/', 1)[0]
        parsed = parse_index(record['stanza'].encode(), origin)
        if list(parsed.values()) != [record]:
            raise ValueError('Locked metadata does not match its package stanza')
        records[record['name']] = record
    if closure(records, lock['roots']) != lock['packages']:
        raise ValueError('Lock is not a complete canonical dependency closure')
    if sum(record['size'] for record in lock['packages']) > 256 << 20:
        raise ValueError('Offline repository exceeds size limit')


def resolve(arch):
    records = {}
    origins = []
    base = 'https://bin.entware.net/' + FEEDS[arch]
    for origin in (base, base + '/keenetic'):
        data = fetch(origin + '/Packages', 16 << 20)
        origins.append({'url': origin + '/Packages', 'sha256': hashlib.sha256(data).hexdigest()})
        records.update(parse_index(data, origin))  # Keenetic's higher-priority feed wins.
    lock = {'format': 1, 'arch': arch, 'roots': ROOTS, 'indexes': origins, 'packages': closure(records, ROOTS)}
    validate_lock(lock)
    return lock


def download_repository(lock, output):
    validate_lock(lock)
    if output.exists():
        raise ValueError('Output must be a new directory')
    payloads = []
    for record in lock['packages']:
        data = fetch(record['url'], record['size'])
        verify(record, data)
        payloads.append((record['filename'], data))
    # No output is published until every package has passed verification.
    output.mkdir(parents=True)
    for name, data in payloads:
        (output / name).write_bytes(data)
    (output / 'Packages').write_text(''.join(p['stanza'] for p in lock['packages']), encoding='utf-8')
    (output / 'reviewed-lock.json').write_text(json.dumps(lock, indent=2) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    resolve_parser = commands.add_parser('resolve', help='Create a candidate lock for human/security review')
    resolve_parser.add_argument('arch', choices=FEEDS)
    resolve_parser.add_argument('output', type=pathlib.Path)
    fetch_parser = commands.add_parser('fetch', help='Fetch exact package bytes from an explicitly reviewed lock')
    fetch_parser.add_argument('lock', type=pathlib.Path)
    fetch_parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args()
    if args.command == 'resolve':
        lock = resolve(args.arch)
        with args.output.open('x', encoding='utf-8') as output:
            output.write(json.dumps(lock, indent=2) + '\n')
    else:
        download_repository(json.loads(args.lock.read_text()), args.output)


if __name__ == '__main__':
    main()
