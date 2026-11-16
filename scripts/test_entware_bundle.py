import hashlib
import importlib.util
import io
import gzip
import tarfile
import tempfile
import pathlib
import ssl
import urllib.error
import http.server
import threading
import subprocess
import shutil
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('entware_bundle', pathlib.Path(__file__).with_name('entware_bundle.py'))
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


def stanza(name, dependencies='', filename=None, payload=b'package'):
    return (f'Package: {name}\nVersion: 1.0-1\nArchitecture: all\n'
            f'Depends: {dependencies}\nFilename: {filename or name + ".ipk"}\n'
            f'Size: {len(payload)}\nSHA256sum: {hashlib.sha256(payload).hexdigest()}\n\n')


class RepositoryTests(unittest.TestCase):
    def test_complete_transitive_closure_is_deterministic(self):
        records = bundle.parse_index((stanza('app', 'lib (>= 1.0), tool') + stanza('lib', 'runtime') + stanza('runtime') + stanza('tool')).encode(), 'https://bin.entware.net/test')
        self.assertEqual([p['name'] for p in bundle.closure(records, ['app'])], ['app', 'lib', 'runtime', 'tool'])
        self.assertEqual(bundle.closure(records, ['app']), bundle.closure(records, ['app', 'lib']))

    def test_virtual_dependency_requires_explicit_matching_provider(self):
        text = stanza('app', 'ca-certs') + stanza('ca-bundle').replace('Depends: ', 'Provides: ca-certs\nDepends: ')
        records = bundle.parse_index(text.encode(), 'https://bin.entware.net/test')
        with self.assertRaises(ValueError):
            bundle.closure(records, ['app'])
        self.assertEqual([p['name'] for p in bundle.closure(records, ['app'], {'ca-certs': 'ca-bundle'})], ['app', 'ca-bundle'])
        with self.assertRaises(ValueError):
            bundle.closure(records, ['app'], {'ca-certs': 'app'})

    def test_missing_dependency_and_unsupported_alternative_fail_closed(self):
        for depends in ('missing', 'lib | other'):
            records = bundle.parse_index(stanza('app', depends).encode(), 'https://bin.entware.net/test')
            with self.assertRaises(ValueError):
                bundle.closure(records, ['app'])

    def test_reject_duplicate_fields_packages_and_unsafe_filenames(self):
        for text in (stanza('app') + stanza('app'), stanza('app').replace('Version:', 'Package: app\nVersion:'), stanza('app', filename='../outside.ipk'), stanza('app', filename='https://evil.invalid/app.ipk'), stanza('app').replace('SHA256sum:', 'MD5Sum:')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                bundle.parse_index(text.encode(), 'https://bin.entware.net/test')

    def test_unselected_large_package_does_not_block_small_closure(self):
        index = stanza('app') + stanza('large').replace('Size: 7', 'Size: 67108865')
        records = bundle.parse_index(index.encode(), 'https://bin.entware.net/test')
        self.assertEqual([p['name'] for p in bundle.closure(records, ['app'])], ['app'])
        lock = {'format': 1, 'arch': 'arm64', 'roots': ['large'], 'packages': [records['large']]}
        with self.assertRaises(ValueError):
            bundle.validate_lock(lock)

    def test_index_stanza_roundtrip_preserves_description_whitespace(self):
        text = stanza('app').rstrip('\n') + '\nDescription: fixture\n continued description \n\n' + stanza('other')
        record = bundle.parse_index(text.encode(), 'https://bin.entware.net/test')['app']
        bundle.validate_lock({'format': 1, 'arch': 'arm64', 'roots': ['app'], 'packages': [record]})

    def test_package_tampering_and_truncation_rejected(self):
        record = bundle.parse_index(stanza('app').encode(), 'https://bin.entware.net/test')['app']
        bundle.verify(record, b'package')
        for data in (b'packagf', b'packag', b'package!'):
            with self.assertRaises(ValueError):
                bundle.verify(record, data)

    def test_lock_rejects_changed_metadata_missing_roots_and_foreign_urls(self):
        record = bundle.parse_index(stanza('app').encode(), 'https://bin.entware.net/test')['app']
        good = {'format': 1, 'arch': 'arm64', 'roots': ['app'], 'packages': [record]}
        bundle.validate_lock(good)
        for change in ({'roots': ['missing']}, {'packages': [dict(record, url='http://bin.entware.net/app.ipk')]}, {'packages': [dict(record, sha256='bad')]}, {'packages': [record, record]}, {'arch': 'other'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                bundle.validate_lock(dict(good, **change))


class BundleTests(unittest.TestCase):
    def fixture(self):
        install = b'if ! opkg update >/dev/null 2>&1\nfor ipk in libgcc libc; do\nif ! opkg install $ipk >/dev/null 2>&1\n'
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            for name, data in [('bin/install', install), ('etc/opkg.conf', b'src/gz entware http://bin.entware.net/test\n')]:
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        base = stream.getvalue()
        record = bundle.parse_index(stanza('app').encode(), 'https://bin.entware.net/test')['app']
        lock = {'format': 1, 'arch': 'arm64', 'roots': ['app'], 'packages': [record]}
        return base, lock

    def test_bundle_deterministic_local_only_and_tamper_rejection(self):
        base, lock = self.fixture()
        with patch.dict(bundle.BASE_PINS, {'arm64': {'size': len(base), 'sha256': hashlib.sha256(base).hexdigest()}}):
            first = bundle.build_archive(base, lock, {'app.ipk': b'package'})
            self.assertEqual(first, bundle.build_archive(base, lock, {'app.ipk': b'package'}))
            with tarfile.open(fileobj=io.BytesIO(first)) as archive:
                install = archive.extractfile('bin/install').read().decode()
                self.assertNotIn('! opkg update', install)
                self.assertNotIn('! opkg install', install)
                self.assertIn('/opt/etc/opkg-offline.conf', install)
                self.assertIn('/opt/bin/env -i PATH=', install)
                self.assertIn('OPKG_CONF_DIR=/opt/.xkeen-installer-repository', install)
                self.assertIn('file:///opt/.xkeen-installer-repository', archive.extractfile('etc/opkg-offline.conf').read().decode())
                self.assertEqual(archive.extractfile('.xkeen-installer-repository/app.ipk').read(), b'package')
            for data in ({}, {'app.ipk': b'packagf'}):
                with self.assertRaises(ValueError):
                    bundle.build_archive(base, lock, data)
            with self.assertRaises(ValueError):
                bundle.build_archive(base + b'tamper', lock, {'app.ipk': b'package'})

    def test_bad_download_does_not_publish_partial_repository(self):
        _, lock = self.fixture()
        with tempfile.TemporaryDirectory() as directory, patch.object(bundle, 'fetch', return_value=b'packagf'):
            output = pathlib.Path(directory) / 'repository'
            with self.assertRaises(ValueError):
                bundle.download_repository(lock, output)
            self.assertFalse(output.exists())


class DownloadTests(unittest.TestCase):
    def test_http_initial_url_and_redirect_rejected_before_fetch(self):
        with self.assertRaises(ValueError):
            bundle.secure_url('http://bin.entware.net/package.ipk')
        for url in ('https://evil.invalid/p.ipk', 'https://user:pass@bin.entware.net/p.ipk', 'https://bin.entware.net:8443/p.ipk', 'https://bin.entware.net/p.ipk#x'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                bundle.secure_url(url)
        redirect = bundle.HTTPSRedirect()
        with self.assertRaises(ValueError):
            redirect.redirect_request(None, None, 302, 'downgrade', {}, 'http://bin.entware.net/app.ipk')

    def test_transient_timeout_retries_same_https_without_fallback(self):
        with patch.object(bundle.urllib.request, 'build_opener') as factory, patch.object(bundle.time, 'sleep'):
            factory.return_value.open.side_effect = urllib.error.URLError(TimeoutError('transient'))
            with self.assertRaises(urllib.error.URLError):
                bundle.fetch('https://bin.entware.net/app.ipk', 100)
            self.assertEqual(factory.return_value.open.call_count, 3)
            self.assertTrue(all(call.args[0] == 'https://bin.entware.net/app.ipk' for call in factory.return_value.open.call_args_list))

    def test_real_tls_rejects_untrusted_certificate_without_importing_ca(self):
        if shutil.which('openssl') is None:
            self.skipTest('openssl is required for the isolated TLS fixture')
        with tempfile.TemporaryDirectory() as directory:
            key = str(pathlib.Path(directory) / 'fixture.key')
            cert = str(pathlib.Path(directory) / 'fixture.crt')
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-subj', '/CN=localhost'], check=True, capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server = http.server.HTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # Only the URL allowlist is relaxed to reach this loopback fixture;
                # fetch still constructs its real, certificate-validating SSL context.
                with patch.object(bundle, 'secure_url', side_effect=lambda value: value):
                    with self.assertRaises(urllib.error.URLError) as result:
                        bundle.fetch('https://127.0.0.1:' + str(server.server_port) + '/fixture', 100)
                    self.assertIsInstance(result.exception.reason, ssl.SSLCertVerificationError)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_untrusted_certificate_has_no_fallback(self):
        with patch.object(bundle.urllib.request, 'build_opener') as factory:
            factory.return_value.open.side_effect = ssl.SSLCertVerificationError('untrusted fixture')
            with self.assertRaises(ssl.SSLCertVerificationError):
                bundle.fetch('https://bin.entware.net/app.ipk', 100)
            self.assertEqual(factory.return_value.open.call_count, 1)

    def test_missing_trust_material_stops_before_network(self):
        with patch.object(bundle.ssl, 'create_default_context') as context, patch.object(bundle.urllib.request, 'build_opener') as factory:
            context.return_value.verify_mode = ssl.CERT_REQUIRED
            context.return_value.check_hostname = True
            context.return_value.cert_store_stats.return_value = {'x509_ca': 0}
            with self.assertRaises(ValueError):
                bundle.fetch('https://bin.entware.net/app.ipk', 100)
            factory.assert_not_called()

    def test_limit_and_non_success_response_rejected(self):
        for status, data in ((200, b'12345'), (404, b'bad')):
            response = io.BytesIO(data)
            response.status = status
            with patch.object(bundle.urllib.request, 'build_opener') as factory:
                factory.return_value.open.return_value = response
                with self.assertRaises(ValueError):
                    bundle.fetch('https://bin.entware.net/app.ipk', 4)


if __name__ == '__main__':
    unittest.main()
