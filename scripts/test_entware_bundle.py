import hashlib
import importlib.util
import io
import pathlib
import ssl
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

    def test_missing_dependency_and_unsupported_alternative_fail_closed(self):
        for depends in ('missing', 'lib | other'):
            records = bundle.parse_index(stanza('app', depends).encode(), 'https://bin.entware.net/test')
            with self.assertRaises(ValueError):
                bundle.closure(records, ['app'])

    def test_reject_duplicate_fields_packages_and_unsafe_filenames(self):
        for text in (stanza('app') + stanza('app'), stanza('app').replace('Version:', 'Package: app\nVersion:'), stanza('app', filename='../outside.ipk'), stanza('app', filename='https://evil.invalid/app.ipk'), stanza('app').replace('SHA256sum:', 'MD5Sum:')):
            with self.subTest(text=text), self.assertRaises(ValueError):
                bundle.parse_index(text.encode(), 'https://bin.entware.net/test')

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

    def test_untrusted_certificate_has_no_fallback(self):
        with patch.object(bundle.urllib.request, 'build_opener') as factory:
            factory.return_value.open.side_effect = ssl.SSLCertVerificationError('untrusted fixture')
            with self.assertRaises(ssl.SSLCertVerificationError):
                bundle.fetch('https://bin.entware.net/app.ipk', 100)
            self.assertEqual(factory.return_value.open.call_count, 1)

    def test_missing_trust_material_stops_before_network(self):
        with patch.object(bundle.ssl, 'create_default_context') as context, patch.object(bundle.urllib.request, 'build_opener') as factory:
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
