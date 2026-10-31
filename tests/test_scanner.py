import hashlib
import json
from types import SimpleNamespace
import zipfile
import pytest
import scanner


def result(code=0, data=None, stderr=b''):
    return SimpleNamespace(returncode=code, stdout=json.dumps(data).encode(), stderr=stderr)


def fixture(tmp_path):
    exe = tmp_path / 'trivy'
    exe.write_bytes(b'synthetic executable')
    receipt = tmp_path / 'receipt.json'
    receipt.write_text(json.dumps({'version': scanner.VERSION, 'signature_verified': True,
                                  'binary_sha256': scanner.digest(exe.read_bytes())}))
    repo = tmp_path / 'repo'
    repo.mkdir()
    return exe, receipt, repo


@pytest.mark.parametrize('severity,expected', [('LOW', 0), ('HIGH', 20), ('CRITICAL', 20)])
def test_scan_counts_only(tmp_path, capsys, severity, expected):
    exe, receipt, repo = fixture(tmp_path)
    fake = 'synthetic-' + 'private-value'
    def runner(argv):
        if '--version' in argv:
            return SimpleNamespace(returncode=0, stdout=f'Version: {scanner.VERSION}\n'.encode())
        if '--download-db-only' in argv:
            return result()
        assert '--skip-db-update' in argv and '--offline-scan' in argv
        return result(data={'SchemaVersion': 2, 'Results': [{'Secrets': [
            {'Severity': severity, 'Match': fake, 'Code': fake, 'Title': fake}],
            'Target': fake}]})
    out = tmp_path / 'out'
    assert scanner.scan_many([repo], exe, receipt, out, runner) == expected
    text = (out / 'summary.json').read_text() + capsys.readouterr().out
    assert fake not in text
    data = json.loads((out / 'summary.json').read_text())
    assert data['repositories'][0]['counts']['secrets'][severity] == 1
    assert data['wrapper_sha256'] == scanner.digest(scanner.HERE.joinpath('scanner.py').read_bytes())


@pytest.mark.parametrize('response,code', [(result(1), 10), (result(stderr=b'429 fixture'), 29),
                                         (result(stderr=b'FATAL fixture'), 10),
                                         (result(data={}), 10)])
def test_failure_stops_following_repositories(tmp_path, response, code):
    exe, receipt, repo = fixture(tmp_path)
    calls = []
    def runner(argv):
        calls.append(argv)
        if '--version' in argv:
            return SimpleNamespace(returncode=0, stdout=f'Version: {scanner.VERSION}\n'.encode())
        if '--download-db-only' in argv:
            return result()
        return response
    out = tmp_path / 'out'
    assert scanner.scan_many([repo, repo], exe, receipt, out, runner) == code
    assert len(calls) == 3
    assert json.loads((out / 'summary.json').read_text())['repositories'][1]['status'] == 'not_scanned'
    assert not (out / 'scan.lock').exists()


@pytest.mark.parametrize('signature_ok,checksum_ok', [(True, True), (False, True), (True, False)])
def test_release_verification(tmp_path, signature_ok, checksum_ok):
    archive = tmp_path / f'trivy_{scanner.VERSION}_Windows-64bit.zip'
    with zipfile.ZipFile(archive, 'w') as package:
        package.writestr('trivy.exe', b'synthetic executable')
        package.writestr('../escape', b'never extracted')
    checksum = tmp_path / 'checksums.txt'
    checksum.write_text(f'{hashlib.sha256(archive.read_bytes()).hexdigest() if checksum_ok else "0" * 64}  {archive.name}\n')
    out = tmp_path / 'tools'
    def runner(argv):
        assert '--certificate-identity' in argv
        assert argv[argv.index('--certificate-identity') + 1].endswith('v' + scanner.VERSION)
        return result(0 if signature_ok else 1)
    if signature_ok and checksum_ok:
        receipt = scanner.verify_release(archive, checksum, tmp_path / 'bundle', out, runner=runner)
        assert receipt['binary_sha256'] == scanner.digest((out / 'trivy.exe').read_bytes())
        assert not (tmp_path / 'escape').exists()
    else:
        with pytest.raises(ValueError):
            scanner.verify_release(archive, checksum, tmp_path / 'bundle', out, runner=runner)
        assert not out.exists()


def test_modified_binary_rejected(tmp_path):
    exe, receipt, _ = fixture(tmp_path)
    exe.write_bytes(b'changed')
    with pytest.raises(ValueError):
        scanner.trusted(exe, receipt, lambda _: pytest.fail('must not execute changed binary'))


def test_schema_rejected():
    with pytest.raises(ValueError):
        scanner.counts(b'{"SchemaVersion": 2}')


def test_stale_success_replaced_before_verification(tmp_path):
    exe, receipt, repo = fixture(tmp_path)
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'summary.json').write_text('{"complete": true}')
    exe.write_bytes(b'tampered')
    with pytest.raises(ValueError):
        scanner.scan_many([repo], exe, receipt, out)
    assert json.loads((out / 'summary.json').read_text())['complete'] is False
    assert not (out / 'scan.lock').exists()


def test_lock_prevents_overlap(tmp_path):
    exe, receipt, repo = fixture(tmp_path)
    out = tmp_path / 'out'
    out.mkdir()
    (out / 'scan.lock').write_text('held')
    with pytest.raises(FileExistsError):
        scanner.scan_many([repo], exe, receipt, out)
    assert (out / 'scan.lock').read_text() == 'held'
