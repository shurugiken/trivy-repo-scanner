"""Pinned, locally scheduled Trivy scans with count-only output."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zipfile

VERSION = '0.76.1'
HERE = Path(__file__).resolve().parent
SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')
ASSETS = {f'trivy_{VERSION}_Windows-64bit.zip': 'trivy.exe',
          f'trivy_{VERSION}_Linux-64bit.tar.gz': 'trivy'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def invoke(argv):
    # Native streams may contain source values. Keep them in memory only.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('TRIVY_')}
    return subprocess.run([str(item) for item in argv], capture_output=True,
                          stdin=subprocess.DEVNULL, timeout=1200, env=env)


def verify_release(archive, checksums, bundle, output, cosign='cosign', runner=invoke):
    # https://www.trivy.dev/docs/latest/getting-started/signature-verification/
    archive, output = Path(archive), Path(output)
    if archive.name not in ASSETS or output.exists():
        raise ValueError('unsupported asset or existing destination')
    data = archive.read_bytes()
    matches = []
    for line in Path(checksums).read_text(encoding='utf-8').splitlines():
        match = re.fullmatch(r'([a-fA-F0-9]{64})\s+\*?(.+)', line)
        if match and match[2] == archive.name:
            matches.append(match[1].lower())
    if matches != [digest(data)]:
        raise ValueError('checksum failed')
    identity = ('https://github.com/aquasecurity/trivy/.github/workflows/'
                f'reusable-release.yaml@refs/tags/v{VERSION}')
    result = runner([cosign, 'verify-blob', archive, '--bundle', bundle,
                     '--certificate-identity', identity,
                     '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com'])
    if result.returncode:
        raise ValueError('signature failed')
    # Recheck bytes after the external verifier; never extract arbitrary paths.
    if archive.read_bytes() != data:
        raise ValueError('asset changed')
    name = ASSETS[archive.name]
    if archive.suffix == '.zip':
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            entries = [item for item in package.infolist() if item.filename == name]
            if len(entries) != 1 or entries[0].file_size > 512 * 1024 * 1024:
                raise ValueError('invalid executable entry')
            binary = package.read(entries[0])
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as package:
            entries = [item for item in package.getmembers() if item.name == name]
            if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 512 * 1024 * 1024:
                raise ValueError('invalid executable entry')
            binary = package.extractfile(entries[0]).read()
    if not binary:
        raise ValueError('empty executable')
    output.mkdir(parents=True)
    exe = output / name
    exe.write_bytes(binary)
    exe.chmod(0o755)
    receipt = {'version': VERSION, 'binary_sha256': digest(binary),
               'archive_sha256': digest(data), 'signature_verified': True}
    (output / 'verified.json').write_text(json.dumps(receipt) + '\n', encoding='utf-8')
    return receipt


def trusted(executable, receipt, runner):
    record = json.loads(Path(receipt).read_text(encoding='utf-8'))
    if (record.get('version') != VERSION or record.get('signature_verified') is not True
            or record.get('binary_sha256') != digest(Path(executable).read_bytes())):
        raise ValueError('binary provenance failed')
    version = runner([executable, '--version'])
    if version.returncode or not re.search(
            rb'(?m)^Version: ' + re.escape(VERSION.encode()) + rb'\r?$', version.stdout):
        raise ValueError('version mismatch')
    return record


def native_status(result):
    if re.search(rb'\b429\b|TOOMANYREQUESTS|rate.limit', result.stderr, re.I):
        return 29
    if result.returncode or re.search(rb'\b(?:ERROR|FATAL)\b', result.stderr):
        return 10
    return 0


def counts(raw):
    data = json.loads(raw)
    if not isinstance(data, dict) or data.get('SchemaVersion') != 2 or not isinstance(data.get('Results'), list):
        raise ValueError('invalid report')
    totals = {kind: dict.fromkeys(SEVERITIES, 0) for kind in ('vulnerabilities', 'secrets')}
    for result in data['Results']:
        if not isinstance(result, dict):
            raise ValueError('invalid result')
        for field, kind in [('Vulnerabilities', 'vulnerabilities'), ('Secrets', 'secrets')]:
            findings = result.get(field) or []
            if not isinstance(findings, list):
                raise ValueError('invalid findings')
            for item in findings:
                if not isinstance(item, dict):
                    raise ValueError('invalid finding')
                severity = item.get('Severity', 'UNKNOWN')
                if severity not in SEVERITIES:
                    severity = 'UNKNOWN'
                totals[kind][severity] += 1
    return totals


def scan_many(repos, executable, receipt, out, runner=invoke):
    out = Path(out).resolve()
    repos = [Path(repo).resolve(strict=True) for repo in repos]
    if not repos or any(not repo.is_dir() or out.is_relative_to(repo) for repo in repos):
        raise ValueError('invalid repository or output location')
    out.mkdir(parents=True, exist_ok=True)
    lock = out / 'scan.lock'
    # No stale lock removal: the operator reviews an interrupted run.
    with lock.open('x'):
        pass
    try:
        (out / 'summary.json').write_text(
            json.dumps({'complete': False, 'exit': 10, 'repositories': []}) + '\n', encoding='utf-8')
        provenance = trusted(executable, receipt, runner)
        base = ['--config', HERE / 'empty.yaml', '--disable-telemetry',
                '--skip-version-check', '--no-progress', '--timeout', '15m',
                '--cache-dir', out / 'cache']
        prepare = runner([executable, 'fs', *base, '--download-db-only'])
        status = native_status(prepare)
        results = []
        for index, repo in enumerate(repos, 1):
            if status:
                results.append({'repository': index, 'status': 'not_scanned'})
                continue
            result = runner([executable, 'fs', *base, '--skip-db-update',
                             '--offline-scan', '--scanners', 'vuln,secret',
                             '--include-dev-deps', '--ignorefile', HERE / 'empty.ignore',
                             '--secret-config', HERE / 'secret.yaml',
                             '--format', 'json', '--exit-code', '0', repo])
            status = native_status(result)
            if status:
                results.append({'repository': index, 'status': 'failed'})
                continue
            try:
                count = counts(result.stdout)
            except (ValueError, TypeError):
                status = 10
                results.append({'repository': index, 'status': 'failed'})
                continue
            results.append({'repository': index, 'status': 'complete', 'counts': count})
        high = any(sum(item['counts'][kind][severity] for kind in ('secrets', 'vulnerabilities')
                       for severity in ('HIGH', 'CRITICAL'))
                   for item in results if item['status'] == 'complete')
        code = status or (20 if high else 0)
        summary = {'complete': status == 0, 'exit': code, 'version': VERSION,
                   'wrapper_sha256': digest(Path(__file__).read_bytes()),
                   'release': provenance, 'repositories': results}
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        print(f'complete={str(status == 0).lower()} repositories={len(repos)} exit={code}')
        return code
    finally:
        lock.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    verify = commands.add_parser('verify')
    for name in ('archive', 'checksums', 'bundle', 'out'):
        verify.add_argument('--' + name, required=True, type=Path)
    run = commands.add_parser('run')
    for name in ('repos', 'executable', 'receipt', 'out'):
        run.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'verify':
            verify_release(args.archive, args.checksums, args.bundle, args.out)
            print('checksum=verified signature=verified version=' + VERSION)
            return 0
        repos = json.loads(args.repos.read_text(encoding='utf-8'))
        if not isinstance(repos, list) or any(not isinstance(item, str) for item in repos):
            raise ValueError('invalid repository list')
        return scan_many(repos, args.executable, args.receipt, args.out)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile):
        print('ERROR: scan incomplete; native output withheld')
        return 10


if __name__ == '__main__':
    raise SystemExit(main())
