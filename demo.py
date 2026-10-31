"""Synthetic scanner subprocess responses; no network or Trivy execution."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import scanner


def main():
    with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as directory:
        root = Path(directory)
        repo = root / 'repo'
        repo.mkdir()
        exe = root / 'synthetic-executable'
        exe.write_bytes(b'fixture only')
        receipt = root / 'receipt.json'
        receipt.write_text(json.dumps({'version': scanner.VERSION, 'signature_verified': True,
                                      'binary_sha256': scanner.digest(exe.read_bytes())}))
        def runner(argv):
            if '--version' in argv:
                return SimpleNamespace(returncode=0, stdout=f'Version: {scanner.VERSION}\n'.encode())
            data = {} if '--download-db-only' in argv else {
                'SchemaVersion': 2, 'Results': [{'Secrets': [{'Severity': 'HIGH', 'Match': 'synthetic value'}]}]}
            return SimpleNamespace(returncode=0, stdout=json.dumps(data).encode(), stderr=b'')
        scanner.scan_many([repo], exe, receipt, root / 'out', runner)
        summary = json.loads((root / 'out' / 'summary.json').read_text())
        print('secret_high=' + str(summary['repositories'][0]['counts']['secrets']['HIGH']))


if __name__ == '__main__':
    main()
