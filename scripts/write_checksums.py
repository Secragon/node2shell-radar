"""Write SHA-256 sums for the release assets in a directory."""

import hashlib
from pathlib import Path
import sys


def main():
    folder = Path(sys.argv[1])
    packages = sorted(path for path in folder.iterdir() if path.suffix == ".exe" or path.name.endswith(".tar.gz"))
    if len(packages) != 2:
        raise SystemExit(f"Expected Windows and Linux packages, got {len(packages)}")
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in packages]
    (folder / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Checksums written for:", ", ".join(path.name for path in packages))


if __name__ == "__main__":
    main()
