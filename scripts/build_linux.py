"""Build a portable Linux archive on Linux (PyInstaller cannot cross-compile)."""

import io
from pathlib import Path
import platform
import subprocess
import sys
import tarfile


def main():
    if not sys.platform.startswith("linux"):
        raise SystemExit("Build the Linux archive on Linux.")

    root = Path(__file__).resolve().parents[1]
    binary = root / "build" / "linux-dist" / "Node2Shell-Radar"
    release = root / "release" / f"Node2Shell-Radar-linux-{platform.machine().lower()}.tar.gz"
    (root / "build" / "pyinstaller-linux").mkdir(parents=True, exist_ok=True)
    subprocess.run([
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
        "--name", binary.name, "--collect-data", "radar", "--paths", str(root),
        "--distpath", str(binary.parent),
        "--workpath", str(root / "build" / "pyinstaller-linux"),
        "--specpath", str(root / "build" / "pyinstaller-linux"),
        str(root / "radar" / "__main__.py"),
    ], cwd=root, check=True)

    release.parent.mkdir(exist_ok=True)
    instructions = ("Node2Shell Radar for Linux\n\n"
                    "Extract this archive, then run ./Node2Shell-Radar.\n"
                    "The executable needs a desktop session and standard Linux graphics libraries.\n"
                    "No Python installation is required.\n")
    with tarfile.open(release, "w:gz") as archive:
        archive.add(binary, arcname=binary.name)
        archive.add(root / "radar" / "data" / "app-icon.png", arcname="app-icon.png")
        data = instructions.encode("utf-8")
        info = tarfile.TarInfo("README-linux.txt")
        info.size = len(data)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(data))
    print(release)


if __name__ == "__main__":
    main()
