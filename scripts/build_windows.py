"""Build the single-file, console-free Windows GUI distribution."""

from pathlib import Path
import subprocess
import sys


def main():
    if sys.platform != "win32":
        raise SystemExit("Build the Windows executable on Windows.")

    root = Path(__file__).resolve().parents[1]
    staged = root / "build" / "pyinstaller-dist" / "Node2Shell Radar.exe"
    release = root / "release" / "Node2Shell Radar.exe"
    icon_source = root / "radar" / "data" / "app-icon.svg"
    icon_outputs = [root / "radar" / "data" / name for name in ("app-icon.png", "app-icon.ico")]
    if any(not path.exists() or path.stat().st_mtime < icon_source.stat().st_mtime for path in icon_outputs):
        subprocess.run([sys.executable, str(root / "scripts" / "build_icon.py")], cwd=root, check=True)
    command = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--distpath", str(staged.parent),
        "--workpath", str(root / "build" / "pyinstaller"),
        str(root / "Node2Shell-Radar.spec"),
    ]
    subprocess.run(command, cwd=root, check=True)
    release.parent.mkdir(exist_ok=True)
    try:
        staged.replace(release)
    except PermissionError as exc:
        raise SystemExit(
            f"Close Node2Shell Radar before replacing {release}. "
            f"The new build is ready at {staged}.") from exc
    print(release)


if __name__ == "__main__":
    main()
