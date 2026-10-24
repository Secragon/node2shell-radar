# -*- mode: python ; coding: utf-8 -*-
"""Single-file Windows GUI build.

Qt6Core uses the Windows system ICU (icuuc.dll). Build environments can have an
unrelated ICU DLL on PATH; PyInstaller may collect it as a false dependency.
That DLL lacks Qt's required exports and makes QtCore fail at startup.
"""

from pathlib import Path
import tomllib

from PyInstaller.utils.hooks import collect_data_files
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo,
    VarStruct, VSVersionInfo,
)


project = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))['project']
version = project['version']
number = tuple(map(int, version.split('.'))) + (0,)
windows_version = VSVersionInfo(
    ffi=FixedFileInfo(filevers=number, prodvers=number),
    kids=[
        StringFileInfo([StringTable('040904B0', [
            StringStruct('CompanyName', 'Secragon'),
            StringStruct('FileDescription', project['description']),
            StringStruct('FileVersion', version),
            StringStruct('OriginalFilename', 'Node2Shell Radar.exe'),
            StringStruct('ProductName', 'Node2Shell Radar'),
            StringStruct('ProductVersion', version),
        ])]),
        VarFileInfo([VarStruct('Translation', [1033, 1200])]),
    ],
)


a = Analysis(
    ['radar/__main__.py'],
    pathex=[str(Path.cwd())],
    binaries=[],
    datas=collect_data_files('radar'),
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# Never shadow Windows' ICU with one picked up from an unrelated program.
a.binaries = [entry for entry in a.binaries if Path(entry[0]).name.lower() != 'icuuc.dll']

pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Node2Shell Radar',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    icon='radar/data/app-icon.ico',
    version=windows_version,
    console=False,
)
