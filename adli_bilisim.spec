# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build specification embedding multi-resolution DFIR app_icon.ico into Windows .exe."""

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('src/ui/assets/*.png', 'src/ui/assets'),
        ('src/ui/assets/*.ico', 'src/ui/assets'),
        ('docs/*.md', 'docs'),
    ],
    hiddenimports=[
        'PySide6.QtSvg',
        'reportlab.graphics.barcode',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AdliBilisimIncelemeSistemi',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    icon='src/ui/assets/app_icon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AdliBilisimIncelemeSistemi',
)
