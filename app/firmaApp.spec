# -*- mode: python ; coding: utf-8 -*-
# python -m PyInstaller --clean firmaApp.spec
import os

block_cipher = None

# Preparar lista de datos de forma correcta
datas = [('../package', 'package'),
        ('pk_entidad.json', '.'),
        ('img/Diego.ico', '.'),
        ('img/Diego.png', '.'),
        ('tkdnd', 'tkdnd'), 
        ('img', 'img'),
        ('../LICENSE', '.')
]

a = Analysis(
    ['firmaApp.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=['dilithium_py', 'dilithium_py.ml_dsa', 'fitz', 'PyMuPDF', 'tkinterdnd2'],
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
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Autofirma SafeInQ',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='img/Diego.ico',
)