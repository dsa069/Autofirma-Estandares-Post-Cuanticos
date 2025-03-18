# -*- mode: python ; coding: utf-8 -*-
import os

block_cipher = None

# Preparar lista de datos de forma correcta
datas = [('../package', 'package'), 
        ('sk_entidad.json', '.'),  # Copiar sk_entidad.json en el mismo directorio del EXE
        ('pk_entidad.json', '.')   # Copiar pk_entidad.json en el mismo directorio del EXE
]  # Esto siempre se incluye

a = Analysis(
    ['entGenApp.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=['dilithium_py', 'dilithium_py.ml_dsa'],
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
    name='EntidadGeneradora',
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
)