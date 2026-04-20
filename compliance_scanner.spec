# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

# Collect customtkinter theme/asset files
customtkinter_datas = collect_data_files('customtkinter')

# Collect all reportlab submodules (it uses internal dynamic loading)
reportlab_hidden = collect_submodules('reportlab')

a = Analysis(
    ['ui/final_gui.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('rulesets', 'rulesets'),
        ('settings.json', '.'),
    ] + customtkinter_datas,
    hiddenimports=[
        # jsonschema internals loaded dynamically
        'jsonschema',
        'jsonschema.validators',
        'jsonschema._types',
        'jsonschema._format',
        'jsonschema.exceptions',
        # Custom compliance functions (loaded via importlib at runtime)
        'core.custom_functions.access_control',
        'core.custom_functions.identification_authentication',
        'core.custom_functions.configuration_management',
        'core.custom_functions.system_communications_protection',
        'core.custom_functions.audit_accountability',
        'core.custom_functions.system_information_integrity',
        'core.custom_functions.firewall',
        'core.custom_functions.users',
        # OS-specific scanners (selected at runtime)
        'core.scanners.windows',
        'core.scanners.debian',
        'core.scanners.base_scanner',
    ] + reportlab_hidden,
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

_icon = 'assets\\icon.ico' if os.path.exists('assets\\icon.ico') else None

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ComplianceScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=_icon,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='ComplianceScanner',
)
