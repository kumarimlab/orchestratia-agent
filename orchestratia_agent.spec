# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for orchestratia-agent standalone Windows executable.
#
# Build: pyinstaller orchestratia_agent.spec
# Output: dist/orchestratia-agent.exe (~25-30MB)
#
# The conpty/ directory must exist in the build root with:
#   conpty/conpty.dll      - ConPTY library from Windows Terminal (MIT)
#   conpty/OpenConsole.exe - Console host from Windows Terminal (MIT)
# These are downloaded by the CI workflow before building.

import os

# Detect if bundled ConPTY files are available (CI downloads them)
conpty_binaries = []
conpty_dir = os.path.join(os.getcwd(), 'conpty')
if os.path.isdir(conpty_dir):
    dll_path = os.path.join(conpty_dir, 'conpty.dll')
    exe_path = os.path.join(conpty_dir, 'OpenConsole.exe')
    if os.path.isfile(dll_path) and os.path.isfile(exe_path):
        # Place both files in conpty/ subdirectory inside the bundle.
        # conpty.dll uses GetModuleFileName to find OpenConsole.exe
        # in its own directory, so they MUST be in the same folder.
        conpty_binaries = [
            (dll_path, 'conpty'),
            (exe_path, 'conpty'),
        ]
        print(f"Including bundled ConPTY: {dll_path}, {exe_path}")
    else:
        print("WARNING: conpty/ dir exists but missing conpty.dll or OpenConsole.exe")
else:
    print("NOTE: conpty/ dir not found — building without bundled ConPTY (will use system conhost)")

a = Analysis(
    ['orchestratia_agent/main.py'],
    pathex=[],
    binaries=conpty_binaries,
    datas=[],
    hiddenimports=[
        # All orchestratia_agent modules
        'orchestratia_agent',
        'orchestratia_agent.cli',
        'orchestratia_agent.config',
        'orchestratia_agent.hub',
        'orchestratia_agent.logging_config',
        'orchestratia_agent.session',
        'orchestratia_agent.session_base',
        'orchestratia_agent.session_windows',
        'orchestratia_agent.conpty',
        'orchestratia_agent.system',
        'orchestratia_agent.tmux',
        'orchestratia_agent.win_input_helper',
        # httpx transport chain
        'httpx._transports.default',
        'httpcore._backends.anyio',
        'httpcore._async.http11',
        'httpcore._async.http_proxy',
        'httpcore._async.connection',
        'httpcore._async.connection_pool',
        'h11',
        'h11._connection',
        'h11._events',
        'h11._state',
        'anyio._backends._asyncio',
        'sniffio',
        # websockets
        'websockets',
        'websockets.legacy',
        'websockets.legacy.client',
        'websockets.asyncio',
        'websockets.asyncio.client',
        # psutil Windows backend
        'psutil',
        'psutil._pswindows',
        'psutil._common',
        # pyte virtual terminal
        'pyte',
        'pyte.screens',
        'pyte.streams',
        # yaml
        'yaml',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        # Exclude POSIX-only modules to reduce size
        'orchestratia_agent.session_posix',
        'termios',
        'fcntl',
        'pty',
        # Exclude unused stdlib modules
        'tkinter',
        'unittest',
        'xmlrpc',
        'pydoc',
        'doctest',
        'test',
        # No longer needed — using bundled conpty.dll instead
        'winpty',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='orchestratia-agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
)
