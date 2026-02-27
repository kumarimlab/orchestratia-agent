# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for orchestratia-agent standalone Windows executable.
#
# Build: pyinstaller orchestratia_agent.spec
# Output: dist/orchestratia-agent.exe (~25-30MB)

a = Analysis(
    ['orchestratia_agent/main.py'],
    pathex=[],
    binaries=[],
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
        # pywinpty (Windows ConPTY)
        'winpty',
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
