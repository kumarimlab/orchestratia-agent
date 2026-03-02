"""Native ConPTY (Windows Pseudo Console) via ctypes.

Replaces pywinpty, which fails in PyInstaller-bundled executables on
Windows 11 24H2+ due to handle lifecycle issues in the .pyd extension.

**Primary path**: Loads a bundled `conpty.dll` + `OpenConsole.exe` from the
Windows Terminal project (MIT-licensed). This bypasses the system conhost.exe,
which has a bug on Win 11 24H2/25H2 where child processes crash with
STATUS_DLL_INIT_FAILED (0xC0000142) when launched via ConPTY.

**Fallback path**: If the bundled DLL is not found, falls back to
kernel32.CreatePseudoConsole (system conhost.exe). This works on older
Windows 10/11 builds that don't have the conhost bug.

Requires Windows 10 build 17763+ (version 1809).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import os
import sys
import time
import uuid

if sys.platform != "win32":
    raise ImportError("conpty is only available on Windows")

kernel32 = ctypes.windll.kernel32

log = logging.getLogger("orchestratia-agent")

# ── Constants ────────────────────────────────────────────────────────
PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STILL_ACTIVE = 259
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102

# Named pipe constants (matching node-pty's approach)
PIPE_ACCESS_INBOUND = 0x00000001
PIPE_ACCESS_OUTBOUND = 0x00000002
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = -1


# ── Structures ───────────────────────────────────────────────────────

class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wt.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wt.BOOL),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("lpReserved", wt.LPWSTR),
        ("lpDesktop", wt.LPWSTR),
        ("lpTitle", wt.LPWSTR),
        ("dwX", wt.DWORD),
        ("dwY", wt.DWORD),
        ("dwXSize", wt.DWORD),
        ("dwYSize", wt.DWORD),
        ("dwXCountChars", wt.DWORD),
        ("dwYCountChars", wt.DWORD),
        ("dwFillAttribute", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("wShowWindow", wt.WORD),
        ("cbReserved2", wt.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wt.HANDLE),
        ("hStdOutput", wt.HANDLE),
        ("hStdError", wt.HANDLE),
    ]


class STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", STARTUPINFOW),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wt.HANDLE),
        ("hThread", wt.HANDLE),
        ("dwProcessId", wt.DWORD),
        ("dwThreadId", wt.DWORD),
    ]


# ── Load bundled conpty.dll or fall back to kernel32 ─────────────────

def _find_bundled_conpty_dll() -> str | None:
    """Locate bundled conpty.dll relative to the running executable/script.

    Search order:
      1. <exe_dir>/conpty/conpty.dll  (PyInstaller one-file: _MEIPASS temp dir)
      2. <script_dir>/conpty/conpty.dll  (development / pip install)
      3. <exe_dir>/conpty.dll  (flat layout)
      4. <script_dir>/conpty.dll  (flat layout)
    """
    search_roots = []

    # PyInstaller sets sys._MEIPASS to the temp extraction directory
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        search_roots.append(meipass)

    # Directory of the running executable (for PyInstaller one-dir or frozen)
    if getattr(sys, "frozen", False):
        search_roots.append(os.path.dirname(sys.executable))

    # Directory of this source file (for development / pip install)
    search_roots.append(os.path.dirname(os.path.abspath(__file__)))

    for root in search_roots:
        # Try conpty/ subdirectory first (matches node-pty layout)
        candidate = os.path.join(root, "conpty", "conpty.dll")
        if os.path.isfile(candidate):
            return candidate
        # Try flat layout
        candidate = os.path.join(root, "conpty.dll")
        if os.path.isfile(candidate):
            return candidate

    return None


def _load_conpty_library():
    """Load the ConPTY library — bundled conpty.dll preferred, kernel32 fallback.

    Returns (dll_handle, use_bundled: bool) tuple.
    When use_bundled=True, function names have a "Conpty" prefix.
    When use_bundled=False, function names are the standard Win32 API names.
    """
    dll_path = _find_bundled_conpty_dll()

    if dll_path:
        # Verify that OpenConsole.exe is alongside the DLL (required by conpty.dll)
        dll_dir = os.path.dirname(dll_path)
        openconsole = os.path.join(dll_dir, "OpenConsole.exe")
        if not os.path.isfile(openconsole):
            log.warning(
                f"Found conpty.dll at {dll_path} but OpenConsole.exe is missing "
                f"from {dll_dir} — falling back to kernel32 (system conhost.exe)"
            )
            return kernel32, False

        try:
            # Use LoadLibraryW so Windows resolves DLL dependencies from its directory
            dll = ctypes.WinDLL(dll_path)
            log.info(f"Loaded bundled conpty.dll from {dll_path}")
            log.info(f"OpenConsole.exe found at {openconsole}")
            return dll, True
        except OSError as e:
            log.warning(f"Failed to load bundled conpty.dll: {e} — falling back to kernel32")
            return kernel32, False

    log.info("Bundled conpty.dll not found — using kernel32 (system conhost.exe)")
    return kernel32, False


_conpty_dll, _use_bundled = _load_conpty_library()


# ── API prototypes ───────────────────────────────────────────────────
# Setting argtypes for ALL functions is critical on 64-bit Windows.
# Without argtypes, ctypes defaults to c_int (32-bit) for integer
# arguments, which can truncate 64-bit HANDLE values.
#
# When using bundled conpty.dll, function names have a "Conpty" prefix:
#   CreatePseudoConsole  -> ConptyCreatePseudoConsole
#   ResizePseudoConsole  -> ConptyResizePseudoConsole
#   ClosePseudoConsole   -> ConptyClosePseudoConsole

def _get_fn(name: str, conpty_name: str):
    """Get function from the loaded DLL, using Conpty-prefixed name if bundled."""
    if _use_bundled:
        return getattr(_conpty_dll, conpty_name)
    return getattr(_conpty_dll, name)


_CreatePseudoConsole = _get_fn("CreatePseudoConsole", "ConptyCreatePseudoConsole")
_CreatePseudoConsole.restype = wt.LONG  # HRESULT
_CreatePseudoConsole.argtypes = [
    wt.DWORD, wt.HANDLE, wt.HANDLE, wt.DWORD,
    ctypes.POINTER(wt.HANDLE),
]

_ResizePseudoConsole = _get_fn("ResizePseudoConsole", "ConptyResizePseudoConsole")
_ResizePseudoConsole.restype = wt.LONG
_ResizePseudoConsole.argtypes = [wt.HANDLE, wt.DWORD]

_ClosePseudoConsole = _get_fn("ClosePseudoConsole", "ConptyClosePseudoConsole")
_ClosePseudoConsole.restype = None
_ClosePseudoConsole.argtypes = [wt.HANDLE]

# These always come from kernel32 (not part of the ConPTY DLL exports)
kernel32.InitializeProcThreadAttributeList.restype = wt.BOOL
kernel32.InitializeProcThreadAttributeList.argtypes = [
    ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.POINTER(ctypes.c_size_t),
]

kernel32.UpdateProcThreadAttribute.restype = wt.BOOL
kernel32.UpdateProcThreadAttribute.argtypes = [
    ctypes.c_void_p, wt.DWORD, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_void_p,
]

kernel32.DeleteProcThreadAttributeList.restype = None
kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]

kernel32.CreatePipe.restype = wt.BOOL
kernel32.CreatePipe.argtypes = [
    ctypes.POINTER(wt.HANDLE),  # hReadPipe
    ctypes.POINTER(wt.HANDLE),  # hWritePipe
    ctypes.POINTER(SECURITY_ATTRIBUTES),  # lpPipeAttributes
    wt.DWORD,                   # nSize
]

kernel32.ReadFile.restype = wt.BOOL
kernel32.ReadFile.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.DWORD,
    ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
]

kernel32.WriteFile.restype = wt.BOOL
kernel32.WriteFile.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.DWORD,
    ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
]

kernel32.PeekNamedPipe.restype = wt.BOOL
kernel32.PeekNamedPipe.argtypes = [
    wt.HANDLE, ctypes.c_void_p, wt.DWORD,
    ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
    ctypes.POINTER(wt.DWORD),
]

kernel32.CreateProcessW.restype = wt.BOOL
kernel32.CreateProcessW.argtypes = [
    wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
    wt.BOOL, wt.DWORD, ctypes.c_void_p, wt.LPCWSTR,
    ctypes.c_void_p, ctypes.POINTER(PROCESS_INFORMATION),
]

kernel32.GetExitCodeProcess.restype = wt.BOOL
kernel32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]

kernel32.TerminateProcess.restype = wt.BOOL
kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]

kernel32.WaitForSingleObject.restype = wt.DWORD
kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]

kernel32.CloseHandle.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]

kernel32.GetLastError.restype = wt.DWORD
kernel32.GetLastError.argtypes = []

# Named pipe APIs (used when bundled conpty.dll is active)
kernel32.CreateNamedPipeW.restype = wt.HANDLE
kernel32.CreateNamedPipeW.argtypes = [
    wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD,
    wt.DWORD, wt.DWORD, wt.DWORD,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
]

kernel32.ConnectNamedPipe.restype = wt.BOOL
kernel32.ConnectNamedPipe.argtypes = [wt.HANDLE, ctypes.c_void_p]

kernel32.CreateFileW.restype = wt.HANDLE
kernel32.CreateFileW.argtypes = [
    wt.LPCWSTR, wt.DWORD, wt.DWORD,
    ctypes.POINTER(SECURITY_ATTRIBUTES),
    wt.DWORD, wt.DWORD, wt.HANDLE,
]


def _create_named_pipe_pair(kind: str) -> tuple[wt.HANDLE, str]:
    """Create a named pipe server handle (bidirectional, like node-pty).

    Returns (server_handle, pipe_name).
    The server handle is passed to ConptyCreatePseudoConsole.
    After CreatePseudoConsole, call ConnectNamedPipe to synchronize.
    """
    pipe_id = uuid.uuid4().hex[:16]
    pipe_name = f"\\\\.\\pipe\\orchestratia-pty-{pipe_id}-{kind}"

    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.lpSecurityDescriptor = None
    sa.bInheritHandle = False  # node-pty uses non-inheritable

    open_mode = (
        PIPE_ACCESS_INBOUND | PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE
    )
    pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT

    handle = kernel32.CreateNamedPipeW(
        pipe_name,
        open_mode,
        pipe_mode,
        1,             # nMaxInstances
        128 * 1024,    # nOutBufferSize (128KB, matches node-pty)
        128 * 1024,    # nInBufferSize
        30000,         # nDefaultTimeOut (30s)
        ctypes.byref(sa),
    )

    if handle is None or handle == wt.HANDLE(INVALID_HANDLE_VALUE).value:
        raise ctypes.WinError()

    return wt.HANDLE(handle), pipe_name


def _pack_coord(cols: int, rows: int) -> int:
    """Pack (cols, rows) into COORD DWORD: X in low word, Y in high word."""
    return ((rows & 0xFFFF) << 16) | (cols & 0xFFFF)


class ConPtyProcess:
    """A process running inside a Windows ConPTY pseudo-console.

    Pure ctypes implementation — zero dependency on pywinpty.
    Uses bundled conpty.dll + OpenConsole.exe when available (bypasses
    broken system conhost.exe on Win 11 24H2/25H2). Falls back to
    kernel32 CreatePseudoConsole on older builds.

    API is compatible with pywinpty's PtyProcess for drop-in replacement.
    """

    def __init__(self) -> None:
        self._hpc: wt.HANDLE | None = None
        self._process_handle: wt.HANDLE | None = None
        self._input_write: wt.HANDLE | None = None
        self._output_read: wt.HANDLE | None = None
        # ConPTY-side pipe ends — must stay open for lifetime of pseudo-console.
        # On Windows 11 24H2+, CreatePseudoConsole does NOT reliably duplicate
        # these handles; closing them severs the ConPTY→pipe I/O path.
        self._pty_input_read: wt.HANDLE | None = None
        self._pty_output_write: wt.HANDLE | None = None
        # Keep references to objects that must stay alive for the ConPTY
        self._attr_buf = None
        self._hpc_ref = None
        self.pid: int = 0
        self._exit_code: int | None = None
        self.using_bundled_conpty: bool = _use_bundled

    @property
    def exitstatus(self) -> int | None:
        if self._exit_code is not None:
            return self._exit_code
        if self._process_handle:
            code = wt.DWORD()
            kernel32.GetExitCodeProcess(self._process_handle, ctypes.byref(code))
            if code.value != STILL_ACTIVE:
                self._exit_code = code.value
        return self._exit_code

    @classmethod
    def spawn(
        cls,
        command: str,
        cwd: str | None = None,
        cols: int = 120,
        rows: int = 40,
    ) -> "ConPtyProcess":
        """Spawn a child process inside a new ConPTY pseudo-console."""
        self = cls()

        if _use_bundled:
            return cls._spawn_named_pipes(self, command, cwd, cols, rows)
        else:
            return cls._spawn_anon_pipes(self, command, cwd, cols, rows)

    @staticmethod
    def _spawn_named_pipes(
        self: "ConPtyProcess",
        command: str,
        cwd: str | None,
        cols: int,
        rows: int,
    ) -> "ConPtyProcess":
        """Spawn using named pipes — matches node-pty/VS Code approach.

        The bundled conpty.dll + OpenConsole.exe requires bidirectional named
        pipes with ConnectNamedPipe synchronization. Anonymous pipes from
        CreatePipe are unidirectional and don't work with the bundled DLL's
        internal I/O routing.
        """
        # ── 1. Create named pipe servers (bidirectional) ─────────────
        pipe_in, in_name = _create_named_pipe_pair("in")
        try:
            pipe_out, out_name = _create_named_pipe_pair("out")
        except Exception:
            kernel32.CloseHandle(pipe_in)
            raise

        log.debug(
            f"ConPTY named pipes (bundled DLL): "
            f"in={in_name} (0x{pipe_in.value or 0:X}) "
            f"out={out_name} (0x{pipe_out.value or 0:X})"
        )

        # ── 2. Create pseudo-console with named pipe server handles ──
        hpc = wt.HANDLE()
        coord = _pack_coord(cols, rows)
        hr = _CreatePseudoConsole(
            coord,
            pipe_in,
            pipe_out,
            0,
            ctypes.byref(hpc),
        )
        if hr != 0:
            kernel32.CloseHandle(pipe_in)
            kernel32.CloseHandle(pipe_out)
            raise OSError(f"ConptyCreatePseudoConsole failed: HRESULT 0x{hr:08X}")

        log.debug(f"ConPTY hpc=0x{hpc.value or 0:X} (bundled DLL)")

        # ── 3. Wait for ConPTY to connect to the named pipes ────────
        # ConnectNamedPipe blocks until the ConPTY (OpenConsole.exe)
        # connects as a client. This synchronization is critical.
        kernel32.ConnectNamedPipe(pipe_in, None)
        kernel32.ConnectNamedPipe(pipe_out, None)
        log.debug("ConPTY connected to named pipes")

        # ── 4. Process thread attribute list ─────────────────────────
        attr_size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))

        attr_buf = (ctypes.c_byte * attr_size.value)()
        if not kernel32.InitializeProcThreadAttributeList(
            attr_buf, 1, 0, ctypes.byref(attr_size)
        ):
            _ClosePseudoConsole(hpc)
            kernel32.CloseHandle(pipe_in)
            kernel32.CloseHandle(pipe_out)
            raise ctypes.WinError()

        hpc_ref = wt.HANDLE(hpc.value)
        if not kernel32.UpdateProcThreadAttribute(
            attr_buf, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            ctypes.byref(hpc_ref), ctypes.sizeof(wt.HANDLE), None, None,
        ):
            kernel32.DeleteProcThreadAttributeList(attr_buf)
            _ClosePseudoConsole(hpc)
            kernel32.CloseHandle(pipe_in)
            kernel32.CloseHandle(pipe_out)
            raise ctypes.WinError()

        # ── 5. Create child process ──────────────────────────────────
        si = STARTUPINFOEX()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        si.lpAttributeList = ctypes.addressof(attr_buf)

        pi = PROCESS_INFORMATION()
        cmd_buf = ctypes.create_unicode_buffer(command)

        success = kernel32.CreateProcessW(
            None, cmd_buf, None, None,
            False, EXTENDED_STARTUPINFO_PRESENT,
            None, cwd, ctypes.byref(si), ctypes.byref(pi),
        )
        kernel32.DeleteProcThreadAttributeList(attr_buf)

        if not success:
            err = ctypes.WinError()
            _ClosePseudoConsole(hpc)
            kernel32.CloseHandle(pipe_in)
            kernel32.CloseHandle(pipe_out)
            raise err

        kernel32.CloseHandle(pi.hThread)

        # With named pipes, both handles are bidirectional:
        # pipe_in = we write to this (input to ConPTY → child stdin)
        # pipe_out = we read from this (child stdout → ConPTY → us)
        self._hpc = wt.HANDLE(hpc.value)
        self._process_handle = wt.HANDLE(pi.hProcess)
        self._input_write = wt.HANDLE(pipe_in.value)
        self._output_read = wt.HANDLE(pipe_out.value)
        self._pty_input_read = None   # Not used with named pipes
        self._pty_output_write = None  # Not used with named pipes
        self.pid = pi.dwProcessId
        self._attr_buf = attr_buf
        self._hpc_ref = hpc_ref

        log.debug(
            f"ConPTY process pid={self.pid} "
            f"proc=0x{pi.hProcess or 0:X} "
            f"in=0x{pipe_in.value or 0:X} "
            f"out=0x{pipe_out.value or 0:X} "
            f"(named pipes, bundled DLL)"
        )
        return self

    @staticmethod
    def _spawn_anon_pipes(
        self: "ConPtyProcess",
        command: str,
        cwd: str | None,
        cols: int,
        rows: int,
    ) -> "ConPtyProcess":
        """Spawn using anonymous pipes — fallback for kernel32 path."""
        # ── 1. Create anonymous pipes ────────────────────────────────
        sa = SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
        sa.lpSecurityDescriptor = None
        sa.bInheritHandle = True

        pipe_in_read = wt.HANDLE()
        pipe_in_write = wt.HANDLE()
        pipe_out_read = wt.HANDLE()
        pipe_out_write = wt.HANDLE()

        if not kernel32.CreatePipe(
            ctypes.byref(pipe_in_read), ctypes.byref(pipe_in_write),
            ctypes.byref(sa), 0
        ):
            raise ctypes.WinError()

        if not kernel32.CreatePipe(
            ctypes.byref(pipe_out_read), ctypes.byref(pipe_out_write),
            ctypes.byref(sa), 0
        ):
            kernel32.CloseHandle(pipe_in_read)
            kernel32.CloseHandle(pipe_in_write)
            raise ctypes.WinError()

        log.debug(
            f"ConPTY anon pipes (kernel32): "
            f"in_r=0x{pipe_in_read.value or 0:X} "
            f"in_w=0x{pipe_in_write.value or 0:X} "
            f"out_r=0x{pipe_out_read.value or 0:X} "
            f"out_w=0x{pipe_out_write.value or 0:X}"
        )

        # ── 2. Create pseudo-console ─────────────────────────────────
        hpc = wt.HANDLE()
        coord = _pack_coord(cols, rows)
        hr = _CreatePseudoConsole(
            coord, pipe_in_read, pipe_out_write, 0, ctypes.byref(hpc),
        )
        if hr != 0:
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise OSError(f"CreatePseudoConsole failed: HRESULT 0x{hr:08X}")

        log.debug(f"ConPTY hpc=0x{hpc.value or 0:X} (kernel32)")

        # ── 3. Process thread attribute list ─────────────────────────
        attr_size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))

        attr_buf = (ctypes.c_byte * attr_size.value)()
        if not kernel32.InitializeProcThreadAttributeList(
            attr_buf, 1, 0, ctypes.byref(attr_size)
        ):
            _ClosePseudoConsole(hpc)
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise ctypes.WinError()

        hpc_ref = wt.HANDLE(hpc.value)
        if not kernel32.UpdateProcThreadAttribute(
            attr_buf, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            ctypes.byref(hpc_ref), ctypes.sizeof(wt.HANDLE), None, None,
        ):
            kernel32.DeleteProcThreadAttributeList(attr_buf)
            _ClosePseudoConsole(hpc)
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise ctypes.WinError()

        # ── 4. Create child process ──────────────────────────────────
        si = STARTUPINFOEX()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        si.lpAttributeList = ctypes.addressof(attr_buf)

        pi = PROCESS_INFORMATION()
        cmd_buf = ctypes.create_unicode_buffer(command)

        success = kernel32.CreateProcessW(
            None, cmd_buf, None, None,
            False, EXTENDED_STARTUPINFO_PRESENT,
            None, cwd, ctypes.byref(si), ctypes.byref(pi),
        )
        kernel32.DeleteProcThreadAttributeList(attr_buf)

        if not success:
            err = ctypes.WinError()
            _ClosePseudoConsole(hpc)
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise err

        kernel32.CloseHandle(pi.hThread)

        self._hpc = wt.HANDLE(hpc.value)
        self._process_handle = wt.HANDLE(pi.hProcess)
        self._input_write = wt.HANDLE(pipe_in_write.value)
        self._output_read = wt.HANDLE(pipe_out_read.value)
        self._pty_input_read = wt.HANDLE(pipe_in_read.value)
        self._pty_output_write = wt.HANDLE(pipe_out_write.value)
        self.pid = pi.dwProcessId
        self._attr_buf = attr_buf
        self._hpc_ref = hpc_ref

        log.debug(
            f"ConPTY process pid={self.pid} "
            f"proc=0x{pi.hProcess or 0:X} "
            f"in=0x{pipe_in_write.value or 0:X} "
            f"out=0x{pipe_out_read.value or 0:X} "
            f"(anon pipes, kernel32)"
        )
        return self

    def peek(self) -> int:
        """Check how many bytes are available to read without blocking."""
        if not self._output_read:
            return 0
        available = wt.DWORD()
        success = kernel32.PeekNamedPipe(
            self._output_read, None, 0, None, ctypes.byref(available), None,
        )
        if not success:
            return -1
        return available.value

    def read(self, size: int = 4096) -> str:
        """Read from ConPTY output pipe. Returns str. Raises EOFError on close."""
        if not self._output_read:
            raise EOFError("ConPTY pipe not open")
        buf = ctypes.create_string_buffer(size)
        bytes_read = wt.DWORD()
        success = kernel32.ReadFile(
            self._output_read, buf, size, ctypes.byref(bytes_read), None,
        )
        if not success or bytes_read.value == 0:
            err = kernel32.GetLastError()
            raise EOFError(f"ConPTY pipe closed (ReadFile={success}, err={err})")
        return buf.raw[: bytes_read.value].decode("utf-8", errors="replace")

    def write(self, data: str | bytes) -> None:
        """Write to ConPTY input pipe."""
        if not self._input_write:
            return
        if isinstance(data, str):
            data = data.encode("utf-8")
        written = wt.DWORD()
        success = kernel32.WriteFile(
            self._input_write, data, len(data), ctypes.byref(written), None,
        )
        if not success:
            err = kernel32.GetLastError()
            log.warning(f"ConPTY WriteFile failed: err={err}")

    def isalive(self) -> bool:
        """Check if the child process is still running."""
        if self._exit_code is not None:
            return False
        if not self._process_handle:
            return False
        code = wt.DWORD()
        kernel32.GetExitCodeProcess(self._process_handle, ctypes.byref(code))
        if code.value == STILL_ACTIVE:
            return True
        self._exit_code = code.value
        return False

    def setwinsize(self, rows: int, cols: int) -> None:
        """Resize the pseudo-console."""
        if self._hpc:
            _ResizePseudoConsole(self._hpc, _pack_coord(cols, rows))

    def terminate(self, force: bool = False) -> None:
        """Terminate the child process."""
        if self._process_handle:
            kernel32.TerminateProcess(self._process_handle, 1)

    def close(self) -> None:
        """Close all handles."""
        if self._hpc:
            _ClosePseudoConsole(self._hpc)
            self._hpc = None
        # Close ConPTY-side pipe ends AFTER ClosePseudoConsole
        if self._pty_input_read:
            kernel32.CloseHandle(self._pty_input_read)
            self._pty_input_read = None
        if self._pty_output_write:
            kernel32.CloseHandle(self._pty_output_write)
            self._pty_output_write = None
        if self._input_write:
            kernel32.CloseHandle(self._input_write)
            self._input_write = None
        if self._output_read:
            kernel32.CloseHandle(self._output_read)
            self._output_read = None
        if self._process_handle:
            kernel32.CloseHandle(self._process_handle)
            self._process_handle = None
        self._attr_buf = None
        self._hpc_ref = None

    def __del__(self) -> None:
        self.close()
