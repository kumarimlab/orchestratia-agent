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

        # ── 1. Create pipes ──────────────────────────────────────────
        # Use SECURITY_ATTRIBUTES with bInheritHandle=TRUE.
        # While the Microsoft sample passes NULL, some Windows 11 builds
        # require inheritable handles for the ConPTY to properly duplicate
        # and use the pipe ends internally.
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

        conpty_mode = "bundled conpty.dll" if _use_bundled else "kernel32 (system conhost)"
        log.debug(
            f"ConPTY pipes ({conpty_mode}): "
            f"in_r=0x{pipe_in_read.value or 0:X} "
            f"in_w=0x{pipe_in_write.value or 0:X} "
            f"out_r=0x{pipe_out_read.value or 0:X} "
            f"out_w=0x{pipe_out_write.value or 0:X}"
        )

        # ── 2. Create pseudo-console ─────────────────────────────────
        hpc = wt.HANDLE()
        coord = _pack_coord(cols, rows)
        hr = _CreatePseudoConsole(
            coord,
            pipe_in_read,
            pipe_out_write,
            0,
            ctypes.byref(hpc),
        )
        if hr != 0:
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise OSError(f"CreatePseudoConsole failed: HRESULT 0x{hr:08X}")

        log.debug(f"ConPTY hpc=0x{hpc.value or 0:X} (via {'bundled DLL' if _use_bundled else 'kernel32'})")

        # IMPORTANT: Do NOT close pipe_in_read / pipe_out_write here.
        # On Windows 11 24H2 (build 26100+), CreatePseudoConsole does NOT
        # reliably duplicate these handles internally.  Closing them before
        # ClosePseudoConsole severs the I/O path and results in 0 bytes ever
        # appearing in the output pipe.  Keep them alive on self and close
        # them only in close() alongside the pseudo-console itself.

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

        # Store HPCON in a ctypes handle so we can pass its address.
        # CRITICAL: keep a reference to both attr_buf and hpc_ref on self
        # so they are NOT garbage collected while the process is running.
        # UpdateProcThreadAttribute stores a POINTER to hpc_ref, not a copy.
        hpc_ref = wt.HANDLE(hpc.value)
        if not kernel32.UpdateProcThreadAttribute(
            attr_buf,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            ctypes.byref(hpc_ref),
            ctypes.sizeof(wt.HANDLE),
            None,
            None,
        ):
            kernel32.DeleteProcThreadAttributeList(attr_buf)
            _ClosePseudoConsole(hpc)
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise ctypes.WinError()

        # ── 4. Create process ────────────────────────────────────────
        si = STARTUPINFOEX()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        si.lpAttributeList = ctypes.addressof(attr_buf)

        pi = PROCESS_INFORMATION()

        cmd_buf = ctypes.create_unicode_buffer(command)

        success = kernel32.CreateProcessW(
            None,                          # lpApplicationName
            cmd_buf,                       # lpCommandLine
            None,                          # lpProcessAttributes
            None,                          # lpThreadAttributes
            False,                         # bInheritHandles
            EXTENDED_STARTUPINFO_PRESENT,  # dwCreationFlags
            None,                          # lpEnvironment (inherit)
            cwd,                           # lpCurrentDirectory
            ctypes.byref(si),              # lpStartupInfo
            ctypes.byref(pi),              # lpProcessInformation
        )

        # Clean up attribute list AFTER CreateProcessW
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
        # Keep ConPTY-side pipe ends alive (see note above about Win 11 24H2)
        self._pty_input_read = wt.HANDLE(pipe_in_read.value)
        self._pty_output_write = wt.HANDLE(pipe_out_write.value)
        self.pid = pi.dwProcessId
        # Prevent GC of objects that the attribute list pointed to
        self._attr_buf = attr_buf
        self._hpc_ref = hpc_ref

        log.debug(
            f"ConPTY process pid={self.pid} "
            f"proc=0x{pi.hProcess or 0:X} "
            f"in=0x{pipe_in_write.value or 0:X} "
            f"out=0x{pipe_out_read.value or 0:X}"
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
