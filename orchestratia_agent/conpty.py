"""Native ConPTY (Windows Pseudo Console) via ctypes.

Replaces pywinpty, which fails in PyInstaller-bundled executables on
Windows 11 24H2+ due to handle lifecycle issues in the .pyd extension.

Uses kernel32 CreatePseudoConsole with anonymous pipes.
Requires Windows 10 build 17763+ (version 1809).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import logging
import sys

if sys.platform != "win32":
    raise ImportError("conpty is only available on Windows")

kernel32 = ctypes.windll.kernel32

log = logging.getLogger("orchestratia-agent")

# ── Constants ────────────────────────────────────────────────────────
PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STARTF_USESTDHANDLES = 0x00000100
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


# ── API prototypes ───────────────────────────────────────────────────
# Setting argtypes for ALL functions is critical on 64-bit Windows.
# Without argtypes, ctypes defaults to c_int (32-bit) for integer
# arguments, which can truncate 64-bit HANDLE values.

kernel32.CreatePseudoConsole.restype = wt.LONG  # HRESULT
kernel32.CreatePseudoConsole.argtypes = [
    wt.DWORD, wt.HANDLE, wt.HANDLE, wt.DWORD,
    ctypes.POINTER(wt.HANDLE),
]

kernel32.ResizePseudoConsole.restype = wt.LONG
kernel32.ResizePseudoConsole.argtypes = [wt.HANDLE, wt.DWORD]

kernel32.ClosePseudoConsole.restype = None
kernel32.ClosePseudoConsole.argtypes = [wt.HANDLE]

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
    Uses kernel32 CreatePseudoConsole with anonymous pipes.

    API is compatible with pywinpty's PtyProcess for drop-in replacement.
    """

    def __init__(self) -> None:
        self._hpc: wt.HANDLE | None = None
        self._process_handle: wt.HANDLE | None = None
        self._input_write: wt.HANDLE | None = None
        self._output_read: wt.HANDLE | None = None
        # ConPTY-side pipe ends — must stay open for lifetime of pseudo-console
        self._pty_input_read: wt.HANDLE | None = None
        self._pty_output_write: wt.HANDLE | None = None
        # Keep reference to attr_buf so it's not garbage collected
        self._attr_buf = None
        self.pid: int = 0
        self._exit_code: int | None = None

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
            f"ConPTY pipes: "
            f"in_r=0x{pipe_in_read.value or 0:X} "
            f"in_w=0x{pipe_in_write.value or 0:X} "
            f"out_r=0x{pipe_out_read.value or 0:X} "
            f"out_w=0x{pipe_out_write.value or 0:X}"
        )

        # ── 2. Create pseudo-console ─────────────────────────────────
        hpc = wt.HANDLE()
        coord = _pack_coord(cols, rows)
        hr = kernel32.CreatePseudoConsole(
            coord, pipe_in_read, pipe_out_write, 0, ctypes.byref(hpc),
        )
        if hr != 0:
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise OSError(f"CreatePseudoConsole failed: HRESULT 0x{hr:08X}")

        log.debug(f"ConPTY hpc=0x{hpc.value or 0:X}")

        # ── 3. Process thread attribute list ─────────────────────────
        attr_size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))

        attr_buf = (ctypes.c_byte * attr_size.value)()
        if not kernel32.InitializeProcThreadAttributeList(
            attr_buf, 1, 0, ctypes.byref(attr_size)
        ):
            kernel32.ClosePseudoConsole(hpc)
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise ctypes.WinError()

        # HPCON is already a void* — pass its value directly, not byref.
        if not kernel32.UpdateProcThreadAttribute(
            attr_buf, 0, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
            hpc.value, ctypes.sizeof(wt.HANDLE), None, None,
        ):
            kernel32.DeleteProcThreadAttributeList(attr_buf)
            kernel32.ClosePseudoConsole(hpc)
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise ctypes.WinError()

        # ── 4. Create child process ──────────────────────────────────
        si = STARTUPINFOEX()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
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
            kernel32.ClosePseudoConsole(hpc)
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
            kernel32.ResizePseudoConsole(self._hpc, _pack_coord(cols, rows))

    def terminate(self, force: bool = False) -> None:
        """Terminate the child process."""
        if self._process_handle:
            kernel32.TerminateProcess(self._process_handle, 1)

    def close(self) -> None:
        """Close all handles."""
        if self._hpc:
            kernel32.ClosePseudoConsole(self._hpc)
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

    def __del__(self) -> None:
        self.close()
