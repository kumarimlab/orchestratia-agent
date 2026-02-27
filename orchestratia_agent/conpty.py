"""Native ConPTY (Windows Pseudo Console) via ctypes.

Replaces pywinpty, which fails in PyInstaller-bundled executables on
Windows 11 24H2+ due to handle lifecycle issues in the .pyd extension.

Uses the Windows Pseudo Console API directly through kernel32.dll.
Requires Windows 10 build 17763+ (version 1809).
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import sys

if sys.platform != "win32":
    raise ImportError("conpty is only available on Windows")

kernel32 = ctypes.windll.kernel32

# ── Constants ────────────────────────────────────────────────────────
PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
STILL_ACTIVE = 259


# ── Structures ───────────────────────────────────────────────────────

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
# COORD is a 4-byte struct (SHORT X, SHORT Y) passed by value.
# We pack it as a DWORD: cols (X) in low 16 bits, rows (Y) in high 16 bits.

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


def _pack_coord(cols: int, rows: int) -> int:
    """Pack (cols, rows) into COORD DWORD: X in low word, Y in high word."""
    return ((rows & 0xFFFF) << 16) | (cols & 0xFFFF)


class ConPtyProcess:
    """A process running inside a Windows ConPTY pseudo-console.

    Pure ctypes implementation — zero dependency on pywinpty.
    API is compatible with pywinpty's PtyProcess for drop-in replacement.
    """

    def __init__(self) -> None:
        self._hpc: int | None = None
        self._process_handle: int | None = None
        self._input_write: int | None = None
        self._output_read: int | None = None
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

        # ── 1. Create pipes ──────────────────────────────────────────
        # Input:  we write → pipe_in_write → [ConPTY] → child stdin
        # Output: child stdout → [ConPTY] → pipe_out_write → pipe_out_read → we read
        pipe_in_read = wt.HANDLE()
        pipe_in_write = wt.HANDLE()
        pipe_out_read = wt.HANDLE()
        pipe_out_write = wt.HANDLE()

        if not kernel32.CreatePipe(
            ctypes.byref(pipe_in_read), ctypes.byref(pipe_in_write), None, 0
        ):
            raise ctypes.WinError()

        if not kernel32.CreatePipe(
            ctypes.byref(pipe_out_read), ctypes.byref(pipe_out_write), None, 0
        ):
            kernel32.CloseHandle(pipe_in_read)
            kernel32.CloseHandle(pipe_in_write)
            raise ctypes.WinError()

        # ── 2. Create pseudo-console ─────────────────────────────────
        hpc = wt.HANDLE()
        coord = _pack_coord(cols, rows)
        hr = kernel32.CreatePseudoConsole(
            coord,
            pipe_in_read.value,
            pipe_out_write.value,
            0,
            ctypes.byref(hpc),
        )
        if hr != 0:
            for h in (pipe_in_read, pipe_in_write, pipe_out_read, pipe_out_write):
                kernel32.CloseHandle(h)
            raise OSError(f"CreatePseudoConsole failed: HRESULT 0x{hr:08X}")

        # Pseudo-console now owns these pipe ends — close our copies
        kernel32.CloseHandle(pipe_in_read)
        kernel32.CloseHandle(pipe_out_write)

        # ── 3. Process thread attribute list ─────────────────────────
        attr_size = ctypes.c_size_t(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))

        attr_buf = (ctypes.c_byte * attr_size.value)()
        if not kernel32.InitializeProcThreadAttributeList(
            attr_buf, 1, 0, ctypes.byref(attr_size)
        ):
            kernel32.ClosePseudoConsole(hpc)
            kernel32.CloseHandle(pipe_in_write)
            kernel32.CloseHandle(pipe_out_read)
            raise ctypes.WinError()

        # Store HPCON in a ctypes pointer so we can pass its address
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
            kernel32.ClosePseudoConsole(hpc)
            kernel32.CloseHandle(pipe_in_write)
            kernel32.CloseHandle(pipe_out_read)
            raise ctypes.WinError()

        # ── 4. Create process ────────────────────────────────────────
        si = STARTUPINFOEX()
        si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEX)
        si.lpAttributeList = ctypes.addressof(attr_buf)

        pi = PROCESS_INFORMATION()

        # CreateProcessW requires a mutable command-line buffer
        cmd_buf = ctypes.create_unicode_buffer(command)

        success = kernel32.CreateProcessW(
            None,                          # lpApplicationName
            cmd_buf,                       # lpCommandLine (mutable)
            None,                          # lpProcessAttributes
            None,                          # lpThreadAttributes
            False,                         # bInheritHandles
            EXTENDED_STARTUPINFO_PRESENT,  # dwCreationFlags
            None,                          # lpEnvironment (inherit)
            cwd,                           # lpCurrentDirectory
            ctypes.byref(si),              # lpStartupInfo
            ctypes.byref(pi),              # lpProcessInformation
        )

        kernel32.DeleteProcThreadAttributeList(attr_buf)

        if not success:
            err = ctypes.WinError()
            kernel32.ClosePseudoConsole(hpc)
            kernel32.CloseHandle(pipe_in_write)
            kernel32.CloseHandle(pipe_out_read)
            raise err

        # Close thread handle — we only need the process handle
        kernel32.CloseHandle(pi.hThread)

        self._hpc = hpc.value
        self._process_handle = pi.hProcess
        self._input_write = pipe_in_write.value
        self._output_read = pipe_out_read.value
        self.pid = pi.dwProcessId

        return self

    def read(self, size: int = 4096) -> str:
        """Read from ConPTY output pipe. Returns str. Raises EOFError on close."""
        buf = ctypes.create_string_buffer(size)
        bytes_read = wt.DWORD()
        success = kernel32.ReadFile(
            self._output_read, buf, size, ctypes.byref(bytes_read), None,
        )
        if not success or bytes_read.value == 0:
            raise EOFError("ConPTY pipe closed")
        return buf.raw[: bytes_read.value].decode("utf-8", errors="replace")

    def write(self, data: str | bytes) -> None:
        """Write to ConPTY input pipe."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        written = wt.DWORD()
        kernel32.WriteFile(
            self._input_write, data, len(data), ctypes.byref(written), None,
        )

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
        if self._input_write:
            kernel32.CloseHandle(self._input_write)
            self._input_write = None
        if self._output_read:
            kernel32.CloseHandle(self._output_read)
            self._output_read = None
        if self._process_handle:
            kernel32.CloseHandle(self._process_handle)
            self._process_handle = None

    def __del__(self) -> None:
        self.close()
