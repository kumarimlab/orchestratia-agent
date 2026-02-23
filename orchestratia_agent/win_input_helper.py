"""Helper script to inject keyboard events via WriteConsoleInput.

Spawned as a separate process to avoid disrupting the agent's console.
Usage: python -m orchestratia_agent.win_input_helper <pid> [char]

Attaches to the target process's console, writes a KEY_EVENT INPUT_RECORD,
and exits. This bypasses ConPTY's VT-to-key-event translation, which fails
for some TUI apps (e.g., Codex CLI doesn't register \\r as Enter).
"""

import ctypes
import ctypes.wintypes
import sys


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m orchestratia_agent.win_input_helper <pid> [char]", file=sys.stderr)
        sys.exit(1)

    pid = int(sys.argv[1])
    char = sys.argv[2] if len(sys.argv) > 2 else "\r"

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # Attach to the target process's console (ConPTY pseudo-console)
    if not kernel32.AttachConsole(ctypes.wintypes.DWORD(pid)):
        err = ctypes.get_last_error()
        print(f"AttachConsole({pid}) failed: error {err}", file=sys.stderr)
        sys.exit(1)

    # Get console input handle (STD_INPUT_HANDLE = -10)
    handle = kernel32.GetStdHandle(ctypes.wintypes.DWORD(0xFFFFFFF6))
    if handle in (-1, 0, None):
        print("GetStdHandle failed", file=sys.stderr)
        kernel32.FreeConsole()
        sys.exit(2)

    # ── Define INPUT_RECORD structures ──

    class KEY_EVENT_RECORD(ctypes.Structure):
        _fields_ = [
            ("bKeyDown", ctypes.wintypes.BOOL),
            ("wRepeatCount", ctypes.wintypes.WORD),
            ("wVirtualKeyCode", ctypes.wintypes.WORD),
            ("wVirtualScanCode", ctypes.wintypes.WORD),
            ("uChar", ctypes.c_wchar),
            ("dwControlKeyState", ctypes.wintypes.DWORD),
        ]

    class INPUT_RECORD_UNION(ctypes.Union):
        _fields_ = [("KeyEvent", KEY_EVENT_RECORD)]

    class INPUT_RECORD(ctypes.Structure):
        _anonymous_ = ("_Event",)
        _fields_ = [
            ("EventType", ctypes.wintypes.WORD),
            ("_Event", INPUT_RECORD_UNION),
        ]

    # Map character to virtual key code and scan code
    KEY_EVENT_TYPE = 0x0001
    if char == "\r":
        vk = 0x0D   # VK_RETURN
        scan = 0x1C  # Enter scan code
    elif char == "\n":
        vk = 0x0D
        scan = 0x1C
    elif char == "\x1b":
        vk = 0x1B   # VK_ESCAPE
        scan = 0x01
    else:
        vk = ord(char.upper()) if char.isalpha() else ord(char)
        scan = 0

    # Create key-down + key-up events
    records = (INPUT_RECORD * 2)()
    for i, key_down in enumerate([True, False]):
        records[i].EventType = KEY_EVENT_TYPE
        records[i].KeyEvent.bKeyDown = key_down
        records[i].KeyEvent.wRepeatCount = 1
        records[i].KeyEvent.wVirtualKeyCode = vk
        records[i].KeyEvent.wVirtualScanCode = scan
        records[i].KeyEvent.uChar = char
        records[i].KeyEvent.dwControlKeyState = 0

    written = ctypes.wintypes.DWORD()
    result = kernel32.WriteConsoleInputW(handle, records, 2, ctypes.byref(written))

    kernel32.FreeConsole()

    if result and written.value == 2:
        print("OK")
        sys.exit(0)
    else:
        err = ctypes.get_last_error()
        print(f"WriteConsoleInputW failed: result={result}, written={written.value}, err={err}", file=sys.stderr)
        sys.exit(3)


if __name__ == "__main__":
    main()
