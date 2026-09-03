#!/usr/bin/env python3
"""Drive a terminal UI under a fixed 120x40 pseudo-terminal and assert what it did.

The TUI lanes cannot be checked by capturing stdout: without a terminal the UI
refuses to start, and with one the output is a stream of cursor moves rather
than lines. So this driver gives the command a real pseudo-terminal, renders
what the command draws into a screen the same size the frozen captures use,
waits for a marker to appear, sends keys, and then asserts four things:

* the exit status;
* that the alternate screen was left after the marker, so the session did not
  die inside it;
* that raw mode was turned off again, read back from the terminal itself
  rather than from anything the program printed;
* that named strings did or did not appear on screen.

Only the standard library is used, and only on Linux and macOS: Windows has no
``pty`` module, so there the driver prints why it did nothing and succeeds. The
hosted TUI gate runs on Linux.
"""

from __future__ import annotations

import argparse
import codecs
import hashlib
import os
import select
import subprocess
import sys
import time

COLUMNS = 120
LINES = 40

ENTER_ALTERNATE_SCREEN = "\x1b[?1049h"
LEAVE_ALTERNATE_SCREEN = "\x1b[?1049l"

# How long the driver waits for a frame to stop changing after a keystroke, and
# how long it keeps waiting for one to arrive at all. A redraw is one write of
# a few kilobytes, so idling this long means the UI has finished with the key.
SETTLE_IDLE = 0.35
SETTLE_LIMIT = 5.0


class DriverError(Exception):
    """The session could not be driven: a timeout, a spawn failure, bad usage."""


class AssertionFailure(Exception):
    """The session ran and did not do what it was asked to prove."""


class Screen:
    """A fixed-size character grid fed with what the command wrote.

    Enough of the terminal to place the text a full-screen UI draws: cursor
    positioning, relative cursor moves, the two erase commands, and the control
    characters. Everything else - colours, mouse modes, alternate screen - moves
    no text and is skipped. The raw stream is kept too, because the
    alternate-screen assertion is about the escape bytes rather than the text.
    """

    def __init__(self, lines: int = LINES, columns: int = COLUMNS) -> None:
        self.lines = lines
        self.columns = columns
        self.grid = [[" "] * columns for _ in range(lines)]
        self.line = 0
        self.column = 0
        self.raw = ""
        self.cursor_requests = 0
        self._pending = ""

    def feed(self, text: str) -> None:
        self.raw += text
        data = self._pending + text
        self._pending = ""
        index = 0
        while index < len(data):
            char = data[index]
            if char == "\x1b":
                consumed = self._escape(data, index)
                if consumed is None:
                    # An escape sequence split across two reads. Keep it for
                    # the next chunk rather than printing its letters.
                    self._pending = data[index:]
                    return
                index += consumed
                continue
            index += 1
            if char == "\n":
                self.line = min(self.line + 1, self.lines - 1)
            elif char == "\r":
                self.column = 0
            elif char == "\b":
                self.column = max(self.column - 1, 0)
            elif char == "\t":
                self.column = min((self.column // 8 + 1) * 8, self.columns - 1)
            elif char >= " ":
                self._put(char)

    def text(self) -> str:
        return "\n".join("".join(line).rstrip() for line in self.grid)

    def _put(self, char: str) -> None:
        if self.column >= self.columns:
            self.column = 0
            self.line = min(self.line + 1, self.lines - 1)
        self.grid[self.line][self.column] = char
        self.column += 1

    def _escape(self, data: str, start: int) -> int | None:
        """How many characters the escape sequence at `start` occupies.

        `None` means the sequence is incomplete and the caller should wait for
        more input rather than treating its bytes as text.
        """
        if start + 1 >= len(data):
            return None
        introducer = data[start + 1]
        if introducer == "[":
            return self._control_sequence(data, start)
        if introducer in "]P^_":
            return self._string_sequence(data, start)
        if introducer in "()*+":
            # A character-set designation: the introducer and one more byte.
            return 3 if start + 2 < len(data) else None
        return 2

    def _control_sequence(self, data: str, start: int) -> int | None:
        index = start + 2
        while index < len(data) and data[index] in "0123456789;:?<>=!$\"' ":
            index += 1
        if index >= len(data):
            return None
        self._apply(data[start + 2 : index], data[index])
        return index - start + 1

    def _string_sequence(self, data: str, start: int) -> int | None:
        """An OSC, DCS, PM or APC string, ended by BEL or ST. It draws nothing."""
        bell = data.find("\x07", start)
        terminator = data.find("\x1b\\", start + 2)
        if bell < 0 and terminator < 0:
            return None
        if bell >= 0 and (terminator < 0 or bell < terminator):
            return bell - start + 1
        return terminator - start + 2

    def _apply(self, parameters: str, final: str) -> None:
        if final == "n" and parameters.lstrip("?") == "6":
            # A cursor-position request. The UI blocks on the answer at
            # startup, so the driver has to count these and reply.
            self.cursor_requests += 1
            return
        if parameters.startswith("?"):
            # A private mode: alternate screen, mouse reporting, cursor
            # visibility. None of them moves the cursor or writes a character.
            return
        numbers = []
        for field in parameters.split(";"):
            try:
                numbers.append(int(field))
            except ValueError:
                numbers.append(0)
        first = numbers[0] if numbers else 0

        if final in "Hf":
            self.line = self._clamp(numbers[0] if numbers else 1, self.lines)
            self.column = self._clamp(numbers[1] if len(numbers) > 1 else 1, self.columns)
        elif final == "A":
            self.line = max(self.line - max(first, 1), 0)
        elif final == "B":
            self.line = min(self.line + max(first, 1), self.lines - 1)
        elif final == "C":
            self.column = min(self.column + max(first, 1), self.columns - 1)
        elif final == "D":
            self.column = max(self.column - max(first, 1), 0)
        elif final == "G":
            self.column = self._clamp(first if first else 1, self.columns)
        elif final == "d":
            self.line = self._clamp(first if first else 1, self.lines)
        elif final == "J":
            self._erase_display(first)
        elif final == "K":
            self._erase_line(first)

    @staticmethod
    def _clamp(value: int, limit: int) -> int:
        return max(0, min(value - 1, limit - 1))

    def _erase_display(self, mode: int) -> None:
        if mode in (2, 3):
            self.grid = [[" "] * self.columns for _ in range(self.lines)]
            return
        if mode == 0:
            self._erase_line(0)
            for line in range(self.line + 1, self.lines):
                self.grid[line] = [" "] * self.columns
            return
        self._erase_line(1)
        for line in range(0, self.line):
            self.grid[line] = [" "] * self.columns

    def _erase_line(self, mode: int) -> None:
        if mode == 1:
            span = range(0, min(self.column + 1, self.columns))
        elif mode == 2:
            span = range(0, self.columns)
        else:
            span = range(self.column, self.columns)
        for column in span:
            self.grid[self.line][column] = " "


class Session:
    """One driven pseudo-terminal session and everything it produced."""

    def __init__(self) -> None:
        self.screen = Screen()
        self.frames: list[str] = []
        self.status: int | None = None
        self.marker_offset: int | None = None
        self.raw_mode_restored: bool | None = None
        self.answered_cursor_requests = 0

    def answer_cursor_requests(self, master: int) -> None:
        """Reply to every cursor-position request the UI has made.

        A real terminal answers `ESC[6n`, and crossterm waits for that answer
        before it will hand back a terminal at all. Nothing else the UI sends
        needs a reply.
        """
        while self.answered_cursor_requests < self.screen.cursor_requests:
            self.answered_cursor_requests += 1
            report = f"\x1b[{self.screen.line + 1};{self.screen.column + 1}R"
            os.write(master, report.encode("ascii"))

    def contains(self, needle: str) -> bool:
        return any(needle in frame for frame in self.frames)

    def left_alternate_screen(self) -> bool:
        """The leave sequence, after the point the marker was first drawn.

        Taken after the marker on purpose: a session that never started would
        also leave the alternate screen, and that is not what this proves.
        """
        offset = self.marker_offset or 0
        return self.screen.raw.find(LEAVE_ALTERNATE_SCREEN, offset) >= 0


def decode_key(key: str) -> bytes:
    """A key as bytes, accepting the usual escapes so `\\r` can be sent."""
    return codecs.decode(key.encode("utf-8"), "unicode_escape").encode("latin-1")


def digest(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def raw_mode_is_off(fd: int) -> bool:
    """Whether the terminal is back in its cooked state.

    Read from the terminal rather than from the program's output: raw mode is a
    `tcsetattr` call and prints nothing, so a session that restored the
    alternate screen and left the terminal raw would look identical on the
    stream and be unusable afterwards.
    """
    import termios

    try:
        attributes = termios.tcgetattr(fd)
    except termios.error:
        return False
    local = attributes[3]
    return bool(local & termios.ECHO) and bool(local & termios.ICANON)


def open_terminal() -> tuple[int, int]:
    import fcntl
    import pty
    import struct
    import termios

    master, slave = pty.openpty()
    # Set before the child starts, so the first frame it draws is already the
    # size the frozen captures were taken at.
    size = struct.pack("HHHH", LINES, COLUMNS, 0, 0)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, size)
    return master, slave


def spawn(command: list[str], slave: int, cwd: str | None, environment: dict[str, str]):
    import fcntl
    import termios

    def become_terminal_leader() -> None:
        # A new session plus TIOCSCTTY makes this pty the child's controlling
        # terminal, so a UI that opens /dev/tty reaches the driver's terminal
        # and not the one the test runner was started from.
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    return subprocess.Popen(
        command,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=cwd,
        env=environment,
        preexec_fn=become_terminal_leader,
    )


def read_available(master: int, session: Session, deadline: float, decoder) -> bool:
    """Feed whatever is readable before `deadline`. False on end of input."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return True
    readable, _, _ = select.select([master], [], [], min(remaining, 0.1))
    if not readable:
        return True
    try:
        chunk = os.read(master, 65536)
    except OSError:
        return False
    if not chunk:
        return False
    session.screen.feed(decoder.decode(chunk))
    session.answer_cursor_requests(master)
    return True


def wait_for_marker(master: int, session: Session, marker: str, timeout: float, decoder) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in session.screen.text():
            session.marker_offset = len(session.screen.raw)
            session.frames.append(session.screen.text())
            return
        if not read_available(master, session, deadline, decoder):
            break
    raise DriverError(
        f"the marker {marker!r} never appeared within {timeout:g}s\n"
        f"--- screen ---\n{session.screen.text()}"
    )


def settle(master: int, session: Session, decoder) -> None:
    """Read until the UI stops drawing, then record the frame it settled on."""
    limit = time.monotonic() + SETTLE_LIMIT
    idle_until = time.monotonic() + SETTLE_IDLE
    while time.monotonic() < min(limit, idle_until):
        before = len(session.screen.raw)
        if not read_available(master, session, min(limit, idle_until), decoder):
            break
        if len(session.screen.raw) != before:
            idle_until = time.monotonic() + SETTLE_IDLE
    session.frames.append(session.screen.text())


def drain(master: int, session: Session, process, timeout: float, decoder) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not read_available(master, session, deadline, decoder):
            break
        if process.poll() is not None and not select.select([master], [], [], 0)[0]:
            break
    session.frames.append(session.screen.text())


def drive(
    command: list[str],
    marker: str,
    keys: list[str],
    timeout: float,
    cwd: str | None,
    environment: dict[str, str],
) -> Session:
    session = Session()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    master, slave = open_terminal()
    try:
        process = spawn(command, slave, cwd, environment)
    except OSError as error:
        os.close(master)
        os.close(slave)
        raise DriverError(f"cannot run {command[0]}: {error}") from error
    # The parent must not hold the slave open, or reads on the master never see
    # end of input after the child exits.
    os.close(slave)

    try:
        wait_for_marker(master, session, marker, timeout, decoder)
        for key in keys:
            os.write(master, decode_key(key))
            settle(master, session, decoder)
        drain(master, session, process, timeout, decoder)
        try:
            session.status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait()
            raise DriverError(f"the session did not exit within {timeout:g}s") from error
        session.raw_mode_restored = raw_mode_is_off(master)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        os.close(master)
    return session


def check(session: Session, arguments: argparse.Namespace, unchanged: dict[str, str]) -> None:
    problems = []
    if session.status != arguments.status:
        problems.append(f"exit status {session.status}, expected {arguments.status}")
    if not session.left_alternate_screen():
        problems.append("the alternate screen was never left after the marker")
    if not session.raw_mode_restored:
        problems.append("raw mode was still enabled when the session ended")
    for needle in arguments.expect:
        if not session.contains(needle):
            problems.append(f"{needle!r} never appeared on screen")
    for needle in arguments.absent:
        if session.contains(needle):
            problems.append(f"{needle!r} appeared on screen and should not have")
    for path, before in unchanged.items():
        if digest(path) != before:
            problems.append(f"{path} changed and should not have")
    if problems:
        raise AssertionFailure(
            "\n".join(problems) + "\n--- final screen ---\n" + session.screen.text()
        )


def parse_environment(pairs: list[str]) -> dict[str, str]:
    environment = dict(os.environ)
    for pair in pairs:
        name, separator, value = pair.partition("=")
        if not separator:
            raise DriverError(f"--env expects NAME=VALUE, got {pair!r}")
        environment[name] = value
    return environment


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", required=True, help="text to wait for before sending keys")
    parser.add_argument("--key", action="append", default=[], help="key to send, in order")
    parser.add_argument("--expect", action="append", default=[], help="text that must appear")
    parser.add_argument("--absent", action="append", default=[], help="text that must not appear")
    parser.add_argument("--status", type=int, default=0, help="the exit status to require")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--cwd")
    parser.add_argument("--env", action="append", default=[], help="NAME=VALUE for the child")
    parser.add_argument(
        "--unchanged",
        action="append",
        default=[],
        help="file whose bytes must be the same afterwards",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args(argv)

    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required after --")

    if os.name != "posix":
        print("skip: this driver needs a POSIX pseudo-terminal; the TUI gate runs on Linux")
        return 0

    try:
        unchanged = {path: digest(path) for path in arguments.unchanged}
        session = drive(
            command,
            arguments.marker,
            arguments.key,
            arguments.timeout,
            arguments.cwd,
            parse_environment(arguments.env),
        )
        check(session, arguments, unchanged)
    except AssertionFailure as error:
        print(f"FAIL {' '.join(command)}\n{error}", file=sys.stderr)
        return 1
    except DriverError as error:
        print(f"ERROR {' '.join(command)}\n{error}", file=sys.stderr)
        return 2

    print(
        f"ok {' '.join(command)}: exit {session.status}, "
        f"{len(arguments.key)} key(s), terminal restored"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
