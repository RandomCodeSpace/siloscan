"""Unit tests for the PTY driver's stream parsing, against a fake stream.

No pseudo-terminal is opened here. What is under test is the part that decides
whether a session did what it was asked to: where text lands on the screen,
which escape sequences move the cursor, and how the alternate-screen and
frame-history assertions read the stream. Getting that wrong makes the hosted
TUI lane pass for the wrong reason, which is the failure worth a unit test.
"""

import unittest

import tui_pty


def render(*chunks: str) -> tui_pty.Screen:
    screen = tui_pty.Screen(lines=4, columns=20)
    for chunk in chunks:
        screen.feed(chunk)
    return screen


class ScreenTest(unittest.TestCase):
    def test_plain_text_lands_on_the_first_line(self):
        screen = render("hello")
        self.assertEqual(screen.text().splitlines()[0], "hello")

    def test_carriage_return_and_newline_move_the_cursor(self):
        screen = render("one\r\ntwo")
        self.assertEqual(screen.text().splitlines()[:2], ["one", "two"])

    def test_absolute_positioning_places_text(self):
        screen = render("\x1b[3;5Hhere")
        self.assertEqual(screen.text().splitlines()[2], "    here")

    def test_relative_cursor_moves(self):
        screen = render("\x1b[2;2Hab\x1b[2Dx\x1b[1Bz")
        lines = screen.text().splitlines()
        self.assertEqual(lines[1], " xb")
        self.assertEqual(lines[2], "  z")

    def test_erase_display_clears_everything(self):
        screen = render("keep\x1b[2J")
        self.assertEqual(screen.text().strip(), "")

    def test_erase_line_clears_from_the_cursor(self):
        screen = render("abcdef\x1b[1;4H\x1b[K")
        self.assertEqual(screen.text().splitlines()[0], "abc")

    def test_colour_sequences_draw_nothing(self):
        screen = render("\x1b[31mred\x1b[0m")
        self.assertEqual(screen.text().splitlines()[0], "red")

    def test_private_modes_draw_nothing(self):
        screen = render(tui_pty.ENTER_ALTERNATE_SCREEN + "x" + tui_pty.LEAVE_ALTERNATE_SCREEN)
        self.assertEqual(screen.text().splitlines()[0], "x")

    def test_operating_system_commands_are_skipped(self):
        screen = render("\x1b]0;a window title\x07done")
        self.assertEqual(screen.text().splitlines()[0], "done")

    def test_an_escape_split_across_reads_is_not_printed(self):
        screen = render("\x1b[3;", "5Hhere")
        self.assertEqual(screen.text().splitlines()[2], "    here")

    def test_a_cursor_position_request_is_counted_and_draws_nothing(self):
        screen = render("a\x1b[6nb")
        self.assertEqual(screen.cursor_requests, 1)
        self.assertEqual(screen.text().splitlines()[0], "ab")

    def test_text_wraps_at_the_right_margin(self):
        screen = render("x" * 22)
        lines = screen.text().splitlines()
        self.assertEqual(lines[0], "x" * 20)
        self.assertEqual(lines[1], "xx")

    def test_the_raw_stream_keeps_the_escapes(self):
        screen = render("\x1b[2Jtext")
        self.assertIn("\x1b[2J", screen.raw)


class SessionTest(unittest.TestCase):
    def session(self) -> tui_pty.Session:
        return tui_pty.Session()

    def test_a_leave_before_the_marker_does_not_count(self):
        session = self.session()
        session.screen.feed(tui_pty.LEAVE_ALTERNATE_SCREEN + "ready")
        session.marker_offset = len(session.screen.raw)
        self.assertFalse(session.left_alternate_screen())

    def test_a_leave_after_the_marker_counts(self):
        session = self.session()
        session.screen.feed("ready")
        session.marker_offset = len(session.screen.raw)
        session.screen.feed(tui_pty.LEAVE_ALTERNATE_SCREEN)
        self.assertTrue(session.left_alternate_screen())

    def test_frames_keep_text_the_next_frame_overwrote(self):
        session = self.session()
        session.frames.append("refused: read-only")
        session.frames.append("dashboard")
        self.assertTrue(session.contains("refused: read-only"))
        self.assertFalse(session.contains("nothing like this"))

    def test_cursor_requests_are_answered_once_each(self):
        written = []

        class FakeTerminal:
            @staticmethod
            def write(fd, data):
                written.append(data)
                return len(data)

        session = self.session()
        session.screen.feed("\x1b[1;1H\x1b[6n")
        original = tui_pty.os.write
        tui_pty.os.write = FakeTerminal.write
        try:
            session.answer_cursor_requests(0)
            session.answer_cursor_requests(0)
        finally:
            tui_pty.os.write = original
        self.assertEqual(written, [b"\x1b[1;1R"])


class KeyTest(unittest.TestCase):
    def test_plain_keys_pass_through(self):
        self.assertEqual(tui_pty.decode_key("q"), b"q")

    def test_escapes_are_decoded(self):
        self.assertEqual(tui_pty.decode_key("\\r"), b"\r")
        self.assertEqual(tui_pty.decode_key("\\x1b"), b"\x1b")


if __name__ == "__main__":
    unittest.main()
