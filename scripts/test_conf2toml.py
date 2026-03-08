#!/usr/bin/env python3
"""
test_conf2toml.py — Unit tests for the conf2toml.py migration script.

Run with:
    python3 scripts/test_conf2toml.py
or:
    python3 -m pytest scripts/test_conf2toml.py -v
"""

import sys
import unittest
from pathlib import Path

# Allow importing conf2toml regardless of cwd
sys.path.insert(0, str(Path(__file__).parent))
from conf2toml import Conf2Toml, to_toml_value, tcl_unquote, _strip_tcl_comment


class TestTclHelpers(unittest.TestCase):
    """Low-level Tcl parsing helpers."""

    def test_unquote_double(self):
        self.assertEqual(tcl_unquote('"hello"'), "hello")

    def test_unquote_braces(self):
        self.assertEqual(tcl_unquote('{hello world}'), "hello world")

    def test_unquote_bare(self):
        self.assertEqual(tcl_unquote('42'), "42")

    def test_strip_comment_semicolon(self):
        self.assertEqual(_strip_tcl_comment('set nick "Bot" ; # comment'), 'set nick "Bot"')

    def test_strip_comment_no_comment(self):
        self.assertEqual(_strip_tcl_comment('set nick "Bot"'), 'set nick "Bot"')

    def test_strip_comment_semicolon_in_quotes(self):
        # Semicolon inside a quoted string must NOT be treated as comment start
        self.assertEqual(
            _strip_tcl_comment('set realname "a;b"'),
            'set realname "a;b"'
        )


class TestTomlValue(unittest.TestCase):
    """Value serialisation."""

    def test_integer(self):
        self.assertEqual(to_toml_value("42"), "42")
        self.assertEqual(to_toml_value('"42"'), "42")

    def test_negative_integer(self):
        self.assertEqual(to_toml_value("-1"), "-1")

    def test_boolean_true(self):
        self.assertEqual(to_toml_value("1"), "true")

    def test_boolean_false(self):
        self.assertEqual(to_toml_value("0"), "false")

    def test_quoted_string(self):
        self.assertEqual(to_toml_value('"hello"'), '"hello"')

    def test_braced_string(self):
        self.assertEqual(to_toml_value('{hello world}'), '"hello world"')

    def test_string_with_backslash(self):
        self.assertEqual(to_toml_value('"a\\b"'), '"a\\\\b"')

    def test_string_with_double_quote(self):
        self.assertEqual(to_toml_value('"say \\"hi\\""'), '"say \\"hi\\""')


class TestConf2Toml(unittest.TestCase):
    """Full conversion tests."""

    def _convert(self, conf: str) -> str:
        c = Conf2Toml()
        c.parse(conf)
        return c.render()

    # ── Basic set commands ────────────────────────────────────────────────

    def test_nick(self):
        toml = self._convert('set nick "MyBot"')
        self.assertIn('nick = "MyBot"', toml)
        self.assertIn('[bot]', toml)

    def test_altnick(self):
        toml = self._convert('set altnick "MyBot0"')
        self.assertIn('altnick = "MyBot0"', toml)

    def test_integer_setting(self):
        toml = self._convert('set max-socks 100')
        self.assertIn('max_socks = 100', toml)
        self.assertIn('[behaviour]', toml)

    def test_boolean_zero(self):
        toml = self._convert('set stealth-telnets 0')
        self.assertIn('stealth_telnets = false', toml)

    def test_boolean_one(self):
        toml = self._convert('set require-p 1')
        self.assertIn('require_p = true', toml)

    def test_dash_to_underscore(self):
        toml = self._convert('set botnet-nick "MyBotNet"')
        self.assertIn('botnet_nick = "MyBotNet"', toml)

    def test_owner(self):
        toml = self._convert('set owner "Alice, Bob"')
        self.assertIn('owner = "Alice, Bob"', toml)

    # ── Server directives ─────────────────────────────────────────────────

    def test_server_plain(self):
        toml = self._convert('server add irc.example.com 6667')
        self.assertIn('[servers]', toml)
        self.assertIn('"irc.example.com:6667"', toml)

    def test_server_ssl(self):
        toml = self._convert('server add irc.example.com +6697')
        self.assertIn('"irc.example.com:+6697"', toml)

    def test_server_with_password(self):
        toml = self._convert('server add irc.example.com 6669 mypass')
        self.assertIn('"irc.example.com:6669:mypass"', toml)

    def test_multiple_servers(self):
        conf = "server add a.example.com 6667\nserver add b.example.com +6697"
        toml = self._convert(conf)
        self.assertIn('"a.example.com:6667"', toml)
        self.assertIn('"b.example.com:+6697"', toml)

    # ── Channel directives ────────────────────────────────────────────────

    def test_channel_add(self):
        toml = self._convert('channel add #egghelp')
        self.assertIn('[channels]', toml)
        self.assertIn('"#egghelp"', toml)

    def test_multiple_channels(self):
        conf = "channel add #egghelp\nchannel add #eggdev"
        toml = self._convert(conf)
        self.assertIn('"#egghelp"', toml)
        self.assertIn('"#eggdev"', toml)

    # ── Module loading ────────────────────────────────────────────────────

    def test_loadmodule(self):
        toml = self._convert('loadmodule server')
        self.assertIn('[modules]', toml)
        self.assertIn('"server"', toml)

    def test_multiple_modules(self):
        conf = "loadmodule server\nloadmodule irc\nloadmodule ctcp"
        toml = self._convert(conf)
        for mod in ('"server"', '"irc"', '"ctcp"'):
            self.assertIn(mod, toml)

    # ── Logging ───────────────────────────────────────────────────────────

    def test_logfile(self):
        toml = self._convert('logfile mco * eggdrop.log')
        self.assertIn('[logging]', toml)
        self.assertIn('"mco * eggdrop.log"', toml)

    def test_logfile_quoted(self):
        toml = self._convert('logfile mco * "logs/eggdrop.log"')
        self.assertIn('"mco * logs/eggdrop.log"', toml)

    # ── Source / help ─────────────────────────────────────────────────────

    def test_source(self):
        toml = self._convert('source scripts/alltools.tcl')
        self.assertIn('[scripts]', toml)
        self.assertIn('"scripts/alltools.tcl"', toml)

    def test_loadhelp(self):
        toml = self._convert('loadhelp userinfo.help')
        self.assertIn('[help]', toml)
        self.assertIn('"userinfo.help"', toml)

    # ── Tcl commands (unbind, bind, proc) ─────────────────────────────────

    def test_unbind_goes_to_tcl(self):
        toml = self._convert('unbind dcc n simul *dcc:simul')
        self.assertIn('[tcl]', toml)
        self.assertIn('unbind dcc n simul', toml)

    def test_bind_goes_to_tcl(self):
        toml = self._convert('bind evnt - init-server evnt:init_server')
        self.assertIn('[tcl]', toml)

    def test_proc_single_line_goes_to_tcl(self):
        """A proc whose body is all on one line is a balanced single-line cmd."""
        toml = self._convert('proc myproc {} { return 1 }')
        self.assertIn('[tcl]', toml)
        self.assertIn('myproc', toml)

    def test_proc_multiline_uses_triple_quote(self):
        """Multi-line proc definitions must be wrapped in triple-quoted strings."""
        conf = (
            'proc myproc {args} {\n'
            '  putlog "hello"\n'
            '  return 1\n'
            '}'
        )
        toml = self._convert(conf)
        self.assertIn('[tcl]', toml)
        self.assertIn('"""', toml)
        self.assertIn('proc myproc', toml)
        self.assertIn('putlog', toml)

    def test_multiline_proc_does_not_split_body(self):
        """Each line of the proc body must not become a separate [tcl] entry."""
        conf = (
            'proc foo {} {\n'
            '  set x 1\n'
            '  return $x\n'
            '}'
        )
        toml = self._convert(conf)
        # The body lines should appear together inside the triple-quoted block,
        # not as multiple separate commands = [...] entries.
        self.assertIn('set x 1', toml)
        self.assertIn('return $x', toml)
        # Only one triple-quoted block (one '"""' pair = two occurrences)
        self.assertEqual(toml.count('"""'), 2)

    def test_namespace_multiline(self):
        """namespace eval blocks span multiple lines — same treatment as proc."""
        conf = (
            'namespace eval myns {\n'
            '  variable foo 1\n'
            '}'
        )
        toml = self._convert(conf)
        self.assertIn('"""', toml)
        self.assertIn('namespace eval myns', toml)

    def test_multiline_then_single_line(self):
        """Multi-line block followed by single-line bind — both in [tcl]."""
        conf = (
            'proc evnt:init {args} {\n'
            '  putlog "inited"\n'
            '}\n'
            'bind evnt - init-server evnt:init'
        )
        toml = self._convert(conf)
        self.assertIn('"""', toml)
        self.assertIn('bind evnt', toml)

    # ── Comment and blank line handling ───────────────────────────────────

    def test_comments_skipped(self):
        toml = self._convert('# This is a comment\nset nick "Bot"')
        self.assertIn('nick = "Bot"', toml)
        self.assertNotIn('This is a comment', toml)

    def test_shebang_skipped(self):
        toml = self._convert('#! /usr/local/bin/eggdrop\nset nick "Bot"')
        self.assertIn('nick = "Bot"', toml)
        self.assertNotIn('#!/', toml)
        self.assertNotIn('/usr/local', toml)

    def test_die_skipped(self):
        toml = self._convert('die "Edit your config!"')
        self.assertNotIn('die', toml)

    def test_blank_lines_skipped(self):
        toml = self._convert('\n\n\nset nick "Bot"\n\n')
        self.assertIn('nick = "Bot"', toml)

    # ── Inline comment stripping ──────────────────────────────────────────

    def test_inline_comment_stripped(self):
        toml = self._convert('set nick "Bot"  ; # comment here')
        self.assertIn('nick = "Bot"', toml)
        self.assertNotIn('comment', toml)

    # ── Section ordering ──────────────────────────────────────────────────

    def test_modules_before_bot(self):
        conf = "set nick \"Bot\"\nloadmodule server"
        toml = self._convert(conf)
        idx_modules = toml.index('[modules]')
        idx_bot = toml.index('[bot]')
        self.assertLess(idx_modules, idx_bot)

    def test_scripts_near_end(self):
        conf = "set nick \"Bot\"\nsource scripts/foo.tcl"
        toml = self._convert(conf)
        idx_bot = toml.index('[bot]')
        idx_scripts = toml.index('[scripts]')
        self.assertLess(idx_bot, idx_scripts)

    # ── Round-trip smoke test ─────────────────────────────────────────────

    def test_full_minimal_config(self):
        conf = """\
#! /usr/local/bin/eggdrop
set nick "TestBot"
set altnick "TestBot0"
set username "testbot"
set owner "Alice"
server add irc.libera.chat +6697
channel add #test
loadmodule server
loadmodule irc
logfile mco * eggdrop.log
source scripts/alltools.tcl
unbind dcc n simul *dcc:simul
die "edit me"
"""
        toml = self._convert(conf)
        # All key sections present
        for section in ('[bot]', '[servers]', '[channels]', '[modules]',
                        '[logging]', '[scripts]', '[tcl]'):
            self.assertIn(section, toml, f"Missing section: {section}")
        # No shebang or die
        self.assertNotIn('#!', toml)
        self.assertNotIn('die', toml)
        # Key values
        self.assertIn('nick = "TestBot"', toml)
        self.assertIn('"irc.libera.chat:+6697"', toml)
        self.assertIn('"#test"', toml)
        self.assertIn('"server"', toml)
        self.assertIn('"mco * eggdrop.log"', toml)


if __name__ == "__main__":
    unittest.main(verbosity=2)
