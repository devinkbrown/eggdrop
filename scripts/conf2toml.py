#!/usr/bin/env python3
"""
conf2toml.py — Migrate an Eggdrop .conf (Tcl-script) config to .toml format.

Usage:
    python3 scripts/conf2toml.py [options] INPUT.conf [OUTPUT.toml]

If OUTPUT is omitted the TOML is written to stdout.

Options:
    -h, --help      Show this help and exit.
    --no-comments   Omit explanatory comments in the output.

What is converted:
    set varname "value"            → key = "value" in the appropriate section
    set varname N                  → key = N
    server add host [+]port [pw]   → [servers] list entry
    channel add #chan              → [channels] list entry
    loadmodule name                → [modules] load entry
    logfile flags chan file         → [logging] entries entry
    source path/to/script.tcl      → [scripts] load entry
    loadhelp file.help             → [help] load entry
    unbind / bind (simple)         → [tcl] commands entry

What is NOT converted:
    Arbitrary Tcl (if/proc/expr/etc.) — appended verbatim to a
    [tcl] commands = [...] block so they are still evaluated at
    startup. Review these manually.

Copyright (C) 2026 Eggheads Development Team
License: GPL v2
"""

import argparse
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Variable → TOML section mapping
# ---------------------------------------------------------------------------

# Maps Tcl variable names to (section, toml_key).
# Variables not in this table go into [other] and a warning is printed.
VAR_MAP = {
    # [bot]
    "nick":             ("bot", "nick"),
    "altnick":          ("bot", "altnick"),
    "realname":         ("bot", "realname"),
    "username":         ("bot", "username"),
    "admin":            ("bot", "admin"),
    "network":          ("bot", "network"),
    "owner":            ("bot", "owner"),
    "botnet-nick":      ("bot", "botnet_nick"),
    "pidfile":          ("bot", "pidfile"),
    "notify-newusers":  ("bot", "notify_newusers"),
    "default-flags":    ("bot", "default_flags"),
    "whois-fields":     ("bot", "whois_fields"),
    "timezone":         ("bot", "timezone"),
    "offset":           ("bot", "offset"),

    # [paths]
    "userfile":         ("paths", "userfile"),
    "chanfile":         ("paths", "chanfile"),
    "notefile":         ("paths", "notefile"),
    "help-path":        ("paths", "help_path"),
    "text-path":        ("paths", "text_path"),
    "motd":             ("paths", "motd"),
    "telnet-banner":    ("paths", "telnet_banner"),
    "mod-path":         ("paths", "mod_path"),
    "userfile-perm":    ("paths", "userfile_perm"),

    # [logging]
    "max-logs":             ("logging", "max_logs"),
    "max-logsize":          ("logging", "max_logsize"),
    "raw-log":              ("logging", "raw_log"),
    "log-time":             ("logging", "log_time"),
    "timestamp-format":     ("logging", "timestamp_format"),
    "keep-all-logs":        ("logging", "keep_all_logs"),
    "logfile-suffix":       ("logging", "logfile_suffix"),
    "switch-logfiles-at":   ("logging", "switch_logfiles_at"),
    "quiet-save":           ("logging", "quiet_save"),
    "log-forever":          ("logging", "log_forever"),

    # [network]
    "vhost4":           ("network", "vhost4"),
    "vhost6":           ("network", "vhost6"),
    "nat-ip":           ("network", "nat_ip"),
    "prefer-ipv6":      ("network", "prefer_ipv6"),
    "default-port":     ("network", "default_port"),
    "connect-timeout":  ("network", "connect_timeout"),
    "resolve-timeout":  ("network", "resolve_timeout"),
    "reserved-portrange": ("network", "reserved_portrange"),
    "dns-dot-server":   ("network", "dns_dot_server"),
    "dns-dot-port":     ("network", "dns_dot_port"),
    "dns-dot-servername": ("network", "dns_dot_servername"),

    # [ssl]
    "ssl-privatekey":       ("ssl", "ssl_privatekey"),
    "ssl-certificate":      ("ssl", "ssl_certificate"),
    "ssl-capath":           ("ssl", "capath"),
    "ssl-cafile":           ("ssl", "ssl_cafile"),
    "ssl-ciphers":          ("ssl", "ssl_ciphers"),
    "ssl-dhparam":          ("ssl", "ssl_dhparam"),
    "ssl-verify-depth":     ("ssl", "ssl_verify_depth"),
    "ssl-cert-auth":        ("ssl", "ssl_cert_auth"),
    "ssl-verify-dcc":       ("ssl", "ssl_verify_dcc"),
    "ssl-verify-bots":      ("ssl", "ssl_verify_bots"),
    "ssl-verify-clients":   ("ssl", "ssl_verify_clients"),

    # [security]
    "must-be-owner":        ("security", "must_be_owner"),
    "stealth-telnets":      ("security", "stealth_telnets"),
    "stealth-prompt":       ("security", "stealth_prompt"),
    "require-p":            ("security", "require_p"),
    "open-telnets":         ("security", "open_telnets"),
    "protect-telnet":       ("security", "protect_telnet"),
    "dcc-sanitycheck":      ("security", "dcc_sanitycheck"),
    "dcc-flood-thr":        ("security", "dcc_flood_thr"),
    "telnet-flood":         ("security", "telnet_flood"),
    "paranoid-telnet-flood": ("security", "paranoid_telnet_flood"),
    "password-timeout":     ("security", "password_timeout"),
    "cidr-support":         ("security", "cidr_support"),
    "show-uname":           ("security", "show_uname"),

    # [behaviour]
    "max-socks":        ("behaviour", "max_socks"),
    "allow-dk-cmds":    ("behaviour", "allow_dk_cmds"),
    "dupwait-timeout":  ("behaviour", "dupwait_timeout"),
    "check-stoned":     ("behaviour", "check_stoned"),
    "serverror-quit":   ("behaviour", "serverror_quit"),
    "max-queue-msg":    ("behaviour", "max_queue_msg"),
    "trigger-on-ignore": ("behaviour", "trigger_on_ignore"),
    "exclusive-binds":  ("behaviour", "exclusive_binds"),
    "double-mode":      ("behaviour", "double_mode"),
    "double-server":    ("behaviour", "double_server"),
    "double-help":      ("behaviour", "double_help"),
    "optimize-kicks":   ("behaviour", "optimize_kicks"),
    "stack-limit":      ("behaviour", "stack_limit"),
    "hourly-updates":   ("behaviour", "hourly_updates"),
    "ignore-time":      ("behaviour", "ignore_time"),
    "remote-boots":     ("behaviour", "remote_boots"),
    "share-unlinks":    ("behaviour", "share_unlinks"),
    "wait-split":       ("behaviour", "wait_split"),
    "wait-info":        ("behaviour", "wait_info"),
    "ident-timeout":    ("behaviour", "ident_timeout"),
    "console":          ("behaviour", "console_flags"),

    # [irc]
    "net-type":         ("irc", "net_type"),
    "nick-len":         ("irc", "nick_len"),
    "ctcp-mode":        ("irc", "ctcp_mode"),
    "bounce-bans":      ("irc", "bounce_bans"),
    "bounce-exempts":   ("irc", "bounce_exempts"),
    "bounce-invites":   ("irc", "bounce_invites"),
    "bounce-modes":     ("irc", "bounce_modes"),
    "use-exempts":      ("irc", "use_exempts"),
    "use-invites":      ("irc", "use_invites"),
    "learn-users":      ("irc", "learn_users"),
    "mode-buf-length":  ("irc", "mode_buf_length"),
    "opchars":          ("irc", "opchars"),
    "no-chanrec-info":  ("irc", "no_chanrec_info"),
    "prevent-mixing":   ("irc", "prevent_mixing"),
    "kick-method":      ("irc", "kick_method"),
    "include-lk":       ("irc", "include_lk"),
    "rfc-compliant":    ("irc", "rfc_compliant"),
    "check-mode-r":     ("irc", "check_mode_r"),

    # [transfer]
    "max-dloads":       ("transfer", "max_dloads"),
    "dcc-block":        ("transfer", "dcc_block"),
    "xfer-timeout":     ("transfer", "xfer_timeout"),
    "sharefail-unlink": ("transfer", "sharefail_unlink"),
    "allow-resync":     ("transfer", "allow_resync"),
    "resync-time":      ("transfer", "resync_time"),

    # [filesys]
    "files-path":       ("filesys", "files_path"),
    "incoming-path":    ("filesys", "incoming_path"),
    "upload-to-pwd":    ("filesys", "upload_to_pwd"),
    "filedb-path":      ("filesys", "filedb_path"),
    "max-file-users":   ("filesys", "max_file_users"),
    "max-filesize":     ("filesys", "max_filesize"),

    # [notes]
    "max-notes":        ("notes", "max_notes"),
    "note-life":        ("notes", "note_life"),
    "allow-fwd":        ("notes", "allow_fwd"),
    "notify-users":     ("notes", "notify_users"),
    "notify-onjoin":    ("notes", "notify_onjoin"),

    # [console]
    "console-autosave": ("console", "console_autosave"),
    "force-channel":    ("console", "force_channel"),
    "info-party":       ("console", "info_party"),

    # [crypto]
    "pbkdf2-method":    ("crypto", "pbkdf2_method"),
    "pbkdf2-rounds":    ("crypto", "pbkdf2_rounds"),
    "blowfish-use-mode": ("crypto", "blowfish_use_mode"),
    "remove-pass":      ("crypto", "remove_pass"),

    # [ident]
    "ident-method":     ("ident", "ident_method"),
    "ident-port":       ("ident", "ident_port"),

    # share.mod
    "private-global":   ("share", "private_global"),
    "private-globals":  ("share", "private_globals"),
    "private-user":     ("share", "private_user"),
    "override-bots":    ("share", "override_bots"),
    "share-compressed": ("share", "share_compressed"),
    "compress-level":   ("share", "compress_level"),
}

# Prefer this section order in the output
SECTION_ORDER = [
    "modules", "bot", "servers", "channels", "paths",
    "logging", "network", "ssl", "security", "behaviour",
    "irc", "transfer", "filesys", "notes", "console", "crypto",
    "ident", "share", "other", "scripts", "help", "tcl",
]


# ---------------------------------------------------------------------------
# Tcl value → TOML value helpers
# ---------------------------------------------------------------------------

def tcl_unquote(s: str) -> str:
    """Strip surrounding Tcl quotes/braces and unescape the content."""
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        inner = s[1:-1]
        # Apply Tcl escape sequences for double-quoted strings
        inner = inner.replace('\\"', '"').replace('\\\\', '\\')
        inner = inner.replace('\\n', '\n').replace('\\t', '\t')
        return inner
    if s.startswith('{') and s.endswith('}'):
        # Brace-quoted strings: no escape processing in Tcl
        return s[1:-1]
    return s


def to_toml_value(raw: str) -> str:
    """Convert a Tcl value to a TOML value string (already serialised)."""
    val = tcl_unquote(raw)
    # Boolean (check before integer so bare "1"/"0" become true/false)
    if val.lower() in ('1', 'true', 'yes'):
        return 'true'
    if val.lower() in ('0', 'false', 'no'):
        return 'false'
    # Bare integer
    if re.match(r'^-?\d+$', val):
        return val
    # Bare float
    if re.match(r'^-?\d+\.\d+$', val):
        return val
    # Everything else: quoted string (escape backslashes and double-quotes)
    escaped = val.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{escaped}"'


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class Conf2Toml:
    def __init__(self, no_comments: bool = False):
        self.no_comments = no_comments
        # section → list of (key, toml_value) tuples
        self.sections: dict[str, list] = {s: [] for s in SECTION_ORDER}
        self.sections["tcl"] = []   # raw Tcl commands
        self.warnings: list[str] = []

    def _add(self, section: str, key: str, value: str):
        if section not in self.sections:
            self.sections[section] = []
        self.sections[section].append((key, value))

    def _warn(self, msg: str, lineno: int):
        self.warnings.append(f"  line {lineno}: {msg}")

    def parse(self, text: str):
        lines = text.splitlines()
        lineno = 0
        for line in lines:
            lineno += 1
            stripped = line.strip()

            # Skip blank lines, comments, and the shebang
            if not stripped or stripped.startswith('#') or \
               stripped.startswith(';') or stripped.startswith('#!'):
                continue

            # Remove inline comments (after ; or #, not inside quotes)
            # Simple approach: strip after the first unquoted semicolon
            stripped = _strip_tcl_comment(stripped)

            # set varname value
            m = re.match(r'^set\s+([\w\-.()\[\]]+)\s+(.*)', stripped)
            if m:
                varname = m.group(1).strip()
                rawval  = m.group(2).strip()
                if varname in VAR_MAP:
                    sec, key = VAR_MAP[varname]
                    self._add(sec, key, to_toml_value(rawval))
                else:
                    # Unknown variable — still emit it in [other]
                    key = varname.replace('-', '_')
                    self._add("other", key, to_toml_value(rawval))
                    self._warn(f"Unknown variable '{varname}' → [other].{key}", lineno)
                continue

            # server add host [+]port [password]
            m = re.match(r'^server\s+add\s+(\S+)\s*(\+?\d+)?\s*(\S+)?', stripped)
            if m:
                host = m.group(1)
                port = m.group(2) or ""
                pw   = m.group(3) or ""
                if port and pw:
                    entry = f"{host}:{port}:{pw}"
                elif port:
                    entry = f"{host}:{port}"
                else:
                    entry = host
                self._add("servers", "_list", f'"{entry}"')
                continue

            # channel add #chan [options]
            m = re.match(r'^channel\s+add\s+(#\S+)', stripped)
            if m:
                self._add("channels", "_list", f'"{m.group(1)}"')
                continue

            # loadmodule name
            m = re.match(r'^loadmodule\s+(\S+)', stripped)
            if m:
                self._add("modules", "_load", f'"{m.group(1)}"')
                continue

            # logfile flags channel "file"
            m = re.match(r'^logfile\s+(\S+)\s+(\S+)\s+"?([^"]+)"?', stripped)
            if m:
                entry = f"{m.group(1)} {m.group(2)} {m.group(3)}"
                self._add("logging", "_entries", f'"{entry}"')
                continue

            # source path/to/script.tcl
            m = re.match(r'^source\s+(\S+)', stripped)
            if m:
                self._add("scripts", "_load", f'"{m.group(1)}"')
                continue

            # loadhelp file.help
            m = re.match(r'^loadhelp\s+(\S+)', stripped)
            if m:
                self._add("help", "_load", f'"{m.group(1)}"')
                continue

            # die — skip (validation guards not needed in TOML)
            if re.match(r'^die\s+', stripped):
                continue

            # if {[file exists ...]} { die ... } — skip
            if re.match(r'^if\s+.*die', stripped):
                continue

            # unbind / bind / proc / putquick — pass as raw [tcl] command
            if re.match(r'^(unbind|bind|proc|putquick|pysource|listen)\s', stripped):
                escaped = stripped.replace('\\', '\\\\').replace('"', '\\"')
                self._add("tcl", "_commands", f'"{escaped}"')
                continue

            # Anything else we don't recognise
            escaped = stripped.replace('\\', '\\\\').replace('"', '\\"')
            self._add("tcl", "_commands", f'"{escaped}"')
            self._warn(f"Unrecognised line passed to [tcl]: {stripped[:60]}", lineno)

    def render(self) -> str:
        out = []
        out.append("# Eggdrop TOML configuration file")
        out.append("# Converted from .conf by scripts/conf2toml.py")
        out.append("# Review this file before use, especially the [tcl] section.")
        out.append("")

        for sec in SECTION_ORDER:
            items = self.sections.get(sec, [])
            if not items:
                continue

            # Special list sections
            if sec == "servers":
                list_items = [v for k, v in items if k == "_list"]
                other = [(k, v) for k, v in items if k != "_list"]
                if list_items:
                    out.append("[servers]")
                    out.append("list = [")
                    for v in list_items:
                        out.append(f"  {v},")
                    out.append("]")
                    out.append("")
                for k, v in other:
                    if not out or out[-1]:
                        pass
                    out.append(f"{k} = {v}")
                continue

            if sec == "channels":
                list_items = [v for k, v in items if k == "_list"]
                if list_items:
                    out.append("[channels]")
                    out.append("list = [" + ", ".join(list_items) + "]")
                    out.append("")
                continue

            if sec == "modules":
                list_items = [v for k, v in items if k == "_load"]
                if list_items:
                    out.append("[modules]")
                    out.append("load = [")
                    for v in list_items:
                        out.append(f"  {v},")
                    out.append("]")
                    out.append("")
                continue

            if sec == "logging":
                # regular kv items first, then entries array
                regular = [(k, v) for k, v in items if k != "_entries"]
                entries = [v for k, v in items if k == "_entries"]
                out.append("[logging]")
                for k, v in regular:
                    out.append(f"{k} = {v}")
                if entries:
                    out.append("entries = [")
                    for v in entries:
                        out.append(f"  {v},")
                    out.append("]")
                out.append("")
                continue

            if sec == "scripts":
                list_items = [v for k, v in items if k == "_load"]
                if list_items:
                    out.append("[scripts]")
                    out.append("load = [")
                    for v in list_items:
                        out.append(f"  {v},")
                    out.append("]")
                    out.append("")
                continue

            if sec == "help":
                list_items = [v for k, v in items if k == "_load"]
                if list_items:
                    out.append("[help]")
                    out.append("load = [" + ", ".join(list_items) + "]")
                    out.append("")
                continue

            if sec == "tcl":
                list_items = [v for k, v in items if k == "_commands"]
                if list_items:
                    out.append("[tcl]")
                    if not self.no_comments:
                        out.append(
                            "# Raw Tcl commands executed at startup. "
                            "Review these carefully."
                        )
                    out.append("commands = [")
                    for v in list_items:
                        out.append(f"  {v},")
                    out.append("]")
                    out.append("")
                continue

            # Generic section
            out.append(f"[{sec}]")
            for k, v in items:
                out.append(f"{k} = {v}")
            out.append("")

        return "\n".join(out)


def _strip_tcl_comment(line: str) -> str:
    """Strip a trailing inline ; comment from a Tcl line (naively)."""
    in_quote = False
    in_brace = 0
    i = 0
    while i < len(line):
        c = line[i]
        if c == '"' and (i == 0 or line[i-1] != '\\'):
            in_quote = not in_quote
        elif not in_quote:
            if c == '{':
                in_brace += 1
            elif c == '}':
                in_brace -= 1
            elif c == ';' and in_brace == 0:
                return line[:i].strip()
        i += 1
    return line


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Migrate an Eggdrop .conf (Tcl) config to .toml format.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n\n")[0],
    )
    parser.add_argument("input",  help="Input .conf file")
    parser.add_argument("output", nargs="?", help="Output .toml file (default: stdout)")
    parser.add_argument("--no-comments", action="store_true",
                        help="Omit explanatory comments in the output")
    args = parser.parse_args(argv)

    try:
        text = Path(args.input).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"Error reading '{args.input}': {e}", file=sys.stderr)
        return 1

    conv = Conf2Toml(no_comments=args.no_comments)
    conv.parse(text)
    toml_text = conv.render()

    if args.output:
        try:
            Path(args.output).write_text(toml_text + "\n", encoding="utf-8")
            print(f"Written to {args.output}")
        except OSError as e:
            print(f"Error writing '{args.output}': {e}", file=sys.stderr)
            return 1
    else:
        print(toml_text)

    if conv.warnings:
        print("\nWarnings (review these lines in the output):", file=sys.stderr)
        for w in conv.warnings:
            print(w, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
