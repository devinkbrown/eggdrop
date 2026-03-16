"""
eggtools.py — Modern Python utilities for eggdrop scripts.

Copyright (C) 2025 Eggheads Development Team

This module provides high-level, Pythonic wrappers around the eggdrop C API,
replacing the functionality of the legacy alltools.tcl for Python script
authors.  It is designed for Python 3.8+ and makes full use of type hints,
dataclasses, and modern standard library features.

Usage in your Python scripts:
    import eggtools

    # Register a callback for public channel messages
    @eggtools.on_pub("*", "*")
    def handle_pub(nick, host, handle, channel, text):
        if text.startswith("!hello"):
            eggtools.privmsg(channel, f"Hello, {nick}!")

    # Or use the lower-level eggdrop.bind directly:
    eggtools.privmsg("#channel", "Hello world!")
"""

from __future__ import annotations

import functools
import ipaddress
import random
import re
import string
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional

import eggdrop

# ---------------------------------------------------------------------------
# Log level constants (mirror eggdrop's LOG_* C defines)
# ---------------------------------------------------------------------------
LOG_MSGS   = 0x001   # private messages to/from bot
LOG_PUBLIC = 0x002   # public channel messages
LOG_JOIN   = 0x004   # joins / parts / kicks / modes / quits
LOG_MODES  = 0x008   # channel mode changes
LOG_CMDS   = 0x010   # dcc/telnet commands
LOG_MISC   = 0x020   # miscellaneous
LOG_BOTS   = 0x040   # bot-to-bot links
LOG_RAW    = 0x080   # raw server traffic
LOG_FILES  = 0x100   # file transfers
LOG_SRVOUT = 0x40000 # server output (sent)
LOG_DEBUG  = 0x80000 # debug output


# ---------------------------------------------------------------------------
# Data classes for IRC objects
# ---------------------------------------------------------------------------

@dataclass
class Member:
    """Represents a channel member."""
    nick: str
    host: str
    joined: Optional[datetime] = None
    lastseen: Optional[datetime] = None
    account: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Member":
        return cls(
            nick=d.get("nick", ""),
            host=d.get("host", ""),
            joined=d.get("joined"),
            lastseen=d.get("lastseen"),
            account=d.get("account"),
        )

    @property
    def userhost(self) -> str:
        """Return 'nick!user@host'."""
        return f"{self.nick}!{self.host}"


# ---------------------------------------------------------------------------
# IRC output — raw server queues
# ---------------------------------------------------------------------------

def putserv(text: str) -> None:
    """Queue a raw IRC line to the server (normal server queue)."""
    eggdrop.putserv(text)


def putquick(text: str) -> None:
    """Queue a raw IRC line to the server (fast/mode queue)."""
    eggdrop.putquick(text)


def putnow(text: str) -> None:
    """Send a raw IRC line to the server immediately, bypassing queues."""
    eggdrop.putnow(text)


def putdcc(idx: int, text: str) -> None:
    """Send text to a DCC telnet/party-line connection by index."""
    eggdrop.putdcc(idx, text)


# ---------------------------------------------------------------------------
# IRC output — high-level helpers
# ---------------------------------------------------------------------------

def privmsg(dest: str, text: str) -> None:
    """Send a PRIVMSG to a nick or channel (normal server queue)."""
    putserv(f"PRIVMSG {dest} :{text}")


# Aliases for compatibility with alltools.tcl naming
putmsg  = privmsg
putchan = privmsg


def notice(dest: str, text: str) -> None:
    """Send a NOTICE to a nick or channel."""
    putserv(f"NOTICE {dest} :{text}")


putnotc = notice  # alltools.tcl compat


def action(dest: str, text: str) -> None:
    """Send a CTCP ACTION (/me) to a nick or channel."""
    putserv(f"PRIVMSG {dest} :\x01ACTION {text}\x01")


putact = action  # alltools.tcl compat


def kick(channel: str, nick: str, reason: str = "") -> None:
    """Kick a nick from a channel with an optional reason."""
    if reason:
        putquick(f"KICK {channel} {nick} :{reason}")
    else:
        putquick(f"KICK {channel} {nick}")


def mode(channel: str, modes: str, *targets: str) -> None:
    """Set modes on a channel.  Targets are optional extra arguments."""
    args = " ".join(targets)
    putquick(f"MODE {channel} {modes}" + (f" {args}" if args else ""))


def topic(channel: str, text: str) -> None:
    """Change the topic of a channel."""
    putserv(f"TOPIC {channel} :{text}")


def join(channel: str, key: str = "") -> None:
    """Join a channel, with optional key."""
    if key:
        putquick(f"JOIN {channel} {key}")
    else:
        putquick(f"JOIN {channel}")


def part(channel: str, reason: str = "") -> None:
    """Part a channel with an optional reason."""
    if reason:
        putquick(f"PART {channel} :{reason}")
    else:
        putquick(f"PART {channel}")


def ctcp(dest: str, command: str, text: str = "") -> None:
    """Send a CTCP request to a nick or channel."""
    payload = f"\x01{command}"
    if text:
        payload += f" {text}"
    payload += "\x01"
    putserv(f"PRIVMSG {dest} :{payload}")


def ctcp_reply(dest: str, command: str, text: str = "") -> None:
    """Send a CTCP reply (NOTICE) to a nick."""
    payload = f"\x01{command}"
    if text:
        payload += f" {text}"
    payload += "\x01"
    putserv(f"NOTICE {dest} :{payload}")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def putlog(text: str, level: int = LOG_MISC, channel: str = "*") -> None:
    """Write text to the eggdrop log at the given level."""
    eggdrop.putlog(text, level, channel)


def putcmdlog(text: str) -> None:
    """Write text to the eggdrop log at LOG_CMDS level."""
    eggdrop.putlog(text, LOG_CMDS, "*")


# ---------------------------------------------------------------------------
# Bot information
# ---------------------------------------------------------------------------

def botname() -> str:
    """Return the bot's current IRC nickname."""
    return eggdrop.botname()


# ---------------------------------------------------------------------------
# Channel queries
# ---------------------------------------------------------------------------

def channels() -> List[str]:
    """Return a list of channel names the bot is currently in."""
    return eggdrop.channels()


def isonchan(nick: str, channel: str) -> bool:
    """Return True if nick is currently on channel."""
    return bool(eggdrop.isonchan(nick, channel))


def getchanhost(nick: str, channel: str) -> Optional[str]:
    """Return 'user@host' of nick on channel, or None if not found."""
    return eggdrop.getchanhost(nick, channel)


def chanlist(channel: str) -> List[Member]:
    """Return a list of Member objects for all users on channel."""
    return [Member.from_dict(d) for d in eggdrop.chanlist(channel)]


def finduser(nick: str, channel: Optional[str] = None) -> Optional[Member]:
    """Return a Member for nick (optionally restricted to channel), or None."""
    raw = eggdrop.findircuser(nick, channel) if channel else eggdrop.findircuser(nick)
    if raw is None:
        return None
    return Member.from_dict(raw)


# ---------------------------------------------------------------------------
# Channel member status
# ---------------------------------------------------------------------------

def isop(nick: str, channel: str) -> bool:
    """Return True if nick has channel operator (@) status."""
    return bool(eggdrop.isop(nick, channel))


def ishalfop(nick: str, channel: str) -> bool:
    """Return True if nick has half-operator (%) status."""
    return bool(eggdrop.ishalfop(nick, channel))


def isvoice(nick: str, channel: str) -> bool:
    """Return True if nick has voice (+) status."""
    return bool(eggdrop.isvoice(nick, channel))


def isaway(nick: str, channel: str) -> bool:
    """Return True if nick is marked as away on channel."""
    return bool(eggdrop.isaway(nick, channel))


def botisop(channel: str) -> bool:
    """Return True if the bot has op status on channel."""
    return bool(eggdrop.botisop(channel))


def botishalfop(channel: str) -> bool:
    """Return True if the bot has half-op status on channel."""
    return bool(eggdrop.botishalfop(channel))


def botisvoice(channel: str) -> bool:
    """Return True if the bot has voice status on channel."""
    return bool(eggdrop.botisvoice(channel))


def getaccount(nick: str, channel: str) -> Optional[str]:
    """Return the IRC account name of nick on channel, or None if unknown."""
    return eggdrop.getaccount(nick, channel)


def isidentified(nick: str, channel: Optional[str] = None) -> bool:
    """Return True if nick is logged in to services (account known and set).

    Checks all channels if channel is omitted.
    """
    if channel:
        return bool(eggdrop.isidentified(nick, channel))
    return bool(eggdrop.isidentified(nick))


# ---------------------------------------------------------------------------
# Handle / nick resolution
# ---------------------------------------------------------------------------

def nick2hand(nick: str, channel: str) -> Optional[str]:
    """Return the eggdrop handle for nick on channel, or None if unknown."""
    return eggdrop.nick2hand(nick, channel)


def hand2nick(handle: str, channel: str) -> Optional[str]:
    """Return the nick of the user with handle on channel, or None."""
    return eggdrop.hand2nick(handle, channel)


def isbotnick(nick: str) -> bool:
    """Return True if nick matches the bot's current nickname."""
    return bool(eggdrop.isbotnick(nick))


# ---------------------------------------------------------------------------
# User database
# ---------------------------------------------------------------------------

def countusers() -> int:
    """Return the number of users in the userlist."""
    return eggdrop.countusers()


def validuser(handle: str) -> bool:
    """Return True if handle exists in the userlist."""
    return bool(eggdrop.validuser(handle))


def findhandle(host: str) -> Optional[str]:
    """Return the handle matching 'nick!user@host', or None."""
    return eggdrop.finduser(host)


def userlist() -> List[str]:
    """Return a list of all user handles in the userlist."""
    return eggdrop.userlist()


# ---------------------------------------------------------------------------
# Miscellaneous / timing
# ---------------------------------------------------------------------------

def rand(n: int) -> int:
    """Return a random integer in [0, n)."""
    return eggdrop.rand(n)


def unixtime() -> int:
    """Return the current Unix timestamp as an integer."""
    return eggdrop.unixtime()


def duration(seconds: int) -> str:
    """Convert seconds to a human-readable string (e.g. '2 hours 5 minutes')."""
    return eggdrop.duration(seconds)


def maskhost(nick: str, userhost: str) -> str:
    """Create a standard IRC hostmask from nick and user@host."""
    return eggdrop.maskhost(nick, userhost)


def every(interval_seconds: int, fn: Callable, *args) -> None:
    """Register fn to be called approximately every interval_seconds seconds.

    Uses the 'cron' bind internally.  The function is called with no
    arguments by default; pass positional args to be forwarded.

    Example::

        @eggtools.every(300)
        def hello():
            eggtools.privmsg('#mychan', 'Still alive!')
    """
    import math
    minutes = max(1, int(math.ceil(interval_seconds / 60)))
    mask = f"*/{minutes} * * * *"

    @functools.wraps(fn)
    def _wrapper(*_cron_args):
        fn(*args)

    eggdrop.bind("cron", "-|-", mask, _wrapper)


# ---------------------------------------------------------------------------
# IRCv3 helpers
# ---------------------------------------------------------------------------

def cap_req(capability: str) -> None:
    """Send a CAP REQ to request an IRCv3 capability."""
    eggdrop.cap("req", capability)


def tagmsg(tag: str, target: str) -> None:
    """Send an IRCv3 TAGMSG with the given tag string to target."""
    eggdrop.tagmsg(tag, target)


# ---------------------------------------------------------------------------
# IRCX helpers (Microsoft IRC extensions / Ophion)
# ---------------------------------------------------------------------------

def ircxprop(target: str, propname: str, value: str = "") -> None:
    """Get or set an IRCX property.  Omit value to read the current setting."""
    eggdrop.ircxprop(target, propname, value)


def ircxaccess(channel: str, action: str, level: str = "", mask: str = "") -> None:
    """Manage the IRCX access list for channel.

    action='list'                     — retrieve access list
    action='add', level=LEVEL, mask   — grant level to mask
    action='del', mask                — remove mask from access list
    """
    eggdrop.ircxaccess(channel, action, level, mask)


def ircxcreate(channel: str, modes: str = "") -> None:
    """Send an IRCX CREATE command to create channel (bot becomes owner)."""
    eggdrop.ircxcreate(channel, modes)


def ircxnegotiate() -> None:
    """Manually send the IRCX command to enable IRCX mode on the server."""
    eggdrop.ircxnegotiate()


def ircxwhisper(channel: str, target: str, text: str) -> None:
    """Send an Ophion IRCX WHISPER (channel-scoped private message).

    Both the bot and target must be members of channel.
    """
    putserv(f"WHISPER {channel} {target} :{text}")


# ---------------------------------------------------------------------------
# IRCv3 / Ophion message history helpers
# ---------------------------------------------------------------------------

def chathistory(channel: str, subcommand: str = "LATEST", limit: int = 50,
                anchor: str = "") -> None:
    """Request chat history replay from Ophion (requires draft/chathistory cap).

    subcommand : LATEST | BEFORE | AFTER | AROUND | BETWEEN | TARGETS
    limit      : max messages to return (server may cap this)
    anchor     : optional msgid or timestamp for BEFORE/AFTER/AROUND

    Replayed messages arrive as a BATCH of PRIVMSGs/NOTICEs and are
    dispatched normally through the existing pub/msg/notc binds.

    Example — fetch last 100 messages on join::

        @eggtools.on_join()
        def fetch_history(nick, mask, handle, channel):
            if eggtools.isbotnick(nick):
                eggtools.chathistory(channel, 'LATEST', 100)
    """
    if anchor:
        putserv(f"CHATHISTORY {subcommand} {channel} {anchor} {limit}")
    else:
        putserv(f"CHATHISTORY {subcommand} {channel} * {limit}")


def markread(channel: str, msgid: str = "") -> None:
    """Send a MARKREAD command to sync the last-read position (draft/read-marker).

    Omit msgid to query the current position; supply a msgid to update it.
    """
    if msgid:
        putserv(f"MARKREAD {channel} {msgid}")
    else:
        putserv(f"MARKREAD {channel}")


# ---------------------------------------------------------------------------
# Bind decorators — Pythonic event registration
# ---------------------------------------------------------------------------

def _make_bind_decorator(bindtype: str):
    """Factory that creates @on_<bindtype>(mask, flags) decorators."""
    def decorator(mask: str = "*", flags: str = "-|-") -> Callable:
        def wrapper(fn: Callable) -> Callable:
            eggdrop.bind(bindtype, flags, mask, fn)
            return fn
        return wrapper
    return decorator


# One decorator per bind type — add more as needed
on_pub    = _make_bind_decorator("pub")    # public channel commands
on_pubm   = _make_bind_decorator("pubm")   # all public channel messages
on_msg    = _make_bind_decorator("msg")    # private messages to bot
on_msgm   = _make_bind_decorator("msgm")   # all private messages
on_join   = _make_bind_decorator("join")   # channel joins
on_part   = _make_bind_decorator("part")   # channel parts
on_kick   = _make_bind_decorator("kick")   # channel kicks
on_mode   = _make_bind_decorator("mode")   # channel mode changes
on_nick   = _make_bind_decorator("nick")   # nick changes
on_sign   = _make_bind_decorator("sign")   # quit/split
on_notc   = _make_bind_decorator("notc")   # notices
on_ctcp   = _make_bind_decorator("ctcp")   # CTCP requests
on_ctcr   = _make_bind_decorator("ctcr")   # CTCP replies
on_raw    = _make_bind_decorator("raw")    # raw server lines
on_rawt   = _make_bind_decorator("rawt")   # raw server lines with tag dict (IRCv3)
on_time   = _make_bind_decorator("time")   # minutely time events
on_cron   = _make_bind_decorator("cron")   # cron-style events
on_dcc    = _make_bind_decorator("dcc")    # DCC/telnet commands
on_evnt   = _make_bind_decorator("evnt")   # internal eggdrop events
on_monitor = _make_bind_decorator("monitor")  # MONITOR online/offline events

# Ophion / IRCv3 extended events (all use raw binds)
# Usage: @eggtools.on_whisper()  ← fires when bot receives a WHISPER
on_whisper = _make_bind_decorator("raw")   # Ophion WHISPER — use mask="WHISPER"
# Usage: @eggtools.on_prop()     ← fires on IRCX property change (PROP command)
on_prop    = _make_bind_decorator("raw")   # Ophion PROP   — use mask="PROP"
# Usage: @eggtools.on_setname()  ← fires when a user changes their realname
on_setname = _make_bind_decorator("raw")   # IRCv3 SETNAME — use mask="SETNAME"
# Usage: @eggtools.on_chghost()  ← fires on CHGHOST (shared via irc.mod)
on_chghost = _make_bind_decorator("raw")   # IRCv3 CHGHOST — use mask="CHGHOST"


# ---------------------------------------------------------------------------
# String utilities — compatible with alltools.tcl names
# ---------------------------------------------------------------------------

def strlwr(s: str) -> str:
    """Return s converted to lower case."""
    return s.lower()


def strupr(s: str) -> str:
    """Return s converted to upper case."""
    return s.upper()


def strlen(s: str) -> int:
    """Return the number of characters in s."""
    return len(s)


def strcmp(a: str, b: str) -> int:
    """Lexicographic string comparison.  Returns negative, 0, or positive."""
    return (a > b) - (a < b)


def stricmp(a: str, b: str) -> int:
    """Case-insensitive lexicographic string comparison."""
    return strcmp(a.casefold(), b.casefold())


def isnumber(s: str) -> bool:
    """Return True if s can be parsed as an integer."""
    try:
        int(s)
        return True
    except (ValueError, TypeError):
        return False


def randstring(length: int, chars: str = "") -> str:
    """Return a random string of given length.

    chars defaults to ASCII letters + digits (same as alltools.tcl).
    """
    if not chars:
        chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def ordnumber(n: int) -> str:
    """Return the ordinal string for n (e.g. 1 -> '1st', 42 -> '42nd')."""
    if 11 <= (n % 100) <= 13:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


# ---------------------------------------------------------------------------
# Network / IP utilities
# ---------------------------------------------------------------------------

def testip(addr: str) -> bool:
    """Return True if addr is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def hostmatch(pattern: str, host: str) -> bool:
    """Return True if host matches an IRC glob pattern (?, *)."""
    regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return bool(re.fullmatch(regex, host, re.IGNORECASE))


# ---------------------------------------------------------------------------
# User management
# ---------------------------------------------------------------------------

def adduser(handle: str, hostmask: str = "") -> bool:
    """Add a new user to the userlist.  Returns True on success."""
    if hostmask:
        return bool(eggdrop.adduser(handle, hostmask))
    return bool(eggdrop.adduser(handle))


def deluser(handle: str) -> bool:
    """Remove a user from the userlist.  Returns True if removed."""
    return bool(eggdrop.deluser(handle))


def addhost(handle: str, mask: str) -> None:
    """Add a hostmask to an existing user."""
    eggdrop.addhost(handle, mask)


def delhost(handle: str, mask: str) -> bool:
    """Remove a hostmask from a user.  Returns True if the mask was removed."""
    return bool(eggdrop.delhost(handle, mask))


def chattr(handle: str, changes: str = "", channel: Optional[str] = None) -> Optional[str]:
    """Get or set user flags.

    With no changes: returns the current flag string.
    With changes like '+o-v': applies them and returns the new flag string.
    Supply channel to operate on per-channel flags.
    Returns None if the user does not exist.
    """
    if channel:
        return eggdrop.chattr(handle, changes, channel)
    if changes:
        return eggdrop.chattr(handle, changes)
    return eggdrop.chattr(handle)


def matchattr(handle: str, flags: str, channel: Optional[str] = None) -> bool:
    """Return True if user's flags match the flag expression."""
    if channel:
        return bool(eggdrop.matchattr(handle, flags, channel))
    return bool(eggdrop.matchattr(handle, flags))


def passwdok(handle: str, password: str) -> bool:
    """Return True if password is correct for handle."""
    return bool(eggdrop.passwdok(handle, password))


def chhandle(oldhandle: str, newhandle: str) -> bool:
    """Rename a user.  Returns True on success."""
    return bool(eggdrop.chhandle(oldhandle, newhandle))


def save() -> None:
    """Write the userfile to disk immediately."""
    eggdrop.save()


# ---------------------------------------------------------------------------
# Ignore list
# ---------------------------------------------------------------------------

def isignore(mask: str) -> bool:
    """Return True if mask matches an active ignore entry."""
    return bool(eggdrop.isignore(mask))


def newignore(mask: str, creator: str, comment: str,
              lifetime: Optional[int] = None) -> None:
    """Add an ignore entry.

    lifetime is in seconds from now.  Omit (or None) to use the bot's
    default ignore_time setting.  Pass 0 for a permanent ignore.
    """
    if lifetime is not None:
        eggdrop.newignore(mask, creator, comment, lifetime)
    else:
        eggdrop.newignore(mask, creator, comment)


def killignore(mask: str) -> bool:
    """Remove an ignore entry.  Returns True if the entry was found."""
    return bool(eggdrop.killignore(mask))


def ignorelist() -> list:
    """Return a list of dicts describing all ignore entries.

    Each dict has keys: mask, creator, comment, expire, added.
    expire/added are Unix timestamps (0 = permanent).
    """
    return eggdrop.ignorelist()


# ---------------------------------------------------------------------------
# DCC management
# ---------------------------------------------------------------------------

def hand2idx(handle: str) -> int:
    """Return the socket (idx) for handle's DCC chat, or -1 if not connected."""
    return eggdrop.hand2idx(handle)


def idx2hand(sock: int) -> Optional[str]:
    """Return the nick/handle for a DCC socket, or None if not found."""
    return eggdrop.idx2hand(sock)


def killdcc(sock: int, reason: str = "") -> None:
    """Disconnect a DCC connection by socket number."""
    if reason:
        eggdrop.killdcc(sock, reason)
    else:
        eggdrop.killdcc(sock)


def dcclist(type_filter: str = "") -> list:
    """Return a list of dicts describing active DCC connections.

    Each dict has keys: idx, nick, host, type, time, port.
    Optionally filter by type string (e.g. 'chat', 'bot').
    """
    if type_filter:
        return eggdrop.dcclist(type_filter)
    return eggdrop.dcclist()


def dccused() -> int:
    """Return the number of active DCC connections."""
    return eggdrop.dccused()


# ---------------------------------------------------------------------------
# Channel extended queries
# ---------------------------------------------------------------------------

def chanbans(channel: str) -> list:
    """Return a list of ban dicts {mask, who, timer} for channel."""
    return eggdrop.chanbans(channel)


def chanexempts(channel: str) -> list:
    """Return a list of exempt dicts {mask, who, timer} for channel."""
    return eggdrop.chanexempts(channel)


def chaninvites(channel: str) -> list:
    """Return a list of invite dicts {mask, who, timer} for channel."""
    return eggdrop.chaninvites(channel)


def getchanidle(nick: str, channel: str) -> int:
    """Return idle time in minutes for nick on channel, or -1 if not found."""
    return eggdrop.getchanidle(nick, channel)


def topic(channel: str) -> Optional[str]:
    """Return the current topic of channel, or None if unknown."""
    return eggdrop.getchan_topic(channel)


def botonchan(channel: Optional[str] = None) -> bool:
    """Return True if the bot is on channel (or any channel if omitted)."""
    if channel:
        return bool(eggdrop.botonchan(channel))
    return bool(eggdrop.botonchan())


def wasop(nick: str, channel: str) -> bool:
    """Return True if nick was a channel operator before a netsplit."""
    return bool(eggdrop.wasop(nick, channel))


def washalfop(nick: str, channel: str) -> bool:
    """Return True if nick was a half-operator before a netsplit."""
    return bool(eggdrop.washalfop(nick, channel))


def isircbot(nick: str, channel: Optional[str] = None) -> bool:
    """Return True if nick is identified as a bot (IRCv3/005 ISBOT)."""
    if channel:
        return bool(eggdrop.isircbot(nick, channel))
    return bool(eggdrop.isircbot(nick))


def account2nicks(account: str, channel: Optional[str] = None) -> List[str]:
    """Return a list of nicks that are logged in with the given IRC account."""
    if channel:
        return eggdrop.account2nicks(account, channel)
    return eggdrop.account2nicks(account)


def hand2nicks(handle: str, channel: Optional[str] = None) -> List[str]:
    """Return a list of nicks currently on IRC for the given eggdrop handle."""
    if channel:
        return eggdrop.hand2nicks(handle, channel)
    return eggdrop.hand2nicks(handle)


# ---------------------------------------------------------------------------
# Bot networking
# ---------------------------------------------------------------------------

def putbot(botnick: str, message: str) -> None:
    """Send a zapf message to a directly linked bot."""
    eggdrop.putbot(botnick, message)


def putallbots(message: str) -> None:
    """Broadcast a zapf message to all linked bots."""
    eggdrop.putallbots(message)


def islinked(botnick: str) -> bool:
    """Return True if the named bot is currently linked to this bot."""
    return bool(eggdrop.islinked(botnick))


def bots() -> List[str]:
    """Return a list of all linked bot names in the botnet."""
    return eggdrop.bots()


# ---------------------------------------------------------------------------
# Text / string utilities
# ---------------------------------------------------------------------------

def stripcodes(flags: str, text: str) -> str:
    """Strip IRC formatting codes from text.

    flags is a string of characters selecting what to strip:
      c = color codes    b = bold       r = reverse    u = underline
      a = ANSI codes     g = bells      o = ordinary   i = italics
      * = all of the above

    Example::

        clean = eggtools.stripcodes('cb', raw_message)
    """
    return eggdrop.stripcodes(flags, text)


def matchstr(pattern: str, string: str) -> bool:
    """Return True if string matches an IRC glob pattern (? and * wildcards)."""
    return bool(eggdrop.matchstr(pattern, string))
