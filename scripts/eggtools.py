"""
eggtools.py — Python equivalents of eggdrop's alltools.tcl utility functions.

Copyright (C) 2025 Eggheads Development Team

This module provides Python-callable wrappers for common eggdrop IRC bot
operations.  Import it in your Python scripts:

    import eggtools
    eggtools.putmsg("#channel", "Hello!")

Or use it as a drop-in helper alongside the eggdrop module:

    import eggdrop, eggtools

Functions provided:
  IRC output:
    putmsg(dest, text)      send PRIVMSG
    putnotc(dest, text)     send NOTICE
    putact(dest, text)      send ACTION (/me)
    putchan(dest, text)     alias for putmsg (compat)
  Server queues:
    putserv(text)           send raw IRC line (normal queue)
    putquick(text)          send raw IRC line (quick/mode queue)
    putnow(text)            send raw IRC line immediately
  Logging:
    putlog(text)            write to eggdrop log (LOG_MISC)
    putcmdlog(text)         write to command log (LOG_CMDS)
  Channel queries:
    isonchan(nick, chan)    True if nick is on channel
    getchanhost(nick, chan) "user@host" or None
    chanlist(chan)          list of member info dicts
    channels()              list of channel names
  Bot info:
    botname()               bot's current IRC nickname
  String utilities (compat with alltools.tcl names):
    strlwr(s)               s.lower()
    strupr(s)               s.upper()
    strlen(s)               len(s)
    randstring(n)           n random alphanumeric chars
"""

import random
import string
import eggdrop

# IRC logging level constants (mirror eggdrop's LOG_* defines)
LOG_MSGS   = 0x001
LOG_PUBLIC = 0x002
LOG_JOIN   = 0x004
LOG_MODES  = 0x008
LOG_CMDS   = 0x010
LOG_MISC   = 0x020
LOG_BOTS   = 0x040
LOG_RAW    = 0x080
LOG_FILES  = 0x100
LOG_LEV1   = 0x200
LOG_LEV2   = 0x400
LOG_LEV3   = 0x800
LOG_LEV4   = 0x1000
LOG_LEV5   = 0x2000
LOG_LEV6   = 0x4000
LOG_LEV7   = 0x8000
LOG_LEV8   = 0x10000
LOG_WALL   = 0x20000
LOG_SRVOUT = 0x40000
LOG_DEBUG  = 0x80000


# ---- IRC output ---------------------------------------------------------

def putmsg(dest, text):
    """Send a PRIVMSG to a nick or channel."""
    eggdrop.putserv("PRIVMSG %s :%s" % (dest, text))


def putchan(dest, text):
    """Alias for putmsg (compatibility with alltools.tcl)."""
    putmsg(dest, text)


def putnotc(dest, text):
    """Send a NOTICE to a nick or channel."""
    eggdrop.putserv("NOTICE %s :%s" % (dest, text))


def putact(dest, text):
    """Send a CTCP ACTION (/me) to a nick or channel."""
    eggdrop.putserv("PRIVMSG %s :\x01ACTION %s\x01" % (dest, text))


# Re-export the core eggdrop output functions for convenience
putserv  = eggdrop.putserv
putquick = eggdrop.putquick
putnow   = eggdrop.putnow
putdcc   = eggdrop.putdcc


# ---- Logging ------------------------------------------------------------

def putlog(text):
    """Write text to the eggdrop log at LOG_MISC level."""
    eggdrop.putlog(text, LOG_MISC, "*")


def putcmdlog(text):
    """Write text to the eggdrop log at LOG_CMDS level."""
    eggdrop.putlog(text, LOG_CMDS, "*")


# ---- Channel/user queries -----------------------------------------------

def isonchan(nick, chan):
    """Return True if nick is currently on channel."""
    return eggdrop.isonchan(nick, chan)


def getchanhost(nick, chan):
    """Return 'user@host' of nick on channel, or None if not found."""
    return eggdrop.getchanhost(nick, chan)


def chanlist(chan):
    """Return a list of member info dicts for all users on channel.

    Each dict contains: nick, host, joined (datetime), lastseen (datetime),
    account (str or None).
    """
    return eggdrop.chanlist(chan)


def channels():
    """Return a list of channel name strings the bot is in."""
    return eggdrop.channels()


# ---- Bot info -----------------------------------------------------------

def botname():
    """Return the bot's current IRC nickname."""
    return eggdrop.botname()


# ---- String utilities (compat with alltools.tcl) -----------------------

def strlwr(s):
    """Return s converted to lower case."""
    return s.lower()


def strupr(s):
    """Return s converted to upper case."""
    return s.upper()


def strlen(s):
    """Return the length of string s."""
    return len(s)


def strcmp(s1, s2):
    """Lexicographic comparison: returns negative, 0, or positive."""
    return (s1 > s2) - (s1 < s2)


def stricmp(s1, s2):
    """Case-insensitive lexicographic comparison."""
    return strcmp(s1.lower(), s2.lower())


def randstring(length, chars=None):
    """Return a random string of given length.

    chars defaults to alphanumeric characters (matching alltools.tcl).
    """
    if chars is None:
        chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def isnumber(s):
    """Return True if s is a valid integer (optionally with leading sign)."""
    try:
        int(s)
        return True
    except (ValueError, TypeError):
        return False
