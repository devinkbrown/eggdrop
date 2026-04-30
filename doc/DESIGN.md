# devinkbrown/eggdrop — Design and Change Rationale

**Based on:** eggdrop v1.10.1  
**Last updated:** 2026-04-26

This document explains every major change made in this fork, why each change
was made, and what problem it solves.  Changes are grouped by theme, not by
commit order.

---

## Table of Contents

1. [Build system migration (autoconf → Meson)](#1-build-system-migration)
2. [I/O backend overhaul (select → epoll/io_uring/kqueue/IOCP)](#2-io-backend-overhaul)
3. [DNS subsystem replacement (res.c + DoT)](#3-dns-subsystem-replacement)
4. [Memory and allocation (libop slabs, OOM safety)](#4-memory-and-allocation)
5. [String safety (strlcpy/strlcat, op_strbuf_t)](#5-string-safety)
6. [C23 modernisation and dead-code removal](#6-c23-modernisation)
7. [64-bit type migration](#7-64-bit-type-migration)
8. [const correctness](#8-const-correctness)
9. [libop integration](#9-libop-integration)
10. [TOML configuration and setup wizard](#10-toml-configuration)
11. [Optional Tcl / Python scripting engine](#11-optional-tcl--python-scripting)
12. [IRCv3 and IRCX/Ophion protocol support](#12-ircv3-and-ircxophion-protocol-support)
13. [Security hardening](#13-security-hardening)
14. [Performance improvements](#14-performance-improvements)
15. [UTF-8 support](#15-utf-8-support)
16. [SASL authentication extensions](#16-sasl-authentication-extensions)
17. [WebUI](#17-webui)
18. [Windows / IOCP native support](#18-windows--iocp-native-support)
19. [CI / GitHub Actions](#19-ci--github-actions)
20. [Bug fixes](#20-bug-fixes)

---

## 1. Build system migration

**Problem:** Eggdrop originally used autoconf/automake (the `./configure && make`
toolchain from the 1990s).  This system is slow, hard to read, and produces
poor IDE integration.  Adding a new dependency, platform check, or compile
flag requires writing dense M4 macro code.

**Change:** The entire build system was replaced with [Meson](https://mesonbuild.com/).

**Why Meson:**
- Readable Python-like syntax — adding a dependency is one line
- Significantly faster than autoconf (`ninja` vs `make`)
- First-class cross-compilation and native-build support
- Generates `compile_commands.json` for IDE/language-server integration
- Built-in support for sanitizers, LTO, PIE, and hardening flags

**What was added:**
- `meson.build` at the repo root and `src/meson.build` for core sources
- Per-module `meson.build` files for all modules under `src/mod/`
- `meson.build` for the `libop` library
- `post_install.py` to handle data directory installation
- GitHub Actions CI updated to use `meson setup && ninja` everywhere

**Security/hardening options surfaced via Meson:**
- `-Dhardening=true` enables stack-protector, stack-clash protection,
  FORTIFY_SOURCE=2, RELRO+NOW, no-PLT, no-common
- `-Degg-debug=true` enables ASAN + UBSAN
- `-Db_pie=true` enables Position-Independent Executable (ASLR)
- `-Db_lto=true` enables Link-Time Optimisation (dead code elimination, inlining)
- `-Dnative-opt=true` emits `-march=native` for the build host

---

## 2. I/O backend overhaul

**Problem:** Eggdrop's original `net.c` used a `select()` loop — a POSIX API from
1983 that is limited to 1024 file descriptors, does not scale with the number
of open sockets, and performs O(n) scanning on every tick.

**Change:** A tiered I/O backend system was implemented:

| Tier | API | Platform | Notes |
|---|---|---|---|
| 1 | io_uring | Linux ≥5.1 | Zero-copy, kernel-polled, lowest latency |
| 2 | epoll | Linux | O(1) event delivery, unlimited FDs |
| 3 | kqueue | macOS, BSDs | Equivalent to epoll on Apple/FreeBSD |
| 4 | IOCP | Windows | Native Windows async I/O |
| 5 | select | Everywhere | Fallback for old/embedded systems |

**io_uring specifics:**
- SQPOLL mode for kernel-polled submission (zero syscall cost per operation)
- Async RECV operations submitted as SQEs; completions processed as CQEs
- Three bugs in the initial implementation were fixed:
  - SQ tail was not flushed in SQPOLL mode, so the kernel thread never saw new SQEs
  - Buffered recv data was overwritten when a RECV CQE arrived during SOCK_CONNECT
  - The function returned "idle" before dispatching buffered data, deadlocking

**epoll specifics:**
- O(1) `epoll_wait` replaces the O(n) `select()` scan
- `accept4()` is used instead of `accept()` + `fcntl()` to set SOCK_NONBLOCK atomically

**kqueue (macOS/BSD):**
- `kevent()` replaces `select()` on Apple and FreeBSD targets
- TLS handshake completion detection was fixed (POLLIN vs POLLOUT edge case)
- SOCK_CONNECT detection fixed for non-blocking connects under kqueue

**SOCK→DCC map:**
- Original code did a linear scan of the DCC array to map a socket to its
  DCC index on every packet.  Replaced with an O(1) hash map (`dcc_map_set`,
  `dcc_map_clear`, `dcc_map_get`).

**TCP performance:**
- `TCP_NODELAY` and `MSG_MORE` coalescing for IRC protocol output
- `writev()` ring-buffer drain to reduce write syscalls
- TCP keepalive probe tuning to detect dead connections faster
- `sendfile()` zero-copy DCC file transfers on Linux

---

## 3. DNS subsystem replacement

**Problem:** Eggdrop's original DNS code (`coredns.c`) was a hand-rolled stub
resolver written in the 1990s.  It had no CNAME following, no EDNS0 support,
no IPv6 nameserver support, and no encrypted transport.  The threaded fallback
(`EGG_TDNS`) used blocking `getaddrinfo()` in background threads — a correct
approach but one that prevented the main loop from staying fully async.

**Change:** The DNS subsystem was replaced with `res.c`, a full async stub
resolver ported from the Ophion IRC server.  `EGG_TDNS` was removed entirely.

**What res.c provides:**
- Fully async, non-blocking DNS resolution integrated into the main event loop
- EDNS0 in UDP queries for large response support
- Automatic TCP retry when UDP response is truncated (TC bit)
- CNAME chain following
- DoT (DNS-over-TLS) transport for encrypted DNS
  - Auto-reconnect on DoT stream disconnect
  - TLS certificate verification for DoT servers
  - Auto-reconnect uses exponential backoff
- Secure query IDs via `getrandom(2)`
- Full response header validation (ANCOUNT cap, question section validation)
- IPv6-only nameserver support
- Portability fallback for `NAMESERVER_PORT` on systems that don't define it

**Why this matters:** A bot that handles hundreds of DCC connections, channel
events, and server messages in a single-threaded event loop cannot afford to
block on DNS.  The previous threaded approach added thread-safety complexity
and was removed in favour of a clean async design.

---

## 4. Memory and allocation

**Problem:** Eggdrop used `malloc`/`free` for every small allocation — channel
member records, ban records, timer nodes, etc.  This causes heap fragmentation
over time, and every allocation/free pair involves a system call or lock.

**Changes:**

**Slab allocators (op_bh):**  
`op_bh` (block-heap) from libop is a slab allocator that carves fixed-size
objects out of large mmap'd arenas.  Objects that are allocated and freed
frequently (channel members, DCC entries, Tcl hash nodes, timer nodes, module
entries) were routed through `op_bh` slabs:

- `memberlist` / `masklist` in channels.mod — previously `malloc` per member
- `tcl_timer_t` nodes in `chanprog.c`
- `module_entry` and `dependancy` nodes in `modules.c`
- Tclhash binding nodes (`bind_entry`, `bind_table`, `couplet_chain`)
- `userrec`, `chanuserrec`, `user_entry`, `xtra_key` in `userrec.c`
- DCC entry allocation in `dccutil.c`

**OOM safety:**
- `nrealloc` was changed to abort on allocation failure rather than returning
  NULL and allowing callers to dereference a NULL pointer
- `nstrdup` wrapper added to provide a null-safe strdup equivalent

**`malloc` → libop in non-DEBUG builds:**  
In non-`DEBUG_MEM` builds, `nmalloc`/`nrealloc`/`nfree`/`nstrdup` now forward
directly to libop's allocator (`op_malloc`, `op_realloc`, `op_free`), which
has a smaller overhead than glibc's `malloc` for short-lived small objects.

**User account splay-tree index:**  
`get_user_by_host` was O(n) over the user list.  An account dict using a
splay tree provides O(log n) lookup for `account_tag` (IRCv3 account
notifications).

**Patricia trie for CIDR bans:**  
CIDR ban matching was O(n) per message.  A patricia trie provides O(k) lookup
(k = address bits) for the common case of large ban lists.

**Allocator consolidation:**  
All `nmalloc`/`nrealloc`/`nfree` call sites (750+) were migrated to
`op_malloc`/`op_realloc`/`op_free`.  `mem.c` was removed entirely.  In
non-`DEBUG_MEM` builds these map directly to libop's allocator; in debug
builds they use glibc with full leak tracking.

**Hash tables for bind dispatch:**  
Bind table lookup (`find_bind_table`) was O(n) over a linked list.  Each bind
table now carries an `op_htab` mapping mask strings to `tcl_bind_mask_t`
nodes, giving O(1) exact-match dispatch for the common case (`MATCH_EXACT`
and `MATCH_CASE`).

**Hash tables for mask lists:**  
Ban, exempt, and invite mask lists in `channels.mod` each carry an `op_htab`
for O(1) duplicate detection and `ismask()` queries instead of the previous
O(n) linear scan.

**Hash tables for channel member lookup:**  
`ismember()` was O(n) over the member linked list.  Each channel now carries
an `op_htab` mapping nick strings to `memberlist` pointers for O(1) lookup.

---

## 5. String safety

**Problem:** The original codebase used `strcpy`, `strcat`, `sprintf`, `strncpy`,
`strncat`, and `strtok` throughout.  These functions are inherently unsafe:
- `strcpy`/`strcat`: no bounds checking, trivial to overflow
- `sprintf`: no bounds checking
- `strncpy`: does not null-terminate when source is longer than n
- `strncat`: n is the space remaining, not total buffer size — easy to misuse
- `strtok`: uses global state, not re-entrant

**Phase 1 — Safe C string functions:**  
All `strcpy` → `strlcpy`, `strcat` → `strlcat`, `strtok` → `strtok_r`,
`sprintf` → `snprintf` throughout the codebase (35+ sites across 14 files).
`strncpy`/`strncat` were replaced with `memcpy`+explicit null or `strlcpy`/`strlcat`.

**Phase 2 — `sizeof(pointer)` bugs:**  
A systematic audit found many calls of the form:

```c
char *p = some_string;
strlcpy(dest, src, sizeof(p)); // copies sizeof(char*) = 8 bytes, not the buffer
```

These were fixed to use the actual buffer size.  Affected files include
`language.c`, `botnet.c`, `misc.c`, `tclhash.c`, `dcc.c`, `channels.mod`, and more.

**Phase 3 — Dynamic strings (`op_strbuf_t`):**  
`snprintf(buf, N, ...)` still truncates when the result is longer than `N`.
`N` is always a guess.  All remaining string-building patterns were replaced
with `op_strbuf_t`, libop's dynamic string builder with small-string
optimisation (SSO):

```c
// Before
char buf[512];
snprintf(buf, sizeof buf, "%s!%s@%s", nick, user, host);

// After
op_strbuf_t buf;
op_strbuf_printf(&buf, "%s!%s@%s", nick, user, host);
// use op_strbuf_str(&buf)
op_strbuf_free(&buf);
```

`op_strbuf_t` never truncates.  The buffer grows to fit.  The SSO avoids heap
allocation for strings ≤ 23 bytes (covering the majority of IRC hostmasks).

---

## 6. C23 modernisation

**Problem:** The codebase used C89/C99 style throughout: all variables declared
at the top of functions, `#define` for constants, `int` for boolean flags.
This made functions hard to read because you had to scroll up to understand
what a variable was, and `#define` constants are untyped and invisible in
debuggers.

**Changes:**

- **Variables declared at first use** throughout all source files.  In functions
  with many variables this dramatically reduces the cognitive load of reading
  the code.

- **`constexpr` for compile-time constants.**  `#define SALT_LEN 16` becomes
  `constexpr int SALT_LEN = 16;` — typed, visible in debuggers, and checked
  by the compiler for valid use.

- **`bool` flags** replacing `int ok = 0`, `int found = 0`, `int first = 1`.
  Self-documenting and prevents accidental arithmetic on what is logically a
  boolean.

- **`for`-init declarations**: `for (int i = 0; ...)` instead of `int i; for (i = 0; ...)`.
  Scopes the loop variable to the loop, preventing accidental reuse.

- **`[[fallthrough]]`** replacing `__attribute__((fallthrough))` in switch
  statements — the standard C23 syntax.

- **Dead variable and dead code elimination** throughout.  Every module was
  audited and unused variables from refactoring were removed, silencing
  compiler warnings and making the remaining code easier to audit.

**Build standard:** `meson.build` sets `c_std=gnu23` as the default.

---

## 7. 64-bit type migration

**Problem:** Eggdrop used `unsigned long` and `unsigned int` for values that
can exceed 32 bits on modern systems: file transfer sizes, timer IDs, socket
counts.  On 64-bit Linux `unsigned long` happens to be 64 bits, but the code
was not explicit about this assumption.  On Windows, `unsigned long` is 32
bits even on 64-bit systems, making the code silently incorrect.

**Changes:**
- `timer_id` changed from `unsigned long` to `uint64_t`
- DCC transfer sizes (`acked`, `length`) changed to `uint64_t`
- `pump_file_to_sock` return type and `pending_data` parameter changed to `uint64_t`
- Format specifiers updated to `PRIu64` throughout

This makes the intent explicit and produces correct behaviour on Windows and
any future platform where `long` is not 64 bits.

---

## 8. const correctness

**Problem:** Many functions accepted `char *` parameters for strings they never
modified.  This forced callers to cast away `const` when passing string
literals or `const` pointers, and made it impossible for the compiler to
detect accidental writes through read-only parameters.

**Functions updated to `const char *`:**

| File | Functions |
|---|---|
| `misc_file.c` / `.h` | `copyfile`, `movefile`, `file_readable`, `copyfilef`, `fcopyfile` |
| `misc.c` | `kill_bot`, `maskaddr`, `scan_help_file` |
| `tcl.c` | `do_tcl` |
| `tclhash.c` / `.h` | `check_tcl_die` |
| `users.c` | `match_ignore`, `addignore` |
| `dcc.c` | `dcc_telnet_got_ident` |
| `botmsg.c` / `tandem.h` | `botnet_send_chat`, `botnet_send_who`, `botnet_send_unlinked`, `botnet_send_infoq`, `botnet_send_traced`, `botnet_send_trace`, `botnet_send_unlink`, `botnet_send_link`, `botnet_send_motd` |
| `server.mod/servmsg.c` | `check_tcl_stdreply` context parameter |
| `tclegg.h` | `cd_tcl_cmd.name` field |

Functions that genuinely modify their string argument (e.g. `get_user_by_host`
which calls `rmspace()`, `adduser` which strips commas from host strings) were
left as `char *`.  Call sites that pass `op_strbuf_str()` results to those
functions use explicit `(char *)` casts with explanatory comments.

---

## 9. libop integration

**What libop is:** libop is the utility library from the Ophion IRC server.  It
provides production-quality implementations of data structures and I/O
primitives that eggdrop was either missing or implementing poorly.

**Components integrated:**

| Component | Replaces | Purpose |
|---|---|---|
| `op_strbuf_t` | `snprintf` into fixed buffers | Dynamic string builder with SSO |
| `op_bh` (block-heap) | `malloc`/`free` per object | Slab allocator for hot-path objects |
| `op_deque` | ad-hoc linked lists | Double-ended queue for server message queues |
| `op_vec` | fixed-size arrays | Dynamic arrays for hook lists |
| `op_snprintf_append` | `egg_snprintf` compat shim | Printf into existing buffers |

**Why ported from Ophion rather than written fresh:**  
These are mature, tested implementations from an IRC server that runs under
similar workloads to eggdrop.  Writing equivalent code from scratch would
introduce new bugs; importing from a known-good implementation does not.

**`egg_snprintf` removed:**  
The `egg_snprintf` compatibility shim (which wrapped `snprintf` with
non-standard semantics) was removed.  All call sites were updated to use
either standard `snprintf` or `op_strbuf_printf`.

---

## 10. TOML configuration

**Problem:** Eggdrop's traditional configuration format is a Tcl script.  This
is powerful but has two drawbacks:

1. Users who are not Tcl programmers find it opaque
2. When Tcl is disabled (see §11), there is no configuration system at all

**Change:** A new TOML configuration format was added (`eggdrop.toml`).

**What TOML provides:**
- Familiar INI-style sections: `[bot]`, `[network]`, `[irc]`, `[ssl]`, etc.
- Full parity with eggdrop.conf settings (all variables covered)
- Per-channel settings via `[[chanset]]` blocks
- `[sasl]` section for SASL authentication
- `conf2toml` migration tool to convert existing `.conf` files
- Multi-line backslash continuation for long values
- Comment preservation on read

**Setup wizard:**  
A 5-step interactive setup wizard (`run_setup_wizard()`) walks new users through:
1. Bot identity (nick, altnick, realname, username)
2. IRC server (network type menu with per-network defaults, port, SSL, SASL)
3. Channels (up to 8 channels with `#` prefix validation)
4. File paths (userfile, chanfile, logfile — with nick-derived defaults)
5. Modules (notes, seen, transfer, filesys y/n selection)

**Path ordering fix:**  
TOML sections can appear in any order, but module-registered variables (like
`chanfile`) were not available until after `[modules]` was processed.  If
`[paths]` appeared before `[modules]`, `chanfile` was silently dropped.  Fixed
by buffering all `[paths]` key-value pairs during parsing and replaying them
after all modules are loaded.

---

## 11. Optional Tcl / Python scripting

**Problem:** Tcl is a hard dependency of eggdrop.  On many modern systems Tcl
is not installed by default, and bot operators increasingly prefer Python.
Making Tcl optional required changes across the entire codebase.

**Change:** Tcl is now an optional build dependency (`-Dtcl=disabled`).

**What happens in a Tcl-free build:**
- All Tcl-specific code is guarded with `#ifdef HAVE_TCL` / `#else` blocks
- Stub macros in `lush.h` provide no-op replacements for Tcl API calls
- `python.mod` automatically registers as the sole scripting engine via
  `script_register()` when Tcl is absent
- Module-local bind table pointers that were only set inside `#ifdef HAVE_TCL`
  blocks now have `#else` branches that call `find_bind_table()` to retrieve
  pre-created global tables, so Python binds fire correctly

**Python API coverage:**  
90+ Python C API functions in `python.mod/pycmds.c` covering the majority of
the Tcl scripting surface area:

- Channel member status: `isop`, `ishalfop`, `isvoice`, `isaway`, `botisop`,
  `botishalfop`, `botisvoice`, `getaccount`
- Channel presence: `onchan`, `handonchan`, `onchansplit`, `topic`, `validchan`,
  `getchanjoin`, `botisowner`, `isowner`
- Channel modes/actions: `getchanmode`, `pushmode`, `flushmode`, `putkick`,
  `resetbans`, `resetexempts`, `resetinvites`, `resetchan`, `refreshchan`
- Ban/exempt/invite management: `banlist`, `exemptlist`, `invitelist`, `newban`,
  `killban`, `killchanban`, `newexempt`, `killexempt`, `newinvite`, `killinvite`,
  `matchban`, `matchexempt`, `matchinvite`, `stickban`, `unstickban`, `isban`,
  `isexempt`, `isinvite`
- User channel records: `getchaninfo`, `setchaninfo`, `addchanrec`, `delchanrec`,
  `haschanrec`, `setlaston`
- Handle/nick resolution: `nick2hand`, `hand2nick`, `isbotnick`
- User database: `countusers`, `validuser`, `finduser`, `userlist`
- Miscellaneous: `rand`, `unixtime`, `duration`, `maskhost`
- Server/network: `puthelp`, `tagmsg`, `cap`, `jump`
- IRCX/Ophion: `ircxprop`, `ircxaccess`, `ircxcreate`, `ircxnegotiate`
- DNS: `dnsdot`

**Module cross-references:**  
`python.mod` now resolves `channels_funcs`, `irc_funcs`, and `server_funcs`
at startup via `module_find()`, enabling direct access to channel, IRC, and
server module function tables for ban management, mode flushing, and server
commands.  `flush_mode()` was exported from `irc.mod` at function table
slot 29 (`IRC_FLUSH_MODE`).

**`eggtools.py`:**  
A modern Python utility library replacing `alltools.tcl` for Python script
authors.  Provides type-annotated wrappers, decorator-based bind registration
(`@on_pub`, `@on_msg`, …), a `Member` dataclass, a `MaskEntry` dataclass for
ban/exempt/invite entries, `every()` timer helper, and alltools.tcl-compatible
aliases.

**Python 3.14 compatibility:**  
`PyErr_Fetch()` was removed in Python 3.14.  `python.mod` was updated to use
the replacement API (`PyErr_GetRaisedException`).  `PyPreConfig` is used for
UTF-8 mode setup.

**tclhash dispatch unification:**  
`tclhash.c` previously contained a massive `#ifdef HAVE_TCL` / `#else` split
with ~800 lines of duplicated code for bind table management, garbage
collection, match/flag checking, and all `check_tcl_*()` helper functions.
The Tcl and no-Tcl paths were unified into a single implementation using
a `DISPATCH` macro that routes to `trigger_bind()` (Tcl) or
`dispatch_native()` (no-Tcl).  The Tcl-path versions of `check_tcl_*()`
helpers work in both builds because `lush.h` maps `Tcl_SetVar()` to
`egg_setvar()`.  File reduced from 2321 to 1713 lines (26% reduction).

---

## 12. IRCv3 and IRCX/Ophion protocol support

**IRCv3 capabilities added:**

| Capability | Purpose |
|---|---|
| `away-notify` | Receive AWAY updates without polling |
| `multi-prefix` | See all mode prefixes (op + voice simultaneously) |
| `userhost-in-names` | Get full nick!user@host in NAMES replies |
| `chghost` | Track host changes without QUIT/JOIN |
| `account-notify` | Track account login/logout events |
| `account-tag` | Receive account name on every message |
| `extended-join` | Get account name and realname in JOIN messages |
| `invite-notify` | Receive invites sent to other users |
| `message-tags` | Full IRCv3 message tag support |
| `batch` | Batch message grouping (chathistory) |
| `labeled-response` | Match server responses to client commands |
| `chathistory` | Request message history from servers |
| `echo-message` | Receive echo of sent messages |
| `setname` | Change realname on the fly |

**`stdreply` bind:**  
A new Tcl bind for IRCv3 FAIL/WARN/NOTE standard-replies, allowing scripts to
handle structured server error and informational messages.

**IRCX/Ophion support:**  
IRCX is the Microsoft-era IRC extension protocol used by the Ophion IRC server.
Support was added for:

- `IRCX` command negotiation handshake
- `IRCXPROP` channel and user property queries
- `IRCXACCESS` extended access level management
- Per-channel IRCX owner mode (`+q`)
- ISUPPORT `NETWORK=` fallback when 800 reply has no network name

---

## 13. Security hardening

**Build-time hardening (enabled by `-Dhardening=true`):**
- `-fstack-protector-strong` — stack canaries on functions with buffers
- `-fstack-clash-protection` — prevents stack-clash attacks
- `-D_FORTIFY_SOURCE=2` — bounds-checked versions of glibc string functions
- Full RELRO + `now` binding — prevents GOT overwrite attacks
- `-fno-plt` — eliminates PLT trampolines (reduces ROP gadget surface)
- `-fno-common` — prevents BSS section merging bugs

**String safety (covered in §5):**  
All `strcpy`/`strcat`/`sprintf` replaced with bounds-checked equivalents.
`sizeof(pointer)` bugs that silently truncated to 8 bytes were found and fixed
throughout the codebase.

**SASL hardening (covered in §16).**

**TLS:**
- Certificate verification enforced for DoT connections
- SHA-256 fingerprint support for server certificate pinning
- ECDH-X25519 key exchange for SASL EXTERNAL

---

## 14. Performance improvements

| Change | Before | After |
|---|---|---|
| Socket event dispatch | O(n) `select()` scan | O(1) epoll/kqueue/io_uring |
| DCC socket→index lookup | O(n) linear scan | O(1) hash map |
| User account lookup | O(n) user list scan | O(log n) splay tree |
| CIDR ban matching | O(n) per message | O(k) patricia trie |
| Channel member allocation | `malloc`/`free` per member | `op_bh` slab (mmap arena) |
| DCC file transfer | `read`→`write` copy | `sendfile()` zero-copy |
| IRC output coalescing | One `write()` per message | `writev()` ring-buffer drain |
| DNS resolution | Blocking thread or stub resolver | Fully async `res.c` |
| Module linking | Sequential | Parallel (`ninja`) |
| LTO | Off | On by default (`-Db_lto=true`) |
| Native CPU optimisation | Off | On by default (`-march=native`) |
| Bind table lookup | O(n) linked list | O(1) `op_htab` hash map |
| Bind mask dispatch | O(n) per mask list | O(1) `op_htab` exact match |
| Channel member lookup | O(n) `ismember()` scan | O(1) `op_htab` hash map |
| Ban/exempt/invite lookup | O(n) `ismask()` scan | O(1) `op_htab` hash map |
| tclhash code duplication | 2321 lines (800 duplicated) | 1713 lines (unified) |

---

## 15. UTF-8 support

Eggdrop's original core had no UTF-8 awareness.  IRC networks increasingly
require UTF-8 for nick validation, channel topics, and user messages.

**Added to `misc.c`:**
- `utf8_char_len(const unsigned char *)` — byte length of a UTF-8 character
- `utf8_valid(const char *, size_t)` — validate a UTF-8 string
- `utf8_strlen(const char *)` — character count of a UTF-8 string
- `utf8_sanitize(char *)` — replace invalid byte sequences with `?`

---

## 16. SASL authentication extensions

The existing SASL implementation was extended with:

- **ECDH-X25519** key exchange mechanism
- **Secure nonce generation** using `getrandom(2)` instead of `rand()`
- **SASLprep** (RFC 4013) string preparation for PLAIN/SCRAM passwords
- **Mechanism reporting** — the bot logs which SASL mechanism was negotiated
- **SCRAM-SHA-256 and SCRAM-SHA-512** mechanism support
- **SASL configuration in TOML:** `[sasl]` section with `sasl_mechanism`,
  `sasl_username`, `sasl_password`, `sasl_ecdsa_key`, `sasl_x25519_key`,
  `sasl_continue`, `sasl_timeout`

---

## 17. WebUI

A `webui.mod` module provides an embedded HTTP/WebSocket interface for
managing the bot from a browser.  The WebUI DCC telnet host-resolution
path was cleaned up (`webui_dcc_telnet_hostresolved`, `webui_frame`,
`webui_unframe` function pointers registered in `proto.h`).

---

## 18. Windows / IOCP native support

Eggdrop previously supported Windows only through Cygwin.  Native Windows
support was added:

- IOCP (I/O Completion Ports) backend in `net.c` for Windows
- `EGG_NATIVE_WIN32` build path (separate from `CYGWIN_HACKS`, which was removed)
- Cygwin uses the plain POSIX path
- MSVC build instructions added to `INSTALL`
- `INSTALL` rewritten with complete per-platform dependency instructions

---

## 19. CI / GitHub Actions

- All CI workflows updated from `./configure && make` to `meson setup && ninja`
- `-j$(nproc)` replaces hardcoded `-j4` everywhere
- macOS CI: robust Homebrew Tcl/OpenSSL detection, `PKG_CONFIG_PATH` for
  keg-only packages
- CodeQL analysis workflow added
- macOS-specific `LDFLAGS`/`CPPFLAGS` exported for OpenSSL detection

---

## 20. Bug fixes

| Bug | Location | Description |
|---|---|---|
| `channels.c` movefile | `write_channels()` | Temp filename built with `op_strbuf_t` was freed before `movefile()` read it. Fixed: copy to `char tmpfile[PATH_MAX]` before freeing. |
| `notes.c` string concat | `NOTES_EXPIRE_XDAYS` | Treated as a string literal but is a `get_language()` call. Adjacent-string concat caused "called object is not a function". Fixed: split into two `op_strbuf_printf` calls. |
| `msgcmds.c` `days` macro | `irc.mod` | Local variable `int days` expanded to the `days` module.h macro (a function pointer), causing "invalid operands to binary *". Fixed: renamed to `int d`. |
| `botcmd.c` `bot_chan2` | `bot_chan2()` | `i = nextbot(p)` used undeclared `i` — latent bug from TBUF removal. Fixed: `int i = nextbot(p)`. |
| io_uring SQPOLL flush | `net.c` | `io_uring_submit()` was skipped in SQPOLL mode; kernel thread never saw new SQEs. |
| io_uring buffered recv overwrite | `net.c` | Buffered data clobbered when new SQE submitted to same buffer. |
| io_uring idle return | `net.c` | Function returned -3 before dispatching buffered data. |
| TLS handshake stall | `net.c` | SSL handshake stalled when io_uring reported POLLIN-only on SOCK_CONNECT. |
| SOCK_CONNECT kqueue | `net.c` | `kevent()` connect detection used wrong filter. |
| `sizeof(char*)` truncation | 14+ files | `strlcpy(dest, src, sizeof(ptr))` copied 8 bytes instead of the buffer size. |
| `add_server` truncation | `server.mod` | Server names/passwords silently truncated to 7 characters. |
| `next_server` truncation | `server.mod` | Same truncation bug on server cycling. |
| CAP LIST handler | `server.mod` | `msg` used instead of `splitstr` in `find_capability`. |
| DNS strlcpy truncation | `dns.c` | `strlcpy(de->res_data.hostname, hostn, sizeof(char*))` truncated to 8 bytes. |
| `bind_bind_entry` truncation | `tclhash.c` | Proc name truncated due to sizeof-pointer bug. |
| `lastdeletedmask` truncation | `channels.mod` | Same sizeof-pointer bug. |
| TDNS pipe fd re-check | `net.c` | TDNS pipe fds not re-checked after io_uring wait, causing missed hostname resolutions. |
| `list_type` slab/malloc mismatch | `userrec.c` | Objects allocated with slab were freed with `free()`, causing double-free on startup. |
| `configtoml` section ordering | `configtoml.c` | `[paths]` settings dropped when appearing before `[modules]`. |
| `lang_dir` prescan | `configtoml.c` | `lang_dir` not read before `init_language()`, causing spurious "no lang files" errors. |
| No-Tcl heap corruption | `tcl.c` | `max-logs` setting corrupted heap in no-Tcl builds. |
| Python startup crash | `python.mod` | Invalid `VIRTUAL_ENV` and path injection caused crash on startup in some environments. |
| Python 3.14 build | `python.mod` | `PyErr_Fetch()` removed in 3.14; updated to `PyErr_GetRaisedException`. |
| WHOX field order | `irc.mod` | WHOX reply field order mismatch caused account tracking failures. |
| `eggcouplet` TCL r/w flags | `tclegg.c` | Read and write flag checks were merged; separated for correct trace behaviour. |
| IRC account tag | `server.mod` | Account tag not processed on all message types. |
| io_uring foreground freeze | `net.c` | STDOUT blocking in `-t` mode froze the io_uring loop. |
| IRCX double-register | `configtoml.c` | IRCX capability registered twice when wizard was re-run. |
| Help system | `misc.c` | Help file scanning failed for non-standard installation paths. |
| Channel cycling | `irc.mod` | Bot unnecessarily cycled channel when already holding IRCX `+q` owner. |
| `b64_ntop` symbol | various | Modules depended on libresolv's private `__b64_ntop` symbol; replaced with libop base64. |
| No-Tcl `check_tcl_chjn` | `tclhash.c` | Matched on `bot` with `MATCH_EXACT` instead of channel number with `MATCH_MASK`. |
| No-Tcl `check_tcl_chpt` | `tclhash.c` | Same `MATCH_EXACT` vs `MATCH_MASK` mismatch as `check_tcl_chjn`. |
| No-Tcl `check_tcl_dcc` | `tclhash.c` | Missing `BIND_QUIT` return handling — partyline `quit` bind never fired. |
| No-Tcl `check_tcl_bind` | `tclhash.c` | Missing move-to-front optimisation for hot binds, causing O(n) on every dispatch. |

---

*This document is maintained alongside the source.  If you add a significant
change, update the relevant section and add a row to §20 if it is a bug fix.*
