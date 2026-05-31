# perf_track.tcl — periodic dump of ASYNCRECV stats for perf testing
#
# The per-channel PRIVMSG counting is now handled in C (msg_counter.c) and
# logs [MSGRATE] lines directly via HOOK_MINUTELY.  This script only provides
# the utimer-based fallback dump used to correlate timing with [ASYNCRECV]
# lines emitted by the C layer.
#
# Load via eggdrop-libera-perf.toml:
#   [tcl]
#   scripts = ["scripts/perf_track.tcl"]

utimer 60 perf::dump_asyncrecv

namespace eval perf {
    proc dump_asyncrecv {} {
        utimer 60 perf::dump_asyncrecv
    }
}

putlog "\[PERFTRACK\] Message rate tracker started (C layer active)"
