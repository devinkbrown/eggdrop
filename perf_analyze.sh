#!/bin/bash
# perf_analyze.sh — analyze libera-perf.log for async recv + message rate stats
#
# Usage:
#   ./perf_analyze.sh [logfile]          # default: libera-perf.log
#   ./perf_analyze.sh --follow logfile   # live tail mode

set -euo pipefail

LOG="${2:-${1:-libera-perf.log}}"
FOLLOW=0
[[ "${1:-}" == "--follow" ]] && FOLLOW=1

die() { echo "ERROR: $*" >&2; exit 1; }
[[ -f "$LOG" ]] || die "Log file not found: $LOG"

# ---- helpers ----------------------------------------------------------------

field() {
    # Extract key=value from a line; field KEY LINE
    local key="$1" line="$2"
    echo "$line" | grep -oP "(?<=\\b${key}=)[^ ]+"
}

human_bytes() {
    local b=$1
    if   (( b < 1024 ));           then printf "%d B"     $b
    elif (( b < 1048576 ));        then printf "%.1f KB"  "$(echo "scale=1; $b/1024" | bc)"
    elif (( b < 1073741824 ));     then printf "%.2f MB"  "$(echo "scale=2; $b/1048576" | bc)"
    else                                printf "%.2f GB"  "$(echo "scale=2; $b/1073741824" | bc)"
    fi
}

# ---- ASYNCRECV section ------------------------------------------------------

echo "════════════════════════════════════════════════════════"
echo "  ASYNC RECV STATS  ($LOG)"
echo "════════════════════════════════════════════════════════"

mapfile -t ar_lines < <(grep '\[ASYNCRECV\]' "$LOG" 2>/dev/null || true)
n_ar=${#ar_lines[@]}

if (( n_ar == 0 )); then
    echo "  (no [ASYNCRECV] lines yet — bot may not be running)"
else
    echo "  Samples collected : $n_ar"
    echo ""

    # Extract arrays
    declare -a ar_calls ar_bytes ar_hwm ar_calls_s ar_bytes_s ar_t
    for line in "${ar_lines[@]}"; do
        ar_t+=($(field t "$line"))
        ar_calls+=($(field calls "$line"))
        ar_bytes+=($(field bytes "$line"))
        ar_hwm+=($(field hwm "$line"))
        ar_calls_s+=($(field calls_s "$line"))
        ar_bytes_s+=($(field bytes_s "$line"))
    done

    # First / last sample totals
    first_calls=${ar_calls[0]}
    last_calls=${ar_calls[-1]}
    first_bytes=${ar_bytes[0]}
    last_bytes=${ar_bytes[-1]}
    first_t=${ar_t[0]}
    last_t=${ar_t[-1]}
    elapsed=$(( last_t - first_t ))

    echo "  First sample      : $(date -d @$first_t '+%H:%M:%S')  calls=$first_calls  bytes=$(human_bytes $first_bytes)"
    echo "  Last  sample      : $(date -d @$last_t  '+%H:%M:%S')  calls=$last_calls  bytes=$(human_bytes $last_bytes)"
    if (( elapsed > 0 )); then
        delta_calls=$(( last_calls - first_calls ))
        delta_bytes=$(( last_bytes - first_bytes ))
        avg_calls_s=$(echo "scale=2; $delta_calls / $elapsed" | bc)
        avg_bytes_s=$(echo "scale=0; $delta_bytes / $elapsed" | bc)
        echo "  Elapsed           : ${elapsed}s"
        echo "  Avg calls/s       : $avg_calls_s  ($(human_bytes $avg_bytes_s)/s avg throughput)"
    fi

    # HWM across all samples
    max_hwm=0
    for v in "${ar_hwm[@]}"; do
        (( v > max_hwm )) && max_hwm=$v
    done
    echo "  Peak HWM          : $max_hwm concurrent recv() in-flight"

    # Peak windowed rate
    max_calls_s=0
    max_bytes_s=0
    for i in "${!ar_calls_s[@]}"; do
        v=${ar_calls_s[$i]}
        cmp=$(echo "$v > $max_calls_s" | bc)
        (( cmp )) && max_calls_s=$v
        v=${ar_bytes_s[$i]}
        cmp=$(echo "$v > $max_bytes_s" | bc)
        (( cmp )) && max_bytes_s=$v
    done
    echo "  Peak calls/s      : $max_calls_s  (10 s window)"
    echo "  Peak bytes/s      : $(human_bytes ${max_bytes_s%.*})/s  (10 s window)"

    echo ""
    echo "  --- per-minute call rate ---"
    printf "  %-8s  %-10s  %-12s  %-12s  %s\n" TIME CALLS/S BYTES/S HWM BYTES_TOT
    printf "  %-8s  %-10s  %-12s  %-12s  %s\n" "--------" "----------" "------------" "--------" "-----------"
    for i in "${!ar_lines[@]}"; do
        t=${ar_t[$i]}
        printf "  %-8s  %-10s  %-12s  %-12s  %s\n" \
            "$(date -d @$t '+%H:%M:%S')" \
            "${ar_calls_s[$i]}" \
            "${ar_bytes_s[$i]}" \
            "${ar_hwm[$i]}" \
            "$(human_bytes ${ar_bytes[$i]})"
    done
fi

# ---- MSGRATE section --------------------------------------------------------

echo ""
echo "════════════════════════════════════════════════════════"
echo "  MESSAGE RATE BY CHANNEL"
echo "════════════════════════════════════════════════════════"

mapfile -t mr_lines < <(grep '\[MSGRATE\].*chan=#' "$LOG" 2>/dev/null || true)

if (( ${#mr_lines[@]} == 0 )); then
    echo "  (no [MSGRATE] lines yet)"
else
    # Collect per-channel totals from last sample per channel
    declare -A chan_msgs chan_bytes chan_rate

    for line in "${mr_lines[@]}"; do
        chan=$(field chan "$line")
        msgs=$(field total_msgs "$line")
        bytes=$(field total_bytes "$line")
        rate=$(field rate "$line")
        rate="${rate%/s}"
        chan_msgs[$chan]=$msgs
        chan_bytes[$chan]=$bytes
        chan_rate[$chan]=$rate
    done

    printf "  %-20s  %-12s  %-14s  %s\n" CHANNEL "TOTAL MSGS" "TOTAL BYTES" "LAST RATE"
    printf "  %-20s  %-12s  %-14s  %s\n" "--------------------" "----------" "------------" "---------"
    for chan in $(echo "${!chan_msgs[@]}" | tr ' ' '\n' | sort); do
        printf "  %-20s  %-12s  %-14s  %s/s\n" \
            "$chan" "${chan_msgs[$chan]}" \
            "$(human_bytes ${chan_bytes[$chan]})" \
            "${chan_rate[$chan]}"
    done

    # Summary across all channels (grab ALL lines)
    mapfile -t mr_all < <(grep '\[MSGRATE\].*chan=ALL' "$LOG" 2>/dev/null || true)
    if (( ${#mr_all[@]} > 0 )); then
        last_all="${mr_all[-1]}"
        total_m=$(field msgs "$last_all")
        total_b=$(field bytes "$last_all")
        last_rate=$(field rate "$last_all"); last_rate="${last_rate%/s}"
        echo ""
        printf "  %-20s  %-12s  %-14s  %s/s\n" "ALL CHANNELS" "$total_m" "$(human_bytes $total_b)" "$last_rate"
    fi
fi

echo ""
echo "════════════════════════════════════════════════════════"

if [[ $FOLLOW == 1 ]]; then
    echo "  Watching for new entries (Ctrl-C to stop)..."
    echo ""
    tail -Fn0 "$LOG" | while read -r line; do
        if [[ "$line" == *"[ASYNCRECV]"* ]]; then
            t=$(field t "$line")
            calls_s=$(field calls_s "$line")
            bytes_s=$(field bytes_s "$line")
            hwm=$(field hwm "$line")
            bytes=$(field bytes "$line")
            printf "  [RECV] %s  calls/s=%-8s  bytes/s=%-10s  hwm=%-4s  total=%s\n" \
                "$(date -d @$t '+%H:%M:%S')" "$calls_s" "$bytes_s" "$hwm" "$(human_bytes $bytes)"
        elif [[ "$line" == *"[MSGRATE]"*"chan=ALL"* ]]; then
            t=$(field t "$line")
            rate=$(field rate "$line"); rate="${rate%/s}"
            msgs=$(field msgs "$line")
            printf "  [MSG]  %s  rate=%-8s/s  msgs=%s\n" \
                "$(date -d @$t '+%H:%M:%S')" "$rate" "$msgs"
        fi
    done
fi
