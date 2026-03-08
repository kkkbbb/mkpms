#!/system/bin/sh
set -u

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <pid> <mode> <loops> [value_addr] [crc_addr] [bp_ret_addr] [verify_x] [verify_y]" >&2
    exit 2
fi

PID="$1"
MODE="$2"
LOOPS="${3:-100}"
VALUE_ADDR="${4:-0}"
CRC_ADDR="${5:-0}"
BP_RET_ADDR="${6:-0}"
VERIFY_X="${7:-155}"
VERIFY_Y="${8:-2745}"
PATCH_HEX="000080d2c0035fd6"
FAIL_FILE="/data/local/tmp/wxshadow_race_fail.$$"
FAIL_LOG_DIR="/data/local/tmp/wxshadow_race_fail.$$.$MODE"

rm -f "$FAIL_FILE"
rm -rf "$FAIL_LOG_DIR"
mkdir -p "$FAIL_LOG_DIR"

record_fail() {
    echo "$1" >> "$FAIL_FILE"
}

run_cmd() {
    label="$1"
    shift

    out="$FAIL_LOG_DIR/$label.out"
    "$@" >"$out" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        record_fail "$label rc=$rc"
    fi
    return "$rc"
}

tap_loop() {
    i=0
    while [ "$i" -lt $((LOOPS * 4)) ]; do
        input tap "$VERIFY_X" "$VERIFY_Y" >/dev/null 2>&1 || true
        sleep 0.05
        i=$((i + 1))
    done
}

read_loop() {
    i=0
    while [ "$i" -lt $((LOOPS * 8)) ]; do
        run_cmd memread_value /data/local/tmp/memread "$PID" "$VALUE_ADDR" 16 || true
        run_cmd memread_crc /data/local/tmp/memread "$PID" "$CRC_ADDR" 16 || true
        i=$((i + 1))
    done
}

patch_release_loop() {
    i=0
    while [ "$i" -lt "$LOOPS" ]; do
        run_cmd patch /data/local/tmp/wxshadow_client -p "$PID" -a "$VALUE_ADDR" --patch "$PATCH_HEX" || true
        sleep 0.01
        run_cmd release /data/local/tmp/wxshadow_client -p "$PID" -a "$VALUE_ADDR" --release || true
        i=$((i + 1))
    done
}

bp_release_loop() {
    i=0
    while [ "$i" -lt "$LOOPS" ]; do
        run_cmd set_bp /data/local/tmp/wxshadow_client -p "$PID" -a "$BP_RET_ADDR" -r x0=999 || true
        sleep 0.01
        run_cmd release /data/local/tmp/wxshadow_client -p "$PID" -a "$BP_RET_ADDR" --release || true
        i=$((i + 1))
    done
}

release_all_loop() {
    i=0
    while [ "$i" -lt "$LOOPS" ]; do
        run_cmd patch /data/local/tmp/wxshadow_client -p "$PID" -a "$VALUE_ADDR" --patch "$PATCH_HEX" || true
        run_cmd set_bp_crc /data/local/tmp/wxshadow_client -p "$PID" -a "$CRC_ADDR" || true
        sleep 0.01
        run_cmd release_all /data/local/tmp/wxshadow_client -p "$PID" --release || true
        i=$((i + 1))
    done
}

case "$MODE" in
  patch_release) worker=patch_release_loop ;;
  bp_release) worker=bp_release_loop ;;
  release_all) worker=release_all_loop ;;
  *)
    echo "unknown mode: $MODE" >&2
    exit 2
    ;;
esac

start_ts=$(date +%s)
echo "mode=$MODE loops=$LOOPS pid=$PID value=$VALUE_ADDR crc=$CRC_ADDR bp_ret=$BP_RET_ADDR start=$start_ts"

tap_loop &
TAP_PID=$!
read_loop &
READ_PID=$!
$worker &
WORK_PID=$!

wait "$WORK_PID"
WORK_RC=$?
wait "$READ_PID"
READ_RC=$?
wait "$TAP_PID"
TAP_RC=$?

fail_count=0
if [ -f "$FAIL_FILE" ]; then
    fail_count=$(wc -l < "$FAIL_FILE")
fi

end_ts=$(date +%s)
echo "mode=$MODE done work_rc=$WORK_RC read_rc=$READ_RC tap_rc=$TAP_RC fail_count=$fail_count start=$start_ts end=$end_ts"
if [ -f "$FAIL_FILE" ]; then
    echo "fail_sample:"
    sort "$FAIL_FILE" | uniq -c | sed -n '1,20p'
    first_log=$(ls "$FAIL_LOG_DIR" 2>/dev/null | head -n1)
    if [ -n "${first_log:-}" ]; then
        echo "fail_log[$first_log]:"
        sed -n '1,20p' "$FAIL_LOG_DIR/$first_log"
    fi
    rm -f "$FAIL_FILE"
fi
rm -rf "$FAIL_LOG_DIR"
if [ "$WORK_RC" -ne 0 ] || [ "$READ_RC" -ne 0 ] || [ "$TAP_RC" -ne 0 ] || [ "$fail_count" -ne 0 ]; then
    exit 1
fi
exit 0
