#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEVICE_SERIAL="${DEVICE_SERIAL:-10.0.0.205:5555}"
SUPERKEY="${SUPERKEY:-}"
PACKAGE="${PACKAGE:-com.example.crcdemo}"
LIB_NAME="${LIB_NAME:-libcrcdemo.so}"
BUILD_DIR="${BUILD_DIR:-$ROOT_DIR/build}"
DEVICE_TMP="${DEVICE_TMP:-/data/local/tmp}"
KPATCH_ON_DEVICE="${KPATCH_ON_DEVICE:-$DEVICE_TMP/kpatch}"
PATCH_RELEASE_LOOPS="${PATCH_RELEASE_LOOPS:-120}"
BP_RELEASE_LOOPS="${BP_RELEASE_LOOPS:-120}"
RELEASE_ALL_LOOPS="${RELEASE_ALL_LOOPS:-80}"
VERIFY_X="${VERIFY_X:-155}"
VERIFY_Y="${VERIFY_Y:-2745}"
VALUE_SYMBOLS="${VALUE_SYMBOLS:-get_secret_value _Z16get_secret_valuei Java_com_example_crcdemo_MainActivity_getSecretValue}"
CRC_SYMBOLS="${CRC_SYMBOLS:-calculate_crc32 _Z15calculate_crc32PKhm Java_com_example_crcdemo_MainActivity_getCurrentCRC}"
START_APP="${START_APP:-1}"
KEEP_LOADED="${KEEP_LOADED:-0}"
AARCH64_CC="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
READELF_BIN="${READELF_BIN:-readelf}"
OBJDUMP_BIN="${OBJDUMP_BIN:-aarch64-linux-gnu-objdump}"
TMP_DIR=""
LOADED=0
DMESG_BASELINE=0

usage() {
    cat <<USAGE
Usage: $0 --superkey <key> [options]

Options:
  --serial <adb-serial>        Device serial, default: $DEVICE_SERIAL
  --package <pkg>              Android package name, default: $PACKAGE
  --lib <name>                 Target library basename, default: $LIB_NAME
  --verify-x <x>               Tap X coordinate, default: $VERIFY_X
  --verify-y <y>               Tap Y coordinate, default: $VERIFY_Y
  --patch-loops <n>            patch/release loops, default: $PATCH_RELEASE_LOOPS
  --bp-loops <n>               bp/release loops, default: $BP_RELEASE_LOOPS
  --release-all-loops <n>      release_all loops, default: $RELEASE_ALL_LOOPS
  --no-start-app               Do not launch package before testing
  --keep-loaded                Keep wxshadow loaded after script exits
  -h, --help                   Show this message

Environment overrides:
  DEVICE_SERIAL, SUPERKEY, PACKAGE, LIB_NAME, VERIFY_X, VERIFY_Y,
  PATCH_RELEASE_LOOPS, BP_RELEASE_LOOPS, RELEASE_ALL_LOOPS, KPATCH_ON_DEVICE,
  VALUE_SYMBOLS, CRC_SYMBOLS.
USAGE
}

log() {
    printf '[wxshadow-race] %s\n' "$*"
}

die() {
    printf '[wxshadow-race] ERROR: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

adb_shell() {
    adb -s "$DEVICE_SERIAL" shell "$@"
}

adb_su() {
    local quoted
    printf -v quoted '%q' "$*"
    adb -s "$DEVICE_SERIAL" shell "su -c $quoted"
}

require_su() {
    adb -s "$DEVICE_SERIAL" shell 'command -v su >/dev/null 2>&1' ||
        die "device does not provide su; race regression requires su for dmesg and /proc/<pid>/maps access"
}

cleanup() {
    local rc=$?
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    if [ "$KEEP_LOADED" -eq 0 ] && [ "$LOADED" -eq 1 ] && [ -n "$SUPERKEY" ]; then
        adb_su "$KPATCH_ON_DEVICE $SUPERKEY kpm unload wxshadow >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --superkey)
                SUPERKEY="$2"
                shift 2
                ;;
            --serial)
                DEVICE_SERIAL="$2"
                shift 2
                ;;
            --package)
                PACKAGE="$2"
                shift 2
                ;;
            --lib)
                LIB_NAME="$2"
                shift 2
                ;;
            --verify-x)
                VERIFY_X="$2"
                shift 2
                ;;
            --verify-y)
                VERIFY_Y="$2"
                shift 2
                ;;
            --patch-loops)
                PATCH_RELEASE_LOOPS="$2"
                shift 2
                ;;
            --bp-loops)
                BP_RELEASE_LOOPS="$2"
                shift 2
                ;;
            --release-all-loops)
                RELEASE_ALL_LOOPS="$2"
                shift 2
                ;;
            --no-start-app)
                START_APP=0
                shift
                ;;
            --keep-loaded)
                KEEP_LOADED=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
    done
}

build_helpers() {
    mkdir -p "$BUILD_DIR/tools"
    if [ ! -x "$BUILD_DIR/tools/kpatch" ] || [ "$ROOT_DIR/tools/kpatch/kpatch.c" -nt "$BUILD_DIR/tools/kpatch" ]; then
        log "building kpatch helper"
        "$AARCH64_CC" -O2 -static "$ROOT_DIR/tools/kpatch/kpatch.c" -o "$BUILD_DIR/tools/kpatch"
    fi
    if [ ! -x "$BUILD_DIR/memread" ] || [ "$ROOT_DIR/tools/memread.c" -nt "$BUILD_DIR/memread" ]; then
        log "building memread helper"
        "$AARCH64_CC" -O2 -static "$ROOT_DIR/tools/memread.c" -o "$BUILD_DIR/memread"
    fi
}

build_targets() {
    log "building wxshadow artifacts"
    cmake --build "$BUILD_DIR" --target wxshadow.kpm wxshadow_client -j4 >/dev/null
}

push_artifacts() {
    log "pushing artifacts to device"
    adb -s "$DEVICE_SERIAL" push "$BUILD_DIR/kpms/wxshadow/wxshadow.kpm" "$DEVICE_TMP/wxshadow.kpm" >/dev/null
    adb -s "$DEVICE_SERIAL" push "$BUILD_DIR/kpms/wxshadow/wxshadow_client" "$DEVICE_TMP/wxshadow_client" >/dev/null
    adb -s "$DEVICE_SERIAL" push "$BUILD_DIR/memread" "$DEVICE_TMP/memread" >/dev/null
    adb -s "$DEVICE_SERIAL" push "$BUILD_DIR/tools/kpatch" "$DEVICE_TMP/kpatch" >/dev/null
    adb -s "$DEVICE_SERIAL" push "$ROOT_DIR/kpms/wxshadow/scripts/wxshadow_race.sh" "$DEVICE_TMP/wxshadow_race.sh" >/dev/null
    adb_shell "chmod 755 $DEVICE_TMP/wxshadow_client $DEVICE_TMP/memread $DEVICE_TMP/kpatch $DEVICE_TMP/wxshadow_race.sh" >/dev/null
}

load_module() {
    log "loading wxshadow"
    adb_su "$KPATCH_ON_DEVICE $SUPERKEY kpm unload wxshadow >/dev/null 2>&1 || true"
    adb_su "$KPATCH_ON_DEVICE $SUPERKEY hello" >/dev/null
    adb_su "$KPATCH_ON_DEVICE $SUPERKEY kpm load $DEVICE_TMP/wxshadow.kpm" >/dev/null
    LOADED=1
}

start_app_if_needed() {
    if [ "$START_APP" -eq 1 ]; then
        log "launching $PACKAGE"
        adb_shell "monkey -p $PACKAGE -c android.intent.category.LAUNCHER 1" >/dev/null 2>&1 || true
        sleep 2
    fi
}

wait_for_pid() {
    local pid=""
    local i
    for i in $(seq 1 20); do
        pid="$(adb_shell "pidof -s $PACKAGE" | tr -d '\r')"
        if [ -n "$pid" ]; then
            printf '%s\n' "$pid"
            return 0
        fi
        sleep 1
    done
    return 1
}

pull_library() {
    local apk_path apk_file
    TMP_DIR="$(mktemp -d)"
    apk_path="$(adb_shell "pm path $PACKAGE" | tr -d '\r' | sed -n 's/^package://p' | grep '/base\\.apk$' | head -n1)"
    if [ -z "$apk_path" ]; then
        apk_path="$(adb_shell "pm path $PACKAGE" | tr -d '\r' | sed -n 's/^package://p' | head -n1)"
    fi
    [ -n "$apk_path" ] || die "unable to resolve apk path for $PACKAGE"
    apk_file="$TMP_DIR/app.apk"
    adb -s "$DEVICE_SERIAL" pull "$apk_path" "$apk_file" >/dev/null
    unzip -o -j "$apk_file" "lib/arm64-v8a/$LIB_NAME" -d "$TMP_DIR/lib" >/dev/null
    [ -f "$TMP_DIR/lib/$LIB_NAME" ] || die "failed to extract $LIB_NAME from $apk_path"
    printf '%s\n' "$TMP_DIR/lib/$LIB_NAME"
}

lookup_symbol_offset() {
    local lib_path="$1"
    local symbol="$2"
    local value
    value="$($READELF_BIN -Ws "$lib_path" | awk -v sym="$symbol" '$8 == sym && $4 == "FUNC" { print "0x" $2; exit }')"
    printf '%s\n' "$value"
}

resolve_symbol_offset() {
    local lib_path="$1"
    shift
    local symbol value

    for symbol in "$@"; do
        value="$(lookup_symbol_offset "$lib_path" "$symbol")"
        if [ -n "$value" ]; then
            printf '%s %s\n' "$symbol" "$value"
            return 0
        fi
    done
    return 1
}

resolve_ret_offset() {
    local lib_path="$1"
    local symbol="$2"
    local value
    value="$($OBJDUMP_BIN -d "$lib_path" | awk -v sym="$symbol" '
        /^[0-9a-f]+ <.*>:/ {
            name = $2
            sub(/^</, "", name)
            sub(/>:/, "", name)
            sub(/@@.*/, "", name)
            if (name == sym) {
                in_func = 1
                next
            }
            if (in_func) {
                exit
            }
        }
        in_func && $NF == "ret" {
            sub(/:.*/, "", $1)
            print "0x" $1
            exit
        }
    ')"
    [ -n "$value" ] || die "ret not found in $symbol"
    printf '%s\n' "$value"
}

resolve_lib_base() {
    local pid="$1"
    local value
    value="$(adb_su "grep '$LIB_NAME' /proc/$pid/maps | awk '\$3 == \"00000000\" { split(\$1, a, \"-\"); print \"0x\" a[1]; exit }'" | tr -d '\r')"
    [ -n "$value" ] || die "failed to resolve base address for $LIB_NAME in pid $pid"
    printf '%s\n' "$value"
}

hex_add() {
    printf '0x%x\n' "$(( $1 + $2 ))"
}

run_mode() {
    local pid="$1"
    local mode="$2"
    local loops="$3"
    local value_addr="$4"
    local crc_addr="$5"
    local bp_ret_addr="$6"
    local pid_after

    log "running $mode loops=$loops pid=$pid"
    adb_su "$DEVICE_TMP/wxshadow_race.sh $pid $mode $loops $value_addr $crc_addr $bp_ret_addr $VERIFY_X $VERIFY_Y"
    pid_after="$(adb_shell "pidof -s $PACKAGE" | tr -d '\r')"
    [ -n "$pid_after" ] || die "$PACKAGE exited during $mode"
    [ "$pid_after" = "$pid" ] || die "$PACKAGE restarted during $mode: $pid -> $pid_after"
}

check_kernel_log() {
    local bad
    bad="$(adb_su "dmesg | tail -n +$((DMESG_BASELINE + 1)) | grep -E 'step handler: NOT FOUND|BRK: not our breakpoint|Bad page map|Bad page state|BUG: Bad rss-counter' || true" | tr -d '\r')"
    if [ -n "$bad" ]; then
        printf '%s\n' "$bad" >&2
        die "detected suspicious kernel log after race run"
    fi
}

main() {
    local pid lib_path base_addr value_symbol crc_symbol value_off crc_off ret_off value_addr crc_addr bp_ret_addr
    local resolved

    parse_args "$@"
    [ -n "$SUPERKEY" ] || die "--superkey is required"
    need_cmd adb
    need_cmd cmake
    need_cmd unzip
    need_cmd "$AARCH64_CC"
    need_cmd "$READELF_BIN"
    need_cmd "$OBJDUMP_BIN"

    require_su
    build_helpers
    build_targets
    push_artifacts
    DMESG_BASELINE="$(adb_su "dmesg | wc -l" | tr -d '\r[:space:]')"
    load_module
    start_app_if_needed
    pid="$(wait_for_pid)" || die "failed to find pid for $PACKAGE"
    log "resolved pid=$pid"

    lib_path="$(pull_library)"
    base_addr="$(resolve_lib_base "$pid")"
    resolved="$(resolve_symbol_offset "$lib_path" $VALUE_SYMBOLS)" || die "unable to resolve value symbol from: $VALUE_SYMBOLS"
    value_symbol="${resolved%% *}"
    value_off="${resolved#* }"
    resolved="$(resolve_symbol_offset "$lib_path" $CRC_SYMBOLS)" || die "unable to resolve crc symbol from: $CRC_SYMBOLS"
    crc_symbol="${resolved%% *}"
    crc_off="${resolved#* }"
    ret_off="$(resolve_ret_offset "$lib_path" "$value_symbol")"

    value_addr="$(hex_add "$base_addr" "$value_off")"
    crc_addr="$(hex_add "$base_addr" "$crc_off")"
    bp_ret_addr="$(hex_add "$base_addr" "$ret_off")"

    log "base=$base_addr value_symbol=$value_symbol value=$value_addr crc_symbol=$crc_symbol crc=$crc_addr bp_ret=$bp_ret_addr"

    run_mode "$pid" patch_release "$PATCH_RELEASE_LOOPS" "$value_addr" "$crc_addr" "$bp_ret_addr"
    run_mode "$pid" bp_release "$BP_RELEASE_LOOPS" "$value_addr" "$crc_addr" "$bp_ret_addr"
    run_mode "$pid" release_all "$RELEASE_ALL_LOOPS" "$value_addr" "$crc_addr" "$bp_ret_addr"
    check_kernel_log
    log "all device race regressions passed"
}

main "$@"
