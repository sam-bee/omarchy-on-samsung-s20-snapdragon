#!/bin/sh
# One-shot conditional CONTROL1 AP-route helper.
# Production identity comes only from /etc/r8q-usb-route.env. Hardware mode is
# disabled unless R8Q_USB_ROUTE_HARDWARE_MODE=1 is explicit.
set -eu
set -f
umask 077

OFFLINE=${R8Q_OFFLINE_FIXTURE:-0}
if test "$OFFLINE" = 1; then
    PROTOCOL_DIR=${R8Q_PROTOCOL_DIR:?missing R8Q_PROTOCOL_DIR}
    CONFIG_FILE=${R8Q_CONFIG_FILE:?missing R8Q_CONFIG_FILE}
else
    PROTOCOL_DIR=/usr/local/lib/r8q-usb-route
    CONFIG_FILE=/etc/r8q-usb-route.env
fi
PROTOCOL_FILE=$PROTOCOL_DIR/protocol-binding.env
test -f "$PROTOCOL_FILE" || { echo "FAIL:missing protocol binding" >&2; exit 1; }
test ! -L "$PROTOCOL_FILE" || { echo "FAIL:protocol binding is a symlink" >&2; exit 1; }
# shellcheck disable=SC1090
. "$PROTOCOL_FILE"

if test "$OFFLINE" = 1; then
    SYSFS_ROOT=${R8Q_SYSFS_ROOT:-/sys}
    PROC_ROOT=${R8Q_PROC_ROOT:-/proc}
    ETC_ROOT=${R8Q_ETC_ROOT:-/etc}
    STATE_ROOT=${R8Q_STATE_ROOT:-/tmp/r8q-usb-route/state}
    BOOT_DEVICE=${R8Q_BOOT_DEVICE:-/dev/sda23}
    ROOT_DEVICE=${R8Q_ROOT_DEVICE:-/dev/sda36}
    ROOT_DEVICE_HELPER=${R8Q_ROOT_DEVICE_HELPER:-${PROTOCOL_DIR%/usr/local/lib/r8q-usb-route}/usr/local/sbin/r8q-root-device}
    POLL_LIMIT=${R8Q_POLL_LIMIT:-3}
    POLL_SLEEP=${R8Q_POLL_SLEEP:-0}
else
    SYSFS_ROOT=/sys
    PROC_ROOT=/proc
    ETC_ROOT=/etc
    STATE_ROOT=/var/lib/r8q-usb-route
    BOOT_DEVICE=/dev/sda23
    ROOT_DEVICE=/dev/sda36
    ROOT_DEVICE_HELPER=/usr/local/sbin/r8q-root-device
    POLL_LIMIT=100
    POLL_SLEEP=0.05
fi
test "${R8Q_USB_ROUTE_HARDWARE_MODE:-0}" = 1 || {
    echo "FAIL:hardware mode is disabled; set R8Q_USB_ROUTE_HARDWARE_MODE=1 only after independent review" >&2
    exit 1
}
OPTIONAL_NOHOST=${R8Q_USB_ROUTE_OPTIONAL_NOHOST:-0}
case "$OPTIONAL_NOHOST" in
    0|1) ;;
    *) echo "FAIL:optional no-host mode must be 0 or 1" >&2; exit 1 ;;
esac

# Samsung's BC1.2 enum is source-bound: 0x03 is DCP (a wall/sink charger),
# while 0x01 is SDP (the laptop/USB host path retained below).  This value is
# deliberately local to the optional classification; the protocol binding
# file and the host transaction remain byte-for-byte source-bound.
WALL_BC_VALUE=0x03
BC_USB_VALUE_NUM=$((BC_USB_VALUE))
WALL_BC_VALUE_NUM=$((WALL_BC_VALUE))
DCDTMO_MASK=0x04

RECEIPT=
RAW=
ATTEMPT_DIR=
MAILBOX_ATTEMPTED=0
MAILBOX_SUCCEEDED=0
UIC_READS=0
TRANSACTION_INDEX=0
TRANSFER_OUTPUT=
TOTAL_START_CS=0
TOTAL_DEADLINE_CS=0
MANUAL_CLEANUP_REQUIRED=0

die() {
    message=$*
    if test -n "${RECEIPT:-}" && test -f "$RECEIPT"; then
        printf 'schema=r8q-usb-route/v1\noutcome=error\nreason=%s\nmailbox_writes_attempted=%s\nmailbox_writes_succeeded=%s\nuic_reads=%s\nmanual_cleanup_required=%s\nautomatic_retry=false\n' \
            "$message" "$MAILBOX_ATTEMPTED" "$MAILBOX_SUCCEEDED" "$UIC_READS" "$MANUAL_CLEANUP_REQUIRED" >> "$RECEIPT" 2>/dev/null || :
    fi
    echo "FAIL:$message" >&2
    exit 1
}

validate_identity_token() {
    identity_name=$1
    identity_value=$2
    test -n "$identity_value" || die "$identity_name is empty"
    case "$identity_value" in
        *[!A-Za-z0-9._:+-]*) die "$identity_name contains invalid characters" ;;
    esac
}

load_deployment_identity() {
    expected_kernel=
    expected_machine_id=
    expected_root_uuid=
    expected_boot_sha256=
    expected_vermagic=
    expected_gpi_sha256=
    expected_geni_sha256=
    expected_helper_sha256=
    expected_protocol_sha256=
    while IFS= read -r config_line || test -n "$config_line"; do
        case "$config_line" in
            ''|'#'*) continue ;;
            EXPECTED_KERNEL=*)
                test -z "$expected_kernel" || die "duplicate EXPECTED_KERNEL"
                expected_kernel=${config_line#*=}
                validate_identity_token EXPECTED_KERNEL "$expected_kernel"
                ;;
            EXPECTED_MACHINE_ID=*)
                test -z "$expected_machine_id" || die "duplicate EXPECTED_MACHINE_ID"
                expected_machine_id=${config_line#*=}
                validate_identity_token EXPECTED_MACHINE_ID "$expected_machine_id"
                ;;
            EXPECTED_ROOT_UUID=*)
                test -z "$expected_root_uuid" || die "duplicate EXPECTED_ROOT_UUID"
                expected_root_uuid=${config_line#*=}
                validate_identity_token EXPECTED_ROOT_UUID "$expected_root_uuid"
                ;;
            EXPECTED_BOOT_SHA256=*)
                test -z "$expected_boot_sha256" || die "duplicate EXPECTED_BOOT_SHA256"
                expected_boot_sha256=${config_line#*=}
                validate_identity_token EXPECTED_BOOT_SHA256 "$expected_boot_sha256"
                ;;
            EXPECTED_VERMAGIC=*)
                test -z "$expected_vermagic" || die "duplicate EXPECTED_VERMAGIC"
                expected_vermagic=${config_line#*=}
                case "$expected_vermagic" in
                    \'*\') expected_vermagic=${expected_vermagic#\'}; expected_vermagic=${expected_vermagic%\'} ;;
                    \"*\") expected_vermagic=${expected_vermagic#\"}; expected_vermagic=${expected_vermagic%\"} ;;
                    *) die "EXPECTED_VERMAGIC must be quoted" ;;
                esac
                test -n "$expected_vermagic" || die "EXPECTED_VERMAGIC is empty"
                case "$expected_vermagic" in *[\'\"\\]*) die "EXPECTED_VERMAGIC contains quoting characters" ;; esac
                ;;
            EXPECTED_GPI_SHA256=*)
                test -z "$expected_gpi_sha256" || die "duplicate EXPECTED_GPI_SHA256"
                expected_gpi_sha256=${config_line#*=}
                validate_identity_token EXPECTED_GPI_SHA256 "$expected_gpi_sha256"
                ;;
            EXPECTED_GENI_SHA256=*)
                test -z "$expected_geni_sha256" || die "duplicate EXPECTED_GENI_SHA256"
                expected_geni_sha256=${config_line#*=}
                validate_identity_token EXPECTED_GENI_SHA256 "$expected_geni_sha256"
                ;;
            EXPECTED_HELPER_SHA256=*)
                test -z "$expected_helper_sha256" || die "duplicate EXPECTED_HELPER_SHA256"
                expected_helper_sha256=${config_line#*=}
                validate_identity_token EXPECTED_HELPER_SHA256 "$expected_helper_sha256"
                ;;
            EXPECTED_PROTOCOL_SHA256=*)
                test -z "$expected_protocol_sha256" || die "duplicate EXPECTED_PROTOCOL_SHA256"
                expected_protocol_sha256=${config_line#*=}
                validate_identity_token EXPECTED_PROTOCOL_SHA256 "$expected_protocol_sha256"
                ;;
            *) die "unknown deployment identity variable" ;;
        esac
    done < "$CONFIG_FILE" || die "cannot read deployment identity config"
    test -n "$expected_kernel" || die "EXPECTED_KERNEL is missing"
    test -n "$expected_machine_id" || die "EXPECTED_MACHINE_ID is missing"
    test -n "$expected_root_uuid" || die "EXPECTED_ROOT_UUID is missing"
    test -n "$expected_boot_sha256" || die "EXPECTED_BOOT_SHA256 is missing"
    test -n "$expected_vermagic" || die "EXPECTED_VERMAGIC is missing"
    test -n "$expected_gpi_sha256" || die "EXPECTED_GPI_SHA256 is missing"
    test -n "$expected_geni_sha256" || die "EXPECTED_GENI_SHA256 is missing"
    test -n "$expected_helper_sha256" || die "EXPECTED_HELPER_SHA256 is missing"
    test -n "$expected_protocol_sha256" || die "EXPECTED_PROTOCOL_SHA256 is missing"
    case "$expected_machine_id" in
        ????????????????????????????????) ;;
        *) die "EXPECTED_MACHINE_ID is malformed" ;;
    esac
    case "$expected_root_uuid" in
        ????????-????-????-????-????????????) ;;
        *) die "EXPECTED_ROOT_UUID is malformed" ;;
    esac
    case "$expected_machine_id" in
        *[!0123456789abcdef-]*) die "EXPECTED_MACHINE_ID is not lowercase hexadecimal" ;;
    esac
    case "$expected_root_uuid" in
        *[!0123456789abcdef-]*) die "EXPECTED_ROOT_UUID is not lowercase hexadecimal" ;;
    esac
    test "${#expected_boot_sha256}" -eq 64 || die "EXPECTED_BOOT_SHA256 must be 64 hexadecimal characters"
    case "$expected_boot_sha256" in
        *[!0123456789abcdef]*) die "EXPECTED_BOOT_SHA256 is not lowercase hexadecimal" ;;
    esac
    for metadata_hash in "$expected_gpi_sha256" "$expected_geni_sha256" "$expected_helper_sha256" "$expected_protocol_sha256"; do
        test "${#metadata_hash}" -eq 64 || die "deployment metadata hash must be 64 hexadecimal characters"
        case "$metadata_hash" in *[!0123456789abcdef]*) die "deployment metadata hash is not lowercase hexadecimal" ;; esac
    done
    EXPECTED_KERNEL=$expected_kernel
    EXPECTED_MACHINE_ID=$expected_machine_id
    EXPECTED_ROOT_UUID=$expected_root_uuid
    EXPECTED_BOOT_SHA256=$expected_boot_sha256
    EXPECTED_VERMAGIC=$expected_vermagic
    EXPECTED_GPI_SHA256=$expected_gpi_sha256
    EXPECTED_GENI_SHA256=$expected_geni_sha256
    EXPECTED_HELPER_SHA256=$expected_helper_sha256
    EXPECTED_PROTOCOL_SHA256=$expected_protocol_sha256
}

test "$#" = 0 || die "usage: $0"
test -f "$CONFIG_FILE" || die "deployment identity config is missing"
test ! -L "$CONFIG_FILE" || die "deployment identity config is a symlink"
load_deployment_identity
case "$SOURCE_REPOSITORY:$SOURCE_COMMIT:$SOURCE_VERIFIED_FILES" in
    BeneficialCode/android_kernel_samsung_smg7810:efbb7d3b9d0c36bd86bd098a9f0c9fc7cc6b2488:31) ;;
    *) die "source binding mismatch" ;;
esac
test "$SOURCE_MANIFEST_SHA256" = 021f36ceefa0fc9e6f762cd4bacb859f00af357a8d4d28cbfd566ccc64860863 || die "source manifest binding mismatch"
test "$SOURCE_VERIFICATION_SHA256" = 9eb387c140cb31dc38c97695a99eb77ff20e2c99d74e3086ecc1f9bc539a8b2e || die "source verification binding mismatch"
test "$PMIC_ADDRESS:$MUIC_ADDRESS:$UIC_REGISTER:$OPCODE_REGISTER:$END_DATA_REGISTER:$RESPONSE_REGISTER" = 0x66:0x25:0x02:0x21:0x41:0x51 || die "register binding mismatch"
test "$READ_OPCODE:$WRITE_OPCODE:$TARGET_ROUTE:$COM_OPEN:$COM_USB_CP" = 0x05:0x06:0x09:0x3f:0xa4 || die "opcode or route binding mismatch"
test "$ALLOWED_INITIAL_UIC_MASK" = 0x33 || die "initial UIC mask binding mismatch"
test "$CC_STATUS1_REJECT_MASK" = 0xf6 || die "CC_STATUS1 safety mask binding mismatch"

test -f "$ROOT_DEVICE_HELPER" || die "root-device helper is missing"
test ! -L "$ROOT_DEVICE_HELPER" || die "root-device helper is a symlink"
if test "$OFFLINE" = 1; then
    ROOT_DEVICE=$(R8Q_ROOT_DEVICE_OFFLINE=1 \
        R8Q_ROOT_DEVICE_ETC_ROOT="$ETC_ROOT" \
        R8Q_ROOT_DEVICE_PROFILE="${R8Q_ROOT_DEVICE_PROFILE:-$ETC_ROOT/r8q-encrypted-root.env}" \
        R8Q_ROOT_DEVICE_FINDMNT="${R8Q_ROOT_DEVICE_FINDMNT:-findmnt}" \
        R8Q_ROOT_DEVICE_BLKID="${R8Q_ROOT_DEVICE_BLKID:-blkid}" \
        R8Q_ROOT_DEVICE_STAT="${R8Q_ROOT_DEVICE_STAT:-stat}" \
        "$ROOT_DEVICE_HELPER" | tr -d '\r\n') || die "root-device validation failed"
else
    ROOT_DEVICE=$("$ROOT_DEVICE_HELPER" | tr -d '\r\n') || die "root-device validation failed"
fi
case "$ROOT_DEVICE" in
    /dev/*) ;;
    *) die "root-device helper returned an invalid source" ;;
esac

command -v cat >/dev/null 2>&1 || die "cat is unavailable"
command -v date >/dev/null 2>&1 || die "date is unavailable"
command -v tr >/dev/null 2>&1 || die "tr is unavailable"
command -v sleep >/dev/null 2>&1 || die "sleep is unavailable"
command -v uname >/dev/null 2>&1 || die "uname is unavailable"
command -v blkid >/dev/null 2>&1 || die "blkid is unavailable"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is unavailable"
command -v readlink >/dev/null 2>&1 || die "readlink is unavailable"
command -v grep >/dev/null 2>&1 || die "grep is unavailable"
command -v awk >/dev/null 2>&1 || die "awk is unavailable"
command -v timeout >/dev/null 2>&1 || die "timeout is unavailable; refusing unbounded I2C calls"
TIMEOUT_BIN=$(command -v timeout)
I2C_TRANSFER=$(command -v i2ctransfer 2>/dev/null || true)
test -n "$I2C_TRANSFER" || die "i2ctransfer is unavailable"
test -f "$0" || die "helper path is not a regular file"
test ! -L "$0" || die "helper path is a symlink"
PROTOCOL_LINE=$(sha256sum "$PROTOCOL_FILE") || die "protocol binding hash failed"
PROTOCOL_ACTUAL=${PROTOCOL_LINE%% *}
test "$PROTOCOL_ACTUAL" = "$EXPECTED_PROTOCOL_SHA256" || die "protocol binding hash mismatch"
HELPER_LINE=$(sha256sum "$0") || die "helper hash failed"
HELPER_ACTUAL=${HELPER_LINE%% *}
test "$HELPER_ACTUAL" = "$EXPECTED_HELPER_SHA256" || die "helper hash mismatch"

test "$OFFLINE" = 1 || test "$(id -u)" = 0 || die "hardware mode requires root"
test -d "$STATE_ROOT" || mkdir -p "$STATE_ROOT" || die "cannot create state root"
test ! -L "$STATE_ROOT" || die "state root is a symlink"
chmod 0700 "$STATE_ROOT" || die "cannot protect state root"

read_value() {
    test -f "$1" || die "missing file: $1"
    cat "$1" || die "cannot read: $1"
}
readlink_value() {
    readlink -f "$1" 2>/dev/null || die "cannot resolve: $1"
}
hex_lower() { printf '%s' "$1" | tr 'A-F' 'a-f'; }
uptime_cs() {
    value=$(awk '{ printf "%d", $1 * 100 }' "$PROC_ROOT/uptime" 2>/dev/null) || die "cannot read monotonic uptime"
    test -n "$value" || die "empty monotonic uptime"
    printf '%s' "$value"
}
check_total() {
    now=$(uptime_cs)
    test "$now" -lt "$TOTAL_DEADLINE_CS" || die "total helper timeout"
}

BOOT_ID=$(cat "$PROC_ROOT/sys/kernel/random/boot_id" 2>/dev/null || die "cannot read boot id")
BOOT_ID=$(printf '%s' "$BOOT_ID" | tr -d '\r\n')
case "$BOOT_ID" in
    ????????-????-????-????-????????????)
        case "$BOOT_ID" in *[!0123456789abcdef-]*) die "boot id is not lowercase UUID" ;; esac ;;
    *) die "boot id is not UUID-shaped" ;;
esac
ATTEMPT_DIR=$STATE_ROOT/$BOOT_ID
test ! -e "$ATTEMPT_DIR" || die "boot attempt already reserved; refusing retry"
mkdir "$ATTEMPT_DIR" || die "cannot create per-boot state"
chmod 0700 "$ATTEMPT_DIR" || die "cannot protect per-boot state"
if ! (set -C; : > "$ATTEMPT_DIR/attempt.reserved") 2>/dev/null; then
    die "cannot atomically reserve boot attempt"
fi
RECEIPT=$ATTEMPT_DIR/receipt.txt
RAW=$ATTEMPT_DIR/i2c.raw
capture_time=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
UDC_STATE=$(cat "$SYSFS_ROOT/class/udc/a600000.usb/state" 2>/dev/null || printf 'unavailable')
UPTIME_START=$(cat "$PROC_ROOT/uptime" 2>/dev/null || printf 'unavailable')
{
    printf 'schema=r8q-usb-route/v1\noutcome=running\nautomatic_retry=false\n'
    printf 'capture_time_utc=%s\nboot_id=%s\nproc_uptime_start=%s\nudc_state_start=%s\n' "$capture_time" "$BOOT_ID" "$UPTIME_START" "$UDC_STATE"
    printf 'source_repository=%s\nsource_commit=%s\nsource_manifest_sha256=%s\nsource_verification_sha256=%s\nsource_verified_files=%s\n' "$SOURCE_REPOSITORY" "$SOURCE_COMMIT" "$SOURCE_MANIFEST_SHA256" "$SOURCE_VERIFICATION_SHA256" "$SOURCE_VERIFIED_FILES"
    printf 'source_ccic_h_sha256=%s\nsource_muic_h_sha256=%s\nsource_private_h_sha256=%s\nsource_mfd_c_sha256=%s\nsource_irq_c_sha256=%s\nsource_usbc_c_sha256=%s\nsource_muic_c_sha256=%s\n' "$SOURCE_CCIC_H_SHA256" "$SOURCE_MUIC_H_SHA256" "$SOURCE_PRIVATE_H_SHA256" "$SOURCE_MFD_C_SHA256" "$SOURCE_IRQ_C_SHA256" "$SOURCE_USBC_C_SHA256" "$SOURCE_MUIC_C_SHA256"
    printf 'expected_kernel=%s\nexpected_machine_id=%s\nexpected_root_uuid=%s\nexpected_boot_sha256=%s\n' "$EXPECTED_KERNEL" "$EXPECTED_MACHINE_ID" "$EXPECTED_ROOT_UUID" "$EXPECTED_BOOT_SHA256"
    printf 'expected_vermagic=%s\nexpected_gpi_sha256=%s\nexpected_geni_sha256=%s\nexpected_helper_sha256=%s\nexpected_protocol_sha256=%s\n' "$EXPECTED_VERMAGIC" "$EXPECTED_GPI_SHA256" "$EXPECTED_GENI_SHA256" "$EXPECTED_HELPER_SHA256" "$EXPECTED_PROTOCOL_SHA256"
    printf 'adapter_of_suffix=%s\npmic_address=%s\nmuic_address=%s\nallowed_initial_uic_mask=%s\ncc_status1_reject_mask=%s\noptional_nohost_mode=%s\nwall_bc_value=%s\ndcdtmo_mask=%s\n' "$EXPECTED_ADAPTER_OF_SUFFIX" "$PMIC_ADDRESS" "$MUIC_ADDRESS" "$ALLOWED_INITIAL_UIC_MASK" "$CC_STATUS1_REJECT_MASK" "$OPTIONAL_NOHOST" "$WALL_BC_VALUE" "$DCDTMO_MASK"
    printf 'uic_freshness=inference_only\nuic_freshness_basis=quiet_initial_zero_or_cable_subset_then_strict_zero; no_datasheet_proof\n'
    printf 'mailbox_writes_attempted_before_initial_guard=0\nmailbox_writes_succeeded_before_initial_guard=0\nmanual_cleanup_required=0\n'
} > "$RECEIPT" || die "receipt initialization failed"
{
    printf 'schema=r8q-usb-route-raw/v1\nboot_id=%s\nsource_commit=%s\n' "$BOOT_ID" "$SOURCE_COMMIT"
} > "$RAW" || die "raw receipt initialization failed"
trap 'die "interrupted"' HUP INT TERM

TOTAL_START_CS=$(uptime_cs)
TOTAL_DEADLINE_CS=$((TOTAL_START_CS + 2000))

KERNEL=$(uname -r) || die "cannot read kernel release"
test "$KERNEL" = "$EXPECTED_KERNEL" || die "unexpected kernel: $KERNEL"
MACHINE_RAW=$(read_value "$ETC_ROOT/machine-id")
MACHINE_ID=$(printf '%s' "$MACHINE_RAW" | tr -d '\r\n')
test "$MACHINE_ID" = "$EXPECTED_MACHINE_ID" || die "unexpected machine-id"
ROOT_UUID=$(blkid -s UUID -o value "$ROOT_DEVICE") || die "root UUID lookup failed"
ROOT_UUID=$(printf '%s' "$ROOT_UUID" | tr -d '\r\n')
test "$ROOT_UUID" = "$EXPECTED_ROOT_UUID" || die "unexpected root UUID"
if test "$OFFLINE" = 1; then
    test -f "$BOOT_DEVICE" || die "fixture BOOT image is missing"
else
    test -b "$BOOT_DEVICE" || die "BOOT device is not a block device"
fi
BOOT_LINE=$(sha256sum "$BOOT_DEVICE") || die "BOOT hash failed"
BOOT_ACTUAL=${BOOT_LINE%% *}
test "$BOOT_ACTUAL" = "$EXPECTED_BOOT_SHA256" || die "clean BOOT hash mismatch"

ADAPTER=
ADAPTER_OF=
set +f
for candidate in "$SYSFS_ROOT"/bus/i2c/devices/i2c-*; do
    test -e "$candidate" || continue
    test -e "$candidate/of_node" || continue
    resolved=$(readlink_value "$candidate/of_node")
    case "$resolved" in *"$EXPECTED_ADAPTER_OF_SUFFIX") ;; *) continue ;; esac
    test -z "$ADAPTER" || die "multiple SE0 adapters found"
    ADAPTER=$(readlink_value "$candidate")
    ADAPTER_OF=$resolved
done
set -f
test -n "$ADAPTER" || die "SE0 adapter OF path not found"
ADAPTER_BUS=${ADAPTER##*/}
case "$ADAPTER_BUS" in i2c-[0-9]*) ;; *) die "resolved adapter is not an i2c bus" ;; esac
BUS_NUMBER=${ADAPTER_BUS#i2c-}
I2C_DEVICES=$SYSFS_ROOT/bus/i2c/devices
PMIC=$I2C_DEVICES/$BUS_NUMBER-0066
MUIC=$I2C_DEVICES/$BUS_NUMBER-0025
test -e "$PMIC" || die "MAX77705 0x66 DT client is absent"
test -e "$PMIC/of_node" || die "MAX77705 0x66 client has no DT node"
test ! -e "$PMIC/driver" || die "MAX77705 0x66 client is bound"
test ! -e "$MUIC" || die "0x25 MUIC/CCIC client must be absent"
MODULES=$(read_value "$PROC_ROOT/modules")
if printf '%s\n' "$MODULES" | grep -Eiq '(^|[[:space:]])(max77705[^[:space:]]*|ccic[^[:space:]]*|muic[^[:space:]]*|sec_battery[^[:space:]]*)[[:space:]]'; then
    die "MAX/MUIC/charger module is loaded"
fi
{
    printf 'kernel=%s\nmachine_id=%s\nroot_uuid=%s\nboot_device=%s\nboot_sha256=%s\nadapter_bus=%s\nbus_number=%s\nadapter_of=%s\npmic_0066_client=%s\npmic_0066_driver=unbound\nmuic_0025_client=absent\nforbidden_modules=absent\n' "$KERNEL" "$MACHINE_ID" "$ROOT_UUID" "$BOOT_DEVICE" "$BOOT_ACTUAL" "$ADAPTER_BUS" "$BUS_NUMBER" "$ADAPTER_OF" "$PMIC"
    printf 'i2ctransfer=%s\ntimeout=%s\ntotal_start_cs=%s\ntotal_deadline_cs=%s\n' "$I2C_TRANSFER" "$TIMEOUT_BIN" "$TOTAL_START_CS" "$TOTAL_DEADLINE_CS"
} >> "$RECEIPT"

run_i2c() {
    check_total
    TRANSACTION_INDEX=$((TRANSACTION_INDEX + 1))
    OUT=$ATTEMPT_DIR/transaction-$TRANSACTION_INDEX.stdout
    ERR=$ATTEMPT_DIR/transaction-$TRANSACTION_INDEX.stderr
    {
        printf 'transaction=%s\ncommand=%s' "$TRANSACTION_INDEX" "$I2C_TRANSFER"
        for arg in "$@"; do printf ' %s' "$arg"; done
        printf '\n'
    } >> "$RAW"
    if "$TIMEOUT_BIN" 2 "$I2C_TRANSFER" "$@" > "$OUT" 2> "$ERR"; then rc=0; else rc=$?; fi
    printf 'return_code=%s\nstdout_begin\n' "$rc" >> "$RAW"
    cat "$OUT" >> "$RAW"
    printf 'stdout_end\nstderr_begin\n' >> "$RAW"
    cat "$ERR" >> "$RAW"
    printf 'stderr_end\n' >> "$RAW"
    test "$rc" = 0 || die "i2ctransfer failed at transaction $TRANSACTION_INDEX (rc=$rc)"
    TRANSFER_OUTPUT=$(cat "$OUT") || die "cannot capture I2C output"
}

read_byte() {
    if test "$1" = "$MUIC_ADDRESS" && test "$2" = "$UIC_REGISTER"; then
        UIC_READS=$((UIC_READS + 1))
    fi
    run_i2c -y "$BUS_NUMBER" "w1@$1" "$2" r1
    value=$(printf '%s' "$TRANSFER_OUTPUT" | tr -d '\r\n ')
    case "$value" in
        0x[0-9A-Fa-f][0-9A-Fa-f]) TRANSFER_VALUE=$(hex_lower "$value") ;;
        [0-9A-Fa-f][0-9A-Fa-f]) TRANSFER_VALUE=0x$(hex_lower "$value") ;;
        *) die "non-byte output for register $2" ;;
    esac
}

defer_nohost() {
    reason=$1
    printf 'route_outcome=deferred_%s\noptional_nohost=true\nstartup_gate=pass\nuic_reads=%s\nmailbox_writes_attempted=%s\nmailbox_writes_succeeded=%s\nmanual_cleanup_required=0\noutcome=deferred\nautomatic_retry=false\n' \
        "$reason" "$UIC_READS" "$MAILBOX_ATTEMPTED" "$MAILBOX_SUCCEEDED" >> "$RECEIPT"
    trap - HUP INT TERM
    printf 'DEFERRED:no-host route transaction (%s) receipt=%s raw=%s\n' "$reason" "$RECEIPT" "$RAW"
    exit 0
}
read_response_two() {
    run_i2c -y "$BUS_NUMBER" "w1@$MUIC_ADDRESS" "$RESPONSE_REGISTER" r2
    set -- $TRANSFER_OUTPUT
    test "$#" = 2 || die "response is not exactly two bytes"
    case "$1:$2" in
        0x[0-9A-Fa-f][0-9A-Fa-f]:0x[0-9A-Fa-f][0-9A-Fa-f]) RESPONSE_OPCODE=$(hex_lower "$1"); RESPONSE_DATA=$(hex_lower "$2") ;;
        [0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]) RESPONSE_OPCODE=0x$(hex_lower "$1"); RESPONSE_DATA=0x$(hex_lower "$2") ;;
        *) die "response contains non-byte output" ;;
    esac
}
read_response_one() {
    run_i2c -y "$BUS_NUMBER" "w1@$MUIC_ADDRESS" "$RESPONSE_REGISTER" r1
    value=$(printf '%s' "$TRANSFER_OUTPUT" | tr -d '\r\n ')
    case "$value" in
        0x[0-9A-Fa-f][0-9A-Fa-f]) RESPONSE_OPCODE=$(hex_lower "$value") ;;
        [0-9A-Fa-f][0-9A-Fa-f]) RESPONSE_OPCODE=0x$(hex_lower "$value") ;;
        *) die "write response is not one byte" ;;
    esac
}
mailbox_write() {
    MAILBOX_ATTEMPTED=$((MAILBOX_ATTEMPTED + 1))
    run_i2c "$@"
    MAILBOX_SUCCEEDED=$((MAILBOX_SUCCEEDED + 1))
}
wait_completion() {
    phase=$1
    start=$(uptime_cs)
    deadline=$((start + 500))
    count=0
    ready=0
    while test "$count" -lt "$POLL_LIMIT"; do
        now=$(uptime_cs)
        test "$now" -lt "$deadline" || break
        count=$((count + 1))
        read_byte "$MUIC_ADDRESS" "$UIC_REGISTER"
        case "$TRANSFER_VALUE" in
            0x00) ;;
            0x80) ready=1; break ;;
            *) die "unexpected UIC_INT bits during $phase: $TRANSFER_VALUE" ;;
        esac
        test "$POLL_SLEEP" = 0 || sleep "$POLL_SLEEP"
    done
    printf 'phase_%s_poll_start_cs=%s\nphase_%s_poll_deadline_cs=%s\nphase_%s_poll_count=%s\n' "$phase" "$start" "$phase" "$deadline" "$phase" "$count" >> "$RECEIPT"
    test "$ready" = 1 || die "$phase response timeout"
}

read_byte "$PMIC_ADDRESS" "$PMIC_ID_REGISTER"
PMIC_ID=$TRANSFER_VALUE
read_byte "$PMIC_ADDRESS" "$PMIC_REV_REGISTER"
PMIC_REV=$TRANSFER_VALUE
test "$PMIC_ID" = "$PMIC_ID_EXPECTED" || die "unexpected PMIC ID: $PMIC_ID"
PMIC_REV_NUM=$((PMIC_REV))
test $((PMIC_REV_NUM & PMIC_REV_MASK)) -eq $((PMIC_REV_EXPECTED)) || die "unexpected PMIC revision: $PMIC_REV"
read_byte "$MUIC_ADDRESS" "$VBUS_REGISTER"
VBUS=$TRANSFER_VALUE
read_byte "$MUIC_ADDRESS" "$CC_STATUS0_REGISTER"
CC0A=$TRANSFER_VALUE
read_byte "$MUIC_ADDRESS" "$CC_STATUS1_REGISTER"
CC0B=$TRANSFER_VALUE
test $((CC0B & CC_STATUS1_REJECT_MASK)) -eq 0 || die "CC_STATUS1 has water/short/overcurrent/error bits"
VBUS_ASSERTED=$((VBUS & VBUS_REQUIRED_MASK))
BC_CHGTYP_NUM=$((VBUS & BC_CHGTYP_MASK))
DCDTMO_NUM=$((VBUS & DCDTMO_MASK))
CC_STATE_NUM=$((CC0A & CC_SINK_MASK))
printf 'pmic_id=%s\npmic_revision=%s\npmic_revision_low3=0x%02x\nbc_status_0x08=%s\nbc_vbusdet=%s\nbc_chgtyp=0x%02x\nbc_dcdtmo=0x%02x\ncc_status0_0x0a=%s\ncc_state=0x%02x\ncc_status1_0x0b=%s\ncc_status1_reject_mask=%s\ncc_status1_safe=true\n' \
    "$PMIC_ID" "$PMIC_REV" $((PMIC_REV_NUM & PMIC_REV_MASK)) "$VBUS" "$VBUS_ASSERTED" "$BC_CHGTYP_NUM" "$DCDTMO_NUM" "$CC0A" "$CC_STATE_NUM" "$CC0B" "$CC_STATUS1_REJECT_MASK" >> "$RECEIPT"

# Optional mode is intentionally decided from non-clearing PMIC status reads
# only.  No UIC_INT read (which is an active event/ack read) or mailbox write
# may occur on a deferred boot.  A source, water/error state, or unknown CC/BC
# value remains a hard failure in every mode. In optional mode, DCDTmo must be
# clear for both deferred states and the host route.
if test "$OPTIONAL_NOHOST" = 1; then
    test "$DCDTMO_NUM" -eq 0 || die "BC status has DCDTmo asserted"
fi
case "$CC_STATE_NUM" in
    0)
        test "$OPTIONAL_NOHOST" = 1 || die "CC_STATUS0 is not SINK"
        test "$VBUS_ASSERTED" -eq 0 || die "no-host CC status has VBUSDet asserted"
        test "$BC_CHGTYP_NUM" -eq 0 || die "no-host CC status has BC charger type 0x$(printf '%02x' "$BC_CHGTYP_NUM")"
        defer_nohost no_vbus_no_connection
        ;;
    1)
        if test "$VBUS_ASSERTED" -eq 0; then
            die "CC_STATUS0 is SINK while VBUSDet is not asserted"
        fi
        case "$BC_CHGTYP_NUM" in
            "$BC_USB_VALUE_NUM") ;;
            "$WALL_BC_VALUE_NUM")
                test "$OPTIONAL_NOHOST" = 1 || die "BC charger type is wall DCP, not USB type 1"
                defer_nohost wall_dcp
                ;;
            0) die "BC charger type is unknown" ;;
            *) die "BC charger type is unsupported: 0x$(printf '%02x' "$BC_CHGTYP_NUM")" ;;
        esac
        ;;
    2) die "CC_STATUS0 reports SOURCE" ;;
    *) die "CC_STATUS0 has unknown state: 0x$(printf '%02x' "$CC_STATE_NUM")" ;;
esac

# UIC_INT is an active event acknowledgment. Only the source-defined cable/
# detection subset is admitted initially; bit7, SYS/DCD, bit2, or any other
# bit aborts. A second strict zero read is required before any mailbox write.
read_byte "$MUIC_ADDRESS" "$UIC_REGISTER"
INITIAL_UIC=$TRANSFER_VALUE
INITIAL_UIC_NUM=$((INITIAL_UIC))
printf 'initial_uic=%s\ninitial_uic_allowed_mask=%s\nmailbox_writes_attempted_before_initial_guard=%s\nmailbox_writes_succeeded_before_initial_guard=%s\n' "$INITIAL_UIC" "$ALLOWED_INITIAL_UIC_MASK" "$MAILBOX_ATTEMPTED" "$MAILBOX_SUCCEEDED" >> "$RECEIPT"
test $((INITIAL_UIC_NUM & 0xcc)) -eq 0 || die "initial UIC_INT has disallowed bits: $INITIAL_UIC"
read_byte "$MUIC_ADDRESS" "$UIC_REGISTER"
SECOND_UIC=$TRANSFER_VALUE
printf 'second_uic=%s\n' "$SECOND_UIC" >> "$RECEIPT"
test "$SECOND_UIC" = 0x00 || die "second UIC_INT is not zero: $SECOND_UIC"

query_read05() {
    phase=$1
    mailbox_write -y "$BUS_NUMBER" "w2@$MUIC_ADDRESS" "$OPCODE_REGISTER" "$READ_OPCODE"
    mailbox_write -y "$BUS_NUMBER" "w2@$MUIC_ADDRESS" "$END_DATA_REGISTER" 0x00
    wait_completion "$phase"
    read_response_two
    test "$RESPONSE_OPCODE" = "$READ_OPCODE" || die "$phase response opcode mismatch: $RESPONSE_OPCODE"
    printf '%s_control1=%s\n%s_response_opcode=%s\n%s_mailbox_writes_attempted=%s\n%s_mailbox_writes_succeeded=%s\n' "$phase" "$RESPONSE_DATA" "$phase" "$RESPONSE_OPCODE" "$phase" "$MAILBOX_ATTEMPTED" "$phase" "$MAILBOX_SUCCEEDED" >> "$RECEIPT"
}

query_read05 pre
PRIOR_CONTROL1=$RESPONSE_DATA
printf 'prior_control1=%s\n' "$PRIOR_CONTROL1" >> "$RECEIPT"
case "$PRIOR_CONTROL1" in
    0x09)
        ROUTE_OUTCOME=already_AP
        printf 'route_outcome=%s\nwrite06_attempted=false\nmanual_cleanup_required=0\n' "$ROUTE_OUTCOME" >> "$RECEIPT"
        ;;
    0x3f|0xa4)
        case "$PRIOR_CONTROL1" in 0x3f) ROUTE_NAME=COM_OPEN ;; 0xa4) ROUTE_NAME=COM_USB_CP ;; esac
        MANUAL_CLEANUP_REQUIRED=1
        printf 'route_before_write=%s\nroute_name=%s\nwrite06_attempted=true\n' "$PRIOR_CONTROL1" "$ROUTE_NAME" >> "$RECEIPT"
        mailbox_write -y "$BUS_NUMBER" "w3@$MUIC_ADDRESS" "$OPCODE_REGISTER" "$WRITE_OPCODE" "$TARGET_ROUTE"
        mailbox_write -y "$BUS_NUMBER" "w2@$MUIC_ADDRESS" "$END_DATA_REGISTER" 0x00
        wait_completion write06
        read_response_one
        test "$RESPONSE_OPCODE" = "$WRITE_OPCODE" || die "write06 response opcode mismatch: $RESPONSE_OPCODE"
        printf 'write06_response_opcode=%s\nwrite06_target_payload=%s\n' "$RESPONSE_OPCODE" "$TARGET_ROUTE" >> "$RECEIPT"
        query_read05 post
        test "$RESPONSE_DATA" = "$TARGET_ROUTE" || die "post-write CONTROL1 is not 0x09: $RESPONSE_DATA"
        ROUTE_OUTCOME=changed_to_AP
        MANUAL_CLEANUP_REQUIRED=0
        printf 'route_outcome=%s\npost_control1=%s\nmanual_cleanup_required=0\n' "$ROUTE_OUTCOME" "$RESPONSE_DATA" >> "$RECEIPT"
        ;;
    *) die "unknown CONTROL1 route: $PRIOR_CONTROL1" ;;
esac

UPTIME_END=$(cat "$PROC_ROOT/uptime" 2>/dev/null || printf 'unavailable')
UDC_END=$(cat "$SYSFS_ROOT/class/udc/a600000.usb/state" 2>/dev/null || printf 'unavailable')
printf 'proc_uptime_end=%s\nudc_state_end=%s\nmailbox_writes_attempted=%s\nmailbox_writes_succeeded=%s\noutcome=pass\n' "$UPTIME_END" "$UDC_END" "$MAILBOX_ATTEMPTED" "$MAILBOX_SUCCEEDED" >> "$RECEIPT"
trap - HUP INT TERM
printf 'PASS:CONTROL1 boot route receipt=%s raw=%s\n' "$RECEIPT" "$RAW"
