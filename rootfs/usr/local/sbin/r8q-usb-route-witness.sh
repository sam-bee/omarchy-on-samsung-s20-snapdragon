#!/bin/sh
# Read-only witness for the current boot's pre-MAX route receipt.
# This unit never invokes the raw helper, writes I2C, loads modules, or
# reserves a second attempt.  The preparation unit owns the transaction.
set -eu
umask 077

if test "${R8Q_USB_ROUTE_WITNESS_OFFLINE:-0}" = 1; then
    TEST_ROOT=${R8Q_USB_ROUTE_WITNESS_ROOT:?missing R8Q_USB_ROUTE_WITNESS_ROOT}
    PROC_ROOT=$TEST_ROOT/proc
    STATE_ROOT=$TEST_ROOT/var/lib/r8q-usb-route
else
    PROC_ROOT=/proc
    STATE_ROOT=/var/lib/r8q-usb-route
fi

die() {
    echo "r8q-usb-route-witness: ERROR: $*" >&2
    exit 1
}

regular_file() {
    test -f "$1" && test ! -L "$1" || die "receipt is missing or a symlink: $1"
}

regular_dir() {
    test -d "$1" && test ! -L "$1" || die "receipt directory is missing or a symlink: $1"
}

receipt_value() {
    file=$1
    key=$2
    awk -F= -v wanted="$key" '
        BEGIN { found = 0; malformed = 0 }
        {
            if (index($0, "=") == 0) { malformed = 1; next }
            if ($1 == wanted) {
                found++
                value = substr($0, index($0, "=") + 1)
            }
        }
        END {
            if (malformed || found != 1) exit 1
            print value
        }
    ' "$file" || die "missing or duplicate $key in $file"
}

validate_helper_receipt() {
    file=$1
    awk -F= '
        BEGIN { malformed = 0; outcome_count = 0; cleanup_count = 0 }
        {
            if (index($0, "=") == 0) { malformed = 1; next }
            key = $1
            value = substr($0, index($0, "=") + 1)
            count[key]++
            if (key == "outcome") {
                outcome_count++
                outcome[outcome_count] = value
            } else if (key == "manual_cleanup_required") {
                cleanup_count++
                cleanup[cleanup_count] = value
            } else if (key == "cc_status1_reject_mask" ||
                       key == "mailbox_writes_attempted_before_initial_guard" ||
                       key == "mailbox_writes_succeeded_before_initial_guard" ||
                       key == "post_control1") {
                if (count[key] == 1)
                    repeated_value[key] = value
                else if (value != repeated_value[key] || count[key] > 2)
                    duplicate = 1
            } else if (count[key] != 1) {
                duplicate = 1
            }
        }
        END {
            if (malformed || duplicate || outcome_count != 2 ||
                outcome[1] != "running" || outcome[2] != "pass" ||
                cleanup_count != 2 || cleanup[1] != "0" || cleanup[2] != "0" ||
                count["cc_status1_reject_mask"] != 2 ||
                count["mailbox_writes_attempted_before_initial_guard"] != 2 ||
                count["mailbox_writes_succeeded_before_initial_guard"] != 2 ||
                (count["post_control1"] != 0 && count["post_control1"] != 2))
                exit 1
        }
    ' "$file" || die "helper receipt is not an append-only running/pass lifecycle: $file"
}

require_value() {
    file=$1
    key=$2
    expected=$3
    actual=$(receipt_value "$file" "$key")
    test "$actual" = "$expected" || die "$file has $key=$actual, expected $expected"
}

BOOT_ID=$(cat "$PROC_ROOT/sys/kernel/random/boot_id" 2>/dev/null | tr -d '\r\n') || die "cannot read boot ID"
case "$BOOT_ID" in
    ????????-????-????-????-????????????)
        case "$BOOT_ID" in *[!0123456789abcdef-]*) die "boot ID is not lowercase UUID" ;; esac ;;
    *) die "boot ID is not UUID-shaped" ;;
esac

regular_dir "$STATE_ROOT"
WRAPPER_DIR=$STATE_ROOT/wrapper/$BOOT_ID
HELPER_DIR=$STATE_ROOT/$BOOT_ID
regular_dir "$STATE_ROOT/wrapper"
regular_dir "$WRAPPER_DIR"
regular_dir "$HELPER_DIR"
METADATA=$WRAPPER_DIR/metadata.txt
RECEIPT=$HELPER_DIR/receipt.txt
regular_file "$METADATA"
regular_file "$RECEIPT"

require_value "$METADATA" schema r8q-usb-route-wrapper/v1
require_value "$METADATA" boot_id "$BOOT_ID"
require_value "$METADATA" helper_return_code 0
require_value "$METADATA" startup_gate pass
require_value "$METADATA" outcome pass
require_value "$METADATA" automatic_retry false

validate_helper_receipt "$RECEIPT"
require_value "$RECEIPT" schema r8q-usb-route/v1
require_value "$RECEIPT" boot_id "$BOOT_ID"
require_value "$RECEIPT" automatic_retry false
ROUTE_OUTCOME=$(receipt_value "$RECEIPT" route_outcome)
case "$ROUTE_OUTCOME" in
    already_AP|changed_to_AP) ;;
    *) die "current boot has no successful host AP route: $ROUTE_OUTCOME" ;;
esac
MAILBOX_ATTEMPTED=$(receipt_value "$RECEIPT" mailbox_writes_attempted)
MAILBOX_SUCCEEDED=$(receipt_value "$RECEIPT" mailbox_writes_succeeded)
case "$MAILBOX_ATTEMPTED:$MAILBOX_SUCCEEDED" in
    2:2|6:6) ;;
    *) die "host route mailbox receipt is incomplete: $MAILBOX_ATTEMPTED:$MAILBOX_SUCCEEDED" ;;
esac

printf 'PASS:host AP route witness boot=%s route_outcome=%s receipt=%s\n' \
    "$BOOT_ID" "$ROUTE_OUTCOME" "$RECEIPT"
