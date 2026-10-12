#!/bin/sh
# Assemble the NCM gadget and advertise its 500 mA USB2 power budget.
# A known initramfs-bound gadget is briefly rebound when still advertising
# the legacy 2 mA value. systemd-networkd owns the phone-side usb0 address.
set -eu

UDC_ROOT=${R8Q_UDC_ROOT:-/sys/class/udc}
CONFIGFS_ROOT=${R8Q_CONFIGFS_ROOT:-/sys/kernel/config}
G="$CONFIGFS_ROOT/usb_gadget/g1"
MAXPOWER_HELPER=${R8Q_GADGET_MAXPOWER_HELPER:-/usr/local/libexec/r8q-gadget-maxpower.py}
PYTHON3=${R8Q_PYTHON3:-/usr/bin/python3}
TEST_MODE=${R8Q_GADGET_TEST_MODE:-0}
EXPECTED_UDC=a600000.usb
EXPECTED_UDC_VENDOR=0x1d6b
EXPECTED_UDC_PRODUCT=0x0104
EXPECTED_BCD_USB=0x0201
EXPECTED_BM_ATTRIBUTES=0x80
EXPECTED_PRODUCT=r8q-mainline
EXPECTED_MANUFACTURER=Samsung
EXPECTED_SERIAL=r8q0001
EXPECTED_DEVICE_MAC=4e:e0:a2:98:8c:90
EXPECTED_HOST_MAC=aa:dd:21:b3:df:6a

fail() {
    echo "r8q-gadget: ERROR: $*" >&2
    exit 1
}

if [ "$TEST_MODE" != 1 ]; then
    [ "$(id -u)" -eq 0 ] || fail "must run as root"
    [ "$(uname -r)" = 7.1.2-r8q-rtc2 ] || fail "unexpected kernel release"
    [ "$(cat /etc/machine-id)" = 1290f2212bd743569044571db21a6c96 ] || fail "unexpected phone machine-id"
    [ "$(findmnt -n -o UUID /)" = 217b9308-40c7-4eb0-90a9-09ed4e233173 ] || fail "unexpected root UUID"
fi
# Python is optional for bootstrap compatibility.  A bound legacy descriptor
# is deliberately left in place when Python is absent so USB SSH stays usable;
# an unbound gadget can still be prepared with the shell-only write below.
[ ! -L "$UDC_ROOT" ] || fail "UDC sysfs path is a symlink"
[ ! -L "$CONFIGFS_ROOT" ] || fail "ConfigFS path is a symlink"
[ -d "$UDC_ROOT" ] || fail "UDC sysfs directory is unavailable"
[ -d "$CONFIGFS_ROOT" ] || fail "ConfigFS mountpoint is unavailable"

if [ "$TEST_MODE" != 1 ]; then
    if ! grep -q " $CONFIGFS_ROOT configfs " /proc/mounts 2>/dev/null; then
        mount -t configfs none "$CONFIGFS_ROOT" 2>/dev/null || fail "could not mount ConfigFS"
    fi
    grep -q " $CONFIGFS_ROOT configfs " /proc/mounts 2>/dev/null || fail "ConfigFS is not mounted"
fi

# Require the exact r8q UDC class entry. The class entry is normally a symlink;
# -d follows it, while the basename check rejects a redirected controller.
UDC=
UDC_COUNT=0
for candidate in "$UDC_ROOT"/*; do
    [ -e "$candidate" ] || [ -L "$candidate" ] || continue
    [ "${candidate##*/}" = "$EXPECTED_UDC" ] || fail "unexpected UDC entry: $candidate"
    [ -d "$candidate" ] || fail "UDC entry does not resolve to a directory: $candidate"
    RESOLVED_UDC=$(readlink -f "$candidate") || fail "cannot resolve UDC entry"
    [ "${RESOLVED_UDC##*/}" = "$EXPECTED_UDC" ] || fail "unexpected UDC target: $RESOLVED_UDC"
    UDC=${candidate##*/}
    UDC_COUNT=$((UDC_COUNT + 1))
done
[ "$UDC_COUNT" -eq 1 ] || fail "expected exactly one UDC, found $UDC_COUNT"

read_value() {
    path=$1
    [ ! -L "$path" ] || fail "ConfigFS attribute is a symlink: $path"
    [ -f "$path" ] || fail "missing ConfigFS attribute: $path"
    tr -d '\000' < "$path" || fail "cannot read ConfigFS attribute: $path"
}

[ -d "$CONFIGFS_ROOT/usb_gadget" ] || fail "ConfigFS usb_gadget directory is unavailable"
[ ! -L "$G" ] || fail "ConfigFS gadget path is a symlink"
if [ ! -e "$G" ]; then
    # ConfigFS creates the gadget's UDC/attribute files when this directory is
    # created. This is the only preflight creation allowed for a fresh gadget.
    mkdir "$G" || fail "cannot create ConfigFS gadget"
fi
[ -d "$G" ] || fail "ConfigFS gadget is not a directory"

# Read the binding before touching any child layout component. A bound gadget
# must already have the complete known layout; only an unbound fresh gadget
# may have its child directories created below.
[ ! -L "$G/UDC" ] || fail "gadget UDC attribute is a symlink"
[ -f "$G/UDC" ] || fail "missing gadget UDC attribute"
BOUND=$(read_value "$G/UDC") || fail "cannot read gadget UDC binding"
[ -z "$BOUND" ] || [ "$BOUND" = "$UDC" ] || fail "gadget is bound to a different UDC: $BOUND"

# Check every existing layout component before mkdir can create or traverse
# anything. This keeps an unexpected bound layout untouched.
for target in \
    "$G" "$G/strings" "$G/strings/0x409" \
    "$G/configs" "$G/configs/c.1" "$G/configs/c.1/strings" \
    "$G/configs/c.1/strings/0x409" "$G/functions" "$G/functions/ncm.usb0"; do
    [ ! -L "$target" ] || fail "ConfigFS target is a symlink: $target"
done
if [ -z "$BOUND" ]; then
    mkdir -p "$G/strings/0x409" "$G/configs/c.1/strings/0x409" \
             "$G/functions/ncm.usb0"
else
    for target in "$G/strings/0x409" "$G/configs/c.1/strings/0x409" \
        "$G/functions/ncm.usb0"; do
        [ -d "$target" ] || fail "bound gadget layout is incomplete: $target"
    done
fi

write_once() {
    path=$1
    value=$2
    current=$(read_value "$path") || fail "cannot read ConfigFS attribute: $path"
    if [ "$current" != "$value" ]; then
        [ -z "$BOUND" ] || fail "bound gadget attribute differs at $path: $current"
        printf '%s\n' "$value" > "$path" || fail "cannot write ConfigFS attribute: $path"
    fi
    [ "$(read_value "$path")" = "$value" ] || fail "ConfigFS write did not stick: $path"
}

# Complete identity/string/MAC validation or unbound preparation occurs before
# the MaxPower helper and before any final UDC bind.
write_once "$G/idVendor" "$EXPECTED_UDC_VENDOR"
write_once "$G/idProduct" "$EXPECTED_UDC_PRODUCT"
write_once "$G/bcdUSB" "$EXPECTED_BCD_USB"
write_once "$G/strings/0x409/product" "$EXPECTED_PRODUCT"
write_once "$G/strings/0x409/manufacturer" "$EXPECTED_MANUFACTURER"
write_once "$G/strings/0x409/serialnumber" "$EXPECTED_SERIAL"
write_once "$G/configs/c.1/strings/0x409/configuration" ncm
write_once "$G/configs/c.1/bmAttributes" "$EXPECTED_BM_ATTRIBUTES"
write_once "$G/functions/ncm.usb0/dev_addr" "$EXPECTED_DEVICE_MAC"
write_once "$G/functions/ncm.usb0/host_addr" "$EXPECTED_HOST_MAC"

LINK="$G/configs/c.1/ncm.usb0"
FUNCTION="$G/functions/ncm.usb0"
if [ -n "$BOUND" ]; then
    [ -L "$LINK" ] || fail "bound gadget is missing NCM configuration link"
    [ "$(readlink -f "$LINK")" = "$(readlink -f "$FUNCTION")" ] || fail "NCM link points somewhere unexpected"
elif [ -e "$LINK" ] || [ -L "$LINK" ]; then
    [ -L "$LINK" ] || fail "NCM configuration entry is not a symlink: $LINK"
    [ "$(readlink -f "$LINK")" = "$(readlink -f "$FUNCTION")" ] || fail "NCM link points somewhere unexpected"
else
    ln -s "$FUNCTION" "$LINK" || fail "cannot link NCM function"
fi

# An initramfs-created bound gadget is normalized transactionally by the
# helper when Python is available.  If it is absent, preserve a known legacy
# bound gadget untouched with a warning so USB SSH remains available.  A bound
# 500-mA gadget is always a read-only no-op.  An unbound gadget can use the
# shell-only write below, then this wrapper owns the one final bind.
MAXPOWER=$(read_value "$G/configs/c.1/MaxPower") || fail "cannot read MaxPower"
DEFERRED=0
if [ -n "$BOUND" ]; then
    case "$MAXPOWER" in
        500)
            ;;
        2)
            if [ -x "$PYTHON3" ]; then
                [ -x "$MAXPOWER_HELPER" ] || fail "MaxPower helper is unavailable or not executable: $MAXPOWER_HELPER"
                "$PYTHON3" "$MAXPOWER_HELPER" --configfs-root "$CONFIGFS_ROOT" --udc-root "$UDC_ROOT" || \
                    fail "MaxPower helper failed; its bound-gadget rollback was required"
            else
                DEFERRED=1
                echo "r8q-gadget: WARNING: descriptor correction deferred until phone Python 3 is installed (bound MaxPower=2 remains unchanged)" >&2
            fi
            ;;
        *)
            fail "unsupported bound MaxPower: $MAXPOWER"
            ;;
    esac
else
    if [ -x "$PYTHON3" ]; then
        [ -x "$MAXPOWER_HELPER" ] || fail "MaxPower helper is unavailable or not executable: $MAXPOWER_HELPER"
        "$PYTHON3" "$MAXPOWER_HELPER" --prepare-before-bind \
            --configfs-root "$CONFIGFS_ROOT" --udc-root "$UDC_ROOT" || \
            fail "MaxPower preparation failed; gadget remains unbound"
    else
        # Identity and NCM-link validation above has already completed.  The
        # shell-only path is limited to this known unbound MaxPower attribute.
        write_once "$G/configs/c.1/MaxPower" 500
    fi
    [ "$(read_value "$G/configs/c.1/MaxPower")" = 500 ] || fail "MaxPower is not 500 before bind"
    printf '%s\n' "$UDC" > "$G/UDC" || fail "cannot bind gadget to $UDC"
fi

BOUND=$(read_value "$G/UDC") || fail "cannot reread gadget UDC binding"
[ "$BOUND" = "$UDC" ] || fail "gadget binding did not stick: $BOUND"
FINAL_MAXPOWER=$(read_value "$G/configs/c.1/MaxPower") || fail "cannot reread MaxPower"
if [ "$FINAL_MAXPOWER" != 500 ]; then
    [ "$DEFERRED" = 1 ] && [ "$FINAL_MAXPOWER" = 2 ] || fail "MaxPower readback is not 500"
    echo "r8q-gadget: NCM gadget bound to $UDC (MaxPower=2; correction deferred)"
else
    echo "r8q-gadget: NCM gadget bound to $UDC (MaxPower=500mA)"
fi
