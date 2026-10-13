#!/bin/sh
# Load the pinned rtc2 I2C adapter pair, then invoke the reviewed CONTROL1
# helper. This wrapper owns identity/module/receipt guards; the helper owns
# the per-boot route transaction and its persistent receipt.
set -eu
umask 077
REQUESTED_OPTIONAL_NOHOST=${R8Q_USB_ROUTE_OPTIONAL_NOHOST:-0}

ENV_FILE=/etc/r8q-usb-route.env
SYSFS_ROOT=/sys
PROC_MODULES=/proc/modules
ETC_ROOT=/etc
BOOT_DEVICE=/dev/sda23
ROOT_DEVICE=/dev/sda36
RECEIPT_ROOT=/var/lib/r8q-usb-route/wrapper
MODULE_ROOT=/usr/lib/modules
MODPROBE=/usr/bin/modprobe
MODINFO=/usr/bin/modinfo
BLKID=/usr/bin/blkid
SHA256SUM=/usr/bin/sha256sum
UNAME=/usr/bin/uname
RANDOM_BOOT_ID=/proc/sys/kernel/random/boot_id
HELPER_PATH=/usr/local/sbin/r8q-usb-route-ensure.sh
ROOT_DEVICE_HELPER=/usr/local/sbin/r8q-root-device
PROTOCOL_PATH=/usr/local/lib/r8q-usb-route/protocol-binding.env
ROOT_FINDMNT=findmnt
ROOT_STAT=stat

# Offline fixture path injection is deliberately unavailable in production.
if test "${R8Q_USB_ROUTE_OFFLINE:-0}" = 1; then
    TEST_ROOT=${R8Q_USB_ROUTE_TEST_ROOT:?missing R8Q_USB_ROUTE_TEST_ROOT}
    ENV_FILE=${R8Q_USB_ROUTE_ENV_FILE:-$TEST_ROOT/etc/r8q-usb-route.env}
    SYSFS_ROOT=$TEST_ROOT/sys
    PROC_MODULES=$TEST_ROOT/proc/modules
    ETC_ROOT=$TEST_ROOT/etc
    BOOT_DEVICE=$TEST_ROOT/dev/sda23
    ROOT_DEVICE=$TEST_ROOT/dev/sda36
    RECEIPT_ROOT=$TEST_ROOT/var/lib/r8q-usb-route/wrapper
    MODULE_ROOT=$TEST_ROOT/usr/lib/modules
    MODPROBE=${R8Q_USB_ROUTE_MODPROBE:-$TEST_ROOT/bin/modprobe}
    MODINFO=${R8Q_USB_ROUTE_MODINFO:-$TEST_ROOT/bin/modinfo}
    BLKID=${R8Q_USB_ROUTE_BLKID:-$TEST_ROOT/bin/blkid}
    SHA256SUM=${R8Q_USB_ROUTE_SHA256SUM:-/usr/bin/sha256sum}
    UNAME=${R8Q_USB_ROUTE_UNAME:-$TEST_ROOT/bin/uname}
    RANDOM_BOOT_ID=$TEST_ROOT/proc/sys/kernel/random/boot_id
    HELPER_PATH=$TEST_ROOT/usr/local/sbin/r8q-usb-route-ensure.sh
    ROOT_DEVICE_HELPER=${R8Q_USB_ROUTE_ROOT_DEVICE_HELPER:-$TEST_ROOT/usr/local/sbin/r8q-root-device}
    PROTOCOL_PATH=$TEST_ROOT/usr/local/lib/r8q-usb-route/protocol-binding.env
    ROOT_FINDMNT=${R8Q_USB_ROUTE_FINDMNT:-$TEST_ROOT/bin/findmnt}
    ROOT_STAT=${R8Q_USB_ROUTE_STAT:-$TEST_ROOT/bin/stat}
fi

BOOT_ID=
BOOT_DIR=
PHASE=initial

die() {
    reason=$*
    if test -n "${BOOT_DIR:-}" && test -d "$BOOT_DIR"; then
        {
            printf 'schema=r8q-usb-route-wrapper/v1\n'
            printf 'boot_id=%s\nphase=%s\noutcome=error\nreason=%s\nautomatic_retry=false\n' "$BOOT_ID" "$PHASE" "$reason"
        } > "$BOOT_DIR/outcome.error.tmp" 2>/dev/null || true
        if test -f "$BOOT_DIR/outcome.error.tmp"; then
            mv -f "$BOOT_DIR/outcome.error.tmp" "$BOOT_DIR/outcome.error" || true
        fi
    fi
    echo "r8q-usb-route: ERROR: $reason" >&2
    exit 1
}

trim() { sed 's/[[:space:]]*$//'; }

if test "${R8Q_USB_ROUTE_OFFLINE:-0}" != 1; then
    test "$(id -u)" = 0 || die "must run as root"
fi
test -f "$ENV_FILE" || die "missing environment file: $ENV_FILE"
test ! -L "$ENV_FILE" || die "environment file is a symlink"
# The image-owned file is the only source of deployment identity and hashes.
# shellcheck disable=SC1090
. "$ENV_FILE"

# Only r8q-hardware-prepare.service sets this explicit optional mode.  The
# legacy cable-attached unit leaves it at zero and therefore retains the
# original host-only route behavior.  Validate after loading the image-owned
# identity file so that the file cannot silently change the service's mode.
OPTIONAL_NOHOST=$REQUESTED_OPTIONAL_NOHOST
case "$OPTIONAL_NOHOST" in
    0|1) ;;
    *) echo "r8q-usb-route: ERROR: optional no-host mode must be 0 or 1" >&2; exit 1 ;;
esac

: "${EXPECTED_KERNEL:?missing EXPECTED_KERNEL}"
: "${EXPECTED_MACHINE_ID:?missing EXPECTED_MACHINE_ID}"
: "${EXPECTED_ROOT_UUID:?missing EXPECTED_ROOT_UUID}"
: "${EXPECTED_BOOT_SHA256:?missing EXPECTED_BOOT_SHA256}"
: "${EXPECTED_VERMAGIC:?missing EXPECTED_VERMAGIC}"
: "${EXPECTED_GPI_SHA256:?missing EXPECTED_GPI_SHA256}"
: "${EXPECTED_GENI_SHA256:?missing EXPECTED_GENI_SHA256}"
: "${EXPECTED_HELPER_SHA256:?missing EXPECTED_HELPER_SHA256}"
: "${EXPECTED_PROTOCOL_SHA256:?missing EXPECTED_PROTOCOL_SHA256}"

KERNEL=$("$UNAME" -r 2>/dev/null) || die "cannot read kernel release"
test "$KERNEL" = "$EXPECTED_KERNEL" || die "unexpected kernel: $KERNEL"
BOOT_ID=$(cat "$RANDOM_BOOT_ID" 2>/dev/null || die "cannot read boot ID")
BOOT_ID=$(printf '%s' "$BOOT_ID" | tr -d '\r\n')
case "$BOOT_ID" in
    ????????-????-????-????-????????????) case "$BOOT_ID" in *[!0123456789abcdef-]*) die "boot ID is not lowercase UUID" ;; esac ;;
    *) die "boot ID is not UUID-shaped" ;;
esac
MACHINE_ID=$(cat "$ETC_ROOT/machine-id" 2>/dev/null | tr -d '\r\n') || die "cannot read machine ID"
test "$MACHINE_ID" = "$EXPECTED_MACHINE_ID" || die "unexpected machine ID"
test -f "$ROOT_DEVICE_HELPER" || die "root-device helper is missing"
test ! -L "$ROOT_DEVICE_HELPER" || die "root-device helper is a symlink"
if test "${R8Q_USB_ROUTE_OFFLINE:-0}" = 1; then
    ROOT_DEVICE=$(R8Q_ROOT_DEVICE_OFFLINE=1 \
        R8Q_ROOT_DEVICE_ETC_ROOT="$ETC_ROOT" \
        R8Q_ROOT_DEVICE_PROFILE="${R8Q_USB_ROUTE_ROOT_PROFILE:-$ETC_ROOT/r8q-encrypted-root.env}" \
        R8Q_ROOT_DEVICE_FINDMNT="$ROOT_FINDMNT" \
        R8Q_ROOT_DEVICE_BLKID="$BLKID" \
        R8Q_ROOT_DEVICE_STAT="$ROOT_STAT" \
        "$ROOT_DEVICE_HELPER" | tr -d '\r\n') || die "root-device validation failed"
else
    ROOT_DEVICE=$("$ROOT_DEVICE_HELPER" | tr -d '\r\n') || die "root-device validation failed"
fi
case "$ROOT_DEVICE" in
    /dev/*) ;;
    *) die "root-device helper returned an invalid source" ;;
esac
ROOT_UUID=$("$BLKID" -s UUID -o value "$ROOT_DEVICE" 2>/dev/null | tr -d '\r\n') || die "root UUID lookup failed"
test "$ROOT_UUID" = "$EXPECTED_ROOT_UUID" || die "unexpected root UUID"
if test "${R8Q_USB_ROUTE_OFFLINE:-0}" = 1; then
    test -f "$BOOT_DEVICE" || die "BOOT fixture is unavailable"
else
    test -b "$BOOT_DEVICE" || die "BOOT device is not a block device"
fi
BOOT_LINE=$("$SHA256SUM" "$BOOT_DEVICE") || die "BOOT hash failed"
BOOT_ACTUAL=${BOOT_LINE%% *}
test "$BOOT_ACTUAL" = "$EXPECTED_BOOT_SHA256" || die "clean BOOT hash mismatch"

# Bind the helper before changing module state. The helper agent owns its
# protocol/source receipt; this wrapper only verifies the final helper bytes.
test -f "$HELPER_PATH" || die "route helper is missing"
test ! -L "$HELPER_PATH" || die "route helper is a symlink"
HELPER_ACTUAL=$("$SHA256SUM" "$HELPER_PATH" | cut -d ' ' -f1)
test "$HELPER_ACTUAL" = "$EXPECTED_HELPER_SHA256" || die "route helper hash mismatch"
test -f "$PROTOCOL_PATH" || die "route protocol binding is missing"
test ! -L "$PROTOCOL_PATH" || die "route protocol binding is a symlink"
PROTOCOL_ACTUAL=$("$SHA256SUM" "$PROTOCOL_PATH" | cut -d ' ' -f1)
test "$PROTOCOL_ACTUAL" = "$EXPECTED_PROTOCOL_SHA256" || die "route protocol binding hash mismatch"

MODULE_DIR=$MODULE_ROOT/$EXPECTED_KERNEL/updates/r8q-usb-route
GPI_PATH=$MODULE_DIR/gpi.ko
GENI_PATH=$MODULE_DIR/i2c-qcom-geni.ko
test -d "$MODULE_DIR" || die "route module directory is missing"
test ! -L "$MODULE_DIR" || die "route module directory is a symlink"
for module in "$GPI_PATH" "$GENI_PATH"; do
    test -f "$module" || die "route module is missing: $module"
    test ! -L "$module" || die "route module is a symlink: $module"
done
printf '%s  %s\n' "$EXPECTED_GPI_SHA256" "$GPI_PATH" "$EXPECTED_GENI_SHA256" "$GENI_PATH" | "$SHA256SUM" -c - || die "route module hash mismatch"

module_name=$("$MODINFO" -F name "$GPI_PATH" 2>/dev/null | trim) || die "cannot inspect gpi module name"
test "$module_name" = gpi || die "unexpected gpi module name: $module_name"
module_name=$("$MODINFO" -F name "$GENI_PATH" 2>/dev/null | trim) || die "cannot inspect GENI module name"
test "$module_name" = i2c_qcom_geni || die "unexpected GENI module name: $module_name"
for module in "$GPI_PATH" "$GENI_PATH"; do
    vermagic=$("$MODINFO" -F vermagic "$module" 2>/dev/null | trim) || die "cannot inspect module vermagic: $module"
    test "$vermagic" = "$EXPECTED_VERMAGIC" || die "module vermagic mismatch: $module"
    depends=$("$MODINFO" -F depends "$module" 2>/dev/null | tr -d '\r\n') || die "cannot inspect module dependencies: $module"
    test -z "$depends" || die "unexpected module dependency: $module: $depends"
done

module_list=$(cat "$PROC_MODULES" 2>/dev/null) || die "cannot read loaded module list"
seen_gpi=0
seen_geni=0
while read -r name rest; do
    case "$name" in
        '') ;;
        gpi) seen_gpi=$((seen_gpi + 1)) ;;
        i2c_qcom_geni) seen_geni=$((seen_geni + 1)) ;;
        *) die "unexpected module already loaded: $name" ;;
    esac
done <<EOF
$module_list
EOF
test "$seen_gpi" -le 1 || die "duplicate gpi module entries"
test "$seen_geni" -le 1 || die "duplicate GENI module entries"

check_plan() {
    name=$1
    target=$2
    plan=$("$MODPROBE" --show-depends --set-version "$EXPECTED_KERNEL" "$name" 2>&1) || die "cannot inspect modprobe plan: $name"
    found=0
    found_target=0
    plan_gpi=0
    plan_geni=0
    while read -r command path rest; do
        test -n "$command" || continue
        test "$command" = insmod || die "unexpected modprobe operation for $name: $command"
        test -n "$path" || die "empty modprobe path for $name"
        case "$name:$rest" in
            gpi:) ;;
            i2c_qcom_geni:|i2c_qcom_geni:r8q_force_fifo=1) ;;
            *) die "unexpected modprobe options for $name: $rest" ;;
        esac
        resolved=$(readlink -f "$path" 2>/dev/null) || die "cannot resolve modprobe path: $path"
        case "$resolved" in
            "$GPI_PATH") plan_gpi=$((plan_gpi + 1)) ;;
            "$GENI_PATH") plan_geni=$((plan_geni + 1)) ;;
            *) die "modprobe would load unexpected file: $resolved" ;;
        esac
        test "$resolved" = "$target" && found_target=$((found_target + 1))
        found=$((found + 1))
    done <<EOF
$plan
EOF
    test "$found_target" = 1 || die "requested module is absent from modprobe plan: $name"
    test "$found" -ge 1 || die "empty modprobe plan for $name"
    test "${plan_gpi:-0}" -le 1 || die "duplicate GPI modprobe plan entries"
    test "${plan_geni:-0}" -le 1 || die "duplicate GENI modprobe plan entries"
}

if test "$seen_gpi" = 0; then
    check_plan gpi "$GPI_PATH"
    "$MODPROBE" --set-version "$EXPECTED_KERNEL" gpi || die "gpi modprobe failed"
fi
if test "$seen_geni" = 0; then
    check_plan i2c_qcom_geni "$GENI_PATH"
    "$MODPROBE" --set-version "$EXPECTED_KERNEL" i2c_qcom_geni r8q_force_fifo=1 || die "GENI modprobe failed"
fi

module_list=$(cat "$PROC_MODULES" 2>/dev/null) || die "cannot reread loaded module list"
seen_gpi=0
seen_geni=0
while read -r name rest; do
    case "$name" in
        '') ;;
        gpi) seen_gpi=$((seen_gpi + 1)) ;;
        i2c_qcom_geni) seen_geni=$((seen_geni + 1)) ;;
        *) die "unexpected module after load: $name" ;;
    esac
done <<EOF
$module_list
EOF
test "$seen_gpi" = 1 || die "gpi is not loaded exactly once"
test "$seen_geni" = 1 || die "GENI is not loaded exactly once"
FIFO_PARAM=$SYSFS_ROOT/module/i2c_qcom_geni/parameters/r8q_force_fifo
test -f "$FIFO_PARAM" || die "GENI FIFO parameter is unavailable"
case "$(cat "$FIFO_PARAM" | tr -d '\r\n')" in
    1|Y) ;;
    *) die "GENI FIFO parameter is not enabled" ;;
esac

# Never hand the helper a live MAX77705 client or charger driver. An unbound
# DT client may remain for the helper; only a driver link or power-supply
# instance is rejected here.
for name in $(printf '%s\n' "$module_list" | awk '{print $1}'); do
    case "$name" in
        max77705*|max17042*) die "MAX77705 module is active: $name" ;;
    esac
done
for supply in "$SYSFS_ROOT"/class/power_supply/max77705* "$SYSFS_ROOT"/class/power_supply/max17042*; do
    test -e "$supply" || test -L "$supply" || continue
    die "MAX power supply is active: $supply"
done
for driver in \
    "$SYSFS_ROOT"/bus/i2c/drivers/max77705 \
    "$SYSFS_ROOT"/bus/i2c/drivers/max77705-muic \
    "$SYSFS_ROOT"/bus/i2c/drivers/max77705_usbc \
    "$SYSFS_ROOT"/bus/i2c/drivers/max77705-charger \
    "$SYSFS_ROOT"/bus/i2c/drivers/max17042; do
    test -d "$driver" || continue
    for entry in "$driver"/*; do
        test -e "$entry" || test -L "$entry" || continue
        case "${entry##*/}" in
            bind|unbind|uevent|module|new_id|remove_id) ;;
            *) die "MAX driver has an active client: $entry" ;;
        esac
    done
done
for address in 0036 0066 0069; do
    for client in "$SYSFS_ROOT"/bus/i2c/devices/*-"$address"; do
        test -e "$client" || test -L "$client" || continue
        if test -e "$client/driver" || test -L "$client/driver"; then
            case "$address" in
                0036)
                    resolved_driver=$(readlink -f "$client/driver" 2>/dev/null) || die "cannot resolve fuel-gauge driver: $client"
                    test "$resolved_driver" = "$SYSFS_ROOT/bus/i2c/drivers/simple-mfd-i2c" || \
                        die "unexpected 0036 driver: $resolved_driver"
                    ;;
                *) die "MAX I2C client is driver-bound: $client" ;;
            esac
        fi
    done
done

test ! -L "$RECEIPT_ROOT" || die "wrapper receipt root is a symlink"
mkdir -p "$RECEIPT_ROOT" || die "cannot create wrapper receipt root"
BOOT_DIR=$RECEIPT_ROOT/$BOOT_ID
test ! -e "$BOOT_DIR" || die "wrapper receipt already exists for this boot"
test ! -L "$BOOT_DIR" || die "wrapper receipt is a symlink"
mkdir "$BOOT_DIR" || die "cannot create wrapper receipt"
PHASE=helper
trap 'die interrupted' HUP INT TERM
printf 'schema=r8q-usb-route-wrapper/v1\nboot_id=%s\nkernel=%s\nmachine_id=%s\nroot_uuid=%s\nboot_sha256=%s\nhelper_path=%s\nhelper_sha256=%s\nprotocol_sha256=%s\ngpi_sha256=%s\ngeni_sha256=%s\nmodules_after=%s\noptional_nohost_mode=%s\n' \
    "$BOOT_ID" "$KERNEL" "$MACHINE_ID" "$ROOT_UUID" "$BOOT_ACTUAL" "$HELPER_PATH" "$EXPECTED_HELPER_SHA256" "$EXPECTED_PROTOCOL_SHA256" "$EXPECTED_GPI_SHA256" "$EXPECTED_GENI_SHA256" "$(printf '%s' "$module_list" | tr '\n' ';')" "$OPTIONAL_NOHOST" > "$BOOT_DIR/metadata.txt"
HELPER_RC=0
R8Q_HARDWARE_MODE=1 R8Q_USB_ROUTE_HARDWARE_MODE=1 R8Q_USB_ROUTE_OPTIONAL_NOHOST="$OPTIONAL_NOHOST" \
    "$HELPER_PATH" > "$BOOT_DIR/helper.stdout" 2> "$BOOT_DIR/helper.stderr" || HELPER_RC=$?
printf 'helper_return_code=%s\n' "$HELPER_RC" >> "$BOOT_DIR/metadata.txt"
if test "$HELPER_RC" != 0; then
    die "route helper failed rc=$HELPER_RC"
fi
printf 'startup_gate=pass\noutcome=pass\nautomatic_retry=false\n' >> "$BOOT_DIR/metadata.txt"
printf 'r8q-usb-route: helper completed boot=%s receipt=%s\n' "$BOOT_ID" "$BOOT_DIR"
