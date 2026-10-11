#!/bin/sh
# Offline fixtures for the route-gated GPU and dual-sourced touch startup.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
GPU_SERVICE=$ROOT/rootfs/etc/systemd/system/r8q-gpu.service
GPU_CONF=$ROOT/rootfs/etc/modprobe.d/r8q-gpu.conf
TOUCH_SERVICE=$ROOT/rootfs/etc/systemd/system/r8q-touch.service
TOUCH_CONF=$ROOT/rootfs/etc/modprobe.d/r8q-touch-blacklist.conf
HELPER=$ROOT/rootfs/usr/local/sbin/r8q-touch-up.sh
ROUTE=$ROOT/rootfs/etc/systemd/system/r8q-usb-route.service
PREP=$ROOT/rootfs/etc/systemd/system/r8q-hardware-prepare.service
GADGET=$ROOT/rootfs/etc/systemd/system/r8q-usb-gadget.service

contains() { grep -F "$2" "$1" >/dev/null; }
not_contains() { ! grep -F "$2" "$1" >/dev/null; }
fail() { echo "FAIL: $*" >&2; exit 1; }

sh -n "$HELPER"
contains "$GPU_SERVICE" 'Requires=r8q-hardware-prepare.service'
contains "$GPU_SERVICE" 'After=r8q-hardware-prepare.service'
contains "$GPU_SERVICE" 'ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service'
contains "$GPU_SERVICE" 'ExecStart=/usr/bin/modprobe msm separate_gpu_kms=1 r8q_zap_dyn=1 r8q_zap_secvid=0'
not_contains "$GPU_SERVICE" 'After=multi-user.target'
contains "$GPU_SERVICE" '[Install]'
contains "$GPU_SERVICE" 'WantedBy=multi-user.target'
not_contains "$GPU_SERVICE" 'rmmod'
not_contains "$GPU_SERVICE" 'modprobe -r'

contains "$TOUCH_SERVICE" 'Requires=r8q-hardware-prepare.service'
contains "$TOUCH_SERVICE" 'After=r8q-hardware-prepare.service'
contains "$TOUCH_SERVICE" 'ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service'
contains "$TOUCH_SERVICE" 'ExecStart=/usr/local/sbin/r8q-touch-up.sh'
not_contains "$TOUCH_SERVICE" '/root/ts'
not_contains "$TOUCH_SERVICE" 'ExecStart=/usr/bin/insmod'
not_contains "$TOUCH_SERVICE" 'sleep 2'
contains "$TOUCH_SERVICE" '[Install]'
contains "$TOUCH_SERVICE" 'WantedBy=multi-user.target'
not_contains "$HELPER" 'modprobe gpi'
not_contains "$HELPER" 'modprobe i2c_qcom_geni'
not_contains "$HELPER" 'insmod'

contains "$GPU_CONF" 'blacklist llcc_qcom'
contains "$GPU_CONF" 'blacklist msm'
contains "$GPU_CONF" 'options msm separate_gpu_kms=1 r8q_zap_dyn=1 r8q_zap_secvid=0'
contains "$TOUCH_CONF" 'blacklist fts5cu56a'
contains "$TOUCH_CONF" 'blacklist zinitix'

# Every module in the RTC2 closure must be covered by one of the two alias
# blacklists; direct named requests remain available to the ordered units.
# Keep this list tracked and explicit so tests do not depend on ignored build
# output being present.
for module in \
    drm_display_helper drm_dp_aux_bus drm_exec drm_gpuvm msm gpu_sched \
    fts5cu56a zinitix cec llcc_qcom mdt_loader ocmem ubwc_config; do
    if ! grep -F "blacklist $module" "$GPU_CONF" "$TOUCH_CONF" >/dev/null; then
        fail "closure module is not blacklisted: $module"
    fi
done

# Static graph checks: hardware prep -> gadget -> network-pre, with GPU/touch
# waiting on hardware prep and neither optional unit pointing back to multi-user.
contains "$GADGET" 'Before=network-pre.target'
contains "$GADGET" 'Requires=r8q-hardware-prepare.service'
contains "$GADGET" 'After=r8q-hardware-prepare.service'
contains "$GADGET" 'ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service'
contains "$ROUTE" 'ExecStart=/usr/local/sbin/r8q-usb-route-witness.sh'
not_contains "$ROUTE" 'Wants=r8q-usb-gadget.service'
not_contains "$ROUTE" 'After=r8q-usb-gadget.service'
contains "$ROUTE" 'Requires=r8q-hardware-prepare.service'
contains "$ROUTE" 'After=r8q-hardware-prepare.service'
contains "$PREP" 'Before=network-pre.target'
not_contains "$GPU_SERVICE" 'After=multi-user.target'
not_contains "$TOUCH_SERVICE" 'After=multi-user.target'

fixture=$(mktemp -d "${TMPDIR:-/tmp}/r8q-gpu-touch.XXXXXX")
cleanup() { rm -rf "$fixture"; }
trap cleanup EXIT HUP INT TERM
sysfs=$fixture/sys
mkdir -p "$sysfs/module/gpi" "$sysfs/module/i2c_qcom_geni/parameters"
mkdir -p "$sysfs/bus/i2c/drivers/fts5cu56a" "$sysfs/bus/i2c/drivers/Zinitix-TS"
printf 'Y\n' > "$sysfs/module/i2c_qcom_geni/parameters/r8q_force_fifo"
cat > "$fixture/modprobe" <<'EOF_MODPROBE'
#!/bin/sh
set -eu
printf '%s\n' "$1" >> "$R8Q_TOUCH_LOG"
case "$R8Q_TOUCH_MODE:$1" in
    fts:fts5cu56a)
        mkdir -p "$R8Q_TOUCH_SYSFS_ROOT/bus/i2c/drivers/fts5cu56a/5-0049/input/input0/event0" ;;
    zinitix:zinitix|premature:zinitix)
        mkdir -p "$R8Q_TOUCH_SYSFS_ROOT/bus/i2c/drivers/Zinitix-TS/5-0020/input/input0/event0" ;;
    unbound:fts5cu56a|premature:fts5cu56a)
        test "$R8Q_TOUCH_MODE" != premature || mkdir -p "$R8Q_TOUCH_SYSFS_ROOT/bus/i2c/drivers/fts5cu56a/5-0049" ;;
    unbound:zinitix)
        mkdir -p "$R8Q_TOUCH_SYSFS_ROOT/bus/i2c/drivers/Zinitix-TS/5-0020/input/input0/event0" ;;
    *) exit 1 ;;
esac
EOF_MODPROBE
chmod 755 "$fixture/modprobe"

run_helper() {
    R8Q_TOUCH_MODE=${R8Q_TOUCH_MODE:-} \
    R8Q_TOUCH_SYSFS_ROOT="$sysfs" \
    R8Q_TOUCH_MODPROBE_BIN="$fixture/modprobe" \
    R8Q_TOUCH_SLEEP_BIN=/bin/true \
    R8Q_TOUCH_LOGGER_BIN=/bin/true \
    R8Q_TOUCH_TRIES=2 \
    R8Q_TOUCH_LOG="$fixture/modprobe.log" \
        "$HELPER"
}

# FTS wins and zinitix is not requested.
: > "$fixture/modprobe.log"
R8Q_TOUCH_MODE=fts run_helper
test "$(cat "$fixture/modprobe.log")" = fts5cu56a
rm -rf "$sysfs/bus/i2c/drivers/fts5cu56a/5-0049"

# An unbound FTS request falls back only after bounded readiness expires.
: > "$fixture/modprobe.log"
R8Q_TOUCH_MODE=unbound run_helper
expected=$(printf 'fts5cu56a\nzinitix')
test "$(cat "$fixture/modprobe.log")" = "$expected"
rm -rf "$sysfs/bus/i2c/drivers/Zinitix-TS/5-0020"

# A driver binding without an input event is premature and must still fall
# through to the other controller.
: > "$fixture/modprobe.log"
R8Q_TOUCH_MODE=premature run_helper
test "$(cat "$fixture/modprobe.log")" = "$expected"
rm -rf "$sysfs/bus/i2c/drivers/fts5cu56a/5-0049" "$sysfs/bus/i2c/drivers/Zinitix-TS/5-0020"

# Existing FTS binding avoids every module request.
mkdir -p "$sysfs/bus/i2c/drivers/fts5cu56a/5-0049/input/input0/event0"
: > "$fixture/modprobe.log"
R8Q_TOUCH_MODE=fts run_helper
test ! -s "$fixture/modprobe.log"
rm -rf "$sysfs/bus/i2c/drivers/fts5cu56a/5-0049"

# The helper must never accept an unloaded adapter or disabled FIFO mode.
rm -rf "$sysfs/module/gpi"
if R8Q_TOUCH_MODE=fts run_helper >/dev/null 2>&1; then fail 'accepted missing GPI'; fi
mkdir -p "$sysfs/module/gpi"
printf 'N\n' > "$sysfs/module/i2c_qcom_geni/parameters/r8q_force_fifo"
if R8Q_TOUCH_MODE=fts run_helper >/dev/null 2>&1; then fail 'accepted disabled force_fifo'; fi

echo 'r8q-gpu-touch: focused startup fixtures passed'
