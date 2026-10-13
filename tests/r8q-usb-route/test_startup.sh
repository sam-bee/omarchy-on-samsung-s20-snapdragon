#!/bin/sh
# Offline fixture suite for r8q-usb-route-up.sh.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT=$(CDPATH= cd -- "$HERE/../.." && pwd)
WRAPPER=$PROJECT/rootfs/usr/local/sbin/r8q-usb-route-up.sh
KERNEL=7.1.2-r8q-rtc2
VERMAGIC='7.1.2-r8q-rtc2 SMP preempt mod_unload aarch64'
MACHINE_ID=1290f2212bd743569044571db21a6c96
ROOT_UUID=217b9308-40c7-4eb0-90a9-09ed4e233173
BOOT_ID=11111111-1111-1111-1111-111111111111

fail() { echo "FAIL: $*" >&2; exit 1; }

make_fixture() {
    root=$1
    mode=$2
    mkdir -p "$root/bin" "$root/etc" "$root/dev" "$root/proc/sys/kernel/random" "$root/sys/module/i2c_qcom_geni/parameters" "$root/sys/class/power_supply" "$root/sys/bus/i2c/devices" "$root/sys/bus/i2c/drivers/simple-mfd-i2c" "$root/usr/lib/modules/$KERNEL/updates/r8q-usb-route" "$root/usr/local/sbin" "$root/usr/local/lib/r8q-usb-route"
    cp "$PROJECT/rootfs/usr/local/sbin/r8q-root-device" "$root/usr/local/sbin/r8q-root-device"
    chmod 755 "$root/usr/local/sbin/r8q-root-device"
    printf 'offline gpi module fixture\n' > "$root/usr/lib/modules/$KERNEL/updates/r8q-usb-route/gpi.ko"
    printf 'offline geni module fixture\n' > "$root/usr/lib/modules/$KERNEL/updates/r8q-usb-route/i2c-qcom-geni.ko"
    GPI_SHA=$(sha256sum "$root/usr/lib/modules/$KERNEL/updates/r8q-usb-route/gpi.ko" | cut -d ' ' -f1)
    GENI_SHA=$(sha256sum "$root/usr/lib/modules/$KERNEL/updates/r8q-usb-route/i2c-qcom-geni.ko" | cut -d ' ' -f1)
    printf 'fixture-boot\n' > "$root/dev/sda23"
    printf '%s\n' "$BOOT_ID" > "$root/proc/sys/kernel/random/boot_id"
    printf '%s\n' "$MACHINE_ID" > "$root/etc/machine-id"
    : > "$root/proc/modules"
    : > "$root/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo"
    cat > "$root/bin/findmnt" <<'EOF_FINDMNT'
#!/bin/sh
case " $* " in
    *' -o SOURCE '*) printf '%s\n' /dev/sda36 ;;
    *' -o FSTYPE '*) printf '%s\n' ext4 ;;
    *' -o UUID '*) printf '%s\n' 217b9308-40c7-4eb0-90a9-09ed4e233173 ;;
    *) exit 1 ;;
esac
EOF_FINDMNT
    chmod 755 "$root/bin/findmnt"
    cat > "$root/bin/stat" <<'EOF_STAT'
#!/bin/sh
test "$1" = -c && test "$2" = '%u:%g:%a' || exit 1
printf '%s\n' 0:0:600
EOF_STAT
    chmod 755 "$root/bin/stat"
    case "$mode" in
        preloaded)
            printf 'gpi 1 0 - Live 0x0\ni2c_qcom_geni 1 0 - Live 0x0\n' > "$root/proc/modules"
            printf 'Y\n' > "$root/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo"
            ;;
        simple-mfd-container)
            printf 'Y\n' > "$root/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo"
            mkdir -p "$root/sys/bus/i2c/devices/7-0036"
            ln -s "$root/sys/bus/i2c/drivers/simple-mfd-i2c" "$root/sys/bus/i2c/devices/7-0036/driver"
            ;;
        preloaded-bad-fifo)
            printf 'gpi 1 0 - Live 0x0\ni2c_qcom_geni 1 0 - Live 0x0\n' > "$root/proc/modules"
            printf '0\n' > "$root/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo"
            ;;
        bad-module)
            printf 'usbcore 1 0 - Live 0x0\n' > "$root/proc/modules"
            ;;
        max-active)
            : > "$root/sys/class/power_supply/max77705-charger"
            ;;
    esac
    cat > "$root/usr/local/sbin/r8q-usb-route-ensure.sh" <<'EOF_HELPER'
#!/bin/sh
set -eu
printf 'called\n' >> "$R8Q_USB_ROUTE_TEST_ROOT/helper.called"
exit 0
EOF_HELPER
    chmod 755 "$root/usr/local/sbin/r8q-usb-route-ensure.sh"
    helper_hash=$(sha256sum "$root/usr/local/sbin/r8q-usb-route-ensure.sh" | cut -d ' ' -f1)
    printf 'fixture-protocol\n' > "$root/usr/local/lib/r8q-usb-route/protocol-binding.env"
    protocol_hash=$(sha256sum "$root/usr/local/lib/r8q-usb-route/protocol-binding.env" | cut -d ' ' -f1)
    boot_hash=$(sha256sum "$root/dev/sda23" | cut -d ' ' -f1)
    cat > "$root/etc/r8q-usb-route.env" <<EOF_ENV
EXPECTED_KERNEL=$KERNEL
EXPECTED_MACHINE_ID=$MACHINE_ID
EXPECTED_ROOT_UUID=$ROOT_UUID
EXPECTED_BOOT_SHA256=$boot_hash
EXPECTED_VERMAGIC='$VERMAGIC'
EXPECTED_GPI_SHA256=$GPI_SHA
EXPECTED_GENI_SHA256=$GENI_SHA
EXPECTED_HELPER_SHA256=$helper_hash
EXPECTED_PROTOCOL_SHA256=$protocol_hash
EOF_ENV
    cat > "$root/bin/uname" <<EOF_UNAME
#!/bin/sh
printf '%s\\n' "$KERNEL"
EOF_UNAME
    chmod 755 "$root/bin/uname"
    cat > "$root/bin/blkid" <<EOF_BLKID
#!/bin/sh
printf '%s\\n' "$ROOT_UUID"
EOF_BLKID
    chmod 755 "$root/bin/blkid"
    cat > "$root/bin/modinfo" <<'EOF_MODINFO'
#!/bin/sh
set -eu
test "$1" = -F
field=$2
path=$3
case "$field" in
    name)
        case "$path" in *gpi.ko) printf 'gpi\n' ;; *i2c-qcom-geni.ko) printf 'i2c_qcom_geni\n' ;; *) exit 1 ;; esac ;;
    vermagic) printf '7.1.2-r8q-rtc2 SMP preempt mod_unload aarch64\n' ;;
    depends) printf '\n' ;;
    *) exit 1 ;;
esac
EOF_MODINFO
    chmod 755 "$root/bin/modinfo"
    cat > "$root/bin/modprobe" <<'EOF_MODPROBE'
#!/bin/sh
set -eu
show=0
name=
while test "$#" -gt 0; do
    case "$1" in
        --show-depends) show=1 ;;
        --set-version) shift ;;
        r8q_force_fifo=1) ;;
        *) name=$1 ;;
    esac
    shift
done
base=$R8Q_USB_ROUTE_TEST_ROOT/usr/lib/modules/7.1.2-r8q-rtc2/updates/r8q-usb-route
if test "$show" = 1; then
    case "$name" in
        gpi) printf 'insmod %s/gpi.ko\n' "$base" ;;
        i2c_qcom_geni) printf 'insmod %s/i2c-qcom-geni.ko\n' "$base" ;;
        *) exit 1 ;;
    esac
    exit 0
fi
printf '%s\n' "$name" >> "$R8Q_USB_ROUTE_TEST_ROOT/modprobe.called"
case "$name" in
    gpi) printf 'gpi 1 0 - Live 0x0\n' >> "$R8Q_USB_ROUTE_TEST_ROOT/proc/modules" ;;
    i2c_qcom_geni)
        printf 'i2c_qcom_geni 1 0 - Live 0x0\n' >> "$R8Q_USB_ROUTE_TEST_ROOT/proc/modules"
        printf '1\n' > "$R8Q_USB_ROUTE_TEST_ROOT/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo"
        ;;
    *) exit 1 ;;
esac
EOF_MODPROBE
    chmod 755 "$root/bin/modprobe"
}

run_wrapper() {
    root=$1
    R8Q_USB_ROUTE_OFFLINE=1 R8Q_USB_ROUTE_TEST_ROOT="$root"         "$WRAPPER"
}

test_success_and_collision() {
    root=$(mktemp -d)
    make_fixture "$root" empty
    run_wrapper "$root" || fail "empty-module success case failed"
    test -s "$root/helper.called" || fail "helper was not called"
    test "$(cat "$root/proc/modules" | awk '{print $1}' | tr '\n' ' ')" = 'gpi i2c_qcom_geni ' || fail "unexpected modules after load"
    test "$(cat "$root/sys/module/i2c_qcom_geni/parameters/r8q_force_fifo" | tr -d '\r\n')" = 1 || fail "FIFO parameter not enabled"
    test -s "$root/var/lib/r8q-usb-route/wrapper/$BOOT_ID/metadata.txt" || fail "receipt missing"
    if run_wrapper "$root" >/dev/null 2>&1; then fail "same-boot receipt collision was accepted"; fi
    rm -rf "$root"
}

test_preloaded() {
    root=$(mktemp -d)
    make_fixture "$root" preloaded
    run_wrapper "$root" || fail "preloaded case failed"
    test ! -e "$root/modprobe.called" || fail "preloaded modules were reloaded"
    rm -rf "$root"
    root=$(mktemp -d)
    make_fixture "$root" preloaded-bad-fifo
    if run_wrapper "$root" >/dev/null 2>&1; then fail "bad preloaded FIFO value passed"; fi
    test ! -e "$root/helper.called" || fail "helper ran with bad preloaded FIFO"
    rm -rf "$root"
}

test_simple_mfd_container() {
    root=$(mktemp -d)
    make_fixture "$root" simple-mfd-container
    run_wrapper "$root" || fail "simple-mfd-i2c 0036 container case failed"
    test -s "$root/helper.called" || fail "helper was not called with simple-mfd-i2c container"
    rm -rf "$root"
}

test_reject() {
    for mode in bad-module max-active; do
        root=$(mktemp -d)
        make_fixture "$root" "$mode"
        if run_wrapper "$root" >/dev/null 2>&1; then fail "rejected case passed: $mode"; fi
        test ! -e "$root/helper.called" || fail "helper ran in rejected case: $mode"
        rm -rf "$root"
    done
}

test_identity() {
    root=$(mktemp -d)
    make_fixture "$root" empty
    printf 'wrong\n' > "$root/etc/machine-id"
    if run_wrapper "$root" >/dev/null 2>&1; then fail "machine identity mismatch passed"; fi
    test ! -e "$root/helper.called" || fail "helper ran after identity mismatch"
    rm -rf "$root"
}

test_success_and_collision
test_preloaded
test_simple_mfd_container
test_reject
test_identity
echo 'PASS: offline r8q-usb-route wrapper fixtures'
