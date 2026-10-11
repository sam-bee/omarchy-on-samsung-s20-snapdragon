#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
SERVICE=$ROOT/rootfs/etc/systemd/system/r8q-wifi.service
BLACKLIST=$ROOT/rootfs/etc/modprobe.d/r8q-wifi-blacklist.conf
NM_DROPIN=$ROOT/rootfs/etc/systemd/system/NetworkManager.service.d/10-r8q-usb-route.conf
NMCONF=$ROOT/rootfs/etc/NetworkManager/conf.d/10-r8q.conf
HELPER=$ROOT/rootfs/usr/local/sbin/r8q-wifi-up.sh
ROUTE=$ROOT/rootfs/etc/systemd/system/r8q-usb-route.service
PREP=$ROOT/rootfs/etc/systemd/system/r8q-hardware-prepare.service
GADGET=$ROOT/rootfs/etc/systemd/system/r8q-usb-gadget.service

contains() {
    grep -F "$2" "$1" >/dev/null
}

not_contains() {
    ! grep -F "$2" "$1" >/dev/null
}

line_of() {
    awk -v needle="$2" 'index($0, needle) { print NR; exit }' "$1"
}

sh -n "$HELPER"
contains "$SERVICE" 'Requires=r8q-hardware-prepare.service'
contains "$SERVICE" 'After=r8q-hardware-prepare.service'
contains "$NM_DROPIN" 'Requires=r8q-hardware-prepare.service'
contains "$NM_DROPIN" 'After=r8q-hardware-prepare.service'
contains "$NM_DROPIN" 'ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service'
contains "$NM_DROPIN" 'ExecStartPre=/usr/bin/modprobe sha256'
not_contains "$SERVICE" 'r8q-battery.service'
not_contains "$SERVICE" 'r8q-touch.service'
not_contains "$SERVICE" '0000:01:00.0'
not_contains "$SERVICE" 'phy0'
not_contains "$SERVICE" 'setpci'

contains "$BLACKLIST" 'blacklist phy_qcom_qmp_pcie'
contains "$BLACKLIST" 'blacklist qrtr_mhi'
contains "$BLACKLIST" 'blacklist mhi'
contains "$BLACKLIST" 'blacklist qrtr'
contains "$BLACKLIST" 'blacklist cfg80211'
contains "$BLACKLIST" 'blacklist sha256'
contains "$BLACKLIST" 'blacklist rfkill'
contains "$BLACKLIST" 'blacklist mac80211'
contains "$BLACKLIST" 'blacklist qmi_helpers'
contains "$BLACKLIST" 'blacklist libarc4'
contains "$BLACKLIST" 'blacklist ath'

prep_pre=$(line_of "$SERVICE" 'ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service')
sha_pre=$(line_of "$SERVICE" 'ExecStartPre=/usr/bin/modprobe sha256')
phy_load=$(line_of "$SERVICE" 'ExecStart=/usr/bin/modprobe phy-qcom-qmp-pcie')
test "$prep_pre" -lt "$sha_pre"
test "$sha_pre" -lt "$phy_load"
nm_prep_pre=$(line_of "$NM_DROPIN" 'ExecStartPre=/usr/bin/systemctl is-active --quiet r8q-hardware-prepare.service')
nm_sha_pre=$(line_of "$NM_DROPIN" 'ExecStartPre=/usr/bin/modprobe sha256')
test "$nm_prep_pre" -lt "$nm_sha_pre"

# The startup graph remains one-way: hardware prep -> gadget -> network-pre,
# and both NM and Wi-Fi wait for hardware prep. The legacy route also requires
# the prep unit, and no unit may point back to NM.
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
not_contains "$ROUTE" 'After=NetworkManager.service'
not_contains "$GADGET" 'After=NetworkManager.service'

contains "$NMCONF" 'dns=systemd-resolved'
contains "$NMCONF" 'unmanaged-devices=interface-name:usb0'
contains "$NMCONF" '[connection-wifi]'
contains "$NMCONF" 'ipv4.route-metric=50'
contains "$NMCONF" 'ipv6.route-metric=50'
contains "$NMCONF" 'wifi.powersave=2'
contains "$NMCONF" 'wifi.cloned-mac-address=stable'
contains "$NMCONF" 'enabled=false'
not_contains "$NMCONF" 'dns=none'

fixture=$(mktemp -d "${TMPDIR:-/tmp}/r8q-wifi-fixture.XXXXXX")
cleanup() { rm -rf "$fixture"; }
trap cleanup EXIT HUP INT TERM

mkdir -p "$fixture/sys/bus/pci/devices/0000:03:00.0/link"
mkdir -p "$fixture/sys/bus/pci/devices/0000:04:00.0"
mkdir -p "$fixture/sys/class/ieee80211/phy7" "$fixture/sys/class/ieee80211/phy8"
printf '0x17cb\n' > "$fixture/sys/bus/pci/devices/0000:03:00.0/vendor"
printf '0x1101\n' > "$fixture/sys/bus/pci/devices/0000:03:00.0/device"
printf '1\n' > "$fixture/sys/bus/pci/devices/0000:03:00.0/link/l0s_aspm"
printf '1\n' > "$fixture/sys/bus/pci/devices/0000:03:00.0/link/l1_aspm"
ln -s "$fixture/sys/bus/pci/devices/0000:04:00.0" \
    "$fixture/sys/class/ieee80211/phy7/device"
ln -s "$fixture/sys/bus/pci/devices/0000:03:00.0" \
    "$fixture/sys/class/ieee80211/phy8/device"
printf '%s\n' '#!/bin/sh' \
    'printf "%s\\n" "$*" >> "$R8Q_WIFI_LOG"' > "$fixture/logger"
chmod 755 "$fixture/logger"

R8Q_WIFI_SYSFS_ROOT="$fixture/sys" \
R8Q_WIFI_LOGGER_BIN=/bin/true \
R8Q_WIFI_SLEEP_BIN=/bin/true \
    "$HELPER" wait-endpoint
R8Q_WIFI_SYSFS_ROOT="$fixture/sys" \
R8Q_WIFI_LOGGER_BIN="$fixture/logger" \
R8Q_WIFI_LOG="$fixture/log" \
R8Q_WIFI_SLEEP_BIN=/bin/true \
    "$HELPER" wait-phy
contains "$fixture/log" 'ath11k registered phy8'
not_contains "$fixture/log" 'ath11k registered phy7'
R8Q_WIFI_SYSFS_ROOT="$fixture/sys" \
R8Q_WIFI_LOGGER_BIN=/bin/true \
    "$HELPER" disable-aspm
R8Q_WIFI_SYSFS_ROOT="$fixture/sys" \
R8Q_WIFI_LOGGER_BIN=/bin/true \
    "$HELPER" wait-endpoint
R8Q_WIFI_SYSFS_ROOT="$fixture/sys" \
R8Q_WIFI_LOGGER_BIN=/bin/true \
    "$HELPER" wait-phy
R8Q_WIFI_SYSFS_ROOT="$fixture/sys" \
R8Q_WIFI_LOGGER_BIN=/bin/true \
    "$HELPER" disable-aspm
test "$(cat "$fixture/sys/bus/pci/devices/0000:03:00.0/link/l0s_aspm")" = 0
test "$(cat "$fixture/sys/bus/pci/devices/0000:03:00.0/link/l1_aspm")" = 0

if R8Q_WIFI_SYSFS_ROOT="$fixture/missing" \
    R8Q_WIFI_ENDPOINT_TRIES=1 \
    R8Q_WIFI_LOGGER_BIN=/bin/true \
    R8Q_WIFI_SLEEP_BIN=/bin/true \
    "$HELPER" wait-endpoint; then
    echo 'wait-endpoint unexpectedly accepted a missing endpoint' >&2
    exit 1
fi

mkdir -p "$fixture/endpoint-only/sys/bus/pci/devices/0000:03:00.0/link"
printf '0x17cb\n' > "$fixture/endpoint-only/sys/bus/pci/devices/0000:03:00.0/vendor"
printf '0x1101\n' > "$fixture/endpoint-only/sys/bus/pci/devices/0000:03:00.0/device"
R8Q_WIFI_SYSFS_ROOT="$fixture/endpoint-only/sys" \
R8Q_WIFI_LOGGER_BIN=/bin/true \
    "$HELPER" disable-aspm

mkdir -p "$fixture/no-link/sys/bus/pci/devices/0000:03:00.0"
printf '0x17cb\n' > "$fixture/no-link/sys/bus/pci/devices/0000:03:00.0/vendor"
printf '0x1101\n' > "$fixture/no-link/sys/bus/pci/devices/0000:03:00.0/device"
R8Q_WIFI_SYSFS_ROOT="$fixture/no-link/sys" \
R8Q_WIFI_LOGGER_BIN=/bin/true \
    "$HELPER" disable-aspm
if R8Q_WIFI_SYSFS_ROOT="$fixture/endpoint-only/sys" \
    R8Q_WIFI_PHY_TRIES=1 \
    R8Q_WIFI_LOGGER_BIN=/bin/true \
    R8Q_WIFI_SLEEP_BIN=/bin/true \
    "$HELPER" wait-phy; then
    echo 'wait-phy unexpectedly accepted a missing wireless phy' >&2
    exit 1
fi

echo 'r8q-wifi: focused startup fixtures passed'
