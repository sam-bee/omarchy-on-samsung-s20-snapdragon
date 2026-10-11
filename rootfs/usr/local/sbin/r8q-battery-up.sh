#!/bin/sh
# Route-gated MAX17042/MAX77705 startup for the RTC2 image.
#
# This file is deliberately self-contained. It does not source a trial
# helper, use modprobe, use a same-boot baseline, or perform raw I2C access.
# The private module payload is outside /usr/lib/modules so udev coldplug
# cannot load it before r8q-hardware-prepare.service has completed.
#
# The charger and gauge owner is deliberately independent of a USB host.  A
# configured UDC is an optional gadget/desktop capability and is never used as
# evidence that it is safe to bind MAX77705 or MAX17042.  Current-limit policy
# is applied through the bound driver's power_supply attributes only; this
# helper never performs raw I2C access.
# Resolve a failed or partial run with an ordinary reboot; never unload GPI,
# GENI, MAX77705, charger, or fuel-gauge drivers.
set -u

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

EXPECTED_KERNEL=7.1.2-r8q-rtc2
EXPECTED_MACHINE_ID=1290f2212bd743569044571db21a6c96
EXPECTED_ROOT_UUID=217b9308-40c7-4eb0-90a9-09ed4e233173
EXPECTED_VERMAGIC='7.1.2-r8q-rtc2 SMP preempt mod_unload aarch64'
PAYLOAD_DIR=/usr/local/lib/r8q-battery/7.1.2-r8q-rtc2
MODULE_FUEL=$PAYLOAD_DIR/max17042_battery.ko
MODULE_MFD=$PAYLOAD_DIR/max77705.ko
MODULE_CHARGER=$PAYLOAD_DIR/max77705_charger.ko
RECEIPT_DIR=/var/lib/r8q-battery
STAGE_WAIT_SECONDS=20
CURRENT_LIMIT_CAP_UA=500000
# max77705_charger.c encodes CHGIN in 25,000-uA steps but reports
# (register+1)*25,000 uA.  475,000 therefore produces the required 500,000-uA
# driver readback.  Charge current uses a 50,000-uA step and round-trips 500k.
INPUT_LIMIT_WRITE_UA=475000
CHARGE_CURRENT_WRITE_UA=500000
CURRENT_PROPERTY_MIN_UA=100000
CURRENT_PROPERTY_MAX_UA=3200000

MAX17042_SHA256=dab402c9a954140ba1fb9d4ee7cc5b0ba4fdd710ceef6f3e690b81b8d7e3d0e0
MAX77705_SHA256=d762ba600f60aeb861ba9bb74c963213db19eb4db9f928ef8538a1c27472a072
MAX77705_CHARGER_SHA256=724ce35de17beb52dbec938a695b01a9e2e0ee757a4c864ae05b8f59e3cca593

RECEIPT=

die() {
    message=$*
    printf 'r8q-battery: ERROR: %s\n' "$message" >&2
    if [ -n "$RECEIPT" ]; then
        printf 'ERROR: %s\n' "$message" >> "$RECEIPT" 2>/dev/null || true
    fi
    exit 1
}

note() {
    printf 'r8q-battery: %s\n' "$*"
    if [ -n "$RECEIPT" ]; then
        printf '%s\n' "$*" >> "$RECEIPT" || die "cannot append receipt"
    fi
}

must_be_root() {
    [ "$(id -u 2>/dev/null || printf 1)" = 0 ] || die 'must run as root'
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

read_trimmed() {
    [ -r "$1" ] || return 1
    tr -d '\r\n' < "$1"
}

is_uint() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
        *) return 0 ;;
    esac
}

require_range() {
    label=$1
    value=$2
    minimum=$3
    maximum=$4
    is_uint "$value" || die "$label is not an unsigned integer: $value"
    [ "$value" -ge "$minimum" ] && [ "$value" -le "$maximum" ] || \
        die "$label out of range: $value (expected $minimum..$maximum)"
}

new_receipt() {
    [ ! -L "$RECEIPT_DIR" ] || die 'receipt directory must not be a symlink'
    mkdir -p "$RECEIPT_DIR" || die "cannot create $RECEIPT_DIR"
    chmod 700 "$RECEIPT_DIR" 2>/dev/null || true
    stamp=$(date -u '+%Y%m%dT%H%M%SZ') || die 'cannot read UTC time'
    RECEIPT=$RECEIPT_DIR/start-${stamp}.log
    (umask 077; : > "$RECEIPT") || die "cannot create $RECEIPT"
    note 'schema=r8q-battery-start/v1'
    note "utc=$stamp"
    note "boot_id=$(read_trimmed /proc/sys/kernel/random/boot_id 2>/dev/null || printf unavailable)"
}

route_env_value() {
    key=$1
    awk -F= -v wanted="$key" '$1 == wanted {
        value=$2
        sub(/^[[:space:]]*/, "", value)
        sub(/[[:space:]]*$/, "", value)
        gsub(/^"|"$/, "", value)
        print value
        exit
    }' /etc/r8q-usb-route.env
}

require_identity() {
    kernel=$(uname -r 2>/dev/null) || die 'cannot read kernel release'
    [ "$kernel" = "$EXPECTED_KERNEL" ] || die "unexpected kernel: $kernel"
    [ -f /etc/machine-id ] && [ ! -L /etc/machine-id ] || die 'machine-id is unavailable or a symlink'
    machine_id=$(read_trimmed /etc/machine-id) || die 'cannot read machine-id'
    [ "$machine_id" = "$EXPECTED_MACHINE_ID" ] || die "unexpected machine-id: $machine_id"

    [ -f /etc/r8q-usb-route.env ] && [ ! -L /etc/r8q-usb-route.env ] || \
        die 'pinned USB route environment is unavailable or a symlink'
    route_machine_id=$(route_env_value EXPECTED_MACHINE_ID)
    route_root_uuid=$(route_env_value EXPECTED_ROOT_UUID)
    [ "$route_machine_id" = "$EXPECTED_MACHINE_ID" ] || \
        die 'USB route environment has an unexpected machine-id'
    [ "$route_root_uuid" = "$EXPECTED_ROOT_UUID" ] || \
        die 'USB route environment has an unexpected root UUID'

    need_cmd findmnt
    root_uuid=$(findmnt -n -o UUID / 2>/dev/null | tr -d '\r\n') || \
        die 'cannot identify the mounted root UUID'
    [ "$root_uuid" = "$EXPECTED_ROOT_UUID" ] || die "unexpected root UUID: $root_uuid"
    note "identity=kernel:$kernel machine_id:$machine_id root_uuid:$root_uuid"
}

require_irq_pin_state() {
    dt_root=/sys/firmware/devicetree/base
    [ -d "$dt_root" ] && [ ! -L "$dt_root" ] || die 'live device-tree base is unavailable'
    need_cmd find
    need_cmd od
    pin_states=$(find "$dt_root" -type d -name max77705-int-default-state -print 2>/dev/null || true)
    set -- $pin_states
    [ "$#" = 1 ] || die "MAX77705 IRQ pin state is missing or ambiguous: $pin_states"
    pin_state=$1
    [ -f "$pin_state/pins" ] || die 'MAX77705 IRQ pin list is missing'
    pins=$(tr -d '\000\r\n' < "$pin_state/pins" 2>/dev/null || true)
    [ "$pins" = gpio11 ] || die "MAX77705 IRQ pin is not gpio11: $pins"
    [ -f "$pin_state/bias-pull-up" ] || die 'MAX77705 IRQ pin lacks bias-pull-up'
    [ ! -e "$pin_state/bias-disable" ] || die 'MAX77705 IRQ pin has bias-disable'
    [ -f "$pin_state/power-source" ] || die 'MAX77705 IRQ power-source is missing'
    power_source=$(od -An -t x1 -v "$pin_state/power-source" | tr -d ' \t\r\n')
    [ "$power_source" = 00000001 ] || die "MAX77705 IRQ power-source is not big-endian 1: $power_source"
    note "irq_pin_state=$pin_state pins=$pins bias_pull_up=true bias_disable=false power_source=1"
}

require_unit_active() {
    unit=$1
    need_cmd systemctl
    state=$(systemctl show --no-pager --property=ActiveState --value "$unit" 2>/dev/null || true)
    result=$(systemctl show --no-pager --property=Result --value "$unit" 2>/dev/null || true)
    [ "$state" = active ] || die "$unit is not active (state=$state)"
    [ "$result" = success ] || die "$unit did not finish successfully (result=$result)"
    note "unit=$unit state=$state result=$result"
}

module_loaded() {
    awk -v wanted="$1" '$1 == wanted {found=1} END {exit(found ? 0 : 1)}' /proc/modules 2>/dev/null
}

require_no_max_modules() {
    [ -r /proc/modules ] || die 'cannot inspect loaded modules'
    while read -r module rest; do
        case "$module" in
            max17042*|max77705*) die "MAX module is already loaded: $module" ;;
        esac
    done < /proc/modules
}

require_no_max_supplies() {
    for supply in /sys/class/power_supply/max170xx_battery \
                 /sys/class/power_supply/max77705-charger; do
        [ ! -e "$supply" ] || die "MAX power supply already exists: ${supply##*/}"
    done
}

client_path() {
    address=$1
    found=
    for client in /sys/bus/i2c/devices/*-"$address"; do
        [ -e "$client" ] || continue
        [ -z "$found" ] || die "multiple I2C clients at 0x$address"
        found=$client
    done
    [ -n "$found" ] || return 1
    printf '%s\n' "$found"
}

client_driver() {
    client=$1
    if [ -L "$client/driver" ]; then
        readlink -f "$client/driver" 2>/dev/null || printf unresolved
    else
        printf unbound
    fi
}

require_simple_mfd_binding() {
    client=$(client_path 0036) || die 'missing 0x36 fuel-gauge client'
    driver=$(client_driver "$client")
    case "$driver" in
        */i2c/drivers/simple-mfd-i2c) ;;
        *) die "0x36 binding changed: $driver" ;;
    esac
    note "client_0036_driver=$driver"
}

require_unbound_client() {
    address=$1
    client=$(client_path "$address") || die "missing 0x$address client"
    driver=$(client_driver "$client")
    [ "$driver" = unbound ] || die "0x$address is unexpectedly bound: $driver"
    note "client_0x$address=unbound"
}

require_absent_client() {
    if client_path "$1" >/dev/null 2>&1; then
        die "unexpected I2C client at 0x$1"
    fi
    note "client_0x$1=absent"
}

wait_for_client() {
    address=$1
    attempt=0
    while [ "$attempt" -lt "$STAGE_WAIT_SECONDS" ]; do
        client_path "$address" >/dev/null 2>&1 && return 0
        sleep 1
        attempt=$((attempt + 1))
    done
    die "I2C client 0x$address did not appear"
}

wait_for_driver() {
    address=$1
    expected=$2
    attempt=0
    while [ "$attempt" -lt "$STAGE_WAIT_SECONDS" ]; do
        client=$(client_path "$address" 2>/dev/null || true)
        if [ -n "$client" ]; then
            driver=$(client_driver "$client")
            case "$driver" in
                */i2c/drivers/$expected) return 0 ;;
            esac
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    die "I2C client 0x$address did not bind to $expected"
}

wait_for_supply() {
    name=$1
    attempt=0
    while [ "$attempt" -lt "$STAGE_WAIT_SECONDS" ]; do
        [ -d "/sys/class/power_supply/$name" ] && return 0
        sleep 1
        attempt=$((attempt + 1))
    done
    die "power supply did not appear: $name"
}

verify_module() {
    path=$1
    expected_hash=$2
    [ -d "$PAYLOAD_DIR" ] && [ ! -L "$PAYLOAD_DIR" ] || \
        die "private module directory is unavailable or a symlink: $PAYLOAD_DIR"
    [ -f "$path" ] || die "module is missing: $path"
    [ ! -L "$path" ] || die "module must not be a symlink: $path"
    case "$path" in
        /usr/lib/modules/*) die "module is inside the autoload search tree: $path" ;;
        "$PAYLOAD_DIR"/*) ;;
        *) die "module path is outside the pinned payload directory: $path" ;;
    esac
    need_cmd sha256sum
    actual_hash=$(sha256sum "$path" | awk '{print $1}') || die "cannot hash $path"
    [ "$actual_hash" = "$expected_hash" ] || die "hash mismatch for $path: $actual_hash"
    need_cmd modinfo
    vermagic=$(modinfo -F vermagic "$path" 2>/dev/null || true)
    [ "$vermagic" = "$EXPECTED_VERMAGIC" ] || die "vermagic mismatch for $path: $vermagic"
    note "validated_module=$path sha256=$actual_hash vermagic=$vermagic"
}

dump_supply() {
    name=$1
    supply=/sys/class/power_supply/$name
    [ -d "$supply" ] || die "power supply is missing: $name"
    for attr in type status health online present capacity capacity_level \
                voltage_now current_now current_avg charge_now energy_now temp \
                input_current_limit constant_charge_current; do
        if [ -r "$supply/$attr" ]; then
            value=$(read_trimmed "$supply/$attr" 2>/dev/null || true)
            note "${name}.${attr}=$value"
        fi
    done
}

validate_fuel_telemetry() {
    supply=/sys/class/power_supply/max170xx_battery
    [ -d "$supply" ] || die 'fuel-gauge power supply is missing'
    health=$(read_trimmed "$supply/health" 2>/dev/null || true)
    present=$(read_trimmed "$supply/present" 2>/dev/null || true)
    capacity=$(read_trimmed "$supply/capacity" 2>/dev/null || true)
    voltage=$(read_trimmed "$supply/voltage_now" 2>/dev/null || true)
    temp=$(read_trimmed "$supply/temp" 2>/dev/null || true)
    [ "$health" = Good ] || die "fuel health is not Good: $health"
    [ "$present" = 1 ] || die "fuel present is not 1: $present"
    require_range fuel_capacity "$capacity" 0 100
    require_range fuel_voltage_uV "$voltage" 2500000 4500000
    require_range fuel_temp_dC "$temp" 0 450
    note "fuel_plausibility=health:$health present:$present capacity:$capacity voltage_uV:$voltage temp_dC:$temp"
    dump_supply max170xx_battery
}

validate_charger_telemetry() {
    supply=/sys/class/power_supply/max77705-charger
    [ -d "$supply" ] || die 'charger power supply is missing'
    health=$(read_trimmed "$supply/health" 2>/dev/null || true)
    online=$(read_trimmed "$supply/online" 2>/dev/null || true)
    [ "$health" = Good ] || die "charger health is not Good: $health"
    case "$online" in
        0|1) ;;
        *) die "charger online is not 0/1: $online" ;;
    esac
    note "charger_plausibility=health:$health online:$online"
    dump_supply max77705-charger
}

write_sysfs_value() {
    value=$1
    path=$2
    printf '%s\n' "$value" > "$path" || return 1
}

enforce_charge_current_cap() {
    charger_client=$1
    charger_driver=$(client_driver "$charger_client")
    case "$charger_driver" in
        */i2c/drivers/max77705-charger) ;;
        *) die "charger current properties are not owned by max77705-charger: $charger_driver" ;;
    esac

    input_path=/sys/class/power_supply/max77705-charger/input_current_limit
    charge_path=/sys/class/power_supply/max77705-charger/constant_charge_current
    # Read and validate both inherited values before making either write.  A
    # malformed, missing, below-cap, or outside-driver-range value leaves the
    # charger untouched and forces the normal reboot rollback boundary.
    input_limit=$(read_trimmed "$input_path" 2>/dev/null || true)
    charge_current=$(read_trimmed "$charge_path" 2>/dev/null || true)
    require_range input_current_limit_uA "$input_limit" "$CURRENT_PROPERTY_MIN_UA" "$CURRENT_PROPERTY_MAX_UA"
    require_range constant_charge_current_uA "$charge_current" "$CURRENT_PROPERTY_MIN_UA" "$CURRENT_PROPERTY_MAX_UA"
    [ "$input_limit" -ge "$CURRENT_LIMIT_CAP_UA" ] || \
        die "input_current_limit_uA is below conservative cap: $input_limit"
    [ "$charge_current" -ge "$CURRENT_LIMIT_CAP_UA" ] || \
        die "constant_charge_current_uA is below conservative cap: $charge_current"

    input_write=none
    charge_write=none
    if [ "$input_limit" -gt "$CURRENT_LIMIT_CAP_UA" ]; then
        input_write=$INPUT_LIMIT_WRITE_UA
    fi
    if [ "$charge_current" -gt "$CURRENT_LIMIT_CAP_UA" ]; then
        charge_write=$CHARGE_CURRENT_WRITE_UA
    fi

    # Order matters: lower the input budget first, then the battery charge
    # current.  Never write a property that is already at the cap.
    if [ "$input_write" != none ]; then
        write_sysfs_value "$input_write" "$input_path" || \
            die "failed to write input_current_limit_uA=$input_write"
        input_readback=$(read_trimmed "$input_path" 2>/dev/null || true)
        [ "$input_readback" = "$CURRENT_LIMIT_CAP_UA" ] || \
            die "input_current_limit_uA readback is not $CURRENT_LIMIT_CAP_UA: $input_readback"
    fi
    if [ "$charge_write" != none ]; then
        write_sysfs_value "$charge_write" "$charge_path" || \
            die "failed to write constant_charge_current_uA=$charge_write"
    fi

    input_readback=$(read_trimmed "$input_path" 2>/dev/null || true)
    charge_readback=$(read_trimmed "$charge_path" 2>/dev/null || true)
    [ "$input_readback" = "$CURRENT_LIMIT_CAP_UA" ] || \
        die "input_current_limit_uA readback is not $CURRENT_LIMIT_CAP_UA: $input_readback"
    [ "$charge_readback" = "$CURRENT_LIMIT_CAP_UA" ] || \
        die "constant_charge_current_uA readback is not $CURRENT_LIMIT_CAP_UA: $charge_readback"
    note "current_limit_policy=conservative_cap cap_uA=$CURRENT_LIMIT_CAP_UA input_inherited_uA=$input_limit charge_inherited_uA=$charge_current input_write_uA=$input_write charge_write_uA=$charge_write input_readback_uA=$input_readback charge_readback_uA=$charge_readback"
}

require_no_active_compositor() {
    for process in /proc/[0-9]*; do
        [ -r "$process/comm" ] || continue
        comm=$(read_trimmed "$process/comm" 2>/dev/null || true)
        case "$comm" in
            Hyprland|hyprland|gnome-shell|kwin_wayland|kwin_x11|sway|weston|labwc|wayfire)
                die "active compositor detected: $comm (pid ${process##*/})" ;;
        esac
    done
}

load_module() {
    path=$1
    name=$2
    note "loading=$name path=$path"
    "$INSMOD" "$path" >> "$RECEIPT" 2>&1 || \
        die "$name insmod failed; ordinary reboot is the rollback boundary"
    module_loaded "$name" || die "$name is not present in /proc/modules after insmod"
    note "loaded=$name"
}

must_be_root
need_cmd awk
need_cmd date
need_cmd id
need_cmd insmod
need_cmd find
need_cmd od
need_cmd readlink
need_cmd sleep
need_cmd tr
INSMOD=$(command -v insmod)
new_receipt
require_identity
require_unit_active r8q-hardware-prepare.service
require_unit_active r8q-touch.service
require_irq_pin_state
require_no_active_compositor
require_no_max_modules
require_no_max_supplies
require_simple_mfd_binding
wait_for_client 0066
wait_for_client 0069
require_unbound_client 0066
require_unbound_client 0069
require_absent_client 0025
verify_module "$MODULE_FUEL" "$MAX17042_SHA256"
verify_module "$MODULE_MFD" "$MAX77705_SHA256"
verify_module "$MODULE_CHARGER" "$MAX77705_CHARGER_SHA256"

# The expected probe-side mutation for this DT is MAX17042 SALRT=0xff00
# because the fuel-gauge node has no IRQ. This helper deliberately observes
# the resulting power_supply data and never performs a raw register write.
note 'policy=route-first; no raw I2C; driver-owned conservative current cap; no driver unload'
load_module "$MODULE_FUEL" max17042_battery
wait_for_supply max170xx_battery
require_simple_mfd_binding
require_unbound_client 0066
require_unbound_client 0069
require_absent_client 0025
validate_fuel_telemetry
note 'fuel_stage=pass'

load_module "$MODULE_MFD" max77705
wait_for_driver 0066 max77705
client_0066=$(client_path 0066) || die '0x66 disappeared after MFD probe'
mfd_driver=$(client_driver "$client_0066")
case "$mfd_driver" in
    */i2c/drivers/max77705) ;;
    *) die "unexpected 0x66 driver after MFD probe: $mfd_driver" ;;
esac
require_unbound_client 0069
require_absent_client 0025
note "mfd_stage=pass client_0066_driver=$mfd_driver"

load_module "$MODULE_CHARGER" max77705_charger
wait_for_supply max77705-charger
wait_for_driver 0069 max77705-charger
client_0069=$(client_path 0069) || die '0x69 disappeared after charger probe'
charger_driver=$(client_driver "$client_0069")
case "$charger_driver" in
    */i2c/drivers/max77705-charger) ;;
    *) die "unexpected 0x69 driver after charger probe: $charger_driver" ;;
esac
validate_fuel_telemetry
validate_charger_telemetry
enforce_charge_current_cap "$client_0069"
require_absent_client 0025
note "charger_stage=pass client_0069_driver=$charger_driver"
note 'charging_claim=not established by startup; use a bounded time-series monitor'
note "receipt=$RECEIPT"
