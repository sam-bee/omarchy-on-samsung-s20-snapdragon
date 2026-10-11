#!/bin/sh
# Focused fixtures for the read-only current-boot host-route witness.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT=$(CDPATH= cd -- "$HERE/../.." && pwd)
WITNESS=$PROJECT/rootfs/usr/local/sbin/r8q-usb-route-witness.sh
BOOT_ID=11111111-1111-1111-1111-111111111111

fail() { echo "FAIL: $*" >&2; exit 1; }

make_fixture() {
    root=$1
    mode=$2
    mkdir -p "$root/proc/sys/kernel/random" "$root/var/lib/r8q-usb-route/wrapper/$BOOT_ID" "$root/var/lib/r8q-usb-route/$BOOT_ID"
    printf '%s\n' "$BOOT_ID" > "$root/proc/sys/kernel/random/boot_id"
    case "$mode" in
        host-already)
            route_outcome=already_AP
            mailbox_attempted=2
            mailbox_succeeded=2
            ;;
        host-changed)
            route_outcome=changed_to_AP
            mailbox_attempted=6
            mailbox_succeeded=6
            ;;
        deferred)
            route_outcome=deferred_no_vbus_no_connection
            mailbox_attempted=0
            mailbox_succeeded=0
            ;;
        error)
            route_outcome=none
            mailbox_attempted=0
            mailbox_succeeded=0
            ;;
        missing)
            return 0
            ;;
        *) fail "unknown fixture mode: $mode" ;;
    esac
    cat > "$root/var/lib/r8q-usb-route/wrapper/$BOOT_ID/metadata.txt" <<'EOF_METADATA'
schema=r8q-usb-route-wrapper/v1
boot_id=11111111-1111-1111-1111-111111111111
helper_return_code=0
startup_gate=pass
outcome=pass
automatic_retry=false
EOF_METADATA
    cat > "$root/var/lib/r8q-usb-route/$BOOT_ID/receipt.txt" <<EOF_RECEIPT
schema=r8q-usb-route/v1
outcome=running
boot_id=$BOOT_ID
route_outcome=$route_outcome
mailbox_writes_attempted=$mailbox_attempted
mailbox_writes_succeeded=$mailbox_succeeded
manual_cleanup_required=0
automatic_retry=false
EOF_RECEIPT
    if test "$mode" = deferred; then
        cat >> "$root/var/lib/r8q-usb-route/$BOOT_ID/receipt.txt" <<'EOF_DEFERRED'
manual_cleanup_required=0
outcome=deferred
EOF_DEFERRED
    else
        cat >> "$root/var/lib/r8q-usb-route/$BOOT_ID/receipt.txt" <<'EOF_ERROR'
schema=r8q-usb-route/v1
manual_cleanup_required=0
outcome=error
EOF_ERROR
    fi
}

make_actual_helper_fixture() {
    root=$1
    mode=$2
    python3 - "$root" "$mode" "$PROJECT/tests/r8q-usb-route/test_r8q_usb_route.py" <<'PY'
import importlib.util
import shutil
import sys
from pathlib import Path

root = Path(sys.argv[1])
mode = sys.argv[2]
module_path = Path(sys.argv[3])
spec = importlib.util.spec_from_file_location("route_fixture", module_path)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
root.mkdir(parents=True, exist_ok=True)
sysfs, proc, etc, fake_bin, boot, protocol_dir = module.make_tree(root)
result = module.run_fixture(root, sysfs, proc, etc, fake_bin, boot, protocol_dir, mode)
if result.returncode != 0:
    raise SystemExit(f"real helper fixture failed: {result.stderr}")
dest = root / "var/lib/r8q-usb-route"
(dest / "wrapper" / module.BOOT_ID).mkdir(parents=True)
shutil.copytree(root / "state" / module.BOOT_ID, dest / module.BOOT_ID)
(dest / "wrapper" / module.BOOT_ID / "metadata.txt").write_text(
    "schema=r8q-usb-route-wrapper/v1\n"
    f"boot_id={module.BOOT_ID}\n"
    "helper_return_code=0\nstartup_gate=pass\noutcome=pass\n"
    "automatic_retry=false\n",
    encoding="utf-8",
)
PY
}

run_witness() {
    root=$1
    R8Q_USB_ROUTE_WITNESS_OFFLINE=1 \
    R8Q_USB_ROUTE_WITNESS_ROOT="$root" \
        "$WITNESS"
}

for mode in route09 route3f; do
    root=$(mktemp -d)
    make_actual_helper_fixture "$root" "$mode"
    run_witness "$root" || fail "host witness failed: $mode"
    rm -rf "$root"
done

for mode in deferred error missing; do
    root=$(mktemp -d)
    make_fixture "$root" "$mode"
    if run_witness "$root" >/dev/null 2>&1; then
        fail "witness accepted invalid receipt: $mode"
    fi
    rm -rf "$root"
done

echo 'PASS: read-only host route witness fixtures'
