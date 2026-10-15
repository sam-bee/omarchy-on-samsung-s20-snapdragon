#!/usr/bin/env bash
# Relink the completed stage-1 build with matching encrypted-unlock modules.
# This script prepares local build artifacts only; it never contacts a phone.
set -euo pipefail

[[ $# == 0 ]] || { echo "Usage: $0" >&2; exit 2; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
SOURCE="$REPO/out/waydroid-kernel-20261013/source"
OUTPUT="$REPO/out/waydroid-encrypted-20261015/kernel"
INITROOT="$REPO/out/waydroid-encrypted-20261015/initramfs-preparation/initramfs"
JOBS=${R8Q_WAYDROID_ENCRYPTED_JOBS:-2}
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid job count' >&2; exit 2; }

python3 -I -B - "$OUTPUT" "$SOURCE" <<'PY'
from pathlib import Path
import hashlib, json, sys
output, source = map(Path, sys.argv[1:])
stage = json.loads((output / 'stage1-manifest.json').read_text())
assert stage['kind'] == 'r8q-waydroid-encrypted-stage1'
assert stage['kernel_release'] == '7.1.2-r8q-waydroid2'
assert stage['stage2_required'] is True and stage['source'] == str(source)
assert not (output / 'candidate-manifest.json').exists()
assert not (output / 'stage1-finalization.config').exists()
image = output / 'arch/arm64/boot/Image'
assert hashlib.sha256(image.read_bytes()).hexdigest() == stage['image_sha256']
assert (output / 'payload/BOOTAA64.EFI').read_bytes() == image.read_bytes()
modules = output / 'modules'
actual = sorted(str(p.relative_to(modules)) for p in modules.rglob('*.ko'))
assert actual == stage['module_paths'] and len(actual) == stage['module_count'] > 0
config = (output / '.config').read_text()
expected = 'CONFIG_INITRAMFS_SOURCE="' + str(output / 'temporary-accepted-encrypted-initramfs.cpio') + '"'
assert expected in config.splitlines()
(output / 'stage1-finalization.config').write_bytes((output / '.config').read_bytes())
print('Stage-1 identity and staged module inventory PASS')
PY

python3 -I -B "$REPO/scripts/prepare-waydroid-encrypted-initramfs.py" --prepare \
    --kernel-output "$OUTPUT" --output "$INITROOT"

export ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-
"$SOURCE/scripts/config" --file "$OUTPUT/.config" \
    --set-str INITRAMFS_SOURCE "$INITROOT $REPO/initramfs/irfs.devnodes"
make -C "$SOURCE" O="$OUTPUT" olddefconfig
make -C "$SOURCE" O="$OUTPUT" -j"$JOBS" Image
# Refresh built-in metadata from the final link as well as the module indexes.
make -C "$SOURCE" O="$OUTPUT" INSTALL_MOD_PATH="$OUTPUT/modules" DEPMOD=depmod modules_install
cp --reflink=auto "$OUTPUT/arch/arm64/boot/Image" "$OUTPUT/payload/BOOTAA64.EFI"

python3 -I -B "$REPO/scripts/validate-waydroid-encrypted-candidate.py" \
    "$OUTPUT" "$SOURCE" "$INITROOT"
