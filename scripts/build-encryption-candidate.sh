#!/usr/bin/env bash
# Build only an isolated Image. This script does not deploy or format storage.
set -euo pipefail
if [[ $# != 5 ]]; then
    echo "Usage: $0 PATCHED_KERNEL_TREE LIVE_CONFIG PREPARED_INITRAMFS ACTIVE_DTB NEW_OUTPUT" >&2
    exit 2
fi
REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOURCE=$(realpath "$1")
BASELINE=$(realpath "$2")
INITROOT=$(realpath "$3")
DTB=$(realpath "$4")
OUTPUT=$(realpath -m "$5")
JOBS=${R8Q_ENCRYPTION_JOBS:-4}
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ -f "$SOURCE/Makefile" && -f "$BASELINE" && -f "$DTB" ]]
[[ -f "$INITROOT/etc/r8q-encryption-manifest.json" && -x "$INITROOT/init" ]]
[[ ! -e "$OUTPUT" && "$OUTPUT" == "$REPO/out/"* ]]
[[ "$OUTPUT" != "$SOURCE" && "$OUTPUT" != "$INITROOT" ]]
for tool in make clang ld.lld llvm-ar llvm-nm python3 aarch64-linux-gnu-gcc; do
    command -v "$tool" >/dev/null || { echo "Required existing tool missing: $tool" >&2; exit 2; }
done
python3 -I - "$BASELINE" "$INITROOT" "$SOURCE" "$OUTPUT" "$DTB" <<'PY'
import hashlib,json,pathlib,struct,subprocess,sys
def require(condition,message):
 if not condition:raise SystemExit(message)
baseline=pathlib.Path(sys.argv[1]).read_text()
manifest=json.loads((pathlib.Path(sys.argv[2])/'etc/r8q-encryption-manifest.json').read_text())
require(manifest['fail_closed'] is True,'Candidate must fail closed')
require(manifest['kernel_release']=='7.1.2-r8q-rtc2','Wrong module release')
require(not (pathlib.Path(sys.argv[2])/'init.normal').exists(),'Plaintext init fallback is forbidden')
output=pathlib.Path(sys.argv[4])
for root in map(pathlib.Path,sys.argv[2:4]):
 require(not output.is_relative_to(root) and not root.is_relative_to(output),'Output overlaps source/initramfs')
require(hashlib.sha256(baseline.encode()).hexdigest()=='25879d3bf45fa6bc77a7146fcd4fb854e11fbf5f4f14c908eb86020817cbf5dc','This candidate requires the captured live config')
compiler=subprocess.check_output(['clang','--version'],text=True).splitlines()[0]
require('CONFIG_CC_VERSION_TEXT="'+compiler+'"' in baseline,'Compiler differs from the live baseline')
dtb=pathlib.Path(sys.argv[5]).read_bytes()
require(struct.unpack_from('>II',dtb)==(0xd00dfeed,len(dtb)),'Invalid FDT header/size')
require(hashlib.sha256(dtb).hexdigest()=='d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca','DTB differs from the captured active phone payload')
PY
mkdir -p "$OUTPUT"
cp "$BASELINE" "$OUTPUT/baseline.config"
cp "$BASELINE" "$OUTPUT/.config"
python3 -I "$REPO/scripts/validate-encryption-candidate.py" --source-receipt "$SOURCE" "$OUTPUT/kernel-source-before.jsonl"
export ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-
bash "$SOURCE/scripts/kconfig/merge_config.sh" -m -O "$OUTPUT" \
    "$OUTPUT/.config" "$REPO/config/r8q_encryption.config"
"$SOURCE/scripts/config" --file "$OUTPUT/.config" \
    --set-str INITRAMFS_SOURCE "$INITROOT $REPO/initramfs/irfs.devnodes" \
    --set-val INITRAMFS_ROOT_UID "$(id -u)" \
    --set-val INITRAMFS_ROOT_GID "$(id -g)"
# These are host owner IDs to MAP to root, rather than resulting archive IDs.
# validate-encryption-candidate.py checks the produced cpio has UID/GID zero.
make -C "$SOURCE" O="$OUTPUT" olddefconfig
python3 -I - "$OUTPUT" <<'PY'
import hashlib,json,pathlib,re,sys
p=pathlib.Path(sys.argv[1])
def require(condition,message):
 if not condition:raise SystemExit(message)
def config(path):
 result={}
 for line in path.read_text().splitlines():
  if line.startswith('CONFIG_'):k,v=line.split('=',1);result[k]=v
  elif line.startswith('# CONFIG_') and line.endswith(' is not set'):result[line[2:-11]]='n'
 return result
a=config(p/'baseline.config');b=config(p/'.config')
# A newly visible, disabled Kconfig symbol equals an absent symbol; neither
# changes compiled behavior. Record only effective differences.
delta={k:{'before':a.get(k,'n'),'after':b.get(k,'n')} for k in sorted(a.keys()|b.keys()) if a.get(k,'n')!=b.get(k,'n')}
allowed={'CONFIG_BLK_DEV_DM','CONFIG_DM_CRYPT','CONFIG_CRYPTO_AES','CONFIG_CRYPTO_XTS','CONFIG_CRYPTO_AES_ARM64_CE_BLK','CONFIG_CRYPTO_CBC','CONFIG_CRYPTO_AUTHENC','CONFIG_CRYPTO_ESSIV','CONFIG_CRYPTO_LIB_MD5','CONFIG_PNFS_BLOCK','CONFIG_CC_CAN_LINK','CONFIG_INITRAMFS_SOURCE','CONFIG_INITRAMFS_ROOT_UID','CONFIG_INITRAMFS_ROOT_GID'}
require(set(delta)<=allowed,'Unexpected config changes: '+str(set(delta)-allowed))
required=('BLK_DEV_INITRD','MODULES','MODULE_UNLOAD','INPUT','INPUT_EVDEV','I2C','BLK_DEV_DM','DM_CRYPT','CRYPTO_AES','CRYPTO_XTS','CRYPTO_AES_ARM64_CE_BLK','CRYPTO_CBC','CRYPTO_AUTHENC','CRYPTO_ESSIV','CRYPTO_LIB_AES','CRYPTO_LIB_MD5','CRYPTO_LIB_SHA256','SCSI_UFSHCD','SCSI_UFS_QCOM','EXT4_FS','DEVTMPFS','DRM_SIMPLEDRM','EFI','CMDLINE_FORCE')
require(all(b.get('CONFIG_'+k)=='y' for k in required),'Missing built-in prerequisite: '+str({k:b.get('CONFIG_'+k) for k in required if b.get('CONFIG_'+k)!='y'}))
require(b.get('CONFIG_MODVERSIONS')=='n','Module version policy changed')
require(a['CONFIG_CC_VERSION_TEXT']==b['CONFIG_CC_VERSION_TEXT'],'Compiler config changed')
require(b.get('CONFIG_LOCALVERSION')=='"-r8q-rtc2"','Wrong local version')
(p/'config-delta.json').write_text(json.dumps(delta,indent=2)+'\n')
print('Configuration gates passed; '+str(len(delta))+' intended changes')
PY
RELEASE=$(make -s -C "$SOURCE" O="$OUTPUT" kernelrelease)
[[ "$RELEASE" == 7.1.2-r8q-rtc2 ]]
make -C "$SOURCE" O="$OUTPUT" -j"$JOBS" Image
mkdir "$OUTPUT/payload"
cp "$OUTPUT/arch/arm64/boot/Image" "$OUTPUT/payload/BOOTAA64.EFI"
cp "$DTB" "$OUTPUT/payload/R8Q-RTC.DTB"
python3 -I "$REPO/scripts/validate-encryption-candidate.py" "$OUTPUT" "$SOURCE" "$INITROOT"
