#!/bin/busybox ash

set -u
PATH=${PATH:-/bin:/sbin:/usr/bin:/usr/sbin}
export PATH

R8Q_GUARD_CONFIG=${R8Q_GUARD_CONFIG:-/etc/r8q-diagnostic-fallback.conf}
R8Q_GUARD_SYSFS_ROOT=${R8Q_GUARD_SYSFS_ROOT:-/sys/class/block}
R8Q_GUARD_DEV_ROOT=${R8Q_GUARD_DEV_ROOT:-/dev}
R8Q_GUARD_PROC_MOUNTS=${R8Q_GUARD_PROC_MOUNTS:-/proc/mounts}
R8Q_GUARD_PROC_MOUNTINFO=${R8Q_GUARD_PROC_MOUNTINFO:-/proc/self/mountinfo}
R8Q_GUARD_PROC_ROOT=${R8Q_GUARD_PROC_ROOT:-/proc}
R8Q_GUARD_CACHE_MOUNT=${R8Q_GUARD_CACHE_MOUNT:-/run/r8q-diagnostic-cache}
R8Q_GUARD_RECEIPT=${R8Q_GUARD_RECEIPT:-/run/r8q-diagnostic-fallback}
R8Q_GUARD_TEST_MODE=${R8Q_GUARD_TEST_MODE:-0}

GUARD_CHILD_DEADLINE=30
GUARD_CHILD_GRACE=5
if [ "$R8Q_GUARD_TEST_MODE" = 1 ]; then
    GUARD_CHILD_DEADLINE=2
    GUARD_CHILD_GRACE=1
fi

CACHE_PARTUUID=5594c694-c871-4b5f-90b1-690a6f68e0f7
CACHE_PARTNAME=cache
CACHE_BYTES=629145600
CACHE_SECTORS=1228800
CACHE_LOGICAL_BLOCK_SIZE=4096
CACHE_FSTYPE=vfat
ACCEPTED_EFI_SHA256=f42452151822a53899ca826b8e55262f197b1b8fdfe660cab511551daaabb23b
ACCEPTED_EFI_BYTES=67631616
DTB_SHA256=d3a065499c4edff7b430a0fc2bea5f17428ba608bc19d9aed1a02bb1d4f1e0ca
DTB_BYTES=124302
EFI_REL=EFI/BOOT/BOOTAA64.EFI
DTB_REL=EFI/BOOT/R8Q-RTC.DTB

if [ "$R8Q_GUARD_TEST_MODE" = 1 ]; then
    ACCEPTED_EFI_SHA256=${R8Q_GUARD_TEST_ACCEPTED_EFI_SHA256:-$ACCEPTED_EFI_SHA256}
    ACCEPTED_EFI_BYTES=${R8Q_GUARD_TEST_ACCEPTED_EFI_BYTES:-$ACCEPTED_EFI_BYTES}
    DTB_SHA256=${R8Q_GUARD_TEST_DTB_SHA256:-$DTB_SHA256}
    DTB_BYTES=${R8Q_GUARD_TEST_DTB_BYTES:-$DTB_BYTES}
fi

MOUNTED=0
CREATED_NODE=0
CACHE_DEVICE=
GUARD_STATUS=0
ARG_NONCE=
ARG_TAG=
ARG_EXPECTED_EFI_SHA256=
ARG_EXPECTED_DTB_SHA256=

guard_log() {
    printf 'r8q-diagnostic-fallback: %s\n' "$1" >&2
}

guard_fail() {
    guard_log "FAIL CLOSED: $1"
    exit 111
}

guard_cleanup() {
    GUARD_STATUS=$1
    trap - EXIT INT TERM
    if [ "$MOUNTED" -eq 1 ]; then
        sync >/dev/null 2>&1 || GUARD_STATUS=111
        guard_umount_command "$R8Q_GUARD_CACHE_MOUNT" || GUARD_STATUS=111
        MOUNTED=0
    fi
    if [ "$CREATED_NODE" -eq 1 ] && [ -n "$CACHE_DEVICE" ]; then
        rm -f "$CACHE_DEVICE" >/dev/null 2>&1 || GUARD_STATUS=111
    fi
    exit "$GUARD_STATUS"
}

trap 'guard_cleanup "$?"' EXIT
trap 'exit 111' INT TERM

guard_decimal() {
    printf '%s\n' "$1" | grep -Eq '^[0-9][0-9]*$'
}

guard_hash() {
    printf '%s\n' "$1" | grep -Eq '^[0-9a-f][0-9a-f]*$' && [ "${#1}" -eq 64 ]
}

guard_nonce() {
    printf '%s\n' "$1" | grep -Eq '^[0-9a-f][0-9a-f]*$' && [ "${#1}" -eq 32 ]
}

guard_capability_path() {
    GUARD_CAPABILITY=$1
    GUARD_CAPABILITY_PATH=$PATH:
    while [ -n "$GUARD_CAPABILITY_PATH" ]; do
        GUARD_CAPABILITY_ENTRY=${GUARD_CAPABILITY_PATH%%:*}
        GUARD_CAPABILITY_PATH=${GUARD_CAPABILITY_PATH#*:}
        [ -n "$GUARD_CAPABILITY_ENTRY" ] || GUARD_CAPABILITY_ENTRY=.
        [ -x "$GUARD_CAPABILITY_ENTRY/$GUARD_CAPABILITY" ] && return 0
    done
    return 1
}

guard_capabilities() {
    for GUARD_COMMAND in cp mv readlink sha256sum stat; do
        guard_capability_path "$GUARD_COMMAND" || guard_fail "capability-$GUARD_COMMAND"
    done
}

guard_parse_arguments() {
    [ "$#" -eq 0 ] || [ "$#" -eq 8 ] || guard_fail argument-count
    [ "$#" -eq 0 ] && return 0
    [ "$1" = --nonce ] || guard_fail argument-nonce
    [ "$3" = --tag ] || guard_fail argument-tag
    [ "$5" = --expected-efi-sha256 ] || guard_fail argument-efi
    [ "$7" = --expected-dtb-sha256 ] || guard_fail argument-dtb
    ARG_NONCE=$2
    ARG_TAG=$4
    ARG_EXPECTED_EFI_SHA256=$6
    ARG_EXPECTED_DTB_SHA256=$8
}

guard_tag() {
    printf '%s\n' "$1" | grep -Eq '^[A-Za-z0-9._-][A-Za-z0-9._-]*$'
}

guard_field() {
    GUARD_FIELD_KEY=$1
    GUARD_FIELD_FILE=$2
    GUARD_FIELD_VALUE=
    GUARD_FIELD_COUNT=0
    while IFS='=' read -r GUARD_FIELD_NAME GUARD_FIELD_CURRENT || [ -n "${GUARD_FIELD_NAME:-}" ]; do
        if [ "${GUARD_FIELD_NAME:-}" = "$GUARD_FIELD_KEY" ]; then
            GUARD_FIELD_COUNT=$((GUARD_FIELD_COUNT + 1))
            GUARD_FIELD_VALUE=${GUARD_FIELD_CURRENT:-}
        fi
    done < "$GUARD_FIELD_FILE"
    [ "$GUARD_FIELD_COUNT" -eq 1 ] || return 1
    printf '%s' "$GUARD_FIELD_VALUE"
}

guard_parse_config() {
    [ -f "$R8Q_GUARD_CONFIG" ] && [ ! -L "$R8Q_GUARD_CONFIG" ] || guard_fail config-missing
    CONFIG_SCHEMA=$(guard_field schema "$R8Q_GUARD_CONFIG") || guard_fail config-schema
    CONFIG_NONCE=$(guard_field trial_nonce "$R8Q_GUARD_CONFIG") || guard_fail config-nonce
    CONFIG_TAG=$(guard_field trial_tag "$R8Q_GUARD_CONFIG") || guard_fail config-tag
    [ "$CONFIG_SCHEMA" = r8q-diagnostic-fallback-config/v1 ] || guard_fail config-schema
    guard_nonce "$CONFIG_NONCE" || guard_fail config-nonce
    guard_tag "$CONFIG_TAG" || guard_fail config-tag
    CONFIG_LINES=$(grep -c '^' "$R8Q_GUARD_CONFIG") || guard_fail config-read
    [ "$CONFIG_LINES" -eq 3 ] || guard_fail config-unknown-fields
    if [ -n "$ARG_NONCE" ]; then
        [ "$ARG_NONCE" = "$CONFIG_NONCE" ] || guard_fail argument-nonce
        [ "$ARG_TAG" = "$CONFIG_TAG" ] || guard_fail argument-tag
        [ "$ARG_EXPECTED_EFI_SHA256" = "$ACCEPTED_EFI_SHA256" ] || guard_fail argument-efi
        [ "$ARG_EXPECTED_DTB_SHA256" = "$DTB_SHA256" ] || guard_fail argument-dtb
    fi
}

guard_derive_paths() {
    BACKUP_REL="EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-SAVED-$CONFIG_NONCE"
    TEMP_REL="EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-RECOVERY-$CONFIG_NONCE"
    CANDIDATE_COPY_REL="EFI/BOOT/BOOTAA64.EFI.R8Q-DIAG1-CANDIDATE-$CONFIG_NONCE"
    MARKER_REL="EFI/BOOT/R8Q-DIAG1-GUARD-$CONFIG_NONCE.marker"
    MARKER_TEMP_REL="EFI/BOOT/R8Q-DIAG1-GUARD-$CONFIG_NONCE.marker.tmp"
    EFI_PATH="$R8Q_GUARD_CACHE_MOUNT/$EFI_REL"
    DTB_PATH="$R8Q_GUARD_CACHE_MOUNT/$DTB_REL"
    BACKUP_PATH="$R8Q_GUARD_CACHE_MOUNT/$BACKUP_REL"
    TEMP_PATH="$R8Q_GUARD_CACHE_MOUNT/$TEMP_REL"
    CANDIDATE_COPY_PATH="$R8Q_GUARD_CACHE_MOUNT/$CANDIDATE_COPY_REL"
    MARKER_PATH="$R8Q_GUARD_CACHE_MOUNT/$MARKER_REL"
    MARKER_TEMP_PATH="$R8Q_GUARD_CACHE_MOUNT/$MARKER_TEMP_REL"
}

guard_parse_marker() {
    [ -f "$MARKER_PATH" ] && [ ! -L "$MARKER_PATH" ] || guard_fail marker-missing
    MARKER_SCHEMA=$(guard_field schema "$MARKER_PATH") || guard_fail marker-schema
    MARKER_STATE=$(guard_field state "$MARKER_PATH") || guard_fail marker-state
    MARKER_NONCE=$(guard_field nonce "$MARKER_PATH") || guard_fail marker-nonce
    MARKER_TAG=$(guard_field tag "$MARKER_PATH") || guard_fail marker-tag
    MARKER_CANDIDATE_SHA256=$(guard_field candidate_sha256 "$MARKER_PATH") || guard_fail marker-candidate-hash
    MARKER_CANDIDATE_BYTES=$(guard_field candidate_bytes "$MARKER_PATH") || guard_fail marker-candidate-size
    MARKER_ACCEPTED_SHA256=$(guard_field accepted_sha256 "$MARKER_PATH") || guard_fail marker-accepted-hash
    MARKER_ACCEPTED_BYTES=$(guard_field accepted_bytes "$MARKER_PATH") || guard_fail marker-accepted-size
    MARKER_CACHE_PARTUUID=$(guard_field cache_partuuid "$MARKER_PATH") || guard_fail marker-cache-partuuid
    MARKER_CACHE_PARTNAME=$(guard_field cache_partname "$MARKER_PATH") || guard_fail marker-cache-partname
    MARKER_CACHE_BYTES=$(guard_field cache_bytes "$MARKER_PATH") || guard_fail marker-cache-bytes
    MARKER_CACHE_LOGICAL_BLOCK_SIZE=$(guard_field cache_logical_block_size "$MARKER_PATH") || guard_fail marker-cache-logical-block-size
    MARKER_CACHE_FSTYPE=$(guard_field cache_fstype "$MARKER_PATH") || guard_fail marker-cache-fstype
    MARKER_EFI_REL=$(guard_field efi_rel "$MARKER_PATH") || guard_fail marker-efi-rel
    MARKER_DTB_REL=$(guard_field dtb_rel "$MARKER_PATH") || guard_fail marker-dtb-rel
    MARKER_BACKUP_REL=$(guard_field backup_rel "$MARKER_PATH") || guard_fail marker-backup-rel
    MARKER_TEMP_REL=$(guard_field temp_rel "$MARKER_PATH") || guard_fail marker-temp-rel
    MARKER_CANDIDATE_COPY_REL=$(guard_field candidate_copy_rel "$MARKER_PATH") || guard_fail marker-candidate-copy-rel
    MARKER_MARKER_REL=$(guard_field marker_rel "$MARKER_PATH") || guard_fail marker-marker-rel
    [ "$(grep -c '^' "$MARKER_PATH")" -eq 19 ] || guard_fail marker-unknown-fields
    [ "$MARKER_SCHEMA" = r8q-diagnostic-fallback-marker/v1 ] || guard_fail marker-schema
    case "$MARKER_STATE" in armed|consumed) ;; *) guard_fail marker-state ;; esac
    [ "$MARKER_NONCE" = "$CONFIG_NONCE" ] || guard_fail marker-nonce
    [ "$MARKER_TAG" = "$CONFIG_TAG" ] || guard_fail marker-tag
    guard_hash "$MARKER_CANDIDATE_SHA256" || guard_fail marker-candidate-hash
    guard_decimal "$MARKER_CANDIDATE_BYTES" || guard_fail marker-candidate-size
    [ "$MARKER_ACCEPTED_SHA256" = "$ACCEPTED_EFI_SHA256" ] || guard_fail marker-accepted-hash
    [ "$MARKER_ACCEPTED_BYTES" = "$ACCEPTED_EFI_BYTES" ] || guard_fail marker-accepted-size
    [ "$MARKER_CACHE_PARTUUID" = "$CACHE_PARTUUID" ] || guard_fail marker-cache-partuuid
    [ "$MARKER_CACHE_PARTNAME" = "$CACHE_PARTNAME" ] || guard_fail marker-cache-partname
    [ "$MARKER_CACHE_BYTES" = "$CACHE_BYTES" ] || guard_fail marker-cache-bytes
    [ "$MARKER_CACHE_LOGICAL_BLOCK_SIZE" = "$CACHE_LOGICAL_BLOCK_SIZE" ] || guard_fail marker-cache-logical-block-size
    [ "$MARKER_CACHE_FSTYPE" = "$CACHE_FSTYPE" ] || guard_fail marker-cache-fstype
    [ "$MARKER_EFI_REL" = "$EFI_REL" ] || guard_fail marker-efi-rel
    [ "$MARKER_DTB_REL" = "$DTB_REL" ] || guard_fail marker-dtb-rel
    [ "$MARKER_BACKUP_REL" = "$BACKUP_REL" ] || guard_fail marker-backup-rel
    [ "$MARKER_TEMP_REL" = "$TEMP_REL" ] || guard_fail marker-temp-rel
    [ "$MARKER_CANDIDATE_COPY_REL" = "$CANDIDATE_COPY_REL" ] || guard_fail marker-candidate-copy-rel
    [ "$MARKER_MARKER_REL" = "$MARKER_REL" ] || guard_fail marker-marker-rel
    [ ! -e "$MARKER_TEMP_PATH" ] && [ ! -L "$MARKER_TEMP_PATH" ] || guard_fail marker-temp-present
}

guard_uevent_field() {
    GUARD_UEVENT_KEY=$1
    GUARD_UEVENT_FILE=$2
    GUARD_UEVENT_VALUE=
    GUARD_UEVENT_COUNT=0
    while IFS='=' read -r GUARD_UEVENT_NAME GUARD_UEVENT_CURRENT || [ -n "${GUARD_UEVENT_NAME:-}" ]; do
        if [ "${GUARD_UEVENT_NAME:-}" = "$GUARD_UEVENT_KEY" ]; then
            GUARD_UEVENT_COUNT=$((GUARD_UEVENT_COUNT + 1))
            GUARD_UEVENT_VALUE=${GUARD_UEVENT_CURRENT:-}
        fi
    done < "$GUARD_UEVENT_FILE"
    [ "$GUARD_UEVENT_COUNT" -eq 1 ] || return 1
    printf '%s' "$GUARD_UEVENT_VALUE"
}

guard_node_stat() {
    GUARD_NODE_MAJOR=$1
    GUARD_NODE_MINOR=$2
    GUARD_NODE_PATH=$3
    guard_decimal "$GUARD_NODE_MAJOR" || return 1
    guard_decimal "$GUARD_NODE_MINOR" || return 1
    GUARD_EXPECTED_NODE_ID=$(printf '%x:%x' "$GUARD_NODE_MAJOR" "$GUARD_NODE_MINOR")
    GUARD_ACTUAL_NODE_ID=$(stat -c '%t:%T' "$GUARD_NODE_PATH" 2>/dev/null) || return 1
    [ "$GUARD_ACTUAL_NODE_ID" = "$GUARD_EXPECTED_NODE_ID" ]
}

guard_mountinfo_alias_check() {
    [ -r "$R8Q_GUARD_PROC_MOUNTINFO" ] || guard_fail cache-mountinfo
    while IFS= read -r GUARD_MOUNTINFO_LINE || [ -n "${GUARD_MOUNTINFO_LINE:-}" ]; do
        [ -n "${GUARD_MOUNTINFO_LINE:-}" ] || continue
        case "$GUARD_MOUNTINFO_LINE" in
            *' - '*) GUARD_MOUNTINFO_PREFIX=${GUARD_MOUNTINFO_LINE%% - *} ;;
            *) guard_fail cache-mountinfo-format ;;
        esac
        set -- $GUARD_MOUNTINFO_PREFIX
        [ "$#" -ge 6 ] || guard_fail cache-mountinfo-format
        [ "$3" = "$GUARD_MAJOR:$GUARD_MINOR" ] || continue
        guard_fail cache-mount-alias
    done < "$R8Q_GUARD_PROC_MOUNTINFO"
}

guard_node_exists() {
    if [ "$R8Q_GUARD_TEST_MODE" = 1 ]; then
        [ -e "$1" ]
    else
        [ -b "$1" ]
    fi
}

guard_resolve_cache_once() {
    GUARD_MATCHES=0
    CACHE_DEVICE=
    for GUARD_UEVENT_FILE in "$R8Q_GUARD_SYSFS_ROOT"/*/uevent; do
        [ -f "$GUARD_UEVENT_FILE" ] || continue
        GUARD_PARTNAME=$(guard_uevent_field PARTNAME "$GUARD_UEVENT_FILE") || continue
        [ "$GUARD_PARTNAME" = "$CACHE_PARTNAME" ] || continue
        GUARD_MATCHES=$((GUARD_MATCHES + 1))
        GUARD_PARTUUID=$(guard_uevent_field PARTUUID "$GUARD_UEVENT_FILE") || guard_fail cache-partuuid-field
        GUARD_DEVNAME=$(guard_uevent_field DEVNAME "$GUARD_UEVENT_FILE") || guard_fail cache-devname-field
        GUARD_MAJOR=$(guard_uevent_field MAJOR "$GUARD_UEVENT_FILE") || guard_fail cache-major-field
        GUARD_MINOR=$(guard_uevent_field MINOR "$GUARD_UEVENT_FILE") || guard_fail cache-minor-field
        [ "$GUARD_PARTUUID" = "$CACHE_PARTUUID" ] || guard_fail cache-partuuid
        case "$GUARD_DEVNAME" in ''|*/*|.*) guard_fail cache-devname ;; esac
        GUARD_DEVICE_DIR=${GUARD_UEVENT_FILE%/uevent}
        GUARD_SYSFS_MOUNT=$(readlink -f "$R8Q_GUARD_SYSFS_ROOT/../.." 2>/dev/null) || guard_fail cache-sysfs-root
        GUARD_REAL_DEVICE_DIR=$(readlink -f "$GUARD_DEVICE_DIR" 2>/dev/null) || guard_fail cache-sysfs-target
        case "$GUARD_REAL_DEVICE_DIR" in
            "$GUARD_SYSFS_MOUNT"/*) ;;
            *) guard_fail cache-sysfs-target ;;
        esac
        [ "${GUARD_REAL_DEVICE_DIR##*/}" = "$GUARD_DEVNAME" ] || guard_fail cache-sysfs-devname
        GUARD_HOLDERS_DIR="$GUARD_REAL_DEVICE_DIR/holders"
        [ -d "$GUARD_HOLDERS_DIR" ] && [ ! -L "$GUARD_HOLDERS_DIR" ] || guard_fail cache-holders-missing
        for GUARD_HOLDER_ENTRY in "$GUARD_HOLDERS_DIR"/* "$GUARD_HOLDERS_DIR"/.[!.]* "$GUARD_HOLDERS_DIR"/..?*; do
            [ -e "$GUARD_HOLDER_ENTRY" ] || [ -L "$GUARD_HOLDER_ENTRY" ] || continue
            guard_fail cache-holders
        done
        GUARD_SIZE=$(cat "$GUARD_REAL_DEVICE_DIR/size" 2>/dev/null) || guard_fail cache-size-field
        GUARD_LOGICAL_BLOCK_SIZE=$(cat "$(dirname "$GUARD_REAL_DEVICE_DIR")/queue/logical_block_size" 2>/dev/null) || guard_fail cache-logical-block-size-field
        [ "$GUARD_SIZE" = "$CACHE_SECTORS" ] || guard_fail cache-size
        [ "$GUARD_LOGICAL_BLOCK_SIZE" = "$CACHE_LOGICAL_BLOCK_SIZE" ] || guard_fail cache-logical-block-size
        CACHE_DEVICE="$R8Q_GUARD_DEV_ROOT/$GUARD_DEVNAME"
        if ! [ -e "$CACHE_DEVICE" ]; then
            mknod -m 0600 "$CACHE_DEVICE" b "$GUARD_MAJOR" "$GUARD_MINOR" >/dev/null 2>&1 || guard_fail cache-mknod
            CREATED_NODE=1
        fi
        guard_node_exists "$CACHE_DEVICE" || guard_fail cache-node-missing
        guard_node_stat "$GUARD_MAJOR" "$GUARD_MINOR" "$CACHE_DEVICE" || guard_fail cache-node-identity
    done
    [ "$GUARD_MATCHES" -eq 1 ] || return 1
}

guard_resolve_cache() {
    GUARD_WAIT=0
    while [ "$GUARD_WAIT" -lt 30 ]; do
        if guard_resolve_cache_once; then
            return 0
        fi
        GUARD_WAIT=$((GUARD_WAIT + 1))
        [ "$GUARD_WAIT" -lt 30 ] && sleep 1
    done
    guard_fail cache-not-unique
}

guard_child_finished() {
    GUARD_CHILD_PID=$1
    [ -d "$R8Q_GUARD_PROC_ROOT" ] || return 1
    if [ ! -e "$R8Q_GUARD_PROC_ROOT/$GUARD_CHILD_PID" ]; then
        return 0
    fi
    grep -q '^State:[[:space:]]*Z' "$R8Q_GUARD_PROC_ROOT/$GUARD_CHILD_PID/status" 2>/dev/null
}

guard_reap_child() {
    GUARD_CHILD_PID=$1
    guard_child_finished "$GUARD_CHILD_PID" || return 1
    wait "$GUARD_CHILD_PID" >/dev/null 2>&1
    GUARD_CHILD_STATUS=$?
    return 0
}

guard_wait_child_bounded() {
    GUARD_CHILD_PID=$1
    GUARD_CHILD_WAIT_LIMIT=$2
    GUARD_CHILD_WAIT=0
    while :; do
        if guard_reap_child "$GUARD_CHILD_PID"; then
            return 0
        fi
        if ! kill -0 "$GUARD_CHILD_PID" >/dev/null 2>&1; then
            guard_log "could not confirm $GUARD_CHILD_PID exited; refusing unbounded wait"
            return 1
        fi
        [ "$GUARD_CHILD_WAIT" -lt "$GUARD_CHILD_WAIT_LIMIT" ] || return 1
        GUARD_CHILD_WAIT=$((GUARD_CHILD_WAIT + 1))
        sleep 1
    done
}

guard_stop_child_bounded() {
    GUARD_CHILD_PID=$1
    GUARD_CHILD_COMMAND=${2:-command}
    kill -TERM "$GUARD_CHILD_PID" >/dev/null 2>&1 || :
    if guard_wait_child_bounded "$GUARD_CHILD_PID" "$GUARD_CHILD_GRACE"; then
        return "$GUARD_CHILD_STATUS"
    fi
    kill -KILL "$GUARD_CHILD_PID" >/dev/null 2>&1 || :
    if guard_wait_child_bounded "$GUARD_CHILD_PID" "$GUARD_CHILD_GRACE"; then
        return "$GUARD_CHILD_STATUS"
    fi
    guard_log "$GUARD_CHILD_COMMAND helper remained live after TERM and KILL; possible D-state storage hang is unrecoverable"
    return 1
}

guard_run_command_bounded() {
    GUARD_COMMAND=$1
    shift
    "$GUARD_COMMAND" "$@" >/dev/null 2>&1 &
    GUARD_COMMAND_PID=$!
    GUARD_WAIT=0
    while :; do
        if guard_reap_child "$GUARD_COMMAND_PID"; then
            return "$GUARD_CHILD_STATUS"
        fi
        if ! kill -0 "$GUARD_COMMAND_PID" >/dev/null 2>&1; then
            guard_log "could not confirm $GUARD_COMMAND exited; refusing unbounded wait"
            return 1
        fi
        [ "$GUARD_WAIT" -lt "$GUARD_CHILD_DEADLINE" ] || {
            guard_log "$GUARD_COMMAND exceeded bounded deadline; stopping helper"
            guard_stop_child_bounded "$GUARD_COMMAND_PID" "$GUARD_COMMAND" || :
            return 1
        }
        GUARD_WAIT=$((GUARD_WAIT + 1))
        sleep 1
    done
}

guard_mount_command() {
    if [ "$R8Q_GUARD_TEST_MODE" = 1 ] && [ "${R8Q_GUARD_TEST_ASYNC_MOUNT:-0}" != 1 ]; then
        mount "$@" >/dev/null 2>&1
        return $?
    fi
    guard_run_command_bounded mount "$@"
}

guard_umount_command() {
    if [ "$R8Q_GUARD_TEST_MODE" = 1 ] && [ "${R8Q_GUARD_TEST_ASYNC_MOUNT:-0}" != 1 ]; then
        umount "$1" >/dev/null 2>&1
        return $?
    fi
    guard_run_command_bounded umount "$1"
}

guard_mount_line() {
    GUARD_MOUNT_MODE=$1
    GUARD_MOUNT_LINE=$(grep -F "$CACHE_DEVICE $R8Q_GUARD_CACHE_MOUNT $CACHE_FSTYPE " "$R8Q_GUARD_PROC_MOUNTS" 2>/dev/null) || guard_fail cache-mount-identity
    case "$GUARD_MOUNT_MODE:$GUARD_MOUNT_LINE" in
        ro:*' ro,'*|ro:*' ro '*) ;;
        rw:*' rw,'*|rw:*' rw '*) ;;
        *) guard_fail cache-mount-mode ;;
    esac
}

guard_mount_ro() {
    mkdir -p "$R8Q_GUARD_CACHE_MOUNT" || guard_fail cache-mountpoint
    guard_mountinfo_alias_check
    guard_mount_command -t "$CACHE_FSTYPE" -o ro,nosuid,nodev,noexec,uid=0,gid=0,umask=0077 "$CACHE_DEVICE" "$R8Q_GUARD_CACHE_MOUNT" || guard_fail cache-mount
    MOUNTED=1
    guard_mount_line ro
}

guard_remount_rw() {
    guard_mount_command -o remount,rw,nosuid,nodev,noexec,uid=0,gid=0,umask=0077 "$R8Q_GUARD_CACHE_MOUNT" || guard_fail cache-remount
    guard_mount_line rw
}

guard_digest() {
    GUARD_DIGEST_LINE=$(sha256sum "$1" 2>/dev/null) || return 1
    GUARD_DIGEST_VALUE=${GUARD_DIGEST_LINE%% *}
    guard_hash "$GUARD_DIGEST_VALUE" || return 1
    printf '%s' "$GUARD_DIGEST_VALUE"
}

guard_file_identity() {
    GUARD_FILE_PATH=$1
    GUARD_FILE_SHA256=$2
    GUARD_FILE_BYTES=$3
    [ -f "$GUARD_FILE_PATH" ] && [ ! -L "$GUARD_FILE_PATH" ] || guard_fail "file-missing:$GUARD_FILE_PATH"
    GUARD_ACTUAL_BYTES=$(stat -c '%s' "$GUARD_FILE_PATH" 2>/dev/null) || guard_fail "file-size:$GUARD_FILE_PATH"
    [ "$GUARD_ACTUAL_BYTES" = "$GUARD_FILE_BYTES" ] || guard_fail "file-bytes:$GUARD_FILE_PATH"
    GUARD_ACTUAL_SHA256=$(guard_digest "$GUARD_FILE_PATH") || guard_fail "file-hash:$GUARD_FILE_PATH"
    [ "$GUARD_ACTUAL_SHA256" = "$GUARD_FILE_SHA256" ] || guard_fail "file-sha256:$GUARD_FILE_PATH"
}

guard_write_marker() {
    GUARD_MARKER_STATE=$1
    [ "$MOUNTED" -eq 1 ] || guard_fail marker-unmounted
    [ ! -e "$MARKER_TEMP_PATH" ] && [ ! -L "$MARKER_TEMP_PATH" ] || guard_fail marker-temp-present
    {
        printf 'schema=r8q-diagnostic-fallback-marker/v1\n'
        printf 'state=%s\n' "$GUARD_MARKER_STATE"
        printf 'nonce=%s\n' "$CONFIG_NONCE"
        printf 'tag=%s\n' "$CONFIG_TAG"
        printf 'candidate_sha256=%s\n' "$MARKER_CANDIDATE_SHA256"
        printf 'candidate_bytes=%s\n' "$MARKER_CANDIDATE_BYTES"
        printf 'accepted_sha256=%s\n' "$ACCEPTED_EFI_SHA256"
        printf 'accepted_bytes=%s\n' "$ACCEPTED_EFI_BYTES"
        printf 'cache_partuuid=%s\n' "$CACHE_PARTUUID"
        printf 'cache_partname=%s\n' "$CACHE_PARTNAME"
        printf 'cache_bytes=%s\n' "$CACHE_BYTES"
        printf 'cache_logical_block_size=%s\n' "$CACHE_LOGICAL_BLOCK_SIZE"
        printf 'cache_fstype=%s\n' "$CACHE_FSTYPE"
        printf 'efi_rel=%s\n' "$EFI_REL"
        printf 'dtb_rel=%s\n' "$DTB_REL"
        printf 'backup_rel=%s\n' "$BACKUP_REL"
        printf 'temp_rel=%s\n' "$TEMP_REL"
        printf 'candidate_copy_rel=%s\n' "$CANDIDATE_COPY_REL"
        printf 'marker_rel=%s\n' "$MARKER_REL"
    } > "$MARKER_TEMP_PATH" || guard_fail marker-write
    sync >/dev/null 2>&1 || guard_fail marker-sync
    mv "$MARKER_TEMP_PATH" "$MARKER_PATH" >/dev/null 2>&1 || guard_fail marker-rename
    sync >/dev/null 2>&1 || guard_fail marker-sync
    [ "$(grep -c '^' "$MARKER_PATH")" -eq 19 ] || guard_fail marker-readback
    guard_parse_marker
}

guard_copy_candidate() {
    [ ! -e "$CANDIDATE_COPY_PATH" ] && [ ! -L "$CANDIDATE_COPY_PATH" ] || return 0
    cp "$EFI_PATH" "$CANDIDATE_COPY_PATH" >/dev/null 2>&1 || guard_fail candidate-copy
    sync >/dev/null 2>&1 || guard_fail candidate-copy-sync
    guard_file_identity "$CANDIDATE_COPY_PATH" "$MARKER_CANDIDATE_SHA256" "$MARKER_CANDIDATE_BYTES"
}

guard_restore_accepted() {
    [ ! -e "$TEMP_PATH" ] && [ ! -L "$TEMP_PATH" ] || guard_fail temp-present
    cp "$BACKUP_PATH" "$TEMP_PATH" >/dev/null 2>&1 || guard_fail accepted-copy
    sync >/dev/null 2>&1 || guard_fail accepted-copy-sync
    guard_file_identity "$TEMP_PATH" "$ACCEPTED_EFI_SHA256" "$ACCEPTED_EFI_BYTES"
    mv "$TEMP_PATH" "$EFI_PATH" >/dev/null 2>&1 || guard_fail accepted-rename
    sync >/dev/null 2>&1 || guard_fail accepted-rename-sync
    guard_file_identity "$EFI_PATH" "$ACCEPTED_EFI_SHA256" "$ACCEPTED_EFI_BYTES"
}

guard_receipt_text() {
    GUARD_RECEIPT_MOUNT_STATE=$1
    GUARD_RECEIPT_ACTION=$2
    printf 'schema=r8q-diagnostic-fallback-receipt/v1\n'
    printf 'state=consumed\n'
    printf 'action=%s\n' "$GUARD_RECEIPT_ACTION"
    printf 'nonce=%s\n' "$CONFIG_NONCE"
    printf 'tag=%s\n' "$CONFIG_TAG"
    printf 'cache_partuuid=%s\n' "$CACHE_PARTUUID"
    printf 'cache_device=%s\n' "$CACHE_DEVICE"
    printf 'accepted_sha256=%s\n' "$ACCEPTED_EFI_SHA256"
    printf 'accepted_bytes=%s\n' "$ACCEPTED_EFI_BYTES"
    printf 'candidate_sha256=%s\n' "$MARKER_CANDIDATE_SHA256"
    printf 'candidate_bytes=%s\n' "$MARKER_CANDIDATE_BYTES"
    printf 'dtb_sha256=%s\n' "$DTB_SHA256"
    printf 'dtb_bytes=%s\n' "$DTB_BYTES"
    printf 'cache_mount=%s\n' "$GUARD_RECEIPT_MOUNT_STATE"
}

guard_write_receipt() {
    GUARD_RECEIPT_ACTION=$1
    GUARD_RECEIPT_TEMP="$R8Q_GUARD_RECEIPT.tmp"
    [ ! -e "$GUARD_RECEIPT_TEMP" ] && [ ! -L "$GUARD_RECEIPT_TEMP" ] || guard_fail receipt-temp-present
    guard_receipt_text mounted "$GUARD_RECEIPT_ACTION" > "$GUARD_RECEIPT_TEMP" || guard_fail receipt-write
    sync >/dev/null 2>&1 || guard_fail receipt-sync
    mv "$GUARD_RECEIPT_TEMP" "$R8Q_GUARD_RECEIPT" >/dev/null 2>&1 || guard_fail receipt-rename
    [ "$(guard_receipt_text mounted "$GUARD_RECEIPT_ACTION")" = "$(cat "$R8Q_GUARD_RECEIPT")" ] || guard_fail receipt-readback
}

guard_write_unmounted_receipt() {
    GUARD_RECEIPT_ACTION=$1
    guard_receipt_text unmounted "$GUARD_RECEIPT_ACTION" > "$R8Q_GUARD_RECEIPT" || guard_fail receipt-unmounted-write
    [ "$(guard_receipt_text unmounted "$GUARD_RECEIPT_ACTION")" = "$(cat "$R8Q_GUARD_RECEIPT")" ] || guard_fail receipt-unmounted-readback
}

r8q_diagnostic_fallback_run() {
    guard_parse_arguments "$@"
    guard_capabilities
    guard_parse_config
    guard_derive_paths
    guard_resolve_cache
    guard_mount_ro
    guard_parse_marker
    guard_file_identity "$DTB_PATH" "$DTB_SHA256" "$DTB_BYTES"
    guard_file_identity "$BACKUP_PATH" "$ACCEPTED_EFI_SHA256" "$ACCEPTED_EFI_BYTES"
    case "$MARKER_STATE" in
        armed|consumed) ;;
        *) guard_fail marker-state ;;
    esac
    ACTIVE_BYTES=$(stat -c '%s' "$EFI_PATH" 2>/dev/null) || guard_fail active-size
    ACTIVE_SHA256=$(guard_digest "$EFI_PATH") || guard_fail active-hash
    if [ "$MARKER_STATE" = consumed ]; then
        [ "$ACTIVE_SHA256" = "$ACCEPTED_EFI_SHA256" ] || guard_fail consumed-active
        [ "$ACTIVE_BYTES" = "$ACCEPTED_EFI_BYTES" ] || guard_fail consumed-active-size
        guard_file_identity "$CANDIDATE_COPY_PATH" "$MARKER_CANDIDATE_SHA256" "$MARKER_CANDIDATE_BYTES"
        guard_write_receipt idempotent
        if ! guard_umount_command "$R8Q_GUARD_CACHE_MOUNT"; then
            MOUNTED=0
            guard_fail cache-unmount
        fi
        MOUNTED=0
        guard_write_unmounted_receipt idempotent
        return 0
    fi
    if [ "$ACTIVE_SHA256" = "$MARKER_CANDIDATE_SHA256" ] && [ "$ACTIVE_BYTES" = "$MARKER_CANDIDATE_BYTES" ]; then
        if [ -e "$CANDIDATE_COPY_PATH" ] || [ -L "$CANDIDATE_COPY_PATH" ]; then
            guard_file_identity "$CANDIDATE_COPY_PATH" "$MARKER_CANDIDATE_SHA256" "$MARKER_CANDIDATE_BYTES"
        fi
        guard_remount_rw
        guard_copy_candidate
        guard_restore_accepted
        guard_write_marker consumed
        guard_write_receipt restored
    elif [ "$ACTIVE_SHA256" = "$ACCEPTED_EFI_SHA256" ] && [ "$ACTIVE_BYTES" = "$ACCEPTED_EFI_BYTES" ]; then
        guard_file_identity "$CANDIDATE_COPY_PATH" "$MARKER_CANDIDATE_SHA256" "$MARKER_CANDIDATE_BYTES"
        guard_remount_rw
        guard_write_marker consumed
        guard_write_receipt restored-after-retry
    else
        guard_fail active-identity
    fi
    if ! guard_umount_command "$R8Q_GUARD_CACHE_MOUNT"; then
        MOUNTED=0
        guard_fail cache-unmount
    fi
    MOUNTED=0
    guard_write_unmounted_receipt "$GUARD_RECEIPT_ACTION"
    return 0
}

r8q_diagnostic_fallback_run "$@"
