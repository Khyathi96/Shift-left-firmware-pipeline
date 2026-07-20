#!/bin/bash
#extract_firmware.sh - Production CI/CD Extraction Handler 
set -euo pipefail # Fail fast if any command errors out or uses unsassigned variables

TARGET_IMAGE="${1:-}"
OUTPUT_DIR="./extracted_pipeline_rootfs"

echo "===== [Phase 1: Validation] ====="
# 1. Check if an input file argument was provided
if [ -z "$TARGET_IMAGE" ]; then
    echo "[-] ERROR: Missing target firmware argument."
    echo "Usage: $0 <path_to_firmware_binary>"
    exit 1
fi

# 2. Check if the firmware image actually exists in the workspace
if [ ! -f "$TARGET_IMAGE" ]; then
    echo "[-] ERROR: Firmware file not found at path: $TARGET_IMAGE"
    exit 1
fi

echo "[+] Target verified: $TARGET_IMAGE"

echo "===== [Phase 2: Workspace Cleanup] ====="
# Clear out any previous build data to ensure clean security scanning results
if [ -d "$OUTPUT_DIR" ]; then
    echo "[*] Removing stale target directory from previous run..."
    rm -rf "$OUTPUT_DIR"
fi

echo "===== [Phase 3: Automated Extraction] ====="
# Execute extraction. If it fails, script exits immediately due to 'set -e'
echo "[*] Extracting squashfs filesystem layers..."
unsquashfs -d "$OUTPUT_DIR" "$TARGET_IMAGE"

echo "===== [Phase 4: Post-Extraction Sanity Check] ====="
# Verify vital configurations exist before passing to security scanners
if [ -f "$OUTPUT_DIR/etc/config/aws_service.conf" ] && [ -f "$OUTPUT_DIR/usr/lib/opkg/status" ]; then
    echo "[+] SUCCESS: Firmware filesystem structure is intact and vulnerabilities are present."
    echo "[+] Ready for static binary scanning."
else
    echo "[-] WARNING: Extraction completed but key target vectors are missing."
fi

