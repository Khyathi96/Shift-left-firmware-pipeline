#!/bin/bash
#extract_firmware.sh - CI/CD Unpacking script
set -e

TARGET_IMAGE=$1
OUTPUT_DIR="./extracted_pipeline_rootfs"

if [ -z "$TARGET_IMAGE" ]; then
    echo "Error: Please specify the path to the target firmware file."
    exit 1
fi

echo "Starting automated firmware extraction for: $TARGET_IMAGE"

#Run standard unsquashfs directly for lightning-fast unpacking inside the runner
unsquashfs -d "$OUTPUT_DIR" "$TARGET_IMAGE"

echo "Extraction completed successfully. Output directory is ready for scanning."
