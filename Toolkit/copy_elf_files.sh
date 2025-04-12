#!/bin/bash

# Check if <source> and <destination> directories are provided as arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <source_directory> <destination_directory>"
    exit 1
fi

SOURCE_DIR="$1"
DEST_DIR="$2"

# Check if source directory exists
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Error: Source directory '$SOURCE_DIR' does not exist"
    exit 1
fi

# Check if destination directory exists, create it if it doesn't
if [ ! -d "$DEST_DIR" ]; then
    mkdir -p "$DEST_DIR" || {
        echo "Error: Could not create destination directory '$DEST_DIR'"
        exit 1
    }
fi

# Counter for copied files
COPIED_COUNT=0
SKIPPED_COUNT=0

for FILE in "$SOURCE_DIR"/*; do
    # Check if it's a regular file
    if [ -f "$FILE" ]; then
        # Check if file is an ELF binary
        if file "$FILE" | grep -q "ELF"; then
            # Copy the ELF binary
            cp "$FILE" "$DEST_DIR/" && {
                echo "Copied ELF binary: $(basename "$FILE")"
                ((COPIED_COUNT++))
            } || {
                echo "Error: Failed to copy '$(basename "$FILE")'"
            }
        else
            echo "Skipped non-ELF file: $(basename "$FILE")"
            ((SKIPPED_COUNT++))
        fi
    fi
done

echo "--------------------"
echo "Summary:"
echo "ELF binaries copied: $COPIED_COUNT"
echo "Files skipped: $SKIPPED_COUNT"

exit 0

#bash copy_elf_files.sh /usr/bin/ ./benign_elf_opensuse/
