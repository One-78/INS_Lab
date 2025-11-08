#!/bin/bash

echo "=================================="
echo "Lab 3: Symmetric Encryption & Hashing"
echo "=================================="

# Variables
WD="lab3_output"
KEY="00112233445566778889aabbccddeeff"
IV="0102030405060708090a0b0c0d0e0f10"

# Function to check command status
check_status() {
    if [ $? -eq 0 ]; then
        echo "[SUCCESS] $1"
    else
        echo "[FAILED] $1"
        echo "Press Enter to continue or Ctrl+C to exit..."
        read
    fi
}

# Validate input argument
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <bmp_image_file>"
    exit 1
fi

INPUT_BMP="$1"
if [ ! -f "$INPUT_BMP" ]; then
    echo "[ERROR] BMP file not found: $INPUT_BMP"
    exit 1
fi

# Create output directory
echo ""
echo "Step 1: Creating output directory..."
mkdir -p "$WD"
cp "$INPUT_BMP" "$WD/original.bmp"
check_status "Working directory and BMP copy ready"

# Task 1: AES encryption on text (CBC, CFB, OFB)
echo ""
echo "Step 2: AES encryption on text file..."
echo "This is a 64-byte long text file for CSE-478 Lab 3 testing..." > "$WD/plain.txt"

for mode in cbc cfb ofb; do
    openssl enc -aes-128-$mode -e -in "$WD/plain.txt" -out "$WD/encrypted_$mode.bin" -K "$KEY" -iv "$IV" 2>/dev/null
    check_status "Encrypted with AES-128-$mode"

    openssl enc -aes-128-$mode -d -in "$WD/encrypted_$mode.bin" -out "$WD/decrypted_$mode.txt" -K "$KEY" -iv "$IV" 2>/dev/null
    check_status "Decrypted with AES-128-$mode"
done

# Task 2: ECB vs CBC on BMP image
echo ""
echo "Step 3: Encrypting BMP with ECB and CBC..."

# ECB (no padding to keep block alignment)
openssl enc -aes-128-ecb -e -in "$WD/original.bmp" -out "$WD/encrypted_ecb.bmp" -K "$KEY" -iv "$IV" -nopad 2>/dev/null
check_status "BMP encrypted with ECB"

# CBC (uses padding)
openssl enc -aes-128-cbc -e -in "$WD/original.bmp" -out "$WD/encrypted_cbc.bmp" -K "$KEY" -iv "$IV" 2>/dev/null
check_status "BMP encrypted with CBC"

# Restore BMP header (first 54 bytes)
dd if="$WD/original.bmp" of="$WD/encrypted_ecb.bmp" conv=notrunc bs=1 count=54 2>/dev/null
dd if="$WD/original.bmp" of="$WD/encrypted_cbc.bmp" conv=notrunc bs=1 count=54 2>/dev/null
check_status "BMP headers restored for viewing"

# Task 3: Corrupted ciphertext test
echo ""
echo "Step 4: Corrupted ciphertext resilience test..."
echo "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@" > "$WD/corrupt_test.txt"

for mode in ecb cbc cfb ofb; do
    openssl enc -aes-128-$mode -e -in "$WD/corrupt_test.txt" -out "$WD/encrypted_corrupt_$mode.bin" -K "$KEY" -iv "$IV" 2>/dev/null
    cp "$WD/encrypted_corrupt_$mode.bin" "$WD/corrupt30_$mode.bin"

    # Corrupt byte 30 (offset 29)
    orig_byte=$(dd if="$WD/corrupt30_$mode.bin" bs=1 skip=29 count=1 2>/dev/null | xxd -p)
    if [ -n "$orig_byte" ]; then
        new_byte=$(printf "%02x" $((0x${orig_byte} ^ 0x01)))
        printf "$new_byte" | xxd -r -p | dd of="$WD/corrupt30_$mode.bin" bs=1 seek=29 count=1 conv=notrunc 2>/dev/null
    fi

    openssl enc -aes-128-$mode -d -in "$WD/corrupt30_$mode.bin" -out "$WD/decrypted_corrupt_$mode.txt" -K "$KEY" -iv "$IV" 2>/dev/null
    check_status "Decryption test after corruption ($mode)"
done

# Task 4: Padding analysis
echo ""
echo "Step 5: Padding behavior analysis..."
echo "1234567890123456" > "$WD/padding_test.txt"  # Exactly 16 bytes

for mode in ecb cbc cfb ofb; do
    openssl enc -aes-128-$mode -e -in "$WD/padding_test.txt" -out "$WD/padding_$mode.bin" -K "$KEY" -iv "$IV" 2>/dev/null
    size=$(stat -c%s "$WD/padding_$mode.bin")
    echo "Mode: $mode, Size: $size bytes" >> "$WD/padding_report.txt"
done
check_status "Padding report generated"

# Task 5: Message digests
echo ""
echo "Step 6: Generating message digests..."
echo "Hashing input for CSE-478 Lab 3" > "$WD/hash_input.txt"

for algo in md5 sha1 sha256; do
    openssl dgst -$algo "$WD/hash_input.txt" 2>/dev/null | cut -d' ' -f2 > "$WD/hash_$algo.txt"
    check_status "Hash generated ($algo)"
done

# Task 6: HMAC with variable keys
echo ""
echo "Step 7: Generating HMACs..."
for algo in md5 sha1 sha256; do
    for key in "a" "secret" "mykey123"; do
        openssl dgst -$algo -hmac "$key" "$WD/hash_input.txt" 2>/dev/null | cut -d' ' -f2 >> "$WD/hmac_$algo.txt"
    done
    check_status "HMACs generated ($algo)"
done

# Task 7: Hash randomness (avalanche effect)
echo ""
echo "Step 8: Testing hash randomness..."
echo "Randomness test input" > "$WD/rand_test.txt"
openssl dgst -sha256 "$WD/rand_test.txt" 2>/dev/null | cut -d' ' -f2 > "$WD/rand_H1.txt"

# Flip one bit at byte 5 (offset 4)
cp "$WD/rand_test.txt" "$WD/rand_modified.txt"
orig=$(dd if="$WD/rand_modified.txt" bs=1 skip=4 count=1 2>/dev/null | xxd -p)
if [ -n "$orig" ]; then
    new=$(printf "%02x" $((0x$orig ^ 0x01)))
    printf "$new" | xxd -r -p | dd of="$WD/rand_modified.txt" bs=1 seek=4 count=1 conv=notrunc 2>/dev/null
fi
openssl dgst -sha256 "$WD/rand_modified.txt" 2>/dev/null | cut -d' ' -f2 > "$WD/rand_H2.txt"
check_status "Hash randomness test completed"

# Final summary
echo ""
echo "=================================="
echo "Lab 3 Tasks Completed!"
echo "=================================="
echo ""
echo "Output directory: $WD/"
echo "Key files:"
ls -lh "$WD/original.bmp" "$WD/encrypted_ecb.bmp" "$WD/encrypted_cbc.bmp" 2>/dev/null
echo ""
echo "To view encrypted images:"
echo "  - Open $WD/encrypted_ecb.bmp and $WD/encrypted_cbc.bmp in an image viewer"
echo "  - Note: ECB reveals patterns, CBC does not"
echo ""
echo "All encrypted, hashed, and test files are in: $WD/"
echo ""
echo "Script finished!"
