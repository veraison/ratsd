#!/bin/bash

# Test script for CMW examples
# This script validates that the example CMW files are properly formatted

echo "Testing CMW Example Files..."
echo "================================"

EXAMPLES_DIR="$(dirname "$0")"
FAILED_TESTS=0

# Function to test JSON validity
test_json_validity() {
    local file="$1"
    echo -n "Testing $file... "
    
    if jq empty "$file" 2>/dev/null; then
        echo "✓ Valid JSON"
    else
        echo "✗ Invalid JSON"
        ((FAILED_TESTS++))
    fi
}

# Function to test CMW structure
test_cmw_structure() {
    local file="$1"
    echo -n "Testing CMW structure in $file... "
    
    # Check for required __cmwc_t field
    if jq -e '.__cmwc_t == "tag:github.com,2025:veraison/ratsd/cmw"' "$file" >/dev/null 2>&1; then
        echo "✓ Valid CMW structure"
    else
        echo "✗ Invalid CMW structure"
        ((FAILED_TESTS++))
    fi
}

# Function to test base64 fields
test_base64_fields() {
    local file="$1"
    echo -n "Testing base64 fields in $file... "
    
    # Extract all auxblob and outblob values and test if they're valid base64
    local base64_valid=true
    
    while IFS= read -r blob; do
        if [[ -n "$blob" ]]; then
            if ! echo "$blob" | base64 -d >/dev/null 2>&1; then
                base64_valid=false
                break
            fi
        fi
    done < <(jq -r '.. | select(type == "object") | select(has("auxblob")) | .auxblob, .outblob' "$file" 2>/dev/null)
    
    if $base64_valid; then
        echo "✓ Valid base64 encoding"
    else
        echo "✗ Invalid base64 encoding"
        ((FAILED_TESTS++))
    fi
}

# Test all JSON files in the directory
for file in "$EXAMPLES_DIR"/*.json; do
    if [[ -f "$file" ]]; then
        echo
        echo "Testing $(basename "$file"):"
        test_json_validity "$file"
        test_cmw_structure "$file"
        test_base64_fields "$file"
    fi
done

echo
echo "================================"
if [[ $FAILED_TESTS -eq 0 ]]; then
    echo "All tests passed! ✓"
    exit 0
else
    echo "$FAILED_TESTS test(s) failed! ✗"
    exit 1
fi
