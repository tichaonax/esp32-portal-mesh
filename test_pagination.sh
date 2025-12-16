#!/bin/bash
# Test script for ESP32 Portal Token API pagination
# Usage: ./test_pagination.sh <base_url> <api_key>

if [ $# -ne 2 ]; then
    echo "Usage: $0 <base_url> <api_key>"
    echo "Example: $0 http://192.168.0.100 abcd1234efgh5678ijkl9012mnop3456"
    exit 1
fi

BASE_URL=$1
API_KEY=$2

echo "Testing ESP32 Portal Token API pagination..."
echo "Base URL: $BASE_URL"
echo "API Key: ${API_KEY:0:8}..."
echo

# Test single page
echo "Testing single page (first 5 unused tokens)..."
curl -s "$BASE_URL/api/tokens/list?api_key=$API_KEY&status=unused&limit=5" | python3 -m json.tool
echo -e "\n"

# Test pagination manually
echo "Testing pagination manually..."
OFFSET=0
LIMIT=3
PAGE=1

while true; do
    echo "Page $PAGE (offset=$OFFSET, limit=$LIMIT)..."
    RESPONSE=$(curl -s "$BASE_URL/api/tokens/list?api_key=$API_KEY&status=unused&offset=$OFFSET&limit=$LIMIT")

    # Check if response is valid JSON
    if ! echo "$RESPONSE" | python3 -c "import sys, json; json.load(sys.stdin)" 2>/dev/null; then
        echo "Invalid JSON response"
        break
    fi

    # Extract pagination info
    TOTAL_COUNT=$(echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('total_count', 0))")
    RETURNED_COUNT=$(echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('returned_count', 0))")
    HAS_MORE=$(echo "$RESPONSE" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('has_more', False))")

    echo "Total: $TOTAL_COUNT, Returned: $RETURNED_COUNT, Has more: $HAS_MORE"

    # Pretty print tokens
    echo "$RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
tokens = data.get('tokens', [])
for token in tokens:
    print(f'  {token[\"token\"]} - status: {token[\"status\"]}')
"

    if [ "$HAS_MORE" != "True" ]; then
        echo "No more pages"
        break
    fi

    OFFSET=$((OFFSET + LIMIT))
    PAGE=$((PAGE + 1))

    if [ $PAGE -gt 10 ]; then
        echo "Too many pages, stopping"
        break
    fi

    echo
done

echo "Pagination test complete!"