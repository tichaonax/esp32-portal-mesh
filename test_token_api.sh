#!/bin/bash

ESP32_IP="192.168.0.120"
API_KEY="Djk7amUcrX0AJAaIoHgPGOmI7XD8QnZH"

echo "========================================================================"
echo "ESP32 Token API Testing"
echo "ESP32: http://${ESP32_IP}"
echo "========================================================================"
echo ""

# Function to print test header
test_header() {
    echo ""
    echo "========================================================================"
    echo "TEST: $1"
    echo "========================================================================"
}

# Function to make API request and show result
api_request() {
    local method=$1
    local endpoint=$2
    local data=$3
    local desc=$4

    echo "[$desc]"
    echo "Request: $method $endpoint"

    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$ESP32_IP$endpoint")
    else
        response=$(curl -s -X POST -w "\nHTTP_CODE:%{http_code}" -d "$data" "$ESP32_IP$endpoint")
    fi

    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    body=$(echo "$response" | sed '/HTTP_CODE:/d')

    echo "Status: $http_code"
    echo "Response: $body" | head -c 500
    echo ""
    echo ""

    # Return the response body for further processing
    echo "$body"
}

# TEST 1: Check system health
test_header "1. System Health Check"
api_request "GET" "/api/health" "" "Health Check" > /tmp/health.json

# TEST 2: Get AP Info
test_header "2. Get AP Information"
api_request "GET" "/api/ap/info" "" "AP Info" > /tmp/ap_info.json

# TEST 3: Check available slots
test_header "3. Check Available Token Slots"
api_request "GET" "/api/tokens/available_slots?api_key=$API_KEY" "" "Available Slots" > /tmp/slots.json

# TEST 4: Create a single token
test_header "4. Create Single Token"
api_request "POST" "/api/token" "api_key=$API_KEY&duration=120&bandwidth_down=500&bandwidth_up=100&businessId=test-business-001" "Create Token" > /tmp/token1.json

# Extract token from response
TOKEN1=$(grep -o '"token":"[^"]*' /tmp/token1.json | cut -d'"' -f4)
echo "Created token: $TOKEN1"
echo ""

# TEST 5: Get token info
if [ ! -z "$TOKEN1" ]; then
    test_header "5. Get Token Info"
    api_request "GET" "/api/token/info?api_key=$API_KEY&token=$TOKEN1" "" "Token Info" > /tmp/token_info.json
fi

# TEST 6: Create bulk tokens
test_header "6. Create Bulk Tokens (5 tokens)"
api_request "POST" "/api/tokens/bulk_create" "api_key=$API_KEY&count=5&duration=60&bandwidth_down=250&businessId=bulk-test-001" "Bulk Create" > /tmp/bulk_tokens.json

# TEST 7: List tokens with filters
test_header "7. List Tokens (unused only, limit 10)"
api_request "GET" "/api/tokens/list?api_key=$API_KEY&unused_only=true&limit=10" "" "List Tokens" > /tmp/token_list.json

# TEST 8: Test concurrent token creation (tests mutex timeout fix)
test_header "8. Concurrent Token Creation (Tests Mutex Fix)"
echo "Creating 5 tokens concurrently to test mutex timeout..."
echo ""

for i in {1..5}; do
    {
        start=$(date +%s)
        response=$(curl -s -X POST -w "\nHTTP_CODE:%{http_code}" \
            -d "api_key=$API_KEY&duration=30&businessId=concurrent-test-$i" \
            "$ESP32_IP/api/token")
        end=$(date +%s)
        http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)

        if [ "$http_code" = "200" ]; then
            echo "Request $i: ✓ SUCCESS (Status: $http_code, Time: $((end-start))s)"
        elif [ "$http_code" = "503" ]; then
            echo "Request $i: ⚠ SERVER BUSY (Status: 503) - This is expected, should retry"
        else
            echo "Request $i: ✗ FAILED (Status: $http_code)"
        fi
    } &
done

wait
echo ""
echo "Concurrent test complete!"
echo ""

# TEST 9: Batch token info
test_header "9. Batch Token Info Query"
# Get first 3 tokens from list
BATCH_TOKENS=$(grep -o '"token":"[^"]*' /tmp/token_list.json | cut -d'"' -f4 | head -3 | tr '\n' ',' | sed 's/,$//')
if [ ! -z "$BATCH_TOKENS" ]; then
    api_request "GET" "/api/token/batch_info?api_key=$API_KEY&tokens=$BATCH_TOKENS" "" "Batch Info" > /tmp/batch_info.json
fi

# TEST 10: Disable tokens (bulk)
test_header "10. Disable Tokens (Bulk Operation)"
DISABLE_TOKENS=$(grep -o '"token":"[^"]*' /tmp/bulk_tokens.json | cut -d'"' -f4 | head -2 | tr '\n' ',' | sed 's/,$//')
if [ ! -z "$DISABLE_TOKENS" ]; then
    echo "Disabling tokens: $DISABLE_TOKENS"
    api_request "POST" "/api/token/disable" "api_key=$API_KEY&tokens=$DISABLE_TOKENS" "Disable Tokens" > /tmp/disable_result.json
fi

# TEST 11: Purge expired/unused tokens
test_header "11. Purge Tokens (Unused, older than 1 minute)"
api_request "POST" "/api/tokens/purge" "api_key=$API_KEY&unused_only=true&max_age_minutes=1" "Purge Tokens" > /tmp/purge_result.json

# TEST 12: Final health check
test_header "12. Final Health Check"
api_request "GET" "/api/health" "" "Final Health" > /tmp/health_final.json

echo ""
echo "========================================================================"
echo "SUMMARY"
echo "========================================================================"
echo ""
echo "All API endpoint tests completed!"
echo ""
echo "Key files created:"
echo "  - /tmp/health.json         : System health"
echo "  - /tmp/token1.json         : Created token"
echo "  - /tmp/bulk_tokens.json    : Bulk created tokens"
echo "  - /tmp/token_list.json     : Token list"
echo "  - /tmp/disable_result.json : Disabled tokens result"
echo ""
echo "To view detailed results, check the files above."
echo "========================================================================"

# Cleanup
rm -f /tmp/result_*.txt
