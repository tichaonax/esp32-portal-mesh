#!/bin/bash

ESP32_IP="192.168.0.120"
API_KEY="Djk7amUcrX0AJAaIoHgPGOmI7XD8QnZH"

echo "========================================================================"
echo "TOKEN CAPACITY & CONCURRENT CREATION TEST"
echo "========================================================================"
echo ""

# Check current capacity
echo "Step 1: Checking current token capacity..."
current_slots=$(curl -s "http://${ESP32_IP}/api/tokens/available_slots?api_key=$API_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin)['available_slots'])" 2>/dev/null)
max_tokens=$(curl -s "http://${ESP32_IP}/api/tokens/available_slots?api_key=$API_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin)['max_tokens'])" 2>/dev/null)
current_tokens=$(curl -s "http://${ESP32_IP}/api/tokens/available_slots?api_key=$API_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin)['current_tokens'])" 2>/dev/null)

echo "Current slots: $current_slots"
echo "Max tokens: $max_tokens"
echo "Current tokens: $current_tokens"
echo ""

# Test 1: Create 20 concurrent tokens
echo "========================================================================"
echo "TEST 1: Create 20 concurrent token requests"
echo "========================================================================"
echo ""

success_count=0
fail_count=0
busy_count=0

for i in $(seq 1 20); do
    {
        response=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
            -d "api_key=$API_KEY&duration=30&businessId=concurrent-test-$i" \
            "http://${ESP32_IP}/api/token")

        http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)

        if [ "$http_code" = "200" ]; then
            echo "Request $i: ✓ SUCCESS (200)"
            echo "success" > /tmp/token_test_$i.txt
        elif [ "$http_code" = "503" ]; then
            echo "Request $i: ⚠ SERVER BUSY (503)"
            echo "busy" > /tmp/token_test_$i.txt
        elif [ "$http_code" = "507" ]; then
            echo "Request $i: ✗ NO SPACE (507 - Token limit reached)"
            echo "full" > /tmp/token_test_$i.txt
        else
            echo "Request $i: ✗ FAILED ($http_code)"
            echo "fail" > /tmp/token_test_$i.txt
        fi
    } &
done

wait

echo ""
echo "Counting results..."
success_count=$(grep -l "success" /tmp/token_test_*.txt 2>/dev/null | wc -l | tr -d ' ')
busy_count=$(grep -l "busy" /tmp/token_test_*.txt 2>/dev/null | wc -l | tr -d ' ')
full_count=$(grep -l "full" /tmp/token_test_*.txt 2>/dev/null | wc -l | tr -d ' ')
fail_count=$(grep -l "fail" /tmp/token_test_*.txt 2>/dev/null | wc -l | tr -d ' ')

echo "Success (200): $success_count"
echo "Server Busy (503): $busy_count"
echo "No Space (507): $full_count"
echo "Failed (other): $fail_count"
echo ""

# Check capacity after test
echo "Checking capacity after concurrent test..."
new_slots=$(curl -s "http://${ESP32_IP}/api/tokens/available_slots?api_key=$API_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin)['available_slots'])" 2>/dev/null)
new_current=$(curl -s "http://${ESP32_IP}/api/tokens/available_slots?api_key=$API_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin)['current_tokens'])" 2>/dev/null)

echo "Available slots: $new_slots (was $current_slots)"
echo "Current tokens: $new_current (was $current_tokens)"
echo "Tokens created: $((new_current - current_tokens))"
echo ""

# Test 2: Fill to capacity if not already full
if [ "$new_slots" -gt 50 ]; then
    echo "========================================================================"
    echo "TEST 2: Filling token storage to near capacity"
    echo "========================================================================"
    echo ""

    # Calculate how many to create (leave 10 slots free for testing)
    to_create=$((new_slots - 10))

    if [ "$to_create" -gt 0 ]; then
        echo "Creating $to_create tokens in bulk to fill storage..."

        # Create in batches of 50 (max bulk size)
        batches=$(( (to_create + 49) / 50 ))

        for batch in $(seq 1 $batches); do
            batch_size=50
            remaining=$((to_create - (batch - 1) * 50))
            if [ "$remaining" -lt 50 ]; then
                batch_size=$remaining
            fi

            echo "Batch $batch: Creating $batch_size tokens..."
            curl -s -X POST \
                -d "api_key=$API_KEY&count=$batch_size&duration=30&businessId=capacity-test" \
                "http://${ESP32_IP}/api/tokens/bulk_create" > /dev/null

            sleep 1
        done

        echo ""
        echo "Checking capacity after filling..."
        final_slots=$(curl -s "http://${ESP32_IP}/api/tokens/available_slots?api_key=$API_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin)['available_slots'])" 2>/dev/null)
        final_current=$(curl -s "http://${ESP32_IP}/api/tokens/available_slots?api_key=$API_KEY" | python3 -c "import sys, json; print(json.load(sys.stdin)['current_tokens'])" 2>/dev/null)

        echo "Available slots: $final_slots / $max_tokens"
        echo "Current tokens: $final_current / $max_tokens"
    fi
fi

# Test 3: Try to create when near/at capacity
echo ""
echo "========================================================================"
echo "TEST 3: Testing behavior when near/at capacity"
echo "========================================================================"
echo ""

echo "Attempting to create 10 more tokens..."
for i in $(seq 1 10); do
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST \
        -d "api_key=$API_KEY&duration=30&businessId=overflow-test-$i" \
        "http://${ESP32_IP}/api/token")

    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    body=$(echo "$response" | sed '/HTTP_CODE:/d')

    if [ "$http_code" = "200" ]; then
        echo "Request $i: ✓ Created successfully"
    elif [ "$http_code" = "507" ]; then
        error_msg=$(echo "$body" | python3 -c "import sys, json; print(json.load(sys.stdin).get('error', 'No space'))" 2>/dev/null)
        echo "Request $i: ✗ FULL - $error_msg"
        break
    else
        echo "Request $i: Status $http_code"
    fi
    sleep 0.5
done

echo ""
echo "========================================================================"
echo "FINAL CAPACITY STATUS"
echo "========================================================================"

final_health=$(curl -s "http://${ESP32_IP}/api/health")
echo "$final_health" | python3 -m json.tool 2>/dev/null

echo ""
echo "Test complete! Check monitor for any issues."
echo "========================================================================"

# Cleanup
rm -f /tmp/token_test_*.txt
