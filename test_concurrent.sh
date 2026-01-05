#!/bin/bash
# Test concurrent HTTP requests to ESP32 to verify non-blocking behavior

ESP32_IP="192.168.0.120"
LOG_FILE="test_results.log"

echo "Testing ESP32 at http://${ESP32_IP}" | tee "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"

# Function to test endpoint
test_endpoint() {
    local endpoint=$1
    local request_id=$2
    local start_time=$(date +%s.%N)

    echo "[Request $request_id] Starting request to $endpoint"

    response_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "http://${ESP32_IP}${endpoint}" 2>&1)
    local curl_exit=$?

    local end_time=$(date +%s.%N)
    local elapsed=$(echo "$end_time - $start_time" | bc)

    if [ $curl_exit -eq 0 ] && [ "$response_code" = "200" ] || [ "$response_code" = "302" ]; then
        echo "[Request $request_id] ✓ SUCCESS: $endpoint - Status: $response_code, Time: ${elapsed}s"
        return 0
    else
        echo "[Request $request_id] ✗ FAILED: $endpoint - Status: $response_code, Exit: $curl_exit, Time: ${elapsed}s"
        return 1
    fi
}

# Check connectivity
echo ""
echo "Checking connectivity..." | tee -a "$LOG_FILE"
if curl -s -o /dev/null --max-time 5 "http://${ESP32_IP}/"; then
    echo "✓ ESP32 is reachable" | tee -a "$LOG_FILE"
else
    echo "✗ Cannot reach ESP32" | tee -a "$LOG_FILE"
    exit 1
fi

# TEST 1: Multiple concurrent requests to the same endpoint
echo "" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"
echo "TEST 1: 10 concurrent requests to the same endpoint (/)" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"

test1_start=$(date +%s.%N)
for i in {0..9}; do
    test_endpoint "/" $i &
done
wait
test1_end=$(date +%s.%N)
test1_elapsed=$(echo "$test1_end - $test1_start" | bc)
echo "Test 1 completed in ${test1_elapsed}s" | tee -a "$LOG_FILE"

# TEST 2: Concurrent requests to different endpoints
echo "" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"
echo "TEST 2: Concurrent requests to different endpoints" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"

test2_start=$(date +%s.%N)
test_endpoint "/" 0 &
test_endpoint "/api/tokens" 1 &
test_endpoint "/admin" 2 &
test_endpoint "/api/sessions" 3 &
test_endpoint "/api/ap/info" 4 &
wait
test2_end=$(date +%s.%N)
test2_elapsed=$(echo "$test2_end - $test2_start" | bc)
echo "Test 2 completed in ${test2_elapsed}s" | tee -a "$LOG_FILE"

# TEST 3: Rapid-fire requests
echo "" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"
echo "TEST 3: Rapid-fire requests (testing listen backlog)" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"

test3_start=$(date +%s.%N)
for i in {0..7}; do
    sleep 0.1
    test_endpoint "/" $i &
done
wait
test3_end=$(date +%s.%N)
test3_elapsed=$(echo "$test3_end - $test3_start" | bc)
echo "Test 3 completed in ${test3_elapsed}s" | tee -a "$LOG_FILE"

# TEST 4: Concurrent token list requests
echo "" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"
echo "TEST 4: Concurrent token list requests (tests NVS mutex timeout)" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"

test4_start=$(date +%s.%N)
for i in {0..4}; do
    test_endpoint "/api/tokens" $i &
done
wait
test4_end=$(date +%s.%N)
test4_elapsed=$(echo "$test4_end - $test4_start" | bc)
echo "Test 4 completed in ${test4_elapsed}s" | tee -a "$LOG_FILE"

echo "" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"
echo "All tests completed!" | tee -a "$LOG_FILE"
echo "Check $LOG_FILE for full results" | tee -a "$LOG_FILE"
echo "======================================================================" | tee -a "$LOG_FILE"
