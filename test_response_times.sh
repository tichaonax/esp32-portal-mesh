#!/bin/bash

ESP32_IP="192.168.0.120"

echo "========================================================================"
echo "Testing concurrent request response times"
echo "========================================================================"
echo ""

echo "TEST: 5 concurrent requests to /api/ap/info"
echo "If requests don't block each other, they should complete in ~0.1-0.3s"
echo "If they block, each would wait for previous, taking 0.5s+ total"
echo ""

for i in {1..5}; do
    {
        start=$(date +%s.%N)
        curl -s http://${ESP32_IP}/api/ap/info > /dev/null
        end=$(date +%s.%N)
        echo "Request $i completed in $(echo "$end - $start" | bc)s"
    } &
done

wait
echo ""
echo "All requests completed!"
echo ""

echo "========================================================================"
echo "TEST: Sequential vs Concurrent comparison"
echo "========================================================================"
echo ""

# Sequential test
echo "Sequential test (5 requests one after another):"
seq_start=$(date +%s.%N)
for i in {1..5}; do
    curl -s http://${ESP32_IP}/api/ap/info > /dev/null
done
seq_end=$(date +%s.%N)
seq_time=$(echo "$seq_end - $seq_start" | bc)
echo "Total time for sequential: ${seq_time}s"
echo ""

# Concurrent test
echo "Concurrent test (5 requests at the same time):"
conc_start=$(date +%s.%N)
for i in {1..5}; do
    curl -s http://${ESP32_IP}/api/ap/info > /dev/null &
done
wait
conc_end=$(date +%s.%N)
conc_time=$(echo "$conc_end - $conc_start" | bc)
echo "Total time for concurrent: ${conc_time}s"
echo ""

echo "========================================================================"
echo "RESULT ANALYSIS:"
echo "Sequential time: ${seq_time}s"
echo "Concurrent time: ${conc_time}s"

# Compare times
speedup=$(echo "scale=2; $seq_time / $conc_time" | bc)
echo "Speedup: ${speedup}x"

if (( $(echo "$speedup > 2" | bc -l) )); then
    echo "✓ EXCELLENT: Concurrent requests are processed in parallel!"
elif (( $(echo "$speedup > 1.5" | bc -l) )); then
    echo "✓ GOOD: Concurrent requests show some parallelism"
else
    echo "✗ WARNING: Requests may still be blocking (speedup < 1.5x)"
fi
echo "========================================================================"
