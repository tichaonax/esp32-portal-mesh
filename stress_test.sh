#!/bin/bash
echo "========================================================================"
echo "FINAL STRESS TEST: 15 concurrent requests"
echo "========================================================================"
echo ""

for i in $(seq 1 15); do
    {
        if curl -s --max-time 10 http://192.168.0.120/api/ap/info | grep -q "success"; then
            echo "Request $i: ✓ SUCCESS"
            echo "success" > /tmp/result_$i.txt
        else
            echo "Request $i: ✗ FAILED"
            echo "fail" > /tmp/result_$i.txt
        fi
    } &
done

wait

echo ""
echo "========================================================================"
echo "RESULTS:"
success_count=$(ls /tmp/result_*.txt 2>/dev/null | xargs grep -c "success" 2>/dev/null || echo 0)
total_files=$(ls /tmp/result_*.txt 2>/dev/null | wc -l | tr -d ' ')
echo "Successful: $success_count / $total_files"

if [ "$success_count" -eq "$total_files" ] && [ "$total_files" -eq 15 ]; then
    echo "✓ ALL TESTS PASSED - No blocking issues detected!"
else
    echo "⚠ Some requests failed"
fi
echo "========================================================================"

rm -f /tmp/result_*.txt
