#!/bin/bash
# monitor.sh — watches fn35_loader PID and logs memory/CPU every 5s
LOG=/home/z/my-project/fn35/monitor.log
echo "monitor start $(date)" > "$LOG"
while true; do
    PID=$(pgrep -f "fn35_loader.py" | head -1)
    if [ -z "$PID" ]; then
        echo "$(date +%H:%M:%S) PROCESS DEAD" >> "$LOG"
        echo "monitor end $(date)" >> "$LOG"
        break
    fi
    RSS=$(awk '/VmRSS/{print $2}' /proc/$PID/status 2>/dev/null)
    VSZ=$(awk '/VmSize/{print $2}' /proc/$PID/status 2>/dev/null)
    THR=$(awk '/Threads/{print $2}' /proc/$PID/status 2>/dev/null)
    echo "$(date +%H:%M:%S) pid=$PID rss=${RSS}KB vsz=${VSZ}KB threads=${THR}" >> "$LOG"
    sleep 5
done
