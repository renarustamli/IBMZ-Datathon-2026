#!/bin/bash
cd "$(dirname "$0")"
pkill gateway 2>/dev/null
pkill -f "http.server 9000" 2>/dev/null
rm -f logs/connections.jsonl
python3 -m http.server 9000 > /dev/null 2>&1 &
./gateway -mode "${1:-strict}" > gateway.out 2>&1 &
sleep 2
go run ./testclient -id alice-laptop
go run ./testclient -id mallory-laptop -classical
echo "----- notes -----"
cat logs/connections.jsonl
pkill gateway
pkill -f "http.server 9000"
