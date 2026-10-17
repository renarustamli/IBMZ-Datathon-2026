#!/bin/bash
# End-to-end test. Usage: ./test.sh [strict|legacy]
#   strict: alice-laptop (hybrid) connects, mallory-laptop (classical) is refused
#   legacy: mallory-laptop also connects, logged as weak
cd "$(dirname "$0")"
pkill gateway 2>/dev/null
pkill -f "http.server 9000" 2>/dev/null
# Build the ML-DSA-65 (post-quantum) demo certificate if none exists.
if [ ! -f cert.pem ]; then
  go build -o gencert/gencert ./gencert && ./gencert/gencert -pq
fi
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
