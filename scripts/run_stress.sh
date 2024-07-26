#!/usr/bin/env bash

for i in $(seq 100); do
    curl https://127.0.0.1:3000/bytes/$(shuf -i 10-1000 -n 1)?req_id=${i} \
        --cacert keys/server.crt \
        --output /dev/null \
        -w "Total: %{size_download} B in \t%{time_total}s\n" \
        -q -sS &
done

wait
