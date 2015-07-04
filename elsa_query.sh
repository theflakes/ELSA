#!/bin/bash

USER="elsa"
APIKEY="place-api-key-here"

EPOCH=$(date '+%s')
HASH=$(printf '%s' "$EPOCH$APIKEY" |shasum -a 512)

HEADER=$(echo "Authorization: ApiKey $USER:$EPOCH:$HASH" | sed -e s'/\-//')

QUERY=$1
curl -XPOST -k -H "$HEADER" -F "permissions={ \"class_id\": { \"0\": 1 }, \"program_id\": { \"0\": 1 }, \"node_id\": { \"0\": 1 }, \"host_id\": { \"0\": 1 } }" -F "query_string=$QUERY" https://127.0.0.1:3154/API/query > $2
