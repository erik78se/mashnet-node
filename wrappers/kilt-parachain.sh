#!/bin/bash

printf "Starting mashnet-node";

SPEC="$SNAP/dev-specs/kilt-parachain/kilt-westend.json"

exec "$SNAP/target/release/kilt-parachain" \
	"--chain=$SPEC" \
	"--runtime=spiritnet" \
	"--bootnodes" "/dns4/bootnode.kilt.io/tcp/30360/p2p/12D3KooWRPR7q1Rgwurd4QGyUUbVnN4nXYNVzbLeuhFsd9eXmHJk" "/dns4/bootnode.kilt.io/tcp/30361/p2p/12D3KooWDAEqpTRsL76itsabbh4SeaqtCM6v9npQ8eCeqPbbuFE9" \
	"--listen-addr=/ip4/0.0.0.0/tcp/30336" \
	"--collator" "--" "--listen-addr=/ip4/0.0.0.0/tcp/30333" \
	"--chain=westend" "--execution=wasm" "$@"

