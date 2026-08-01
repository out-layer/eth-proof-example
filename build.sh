#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "Building eth-proof-example for wasm32-wasip2..."
rustup target add wasm32-wasip2 2>/dev/null || true
cargo build --target wasm32-wasip2 --release

echo ""
echo "Build complete:"
ls -lh target/wasm32-wasip2/release/eth-proof-example.wasm
echo ""
echo "Run it (needs outbound HTTP, hence -S http):"
echo "  echo '{\"aggregator\":\"0x7d4e742018fb52e48b08be73d041c18b21de6fb5\"}' \\"
echo "    | wasmtime -S http target/wasm32-wasip2/release/eth-proof-example.wasm"
