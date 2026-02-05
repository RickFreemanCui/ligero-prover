#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BRISTOL="${1:-}"
INPUT_BITS="${2:-}"
OUTPUT_BITS="${3:-}"
PACKING="${PACKING:-8192}"
SHADER_PATH="${SHADER_PATH:-$ROOT/shader}"

if [[ -z "$BRISTOL" || -z "$INPUT_BITS" || -z "$OUTPUT_BITS" ]]; then
  echo "Usage: $0 <bristol.txt> <input_bits_string> <output_bits_string>" >&2
  echo "Example: $0 circuits/and2.txt 01 0" >&2
  exit 1
fi

circuit="$(basename "$BRISTOL" .txt)"
GEN_CPP="$ROOT/sdk/cpp/examples/generated/$circuit.cpp"
OUT_WASM="$ROOT/sdk/cpp/examples/generated/$circuit.wasm"

python3 "$ROOT/tools/bristol_to_cpp.py" "$BRISTOL" "$GEN_CPP"

if [[ ! -f "$ROOT/sdk/cpp/build/libligetron.a" ]]; then
  echo "Building SDK (ligetron library)..." >&2
  mkdir -p "$ROOT/sdk/cpp/build"
  (cd "$ROOT/sdk/cpp/build" && emcmake cmake .. && make -j)
fi

echo "Compiling generated circuit to WASM..." >&2
em++ -O2 -I"$ROOT/sdk/cpp/include" -L"$ROOT/sdk/cpp/build" \
  "$GEN_CPP" -o "$OUT_WASM" -lligetron

pack_bits_hex() {
  python3 - "$1" <<'PY'
import sys
s=sys.argv[1].strip()
if not s:
    print("")
    sys.exit(0)
bits=[1 if c=='1' else 0 for c in s]
out=[]
for i in range(0,len(bits),8):
    byte=0
    for j in range(8):
        if i+j < len(bits):
            byte |= (bits[i+j] & 1) << j
    out.append(byte)
print("".join(f"{b:02x}" for b in out))
PY
}

IN_HEX="$(pack_bits_hex "$INPUT_BITS")"
OUT_HEX="$(pack_bits_hex "$OUTPUT_BITS")"
IN_LEN="${#INPUT_BITS}"
OUT_LEN="${#OUTPUT_BITS}"

PROVER_JSON=$(cat <<JSON
{
  "program":"$OUT_WASM",
  "shader-path":"$SHADER_PATH",
  "packing":$PACKING,
  "private-indices":[1],
  "args":[
    {"hex":"$IN_HEX"},
    {"i64":$IN_LEN},
    {"hex":"$OUT_HEX"},
    {"i64":$OUT_LEN}
  ]
}
JSON
)

echo "Running prover..." >&2
"$ROOT/build/webgpu_prover" "$PROVER_JSON"

echo "Running verifier..." >&2
"$ROOT/build/webgpu_verifier" "$PROVER_JSON"

cat <<'EOF'

Input format (prover & verifier):
{
  "program": "<path/to/circuit.wasm>",
  "shader-path": "<path/to/shader>",
  "packing": 8192,
  "gpu-threads": 8192,
  "private-indices": [1,2,...],
  "args": [
    {"hex":"<input bits packed LSB-first>"},
    {"i64":<input bit length>},
    {"hex":"<expected output bits packed LSB-first>"},
    {"i64":<output bit length>}
  ]
}

Proof file:
- Prover writes proof to ./proof_data.gz
- Verifier reads ./proof_data.gz
EOF
