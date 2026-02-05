#!/usr/bin/env python3
import argparse
from pathlib import Path


def _clean_lines(text: str):
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith("//"):
            continue
        yield line


def parse_bristol(path: Path):
    lines = list(_clean_lines(path.read_text()))
    if len(lines) < 3:
        raise ValueError("Invalid bristol file: need at least 3 lines")

    g_w = lines[0].split()
    if len(g_w) < 2:
        raise ValueError("Invalid bristol header: first line must be '<gates> <wires>'")
    num_gates = int(g_w[0])
    num_wires = int(g_w[1])

    inputs = [int(x) for x in lines[1].split()]
    outputs = [int(x) for x in lines[2].split()]
    if not inputs or not outputs:
        raise ValueError("Invalid bristol header: input/output lines empty")

    gates = []
    for line in lines[3:]:
        parts = line.split()
        if len(parts) < 4:
            raise ValueError(f"Invalid gate line: {line}")
        n_in = int(parts[0])
        n_out = int(parts[1])
        if len(parts) < 2 + n_in + n_out + 1:
            raise ValueError(f"Invalid gate line (short): {line}")
        in_wires = [int(x) for x in parts[2:2 + n_in]]
        out_wires = [int(x) for x in parts[2 + n_in:2 + n_in + n_out]]
        op = parts[2 + n_in + n_out]
        gates.append((n_in, n_out, in_wires, out_wires, op))

    if num_gates != len(gates):
        # Not fatal, but warn by adjusting to actual
        num_gates = len(gates)

    return num_gates, num_wires, inputs, outputs, gates


CPP_TEMPLATE_HEAD = """\
/*
 * Auto-generated from a Bristol circuit.
 *
 * Args (JSON -> argv):
 *   [1] <hex> input bits packed in bytes (LSB-first)
 *   [2] <i64> input bit length
 *   [3] <hex> output bits packed in bytes (LSB-first)
 *   [4] <i64> output bit length
 *
 * If argc <= 2, argv[1] is treated as a '0'/'1' string.
 */

#include <cstdint>
#include <cstring>
#include <vector>

#include <ligetron/api.h>
#include <ligetron/bn254fr_class.h>

using ligetron::bn254fr_class;
using ligetron::addmod;
using ligetron::submod;
using ligetron::mulmod;
using ligetron::mulmod_constant;

static inline uint8_t get_bit(const uint8_t* data, size_t i) {
    return (data[i >> 3] >> (i & 7)) & 1;
}

static inline void assert_bool(bn254fr_class& b,
                               bn254fr_class& one,
                               bn254fr_class& zero) {
    bn254fr_class tmp1, tmp2;
    submod(tmp1, b, one);
    mulmod(tmp2, b, tmp1);
    bn254fr_class::assert_equal(tmp2, zero);
}

int main(int argc, char** argv) {
    constexpr size_t kNumWires = __NUM_WIRES__;
    constexpr size_t kNumInputs = __NUM_INPUTS__;
    constexpr size_t kNumOutputs = __NUM_OUTPUTS__;

    if (argc < 2) return 1;

    const uint8_t* in_bytes = reinterpret_cast<const uint8_t*>(argv[1]);
    size_t in_bits = kNumInputs;
    bool in_is_text = false;
    if (argc > 2) {
        in_bits = *reinterpret_cast<const uint64_t*>(argv[2]);
    } else {
        in_is_text = true;
        in_bits = std::strlen(argv[1]);
    }

    if (in_bits < kNumInputs) return 2;

    const uint8_t* out_bytes = nullptr;
    size_t out_bits = 0;
    bool out_is_text = false;
    if (argc > 4) {
        out_bytes = reinterpret_cast<const uint8_t*>(argv[3]);
        out_bits = *reinterpret_cast<const uint64_t*>(argv[4]);
    } else if (argc > 3) {
        out_is_text = true;
        out_bytes = reinterpret_cast<const uint8_t*>(argv[3]);
        out_bits = std::strlen(argv[3]);
    }

    std::vector<bn254fr_class> w(kNumWires);
    bn254fr_class zero(0), one(1), two(2);

    for (size_t i = 0; i < kNumInputs; ++i) {
        uint8_t bit = 0;
        if (in_is_text) {
            bit = (argv[1][i] == '1') ? 1 : 0;
        } else {
            bit = get_bit(in_bytes, i);
        }
        w[i].set_u32(bit);
        assert_bool(w[i], one, zero);
    }

"""


CPP_TEMPLATE_TAIL = """\

    // Outputs are assumed to be the last kNumOutputs wires (Bristol standard).
    if (out_bytes && out_bits >= kNumOutputs) {
        for (size_t i = 0; i < kNumOutputs; ++i) {
            size_t wire_idx = kNumWires - kNumOutputs + i;
            uint8_t bit = 0;
            if (out_is_text) {
                bit = (reinterpret_cast<const char*>(out_bytes)[i] == '1') ? 1 : 0;
            } else {
                bit = get_bit(out_bytes, i);
            }
            bn254fr_class expected(bit);
            bn254fr_class::assert_equal(w[wire_idx], expected);
        }
    }

    return 0;
}
"""


def emit_cpp(num_wires, num_inputs, num_outputs, gates):
    out = []
    head = (CPP_TEMPLATE_HEAD
            .replace("__NUM_WIRES__", str(num_wires))
            .replace("__NUM_INPUTS__", str(num_inputs))
            .replace("__NUM_OUTPUTS__", str(num_outputs)))
    out.append(head)

    for n_in, n_out, ins, outs, op in gates:
        op = op.upper()
        if op in ("XOR", "XOR2"):
            if n_in != 2 or n_out != 1:
                raise ValueError(f"XOR gate must be 2->1, got {n_in}->{n_out}")
            a, b = ins
            o = outs[0]
            out.append(f"    // XOR {a} {b} -> {o}\n")
            out.append(f"    {{\n")
            out.append(f"        bn254fr_class t1, t2;\n")
            out.append(f"        addmod(t1, w[{a}], w[{b}]);\n")
            out.append(f"        mulmod(t2, w[{a}], w[{b}]);\n")
            out.append(f"        mulmod_constant(t2, t2, two);\n")
            out.append(f"        submod(w[{o}], t1, t2);\n")
            out.append(f"    }}\n\n")
        elif op in ("AND", "AND2"):
            if n_in != 2 or n_out != 1:
                raise ValueError(f"AND gate must be 2->1, got {n_in}->{n_out}")
            a, b = ins
            o = outs[0]
            out.append(f"    // AND {a} {b} -> {o}\n")
            out.append(f"    mulmod(w[{o}], w[{a}], w[{b}]);\n\n")
        elif op in ("INV", "NOT"):
            if n_in != 1 or n_out != 1:
                raise ValueError(f"INV gate must be 1->1, got {n_in}->{n_out}")
            a = ins[0]
            o = outs[0]
            out.append(f"    // INV {a} -> {o}\n")
            out.append(f"    submod(w[{o}], one, w[{a}]);\n\n")
        else:
            raise ValueError(f"Unsupported gate op: {op}")

    out.append(CPP_TEMPLATE_TAIL)
    return "".join(out)


def main():
    ap = argparse.ArgumentParser(description="Convert Bristol circuit to Ligetron C++")
    ap.add_argument("bristol", type=Path)
    ap.add_argument("out_cpp", type=Path)
    args = ap.parse_args()

    num_gates, num_wires, inputs, outputs, gates = parse_bristol(args.bristol)
    num_inputs = sum(inputs)
    num_outputs = sum(outputs)

    cpp = emit_cpp(num_wires, num_inputs, num_outputs, gates)
    args.out_cpp.parent.mkdir(parents=True, exist_ok=True)
    args.out_cpp.write_text(cpp)


if __name__ == "__main__":
    main()
