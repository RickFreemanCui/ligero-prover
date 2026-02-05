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
    constexpr size_t kNumWires = 5628;
    constexpr size_t kNumInputs = 129;
    constexpr size_t kNumOutputs = 65;

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

    // AND 118 127 -> 128
    mulmod(w[128], w[118], w[127]);

    // XOR 27 67 -> 129
    {
        bn254fr_class t1, t2;
        addmod(t1, w[27], w[67]);
        mulmod(t2, w[27], w[67]);
        mulmod_constant(t2, t2, two);
        submod(w[129], t1, t2);
    }

    // INV 38 -> 130
    submod(w[130], one, w[38]);

    // XOR 67 88 -> 131
    {
        bn254fr_class t1, t2;
        addmod(t1, w[67], w[88]);
        mulmod(t2, w[67], w[88]);
        mulmod_constant(t2, t2, two);
        submod(w[131], t1, t2);
    }

    // AND 3 14 -> 132
    mulmod(w[132], w[3], w[14]);

    // XOR 104 59 -> 133
    {
        bn254fr_class t1, t2;
        addmod(t1, w[104], w[59]);
        mulmod(t2, w[104], w[59]);
        mulmod_constant(t2, t2, two);
        submod(w[133], t1, t2);
    }

    // XOR 121 73 -> 134
    {
        bn254fr_class t1, t2;
        addmod(t1, w[121], w[73]);
        mulmod(t2, w[121], w[73]);
        mulmod_constant(t2, t2, two);
        submod(w[134], t1, t2);
    }

    // XOR 105 21 -> 135
    {
        bn254fr_class t1, t2;
        addmod(t1, w[105], w[21]);
        mulmod(t2, w[105], w[21]);
        mulmod_constant(t2, t2, two);
        submod(w[135], t1, t2);
    }

    // XOR 9 52 -> 136
    {
        bn254fr_class t1, t2;
        addmod(t1, w[9], w[52]);
        mulmod(t2, w[9], w[52]);
        mulmod_constant(t2, t2, two);
        submod(w[136], t1, t2);
    }

    // XOR 47 77 -> 137
    {
        bn254fr_class t1, t2;
        addmod(t1, w[47], w[77]);
        mulmod(t2, w[47], w[77]);
        mulmod_constant(t2, t2, two);
        submod(w[137], t1, t2);
    }

    // AND 19 90 -> 138
    mulmod(w[138], w[19], w[90]);

    // AND 56 94 -> 139
    mulmod(w[139], w[56], w[94]);

    // XOR 35 19 -> 140
    {
        bn254fr_class t1, t2;
        addmod(t1, w[35], w[19]);
        mulmod(t2, w[35], w[19]);
        mulmod_constant(t2, t2, two);
        submod(w[140], t1, t2);
    }

    // INV 20 -> 141
    submod(w[141], one, w[20]);

    // XOR 20 94 -> 142
    {
        bn254fr_class t1, t2;
        addmod(t1, w[20], w[94]);
        mulmod(t2, w[20], w[94]);
        mulmod_constant(t2, t2, two);
        submod(w[142], t1, t2);
    }

    // XOR 88 126 -> 143
    {
        bn254fr_class t1, t2;
        addmod(t1, w[88], w[126]);
        mulmod(t2, w[88], w[126]);
        mulmod_constant(t2, t2, two);
        submod(w[143], t1, t2);
    }

    // XOR 94 73 -> 144
    {
        bn254fr_class t1, t2;
        addmod(t1, w[94], w[73]);
        mulmod(t2, w[94], w[73]);
        mulmod_constant(t2, t2, two);
        submod(w[144], t1, t2);
    }

    // XOR 18 123 -> 145
    {
        bn254fr_class t1, t2;
        addmod(t1, w[18], w[123]);
        mulmod(t2, w[18], w[123]);
        mulmod_constant(t2, t2, two);
        submod(w[145], t1, t2);
    }

    // AND 94 12 -> 146
    mulmod(w[146], w[94], w[12]);

    // AND 118 80 -> 147
    mulmod(w[147], w[118], w[80]);

    // INV 7 -> 148
    submod(w[148], one, w[7]);

    // XOR 6 96 -> 149
    {
        bn254fr_class t1, t2;
        addmod(t1, w[6], w[96]);
        mulmod(t2, w[6], w[96]);
        mulmod_constant(t2, t2, two);
        submod(w[149], t1, t2);
    }

    // AND 30 48 -> 150
    mulmod(w[150], w[30], w[48]);

    // XOR 124 64 -> 151
    {
        bn254fr_class t1, t2;
        addmod(t1, w[124], w[64]);
        mulmod(t2, w[124], w[64]);
        mulmod_constant(t2, t2, two);
        submod(w[151], t1, t2);
    }

    // INV 102 -> 152
    submod(w[152], one, w[102]);

    // AND 89 127 -> 153
    mulmod(w[153], w[89], w[127]);

    // AND 33 93 -> 154
    mulmod(w[154], w[33], w[93]);

    // XOR 43 115 -> 155
    {
        bn254fr_class t1, t2;
        addmod(t1, w[43], w[115]);
        mulmod(t2, w[43], w[115]);
        mulmod_constant(t2, t2, two);
        submod(w[155], t1, t2);
    }

    // AND 39 33 -> 156
    mulmod(w[156], w[39], w[33]);

    // AND 80 126 -> 157
    mulmod(w[157], w[80], w[126]);

    // XOR 120 120 -> 158
    {
        bn254fr_class t1, t2;
        addmod(t1, w[120], w[120]);
        mulmod(t2, w[120], w[120]);
        mulmod_constant(t2, t2, two);
        submod(w[158], t1, t2);
    }

    // AND 49 114 -> 159
    mulmod(w[159], w[49], w[114]);

    // AND 103 52 -> 160
    mulmod(w[160], w[103], w[52]);

    // AND 124 56 -> 161
    mulmod(w[161], w[124], w[56]);

    // XOR 47 14 -> 162
    {
        bn254fr_class t1, t2;
        addmod(t1, w[47], w[14]);
        mulmod(t2, w[47], w[14]);
        mulmod_constant(t2, t2, two);
        submod(w[162], t1, t2);
    }

    // AND 89 48 -> 163
    mulmod(w[163], w[89], w[48]);

    // AND 96 0 -> 164
    mulmod(w[164], w[96], w[0]);

    // XOR 2 9 -> 165
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2], w[9]);
        mulmod(t2, w[2], w[9]);
        mulmod_constant(t2, t2, two);
        submod(w[165], t1, t2);
    }

    // INV 120 -> 166
    submod(w[166], one, w[120]);

    // XOR 114 85 -> 167
    {
        bn254fr_class t1, t2;
        addmod(t1, w[114], w[85]);
        mulmod(t2, w[114], w[85]);
        mulmod_constant(t2, t2, two);
        submod(w[167], t1, t2);
    }

    // AND 50 0 -> 168
    mulmod(w[168], w[50], w[0]);

    // XOR 97 98 -> 169
    {
        bn254fr_class t1, t2;
        addmod(t1, w[97], w[98]);
        mulmod(t2, w[97], w[98]);
        mulmod_constant(t2, t2, two);
        submod(w[169], t1, t2);
    }

    // AND 21 25 -> 170
    mulmod(w[170], w[21], w[25]);

    // XOR 58 28 -> 171
    {
        bn254fr_class t1, t2;
        addmod(t1, w[58], w[28]);
        mulmod(t2, w[58], w[28]);
        mulmod_constant(t2, t2, two);
        submod(w[171], t1, t2);
    }

    // INV 102 -> 172
    submod(w[172], one, w[102]);

    // XOR 16 115 -> 173
    {
        bn254fr_class t1, t2;
        addmod(t1, w[16], w[115]);
        mulmod(t2, w[16], w[115]);
        mulmod_constant(t2, t2, two);
        submod(w[173], t1, t2);
    }

    // XOR 126 8 -> 174
    {
        bn254fr_class t1, t2;
        addmod(t1, w[126], w[8]);
        mulmod(t2, w[126], w[8]);
        mulmod_constant(t2, t2, two);
        submod(w[174], t1, t2);
    }

    // XOR 47 33 -> 175
    {
        bn254fr_class t1, t2;
        addmod(t1, w[47], w[33]);
        mulmod(t2, w[47], w[33]);
        mulmod_constant(t2, t2, two);
        submod(w[175], t1, t2);
    }

    // XOR 92 97 -> 176
    {
        bn254fr_class t1, t2;
        addmod(t1, w[92], w[97]);
        mulmod(t2, w[92], w[97]);
        mulmod_constant(t2, t2, two);
        submod(w[176], t1, t2);
    }

    // AND 29 88 -> 177
    mulmod(w[177], w[29], w[88]);

    // AND 23 71 -> 178
    mulmod(w[178], w[23], w[71]);

    // AND 64 96 -> 179
    mulmod(w[179], w[64], w[96]);

    // XOR 46 27 -> 180
    {
        bn254fr_class t1, t2;
        addmod(t1, w[46], w[27]);
        mulmod(t2, w[46], w[27]);
        mulmod_constant(t2, t2, two);
        submod(w[180], t1, t2);
    }

    // XOR 15 4 -> 181
    {
        bn254fr_class t1, t2;
        addmod(t1, w[15], w[4]);
        mulmod(t2, w[15], w[4]);
        mulmod_constant(t2, t2, two);
        submod(w[181], t1, t2);
    }

    // AND 117 4 -> 182
    mulmod(w[182], w[117], w[4]);

    // INV 16 -> 183
    submod(w[183], one, w[16]);

    // XOR 73 34 -> 184
    {
        bn254fr_class t1, t2;
        addmod(t1, w[73], w[34]);
        mulmod(t2, w[73], w[34]);
        mulmod_constant(t2, t2, two);
        submod(w[184], t1, t2);
    }

    // AND 28 7 -> 185
    mulmod(w[185], w[28], w[7]);

    // AND 114 110 -> 186
    mulmod(w[186], w[114], w[110]);

    // XOR 93 51 -> 187
    {
        bn254fr_class t1, t2;
        addmod(t1, w[93], w[51]);
        mulmod(t2, w[93], w[51]);
        mulmod_constant(t2, t2, two);
        submod(w[187], t1, t2);
    }

    // AND 86 82 -> 188
    mulmod(w[188], w[86], w[82]);

    // XOR 125 121 -> 189
    {
        bn254fr_class t1, t2;
        addmod(t1, w[125], w[121]);
        mulmod(t2, w[125], w[121]);
        mulmod_constant(t2, t2, two);
        submod(w[189], t1, t2);
    }

    // XOR 38 95 -> 190
    {
        bn254fr_class t1, t2;
        addmod(t1, w[38], w[95]);
        mulmod(t2, w[38], w[95]);
        mulmod_constant(t2, t2, two);
        submod(w[190], t1, t2);
    }

    // XOR 33 37 -> 191
    {
        bn254fr_class t1, t2;
        addmod(t1, w[33], w[37]);
        mulmod(t2, w[33], w[37]);
        mulmod_constant(t2, t2, two);
        submod(w[191], t1, t2);
    }

    // AND 95 70 -> 192
    mulmod(w[192], w[95], w[70]);

    // XOR 33 107 -> 193
    {
        bn254fr_class t1, t2;
        addmod(t1, w[33], w[107]);
        mulmod(t2, w[33], w[107]);
        mulmod_constant(t2, t2, two);
        submod(w[193], t1, t2);
    }

    // AND 38 41 -> 194
    mulmod(w[194], w[38], w[41]);

    // XOR 127 89 -> 195
    {
        bn254fr_class t1, t2;
        addmod(t1, w[127], w[89]);
        mulmod(t2, w[127], w[89]);
        mulmod_constant(t2, t2, two);
        submod(w[195], t1, t2);
    }

    // AND 2 118 -> 196
    mulmod(w[196], w[2], w[118]);

    // AND 100 78 -> 197
    mulmod(w[197], w[100], w[78]);

    // AND 117 27 -> 198
    mulmod(w[198], w[117], w[27]);

    // INV 59 -> 199
    submod(w[199], one, w[59]);

    // AND 71 100 -> 200
    mulmod(w[200], w[71], w[100]);

    // XOR 34 92 -> 201
    {
        bn254fr_class t1, t2;
        addmod(t1, w[34], w[92]);
        mulmod(t2, w[34], w[92]);
        mulmod_constant(t2, t2, two);
        submod(w[201], t1, t2);
    }

    // AND 71 102 -> 202
    mulmod(w[202], w[71], w[102]);

    // AND 104 60 -> 203
    mulmod(w[203], w[104], w[60]);

    // INV 85 -> 204
    submod(w[204], one, w[85]);

    // XOR 21 105 -> 205
    {
        bn254fr_class t1, t2;
        addmod(t1, w[21], w[105]);
        mulmod(t2, w[21], w[105]);
        mulmod_constant(t2, t2, two);
        submod(w[205], t1, t2);
    }

    // INV 62 -> 206
    submod(w[206], one, w[62]);

    // XOR 10 58 -> 207
    {
        bn254fr_class t1, t2;
        addmod(t1, w[10], w[58]);
        mulmod(t2, w[10], w[58]);
        mulmod_constant(t2, t2, two);
        submod(w[207], t1, t2);
    }

    // AND 63 25 -> 208
    mulmod(w[208], w[63], w[25]);

    // XOR 53 108 -> 209
    {
        bn254fr_class t1, t2;
        addmod(t1, w[53], w[108]);
        mulmod(t2, w[53], w[108]);
        mulmod_constant(t2, t2, two);
        submod(w[209], t1, t2);
    }

    // AND 83 18 -> 210
    mulmod(w[210], w[83], w[18]);

    // XOR 24 104 -> 211
    {
        bn254fr_class t1, t2;
        addmod(t1, w[24], w[104]);
        mulmod(t2, w[24], w[104]);
        mulmod_constant(t2, t2, two);
        submod(w[211], t1, t2);
    }

    // AND 97 102 -> 212
    mulmod(w[212], w[97], w[102]);

    // XOR 53 119 -> 213
    {
        bn254fr_class t1, t2;
        addmod(t1, w[53], w[119]);
        mulmod(t2, w[53], w[119]);
        mulmod_constant(t2, t2, two);
        submod(w[213], t1, t2);
    }

    // XOR 38 77 -> 214
    {
        bn254fr_class t1, t2;
        addmod(t1, w[38], w[77]);
        mulmod(t2, w[38], w[77]);
        mulmod_constant(t2, t2, two);
        submod(w[214], t1, t2);
    }

    // XOR 1 63 -> 215
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1], w[63]);
        mulmod(t2, w[1], w[63]);
        mulmod_constant(t2, t2, two);
        submod(w[215], t1, t2);
    }

    // AND 33 98 -> 216
    mulmod(w[216], w[33], w[98]);

    // AND 99 106 -> 217
    mulmod(w[217], w[99], w[106]);

    // XOR 41 32 -> 218
    {
        bn254fr_class t1, t2;
        addmod(t1, w[41], w[32]);
        mulmod(t2, w[41], w[32]);
        mulmod_constant(t2, t2, two);
        submod(w[218], t1, t2);
    }

    // AND 10 4 -> 219
    mulmod(w[219], w[10], w[4]);

    // AND 116 71 -> 220
    mulmod(w[220], w[116], w[71]);

    // XOR 55 92 -> 221
    {
        bn254fr_class t1, t2;
        addmod(t1, w[55], w[92]);
        mulmod(t2, w[55], w[92]);
        mulmod_constant(t2, t2, two);
        submod(w[221], t1, t2);
    }

    // XOR 96 68 -> 222
    {
        bn254fr_class t1, t2;
        addmod(t1, w[96], w[68]);
        mulmod(t2, w[96], w[68]);
        mulmod_constant(t2, t2, two);
        submod(w[222], t1, t2);
    }

    // AND 64 100 -> 223
    mulmod(w[223], w[64], w[100]);

    // AND 85 101 -> 224
    mulmod(w[224], w[85], w[101]);

    // AND 59 6 -> 225
    mulmod(w[225], w[59], w[6]);

    // XOR 86 10 -> 226
    {
        bn254fr_class t1, t2;
        addmod(t1, w[86], w[10]);
        mulmod(t2, w[86], w[10]);
        mulmod_constant(t2, t2, two);
        submod(w[226], t1, t2);
    }

    // AND 49 60 -> 227
    mulmod(w[227], w[49], w[60]);

    // XOR 20 113 -> 228
    {
        bn254fr_class t1, t2;
        addmod(t1, w[20], w[113]);
        mulmod(t2, w[20], w[113]);
        mulmod_constant(t2, t2, two);
        submod(w[228], t1, t2);
    }

    // AND 6 6 -> 229
    mulmod(w[229], w[6], w[6]);

    // XOR 63 97 -> 230
    {
        bn254fr_class t1, t2;
        addmod(t1, w[63], w[97]);
        mulmod(t2, w[63], w[97]);
        mulmod_constant(t2, t2, two);
        submod(w[230], t1, t2);
    }

    // AND 13 82 -> 231
    mulmod(w[231], w[13], w[82]);

    // XOR 34 0 -> 232
    {
        bn254fr_class t1, t2;
        addmod(t1, w[34], w[0]);
        mulmod(t2, w[34], w[0]);
        mulmod_constant(t2, t2, two);
        submod(w[232], t1, t2);
    }

    // XOR 28 53 -> 233
    {
        bn254fr_class t1, t2;
        addmod(t1, w[28], w[53]);
        mulmod(t2, w[28], w[53]);
        mulmod_constant(t2, t2, two);
        submod(w[233], t1, t2);
    }

    // INV 116 -> 234
    submod(w[234], one, w[116]);

    // AND 18 97 -> 235
    mulmod(w[235], w[18], w[97]);

    // INV 96 -> 236
    submod(w[236], one, w[96]);

    // AND 30 36 -> 237
    mulmod(w[237], w[30], w[36]);

    // AND 56 53 -> 238
    mulmod(w[238], w[56], w[53]);

    // XOR 122 62 -> 239
    {
        bn254fr_class t1, t2;
        addmod(t1, w[122], w[62]);
        mulmod(t2, w[122], w[62]);
        mulmod_constant(t2, t2, two);
        submod(w[239], t1, t2);
    }

    // AND 9 44 -> 240
    mulmod(w[240], w[9], w[44]);

    // INV 112 -> 241
    submod(w[241], one, w[112]);

    // XOR 42 85 -> 242
    {
        bn254fr_class t1, t2;
        addmod(t1, w[42], w[85]);
        mulmod(t2, w[42], w[85]);
        mulmod_constant(t2, t2, two);
        submod(w[242], t1, t2);
    }

    // AND 102 19 -> 243
    mulmod(w[243], w[102], w[19]);

    // AND 33 101 -> 244
    mulmod(w[244], w[33], w[101]);

    // AND 39 121 -> 245
    mulmod(w[245], w[39], w[121]);

    // AND 25 89 -> 246
    mulmod(w[246], w[25], w[89]);

    // AND 32 18 -> 247
    mulmod(w[247], w[32], w[18]);

    // XOR 127 85 -> 248
    {
        bn254fr_class t1, t2;
        addmod(t1, w[127], w[85]);
        mulmod(t2, w[127], w[85]);
        mulmod_constant(t2, t2, two);
        submod(w[248], t1, t2);
    }

    // XOR 17 63 -> 249
    {
        bn254fr_class t1, t2;
        addmod(t1, w[17], w[63]);
        mulmod(t2, w[17], w[63]);
        mulmod_constant(t2, t2, two);
        submod(w[249], t1, t2);
    }

    // AND 51 62 -> 250
    mulmod(w[250], w[51], w[62]);

    // XOR 33 74 -> 251
    {
        bn254fr_class t1, t2;
        addmod(t1, w[33], w[74]);
        mulmod(t2, w[33], w[74]);
        mulmod_constant(t2, t2, two);
        submod(w[251], t1, t2);
    }

    // XOR 63 112 -> 252
    {
        bn254fr_class t1, t2;
        addmod(t1, w[63], w[112]);
        mulmod(t2, w[63], w[112]);
        mulmod_constant(t2, t2, two);
        submod(w[252], t1, t2);
    }

    // AND 89 5 -> 253
    mulmod(w[253], w[89], w[5]);

    // XOR 230 124 -> 254
    {
        bn254fr_class t1, t2;
        addmod(t1, w[230], w[124]);
        mulmod(t2, w[230], w[124]);
        mulmod_constant(t2, t2, two);
        submod(w[254], t1, t2);
    }

    // XOR 129 161 -> 255
    {
        bn254fr_class t1, t2;
        addmod(t1, w[129], w[161]);
        mulmod(t2, w[129], w[161]);
        mulmod_constant(t2, t2, two);
        submod(w[255], t1, t2);
    }

    // AND 225 80 -> 256
    mulmod(w[256], w[225], w[80]);

    // AND 32 2 -> 257
    mulmod(w[257], w[32], w[2]);

    // XOR 131 33 -> 258
    {
        bn254fr_class t1, t2;
        addmod(t1, w[131], w[33]);
        mulmod(t2, w[131], w[33]);
        mulmod_constant(t2, t2, two);
        submod(w[258], t1, t2);
    }

    // AND 248 186 -> 259
    mulmod(w[259], w[248], w[186]);

    // XOR 119 94 -> 260
    {
        bn254fr_class t1, t2;
        addmod(t1, w[119], w[94]);
        mulmod(t2, w[119], w[94]);
        mulmod_constant(t2, t2, two);
        submod(w[260], t1, t2);
    }

    // AND 88 220 -> 261
    mulmod(w[261], w[88], w[220]);

    // XOR 84 239 -> 262
    {
        bn254fr_class t1, t2;
        addmod(t1, w[84], w[239]);
        mulmod(t2, w[84], w[239]);
        mulmod_constant(t2, t2, two);
        submod(w[262], t1, t2);
    }

    // XOR 191 74 -> 263
    {
        bn254fr_class t1, t2;
        addmod(t1, w[191], w[74]);
        mulmod(t2, w[191], w[74]);
        mulmod_constant(t2, t2, two);
        submod(w[263], t1, t2);
    }

    // XOR 38 142 -> 264
    {
        bn254fr_class t1, t2;
        addmod(t1, w[38], w[142]);
        mulmod(t2, w[38], w[142]);
        mulmod_constant(t2, t2, two);
        submod(w[264], t1, t2);
    }

    // XOR 160 105 -> 265
    {
        bn254fr_class t1, t2;
        addmod(t1, w[160], w[105]);
        mulmod(t2, w[160], w[105]);
        mulmod_constant(t2, t2, two);
        submod(w[265], t1, t2);
    }

    // XOR 164 8 -> 266
    {
        bn254fr_class t1, t2;
        addmod(t1, w[164], w[8]);
        mulmod(t2, w[164], w[8]);
        mulmod_constant(t2, t2, two);
        submod(w[266], t1, t2);
    }

    // XOR 69 59 -> 267
    {
        bn254fr_class t1, t2;
        addmod(t1, w[69], w[59]);
        mulmod(t2, w[69], w[59]);
        mulmod_constant(t2, t2, two);
        submod(w[267], t1, t2);
    }

    // AND 23 44 -> 268
    mulmod(w[268], w[23], w[44]);

    // XOR 215 231 -> 269
    {
        bn254fr_class t1, t2;
        addmod(t1, w[215], w[231]);
        mulmod(t2, w[215], w[231]);
        mulmod_constant(t2, t2, two);
        submod(w[269], t1, t2);
    }

    // INV 141 -> 270
    submod(w[270], one, w[141]);

    // XOR 18 23 -> 271
    {
        bn254fr_class t1, t2;
        addmod(t1, w[18], w[23]);
        mulmod(t2, w[18], w[23]);
        mulmod_constant(t2, t2, two);
        submod(w[271], t1, t2);
    }

    // XOR 151 185 -> 272
    {
        bn254fr_class t1, t2;
        addmod(t1, w[151], w[185]);
        mulmod(t2, w[151], w[185]);
        mulmod_constant(t2, t2, two);
        submod(w[272], t1, t2);
    }

    // XOR 65 50 -> 273
    {
        bn254fr_class t1, t2;
        addmod(t1, w[65], w[50]);
        mulmod(t2, w[65], w[50]);
        mulmod_constant(t2, t2, two);
        submod(w[273], t1, t2);
    }

    // XOR 201 11 -> 274
    {
        bn254fr_class t1, t2;
        addmod(t1, w[201], w[11]);
        mulmod(t2, w[201], w[11]);
        mulmod_constant(t2, t2, two);
        submod(w[274], t1, t2);
    }

    // AND 119 77 -> 275
    mulmod(w[275], w[119], w[77]);

    // AND 187 43 -> 276
    mulmod(w[276], w[187], w[43]);

    // AND 18 0 -> 277
    mulmod(w[277], w[18], w[0]);

    // XOR 47 119 -> 278
    {
        bn254fr_class t1, t2;
        addmod(t1, w[47], w[119]);
        mulmod(t2, w[47], w[119]);
        mulmod_constant(t2, t2, two);
        submod(w[278], t1, t2);
    }

    // AND 243 191 -> 279
    mulmod(w[279], w[243], w[191]);

    // AND 175 175 -> 280
    mulmod(w[280], w[175], w[175]);

    // XOR 203 36 -> 281
    {
        bn254fr_class t1, t2;
        addmod(t1, w[203], w[36]);
        mulmod(t2, w[203], w[36]);
        mulmod_constant(t2, t2, two);
        submod(w[281], t1, t2);
    }

    // AND 242 27 -> 282
    mulmod(w[282], w[242], w[27]);

    // INV 2 -> 283
    submod(w[283], one, w[2]);

    // INV 68 -> 284
    submod(w[284], one, w[68]);

    // XOR 137 6 -> 285
    {
        bn254fr_class t1, t2;
        addmod(t1, w[137], w[6]);
        mulmod(t2, w[137], w[6]);
        mulmod_constant(t2, t2, two);
        submod(w[285], t1, t2);
    }

    // XOR 79 249 -> 286
    {
        bn254fr_class t1, t2;
        addmod(t1, w[79], w[249]);
        mulmod(t2, w[79], w[249]);
        mulmod_constant(t2, t2, two);
        submod(w[286], t1, t2);
    }

    // AND 234 9 -> 287
    mulmod(w[287], w[234], w[9]);

    // XOR 143 230 -> 288
    {
        bn254fr_class t1, t2;
        addmod(t1, w[143], w[230]);
        mulmod(t2, w[143], w[230]);
        mulmod_constant(t2, t2, two);
        submod(w[288], t1, t2);
    }

    // XOR 88 192 -> 289
    {
        bn254fr_class t1, t2;
        addmod(t1, w[88], w[192]);
        mulmod(t2, w[88], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[289], t1, t2);
    }

    // XOR 199 125 -> 290
    {
        bn254fr_class t1, t2;
        addmod(t1, w[199], w[125]);
        mulmod(t2, w[199], w[125]);
        mulmod_constant(t2, t2, two);
        submod(w[290], t1, t2);
    }

    // AND 97 83 -> 291
    mulmod(w[291], w[97], w[83]);

    // INV 190 -> 292
    submod(w[292], one, w[190]);

    // XOR 32 196 -> 293
    {
        bn254fr_class t1, t2;
        addmod(t1, w[32], w[196]);
        mulmod(t2, w[32], w[196]);
        mulmod_constant(t2, t2, two);
        submod(w[293], t1, t2);
    }

    // XOR 148 36 -> 294
    {
        bn254fr_class t1, t2;
        addmod(t1, w[148], w[36]);
        mulmod(t2, w[148], w[36]);
        mulmod_constant(t2, t2, two);
        submod(w[294], t1, t2);
    }

    // XOR 62 159 -> 295
    {
        bn254fr_class t1, t2;
        addmod(t1, w[62], w[159]);
        mulmod(t2, w[62], w[159]);
        mulmod_constant(t2, t2, two);
        submod(w[295], t1, t2);
    }

    // XOR 60 248 -> 296
    {
        bn254fr_class t1, t2;
        addmod(t1, w[60], w[248]);
        mulmod(t2, w[60], w[248]);
        mulmod_constant(t2, t2, two);
        submod(w[296], t1, t2);
    }

    // XOR 57 107 -> 297
    {
        bn254fr_class t1, t2;
        addmod(t1, w[57], w[107]);
        mulmod(t2, w[57], w[107]);
        mulmod_constant(t2, t2, two);
        submod(w[297], t1, t2);
    }

    // AND 84 98 -> 298
    mulmod(w[298], w[84], w[98]);

    // XOR 15 148 -> 299
    {
        bn254fr_class t1, t2;
        addmod(t1, w[15], w[148]);
        mulmod(t2, w[15], w[148]);
        mulmod_constant(t2, t2, two);
        submod(w[299], t1, t2);
    }

    // AND 78 204 -> 300
    mulmod(w[300], w[78], w[204]);

    // XOR 88 36 -> 301
    {
        bn254fr_class t1, t2;
        addmod(t1, w[88], w[36]);
        mulmod(t2, w[88], w[36]);
        mulmod_constant(t2, t2, two);
        submod(w[301], t1, t2);
    }

    // XOR 217 29 -> 302
    {
        bn254fr_class t1, t2;
        addmod(t1, w[217], w[29]);
        mulmod(t2, w[217], w[29]);
        mulmod_constant(t2, t2, two);
        submod(w[302], t1, t2);
    }

    // AND 57 8 -> 303
    mulmod(w[303], w[57], w[8]);

    // AND 208 207 -> 304
    mulmod(w[304], w[208], w[207]);

    // XOR 247 45 -> 305
    {
        bn254fr_class t1, t2;
        addmod(t1, w[247], w[45]);
        mulmod(t2, w[247], w[45]);
        mulmod_constant(t2, t2, two);
        submod(w[305], t1, t2);
    }

    // AND 122 216 -> 306
    mulmod(w[306], w[122], w[216]);

    // XOR 9 125 -> 307
    {
        bn254fr_class t1, t2;
        addmod(t1, w[9], w[125]);
        mulmod(t2, w[9], w[125]);
        mulmod_constant(t2, t2, two);
        submod(w[307], t1, t2);
    }

    // XOR 60 222 -> 308
    {
        bn254fr_class t1, t2;
        addmod(t1, w[60], w[222]);
        mulmod(t2, w[60], w[222]);
        mulmod_constant(t2, t2, two);
        submod(w[308], t1, t2);
    }

    // XOR 46 194 -> 309
    {
        bn254fr_class t1, t2;
        addmod(t1, w[46], w[194]);
        mulmod(t2, w[46], w[194]);
        mulmod_constant(t2, t2, two);
        submod(w[309], t1, t2);
    }

    // XOR 217 162 -> 310
    {
        bn254fr_class t1, t2;
        addmod(t1, w[217], w[162]);
        mulmod(t2, w[217], w[162]);
        mulmod_constant(t2, t2, two);
        submod(w[310], t1, t2);
    }

    // AND 95 98 -> 311
    mulmod(w[311], w[95], w[98]);

    // XOR 40 223 -> 312
    {
        bn254fr_class t1, t2;
        addmod(t1, w[40], w[223]);
        mulmod(t2, w[40], w[223]);
        mulmod_constant(t2, t2, two);
        submod(w[312], t1, t2);
    }

    // XOR 73 19 -> 313
    {
        bn254fr_class t1, t2;
        addmod(t1, w[73], w[19]);
        mulmod(t2, w[73], w[19]);
        mulmod_constant(t2, t2, two);
        submod(w[313], t1, t2);
    }

    // AND 232 239 -> 314
    mulmod(w[314], w[232], w[239]);

    // AND 130 242 -> 315
    mulmod(w[315], w[130], w[242]);

    // AND 6 244 -> 316
    mulmod(w[316], w[6], w[244]);

    // AND 202 81 -> 317
    mulmod(w[317], w[202], w[81]);

    // XOR 205 86 -> 318
    {
        bn254fr_class t1, t2;
        addmod(t1, w[205], w[86]);
        mulmod(t2, w[205], w[86]);
        mulmod_constant(t2, t2, two);
        submod(w[318], t1, t2);
    }

    // AND 197 176 -> 319
    mulmod(w[319], w[197], w[176]);

    // XOR 175 108 -> 320
    {
        bn254fr_class t1, t2;
        addmod(t1, w[175], w[108]);
        mulmod(t2, w[175], w[108]);
        mulmod_constant(t2, t2, two);
        submod(w[320], t1, t2);
    }

    // XOR 61 60 -> 321
    {
        bn254fr_class t1, t2;
        addmod(t1, w[61], w[60]);
        mulmod(t2, w[61], w[60]);
        mulmod_constant(t2, t2, two);
        submod(w[321], t1, t2);
    }

    // AND 245 227 -> 322
    mulmod(w[322], w[245], w[227]);

    // INV 182 -> 323
    submod(w[323], one, w[182]);

    // XOR 204 10 -> 324
    {
        bn254fr_class t1, t2;
        addmod(t1, w[204], w[10]);
        mulmod(t2, w[204], w[10]);
        mulmod_constant(t2, t2, two);
        submod(w[324], t1, t2);
    }

    // AND 0 37 -> 325
    mulmod(w[325], w[0], w[37]);

    // INV 189 -> 326
    submod(w[326], one, w[189]);

    // XOR 86 42 -> 327
    {
        bn254fr_class t1, t2;
        addmod(t1, w[86], w[42]);
        mulmod(t2, w[86], w[42]);
        mulmod_constant(t2, t2, two);
        submod(w[327], t1, t2);
    }

    // AND 221 232 -> 328
    mulmod(w[328], w[221], w[232]);

    // XOR 63 181 -> 329
    {
        bn254fr_class t1, t2;
        addmod(t1, w[63], w[181]);
        mulmod(t2, w[63], w[181]);
        mulmod_constant(t2, t2, two);
        submod(w[329], t1, t2);
    }

    // XOR 149 184 -> 330
    {
        bn254fr_class t1, t2;
        addmod(t1, w[149], w[184]);
        mulmod(t2, w[149], w[184]);
        mulmod_constant(t2, t2, two);
        submod(w[330], t1, t2);
    }

    // XOR 148 236 -> 331
    {
        bn254fr_class t1, t2;
        addmod(t1, w[148], w[236]);
        mulmod(t2, w[148], w[236]);
        mulmod_constant(t2, t2, two);
        submod(w[331], t1, t2);
    }

    // INV 66 -> 332
    submod(w[332], one, w[66]);

    // AND 240 229 -> 333
    mulmod(w[333], w[240], w[229]);

    // XOR 226 167 -> 334
    {
        bn254fr_class t1, t2;
        addmod(t1, w[226], w[167]);
        mulmod(t2, w[226], w[167]);
        mulmod_constant(t2, t2, two);
        submod(w[334], t1, t2);
    }

    // AND 129 49 -> 335
    mulmod(w[335], w[129], w[49]);

    // XOR 140 188 -> 336
    {
        bn254fr_class t1, t2;
        addmod(t1, w[140], w[188]);
        mulmod(t2, w[140], w[188]);
        mulmod_constant(t2, t2, two);
        submod(w[336], t1, t2);
    }

    // XOR 216 18 -> 337
    {
        bn254fr_class t1, t2;
        addmod(t1, w[216], w[18]);
        mulmod(t2, w[216], w[18]);
        mulmod_constant(t2, t2, two);
        submod(w[337], t1, t2);
    }

    // XOR 182 157 -> 338
    {
        bn254fr_class t1, t2;
        addmod(t1, w[182], w[157]);
        mulmod(t2, w[182], w[157]);
        mulmod_constant(t2, t2, two);
        submod(w[338], t1, t2);
    }

    // AND 80 178 -> 339
    mulmod(w[339], w[80], w[178]);

    // XOR 143 139 -> 340
    {
        bn254fr_class t1, t2;
        addmod(t1, w[143], w[139]);
        mulmod(t2, w[143], w[139]);
        mulmod_constant(t2, t2, two);
        submod(w[340], t1, t2);
    }

    // AND 142 87 -> 341
    mulmod(w[341], w[142], w[87]);

    // AND 92 118 -> 342
    mulmod(w[342], w[92], w[118]);

    // XOR 206 93 -> 343
    {
        bn254fr_class t1, t2;
        addmod(t1, w[206], w[93]);
        mulmod(t2, w[206], w[93]);
        mulmod_constant(t2, t2, two);
        submod(w[343], t1, t2);
    }

    // AND 0 21 -> 344
    mulmod(w[344], w[0], w[21]);

    // AND 35 128 -> 345
    mulmod(w[345], w[35], w[128]);

    // XOR 11 109 -> 346
    {
        bn254fr_class t1, t2;
        addmod(t1, w[11], w[109]);
        mulmod(t2, w[11], w[109]);
        mulmod_constant(t2, t2, two);
        submod(w[346], t1, t2);
    }

    // AND 204 110 -> 347
    mulmod(w[347], w[204], w[110]);

    // XOR 2 239 -> 348
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2], w[239]);
        mulmod(t2, w[2], w[239]);
        mulmod_constant(t2, t2, two);
        submod(w[348], t1, t2);
    }

    // XOR 134 142 -> 349
    {
        bn254fr_class t1, t2;
        addmod(t1, w[134], w[142]);
        mulmod(t2, w[134], w[142]);
        mulmod_constant(t2, t2, two);
        submod(w[349], t1, t2);
    }

    // XOR 77 71 -> 350
    {
        bn254fr_class t1, t2;
        addmod(t1, w[77], w[71]);
        mulmod(t2, w[77], w[71]);
        mulmod_constant(t2, t2, two);
        submod(w[350], t1, t2);
    }

    // AND 222 151 -> 351
    mulmod(w[351], w[222], w[151]);

    // XOR 205 33 -> 352
    {
        bn254fr_class t1, t2;
        addmod(t1, w[205], w[33]);
        mulmod(t2, w[205], w[33]);
        mulmod_constant(t2, t2, two);
        submod(w[352], t1, t2);
    }

    // XOR 30 21 -> 353
    {
        bn254fr_class t1, t2;
        addmod(t1, w[30], w[21]);
        mulmod(t2, w[30], w[21]);
        mulmod_constant(t2, t2, two);
        submod(w[353], t1, t2);
    }

    // XOR 137 23 -> 354
    {
        bn254fr_class t1, t2;
        addmod(t1, w[137], w[23]);
        mulmod(t2, w[137], w[23]);
        mulmod_constant(t2, t2, two);
        submod(w[354], t1, t2);
    }

    // AND 236 5 -> 355
    mulmod(w[355], w[236], w[5]);

    // XOR 172 106 -> 356
    {
        bn254fr_class t1, t2;
        addmod(t1, w[172], w[106]);
        mulmod(t2, w[172], w[106]);
        mulmod_constant(t2, t2, two);
        submod(w[356], t1, t2);
    }

    // INV 219 -> 357
    submod(w[357], one, w[219]);

    // AND 163 151 -> 358
    mulmod(w[358], w[163], w[151]);

    // XOR 95 151 -> 359
    {
        bn254fr_class t1, t2;
        addmod(t1, w[95], w[151]);
        mulmod(t2, w[95], w[151]);
        mulmod_constant(t2, t2, two);
        submod(w[359], t1, t2);
    }

    // XOR 29 124 -> 360
    {
        bn254fr_class t1, t2;
        addmod(t1, w[29], w[124]);
        mulmod(t2, w[29], w[124]);
        mulmod_constant(t2, t2, two);
        submod(w[360], t1, t2);
    }

    // AND 228 6 -> 361
    mulmod(w[361], w[228], w[6]);

    // XOR 192 74 -> 362
    {
        bn254fr_class t1, t2;
        addmod(t1, w[192], w[74]);
        mulmod(t2, w[192], w[74]);
        mulmod_constant(t2, t2, two);
        submod(w[362], t1, t2);
    }

    // XOR 89 161 -> 363
    {
        bn254fr_class t1, t2;
        addmod(t1, w[89], w[161]);
        mulmod(t2, w[89], w[161]);
        mulmod_constant(t2, t2, two);
        submod(w[363], t1, t2);
    }

    // XOR 164 240 -> 364
    {
        bn254fr_class t1, t2;
        addmod(t1, w[164], w[240]);
        mulmod(t2, w[164], w[240]);
        mulmod_constant(t2, t2, two);
        submod(w[364], t1, t2);
    }

    // AND 239 8 -> 365
    mulmod(w[365], w[239], w[8]);

    // AND 160 61 -> 366
    mulmod(w[366], w[160], w[61]);

    // XOR 137 236 -> 367
    {
        bn254fr_class t1, t2;
        addmod(t1, w[137], w[236]);
        mulmod(t2, w[137], w[236]);
        mulmod_constant(t2, t2, two);
        submod(w[367], t1, t2);
    }

    // XOR 36 112 -> 368
    {
        bn254fr_class t1, t2;
        addmod(t1, w[36], w[112]);
        mulmod(t2, w[36], w[112]);
        mulmod_constant(t2, t2, two);
        submod(w[368], t1, t2);
    }

    // AND 144 314 -> 369
    mulmod(w[369], w[144], w[314]);

    // AND 169 173 -> 370
    mulmod(w[370], w[169], w[173]);

    // XOR 125 89 -> 371
    {
        bn254fr_class t1, t2;
        addmod(t1, w[125], w[89]);
        mulmod(t2, w[125], w[89]);
        mulmod_constant(t2, t2, two);
        submod(w[371], t1, t2);
    }

    // XOR 60 77 -> 372
    {
        bn254fr_class t1, t2;
        addmod(t1, w[60], w[77]);
        mulmod(t2, w[60], w[77]);
        mulmod_constant(t2, t2, two);
        submod(w[372], t1, t2);
    }

    // AND 243 85 -> 373
    mulmod(w[373], w[243], w[85]);

    // XOR 241 307 -> 374
    {
        bn254fr_class t1, t2;
        addmod(t1, w[241], w[307]);
        mulmod(t2, w[241], w[307]);
        mulmod_constant(t2, t2, two);
        submod(w[374], t1, t2);
    }

    // XOR 171 69 -> 375
    {
        bn254fr_class t1, t2;
        addmod(t1, w[171], w[69]);
        mulmod(t2, w[171], w[69]);
        mulmod_constant(t2, t2, two);
        submod(w[375], t1, t2);
    }

    // AND 260 141 -> 376
    mulmod(w[376], w[260], w[141]);

    // AND 246 11 -> 377
    mulmod(w[377], w[246], w[11]);

    // XOR 20 38 -> 378
    {
        bn254fr_class t1, t2;
        addmod(t1, w[20], w[38]);
        mulmod(t2, w[20], w[38]);
        mulmod_constant(t2, t2, two);
        submod(w[378], t1, t2);
    }

    // XOR 222 336 -> 379
    {
        bn254fr_class t1, t2;
        addmod(t1, w[222], w[336]);
        mulmod(t2, w[222], w[336]);
        mulmod_constant(t2, t2, two);
        submod(w[379], t1, t2);
    }

    // XOR 148 307 -> 380
    {
        bn254fr_class t1, t2;
        addmod(t1, w[148], w[307]);
        mulmod(t2, w[148], w[307]);
        mulmod_constant(t2, t2, two);
        submod(w[380], t1, t2);
    }

    // XOR 79 98 -> 381
    {
        bn254fr_class t1, t2;
        addmod(t1, w[79], w[98]);
        mulmod(t2, w[79], w[98]);
        mulmod_constant(t2, t2, two);
        submod(w[381], t1, t2);
    }

    // XOR 254 285 -> 382
    {
        bn254fr_class t1, t2;
        addmod(t1, w[254], w[285]);
        mulmod(t2, w[254], w[285]);
        mulmod_constant(t2, t2, two);
        submod(w[382], t1, t2);
    }

    // AND 86 201 -> 383
    mulmod(w[383], w[86], w[201]);

    // AND 307 161 -> 384
    mulmod(w[384], w[307], w[161]);

    // XOR 120 244 -> 385
    {
        bn254fr_class t1, t2;
        addmod(t1, w[120], w[244]);
        mulmod(t2, w[120], w[244]);
        mulmod_constant(t2, t2, two);
        submod(w[385], t1, t2);
    }

    // INV 244 -> 386
    submod(w[386], one, w[244]);

    // XOR 215 78 -> 387
    {
        bn254fr_class t1, t2;
        addmod(t1, w[215], w[78]);
        mulmod(t2, w[215], w[78]);
        mulmod_constant(t2, t2, two);
        submod(w[387], t1, t2);
    }

    // AND 29 124 -> 388
    mulmod(w[388], w[29], w[124]);

    // XOR 318 297 -> 389
    {
        bn254fr_class t1, t2;
        addmod(t1, w[318], w[297]);
        mulmod(t2, w[318], w[297]);
        mulmod_constant(t2, t2, two);
        submod(w[389], t1, t2);
    }

    // AND 166 360 -> 390
    mulmod(w[390], w[166], w[360]);

    // XOR 39 94 -> 391
    {
        bn254fr_class t1, t2;
        addmod(t1, w[39], w[94]);
        mulmod(t2, w[39], w[94]);
        mulmod_constant(t2, t2, two);
        submod(w[391], t1, t2);
    }

    // XOR 112 135 -> 392
    {
        bn254fr_class t1, t2;
        addmod(t1, w[112], w[135]);
        mulmod(t2, w[112], w[135]);
        mulmod_constant(t2, t2, two);
        submod(w[392], t1, t2);
    }

    // XOR 19 361 -> 393
    {
        bn254fr_class t1, t2;
        addmod(t1, w[19], w[361]);
        mulmod(t2, w[19], w[361]);
        mulmod_constant(t2, t2, two);
        submod(w[393], t1, t2);
    }

    // XOR 124 233 -> 394
    {
        bn254fr_class t1, t2;
        addmod(t1, w[124], w[233]);
        mulmod(t2, w[124], w[233]);
        mulmod_constant(t2, t2, two);
        submod(w[394], t1, t2);
    }

    // AND 304 265 -> 395
    mulmod(w[395], w[304], w[265]);

    // AND 235 212 -> 396
    mulmod(w[396], w[235], w[212]);

    // AND 289 177 -> 397
    mulmod(w[397], w[289], w[177]);

    // AND 198 149 -> 398
    mulmod(w[398], w[198], w[149]);

    // XOR 28 37 -> 399
    {
        bn254fr_class t1, t2;
        addmod(t1, w[28], w[37]);
        mulmod(t2, w[28], w[37]);
        mulmod_constant(t2, t2, two);
        submod(w[399], t1, t2);
    }

    // AND 178 35 -> 400
    mulmod(w[400], w[178], w[35]);

    // AND 32 285 -> 401
    mulmod(w[401], w[32], w[285]);

    // AND 137 83 -> 402
    mulmod(w[402], w[137], w[83]);

    // XOR 103 112 -> 403
    {
        bn254fr_class t1, t2;
        addmod(t1, w[103], w[112]);
        mulmod(t2, w[103], w[112]);
        mulmod_constant(t2, t2, two);
        submod(w[403], t1, t2);
    }

    // AND 0 355 -> 404
    mulmod(w[404], w[0], w[355]);

    // XOR 265 243 -> 405
    {
        bn254fr_class t1, t2;
        addmod(t1, w[265], w[243]);
        mulmod(t2, w[265], w[243]);
        mulmod_constant(t2, t2, two);
        submod(w[405], t1, t2);
    }

    // XOR 10 262 -> 406
    {
        bn254fr_class t1, t2;
        addmod(t1, w[10], w[262]);
        mulmod(t2, w[10], w[262]);
        mulmod_constant(t2, t2, two);
        submod(w[406], t1, t2);
    }

    // AND 288 2 -> 407
    mulmod(w[407], w[288], w[2]);

    // XOR 3 347 -> 408
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3], w[347]);
        mulmod(t2, w[3], w[347]);
        mulmod_constant(t2, t2, two);
        submod(w[408], t1, t2);
    }

    // XOR 339 31 -> 409
    {
        bn254fr_class t1, t2;
        addmod(t1, w[339], w[31]);
        mulmod(t2, w[339], w[31]);
        mulmod_constant(t2, t2, two);
        submod(w[409], t1, t2);
    }

    // INV 366 -> 410
    submod(w[410], one, w[366]);

    // AND 147 16 -> 411
    mulmod(w[411], w[147], w[16]);

    // AND 244 225 -> 412
    mulmod(w[412], w[244], w[225]);

    // AND 287 244 -> 413
    mulmod(w[413], w[287], w[244]);

    // AND 318 125 -> 414
    mulmod(w[414], w[318], w[125]);

    // XOR 357 221 -> 415
    {
        bn254fr_class t1, t2;
        addmod(t1, w[357], w[221]);
        mulmod(t2, w[357], w[221]);
        mulmod_constant(t2, t2, two);
        submod(w[415], t1, t2);
    }

    // XOR 170 221 -> 416
    {
        bn254fr_class t1, t2;
        addmod(t1, w[170], w[221]);
        mulmod(t2, w[170], w[221]);
        mulmod_constant(t2, t2, two);
        submod(w[416], t1, t2);
    }

    // XOR 118 339 -> 417
    {
        bn254fr_class t1, t2;
        addmod(t1, w[118], w[339]);
        mulmod(t2, w[118], w[339]);
        mulmod_constant(t2, t2, two);
        submod(w[417], t1, t2);
    }

    // XOR 351 296 -> 418
    {
        bn254fr_class t1, t2;
        addmod(t1, w[351], w[296]);
        mulmod(t2, w[351], w[296]);
        mulmod_constant(t2, t2, two);
        submod(w[418], t1, t2);
    }

    // XOR 326 359 -> 419
    {
        bn254fr_class t1, t2;
        addmod(t1, w[326], w[359]);
        mulmod(t2, w[326], w[359]);
        mulmod_constant(t2, t2, two);
        submod(w[419], t1, t2);
    }

    // AND 108 62 -> 420
    mulmod(w[420], w[108], w[62]);

    // AND 89 279 -> 421
    mulmod(w[421], w[89], w[279]);

    // AND 232 84 -> 422
    mulmod(w[422], w[232], w[84]);

    // XOR 95 196 -> 423
    {
        bn254fr_class t1, t2;
        addmod(t1, w[95], w[196]);
        mulmod(t2, w[95], w[196]);
        mulmod_constant(t2, t2, two);
        submod(w[423], t1, t2);
    }

    // XOR 211 358 -> 424
    {
        bn254fr_class t1, t2;
        addmod(t1, w[211], w[358]);
        mulmod(t2, w[211], w[358]);
        mulmod_constant(t2, t2, two);
        submod(w[424], t1, t2);
    }

    // AND 248 47 -> 425
    mulmod(w[425], w[248], w[47]);

    // XOR 200 27 -> 426
    {
        bn254fr_class t1, t2;
        addmod(t1, w[200], w[27]);
        mulmod(t2, w[200], w[27]);
        mulmod_constant(t2, t2, two);
        submod(w[426], t1, t2);
    }

    // XOR 48 226 -> 427
    {
        bn254fr_class t1, t2;
        addmod(t1, w[48], w[226]);
        mulmod(t2, w[48], w[226]);
        mulmod_constant(t2, t2, two);
        submod(w[427], t1, t2);
    }

    // AND 32 227 -> 428
    mulmod(w[428], w[32], w[227]);

    // XOR 256 233 -> 429
    {
        bn254fr_class t1, t2;
        addmod(t1, w[256], w[233]);
        mulmod(t2, w[256], w[233]);
        mulmod_constant(t2, t2, two);
        submod(w[429], t1, t2);
    }

    // XOR 45 125 -> 430
    {
        bn254fr_class t1, t2;
        addmod(t1, w[45], w[125]);
        mulmod(t2, w[45], w[125]);
        mulmod_constant(t2, t2, two);
        submod(w[430], t1, t2);
    }

    // AND 191 150 -> 431
    mulmod(w[431], w[191], w[150]);

    // AND 75 21 -> 432
    mulmod(w[432], w[75], w[21]);

    // XOR 251 189 -> 433
    {
        bn254fr_class t1, t2;
        addmod(t1, w[251], w[189]);
        mulmod(t2, w[251], w[189]);
        mulmod_constant(t2, t2, two);
        submod(w[433], t1, t2);
    }

    // XOR 272 63 -> 434
    {
        bn254fr_class t1, t2;
        addmod(t1, w[272], w[63]);
        mulmod(t2, w[272], w[63]);
        mulmod_constant(t2, t2, two);
        submod(w[434], t1, t2);
    }

    // AND 217 42 -> 435
    mulmod(w[435], w[217], w[42]);

    // XOR 113 110 -> 436
    {
        bn254fr_class t1, t2;
        addmod(t1, w[113], w[110]);
        mulmod(t2, w[113], w[110]);
        mulmod_constant(t2, t2, two);
        submod(w[436], t1, t2);
    }

    // AND 11 341 -> 437
    mulmod(w[437], w[11], w[341]);

    // AND 267 259 -> 438
    mulmod(w[438], w[267], w[259]);

    // AND 272 277 -> 439
    mulmod(w[439], w[272], w[277]);

    // XOR 262 181 -> 440
    {
        bn254fr_class t1, t2;
        addmod(t1, w[262], w[181]);
        mulmod(t2, w[262], w[181]);
        mulmod_constant(t2, t2, two);
        submod(w[440], t1, t2);
    }

    // AND 294 360 -> 441
    mulmod(w[441], w[294], w[360]);

    // XOR 58 241 -> 442
    {
        bn254fr_class t1, t2;
        addmod(t1, w[58], w[241]);
        mulmod(t2, w[58], w[241]);
        mulmod_constant(t2, t2, two);
        submod(w[442], t1, t2);
    }

    // XOR 149 234 -> 443
    {
        bn254fr_class t1, t2;
        addmod(t1, w[149], w[234]);
        mulmod(t2, w[149], w[234]);
        mulmod_constant(t2, t2, two);
        submod(w[443], t1, t2);
    }

    // XOR 24 47 -> 444
    {
        bn254fr_class t1, t2;
        addmod(t1, w[24], w[47]);
        mulmod(t2, w[24], w[47]);
        mulmod_constant(t2, t2, two);
        submod(w[444], t1, t2);
    }

    // XOR 66 355 -> 445
    {
        bn254fr_class t1, t2;
        addmod(t1, w[66], w[355]);
        mulmod(t2, w[66], w[355]);
        mulmod_constant(t2, t2, two);
        submod(w[445], t1, t2);
    }

    // XOR 4 68 -> 446
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4], w[68]);
        mulmod(t2, w[4], w[68]);
        mulmod_constant(t2, t2, two);
        submod(w[446], t1, t2);
    }

    // XOR 218 258 -> 447
    {
        bn254fr_class t1, t2;
        addmod(t1, w[218], w[258]);
        mulmod(t2, w[218], w[258]);
        mulmod_constant(t2, t2, two);
        submod(w[447], t1, t2);
    }

    // AND 153 322 -> 448
    mulmod(w[448], w[153], w[322]);

    // XOR 355 51 -> 449
    {
        bn254fr_class t1, t2;
        addmod(t1, w[355], w[51]);
        mulmod(t2, w[355], w[51]);
        mulmod_constant(t2, t2, two);
        submod(w[449], t1, t2);
    }

    // AND 68 23 -> 450
    mulmod(w[450], w[68], w[23]);

    // XOR 349 245 -> 451
    {
        bn254fr_class t1, t2;
        addmod(t1, w[349], w[245]);
        mulmod(t2, w[349], w[245]);
        mulmod_constant(t2, t2, two);
        submod(w[451], t1, t2);
    }

    // XOR 279 343 -> 452
    {
        bn254fr_class t1, t2;
        addmod(t1, w[279], w[343]);
        mulmod(t2, w[279], w[343]);
        mulmod_constant(t2, t2, two);
        submod(w[452], t1, t2);
    }

    // AND 348 125 -> 453
    mulmod(w[453], w[348], w[125]);

    // XOR 171 65 -> 454
    {
        bn254fr_class t1, t2;
        addmod(t1, w[171], w[65]);
        mulmod(t2, w[171], w[65]);
        mulmod_constant(t2, t2, two);
        submod(w[454], t1, t2);
    }

    // XOR 271 342 -> 455
    {
        bn254fr_class t1, t2;
        addmod(t1, w[271], w[342]);
        mulmod(t2, w[271], w[342]);
        mulmod_constant(t2, t2, two);
        submod(w[455], t1, t2);
    }

    // XOR 42 297 -> 456
    {
        bn254fr_class t1, t2;
        addmod(t1, w[42], w[297]);
        mulmod(t2, w[42], w[297]);
        mulmod_constant(t2, t2, two);
        submod(w[456], t1, t2);
    }

    // AND 56 71 -> 457
    mulmod(w[457], w[56], w[71]);

    // AND 204 304 -> 458
    mulmod(w[458], w[204], w[304]);

    // XOR 152 331 -> 459
    {
        bn254fr_class t1, t2;
        addmod(t1, w[152], w[331]);
        mulmod(t2, w[152], w[331]);
        mulmod_constant(t2, t2, two);
        submod(w[459], t1, t2);
    }

    // XOR 193 28 -> 460
    {
        bn254fr_class t1, t2;
        addmod(t1, w[193], w[28]);
        mulmod(t2, w[193], w[28]);
        mulmod_constant(t2, t2, two);
        submod(w[460], t1, t2);
    }

    // XOR 289 180 -> 461
    {
        bn254fr_class t1, t2;
        addmod(t1, w[289], w[180]);
        mulmod(t2, w[289], w[180]);
        mulmod_constant(t2, t2, two);
        submod(w[461], t1, t2);
    }

    // XOR 252 60 -> 462
    {
        bn254fr_class t1, t2;
        addmod(t1, w[252], w[60]);
        mulmod(t2, w[252], w[60]);
        mulmod_constant(t2, t2, two);
        submod(w[462], t1, t2);
    }

    // XOR 316 166 -> 463
    {
        bn254fr_class t1, t2;
        addmod(t1, w[316], w[166]);
        mulmod(t2, w[316], w[166]);
        mulmod_constant(t2, t2, two);
        submod(w[463], t1, t2);
    }

    // AND 0 208 -> 464
    mulmod(w[464], w[0], w[208]);

    // XOR 89 254 -> 465
    {
        bn254fr_class t1, t2;
        addmod(t1, w[89], w[254]);
        mulmod(t2, w[89], w[254]);
        mulmod_constant(t2, t2, two);
        submod(w[465], t1, t2);
    }

    // XOR 306 82 -> 466
    {
        bn254fr_class t1, t2;
        addmod(t1, w[306], w[82]);
        mulmod(t2, w[306], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[466], t1, t2);
    }

    // INV 250 -> 467
    submod(w[467], one, w[250]);

    // XOR 102 192 -> 468
    {
        bn254fr_class t1, t2;
        addmod(t1, w[102], w[192]);
        mulmod(t2, w[102], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[468], t1, t2);
    }

    // AND 269 194 -> 469
    mulmod(w[469], w[269], w[194]);

    // INV 3 -> 470
    submod(w[470], one, w[3]);

    // AND 162 128 -> 471
    mulmod(w[471], w[162], w[128]);

    // XOR 205 82 -> 472
    {
        bn254fr_class t1, t2;
        addmod(t1, w[205], w[82]);
        mulmod(t2, w[205], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[472], t1, t2);
    }

    // INV 353 -> 473
    submod(w[473], one, w[353]);

    // XOR 258 143 -> 474
    {
        bn254fr_class t1, t2;
        addmod(t1, w[258], w[143]);
        mulmod(t2, w[258], w[143]);
        mulmod_constant(t2, t2, two);
        submod(w[474], t1, t2);
    }

    // XOR 230 89 -> 475
    {
        bn254fr_class t1, t2;
        addmod(t1, w[230], w[89]);
        mulmod(t2, w[230], w[89]);
        mulmod_constant(t2, t2, two);
        submod(w[475], t1, t2);
    }

    // AND 10 74 -> 476
    mulmod(w[476], w[10], w[74]);

    // XOR 357 353 -> 477
    {
        bn254fr_class t1, t2;
        addmod(t1, w[357], w[353]);
        mulmod(t2, w[357], w[353]);
        mulmod_constant(t2, t2, two);
        submod(w[477], t1, t2);
    }

    // XOR 153 177 -> 478
    {
        bn254fr_class t1, t2;
        addmod(t1, w[153], w[177]);
        mulmod(t2, w[153], w[177]);
        mulmod_constant(t2, t2, two);
        submod(w[478], t1, t2);
    }

    // XOR 350 352 -> 479
    {
        bn254fr_class t1, t2;
        addmod(t1, w[350], w[352]);
        mulmod(t2, w[350], w[352]);
        mulmod_constant(t2, t2, two);
        submod(w[479], t1, t2);
    }

    // XOR 272 169 -> 480
    {
        bn254fr_class t1, t2;
        addmod(t1, w[272], w[169]);
        mulmod(t2, w[272], w[169]);
        mulmod_constant(t2, t2, two);
        submod(w[480], t1, t2);
    }

    // AND 148 320 -> 481
    mulmod(w[481], w[148], w[320]);

    // XOR 114 175 -> 482
    {
        bn254fr_class t1, t2;
        addmod(t1, w[114], w[175]);
        mulmod(t2, w[114], w[175]);
        mulmod_constant(t2, t2, two);
        submod(w[482], t1, t2);
    }

    // XOR 67 305 -> 483
    {
        bn254fr_class t1, t2;
        addmod(t1, w[67], w[305]);
        mulmod(t2, w[67], w[305]);
        mulmod_constant(t2, t2, two);
        submod(w[483], t1, t2);
    }

    // XOR 49 221 -> 484
    {
        bn254fr_class t1, t2;
        addmod(t1, w[49], w[221]);
        mulmod(t2, w[49], w[221]);
        mulmod_constant(t2, t2, two);
        submod(w[484], t1, t2);
    }

    // XOR 167 178 -> 485
    {
        bn254fr_class t1, t2;
        addmod(t1, w[167], w[178]);
        mulmod(t2, w[167], w[178]);
        mulmod_constant(t2, t2, two);
        submod(w[485], t1, t2);
    }

    // XOR 209 328 -> 486
    {
        bn254fr_class t1, t2;
        addmod(t1, w[209], w[328]);
        mulmod(t2, w[209], w[328]);
        mulmod_constant(t2, t2, two);
        submod(w[486], t1, t2);
    }

    // XOR 468 277 -> 487
    {
        bn254fr_class t1, t2;
        addmod(t1, w[468], w[277]);
        mulmod(t2, w[468], w[277]);
        mulmod_constant(t2, t2, two);
        submod(w[487], t1, t2);
    }

    // AND 39 35 -> 488
    mulmod(w[488], w[39], w[35]);

    // XOR 84 135 -> 489
    {
        bn254fr_class t1, t2;
        addmod(t1, w[84], w[135]);
        mulmod(t2, w[84], w[135]);
        mulmod_constant(t2, t2, two);
        submod(w[489], t1, t2);
    }

    // XOR 183 61 -> 490
    {
        bn254fr_class t1, t2;
        addmod(t1, w[183], w[61]);
        mulmod(t2, w[183], w[61]);
        mulmod_constant(t2, t2, two);
        submod(w[490], t1, t2);
    }

    // XOR 427 345 -> 491
    {
        bn254fr_class t1, t2;
        addmod(t1, w[427], w[345]);
        mulmod(t2, w[427], w[345]);
        mulmod_constant(t2, t2, two);
        submod(w[491], t1, t2);
    }

    // XOR 328 401 -> 492
    {
        bn254fr_class t1, t2;
        addmod(t1, w[328], w[401]);
        mulmod(t2, w[328], w[401]);
        mulmod_constant(t2, t2, two);
        submod(w[492], t1, t2);
    }

    // XOR 395 459 -> 493
    {
        bn254fr_class t1, t2;
        addmod(t1, w[395], w[459]);
        mulmod(t2, w[395], w[459]);
        mulmod_constant(t2, t2, two);
        submod(w[493], t1, t2);
    }

    // INV 226 -> 494
    submod(w[494], one, w[226]);

    // XOR 95 335 -> 495
    {
        bn254fr_class t1, t2;
        addmod(t1, w[95], w[335]);
        mulmod(t2, w[95], w[335]);
        mulmod_constant(t2, t2, two);
        submod(w[495], t1, t2);
    }

    // XOR 193 82 -> 496
    {
        bn254fr_class t1, t2;
        addmod(t1, w[193], w[82]);
        mulmod(t2, w[193], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[496], t1, t2);
    }

    // XOR 173 312 -> 497
    {
        bn254fr_class t1, t2;
        addmod(t1, w[173], w[312]);
        mulmod(t2, w[173], w[312]);
        mulmod_constant(t2, t2, two);
        submod(w[497], t1, t2);
    }

    // XOR 239 11 -> 498
    {
        bn254fr_class t1, t2;
        addmod(t1, w[239], w[11]);
        mulmod(t2, w[239], w[11]);
        mulmod_constant(t2, t2, two);
        submod(w[498], t1, t2);
    }

    // AND 223 395 -> 499
    mulmod(w[499], w[223], w[395]);

    // XOR 415 344 -> 500
    {
        bn254fr_class t1, t2;
        addmod(t1, w[415], w[344]);
        mulmod(t2, w[415], w[344]);
        mulmod_constant(t2, t2, two);
        submod(w[500], t1, t2);
    }

    // AND 269 13 -> 501
    mulmod(w[501], w[269], w[13]);

    // XOR 55 375 -> 502
    {
        bn254fr_class t1, t2;
        addmod(t1, w[55], w[375]);
        mulmod(t2, w[55], w[375]);
        mulmod_constant(t2, t2, two);
        submod(w[502], t1, t2);
    }

    // AND 381 55 -> 503
    mulmod(w[503], w[381], w[55]);

    // XOR 312 76 -> 504
    {
        bn254fr_class t1, t2;
        addmod(t1, w[312], w[76]);
        mulmod(t2, w[312], w[76]);
        mulmod_constant(t2, t2, two);
        submod(w[504], t1, t2);
    }

    // XOR 63 179 -> 505
    {
        bn254fr_class t1, t2;
        addmod(t1, w[63], w[179]);
        mulmod(t2, w[63], w[179]);
        mulmod_constant(t2, t2, two);
        submod(w[505], t1, t2);
    }

    // AND 390 414 -> 506
    mulmod(w[506], w[390], w[414]);

    // XOR 462 206 -> 507
    {
        bn254fr_class t1, t2;
        addmod(t1, w[462], w[206]);
        mulmod(t2, w[462], w[206]);
        mulmod_constant(t2, t2, two);
        submod(w[507], t1, t2);
    }

    // AND 323 417 -> 508
    mulmod(w[508], w[323], w[417]);

    // XOR 409 298 -> 509
    {
        bn254fr_class t1, t2;
        addmod(t1, w[409], w[298]);
        mulmod(t2, w[409], w[298]);
        mulmod_constant(t2, t2, two);
        submod(w[509], t1, t2);
    }

    // XOR 205 403 -> 510
    {
        bn254fr_class t1, t2;
        addmod(t1, w[205], w[403]);
        mulmod(t2, w[205], w[403]);
        mulmod_constant(t2, t2, two);
        submod(w[510], t1, t2);
    }

    // XOR 216 264 -> 511
    {
        bn254fr_class t1, t2;
        addmod(t1, w[216], w[264]);
        mulmod(t2, w[216], w[264]);
        mulmod_constant(t2, t2, two);
        submod(w[511], t1, t2);
    }

    // XOR 384 221 -> 512
    {
        bn254fr_class t1, t2;
        addmod(t1, w[384], w[221]);
        mulmod(t2, w[384], w[221]);
        mulmod_constant(t2, t2, two);
        submod(w[512], t1, t2);
    }

    // XOR 347 433 -> 513
    {
        bn254fr_class t1, t2;
        addmod(t1, w[347], w[433]);
        mulmod(t2, w[347], w[433]);
        mulmod_constant(t2, t2, two);
        submod(w[513], t1, t2);
    }

    // AND 209 177 -> 514
    mulmod(w[514], w[209], w[177]);

    // XOR 318 385 -> 515
    {
        bn254fr_class t1, t2;
        addmod(t1, w[318], w[385]);
        mulmod(t2, w[318], w[385]);
        mulmod_constant(t2, t2, two);
        submod(w[515], t1, t2);
    }

    // AND 192 245 -> 516
    mulmod(w[516], w[192], w[245]);

    // AND 390 281 -> 517
    mulmod(w[517], w[390], w[281]);

    // XOR 417 299 -> 518
    {
        bn254fr_class t1, t2;
        addmod(t1, w[417], w[299]);
        mulmod(t2, w[417], w[299]);
        mulmod_constant(t2, t2, two);
        submod(w[518], t1, t2);
    }

    // AND 341 84 -> 519
    mulmod(w[519], w[341], w[84]);

    // AND 110 182 -> 520
    mulmod(w[520], w[110], w[182]);

    // XOR 96 155 -> 521
    {
        bn254fr_class t1, t2;
        addmod(t1, w[96], w[155]);
        mulmod(t2, w[96], w[155]);
        mulmod_constant(t2, t2, two);
        submod(w[521], t1, t2);
    }

    // AND 372 51 -> 522
    mulmod(w[522], w[372], w[51]);

    // AND 156 142 -> 523
    mulmod(w[523], w[156], w[142]);

    // XOR 222 62 -> 524
    {
        bn254fr_class t1, t2;
        addmod(t1, w[222], w[62]);
        mulmod(t2, w[222], w[62]);
        mulmod_constant(t2, t2, two);
        submod(w[524], t1, t2);
    }

    // AND 446 247 -> 525
    mulmod(w[525], w[446], w[247]);

    // XOR 454 238 -> 526
    {
        bn254fr_class t1, t2;
        addmod(t1, w[454], w[238]);
        mulmod(t2, w[454], w[238]);
        mulmod_constant(t2, t2, two);
        submod(w[526], t1, t2);
    }

    // INV 140 -> 527
    submod(w[527], one, w[140]);

    // AND 194 92 -> 528
    mulmod(w[528], w[194], w[92]);

    // AND 201 6 -> 529
    mulmod(w[529], w[201], w[6]);

    // XOR 157 17 -> 530
    {
        bn254fr_class t1, t2;
        addmod(t1, w[157], w[17]);
        mulmod(t2, w[157], w[17]);
        mulmod_constant(t2, t2, two);
        submod(w[530], t1, t2);
    }

    // XOR 237 84 -> 531
    {
        bn254fr_class t1, t2;
        addmod(t1, w[237], w[84]);
        mulmod(t2, w[237], w[84]);
        mulmod_constant(t2, t2, two);
        submod(w[531], t1, t2);
    }

    // AND 379 355 -> 532
    mulmod(w[532], w[379], w[355]);

    // XOR 20 230 -> 533
    {
        bn254fr_class t1, t2;
        addmod(t1, w[20], w[230]);
        mulmod(t2, w[20], w[230]);
        mulmod_constant(t2, t2, two);
        submod(w[533], t1, t2);
    }

    // XOR 47 363 -> 534
    {
        bn254fr_class t1, t2;
        addmod(t1, w[47], w[363]);
        mulmod(t2, w[47], w[363]);
        mulmod_constant(t2, t2, two);
        submod(w[534], t1, t2);
    }

    // XOR 31 249 -> 535
    {
        bn254fr_class t1, t2;
        addmod(t1, w[31], w[249]);
        mulmod(t2, w[31], w[249]);
        mulmod_constant(t2, t2, two);
        submod(w[535], t1, t2);
    }

    // XOR 338 242 -> 536
    {
        bn254fr_class t1, t2;
        addmod(t1, w[338], w[242]);
        mulmod(t2, w[338], w[242]);
        mulmod_constant(t2, t2, two);
        submod(w[536], t1, t2);
    }

    // AND 70 90 -> 537
    mulmod(w[537], w[70], w[90]);

    // XOR 314 276 -> 538
    {
        bn254fr_class t1, t2;
        addmod(t1, w[314], w[276]);
        mulmod(t2, w[314], w[276]);
        mulmod_constant(t2, t2, two);
        submod(w[538], t1, t2);
    }

    // XOR 388 352 -> 539
    {
        bn254fr_class t1, t2;
        addmod(t1, w[388], w[352]);
        mulmod(t2, w[388], w[352]);
        mulmod_constant(t2, t2, two);
        submod(w[539], t1, t2);
    }

    // XOR 343 255 -> 540
    {
        bn254fr_class t1, t2;
        addmod(t1, w[343], w[255]);
        mulmod(t2, w[343], w[255]);
        mulmod_constant(t2, t2, two);
        submod(w[540], t1, t2);
    }

    // XOR 247 223 -> 541
    {
        bn254fr_class t1, t2;
        addmod(t1, w[247], w[223]);
        mulmod(t2, w[247], w[223]);
        mulmod_constant(t2, t2, two);
        submod(w[541], t1, t2);
    }

    // XOR 136 27 -> 542
    {
        bn254fr_class t1, t2;
        addmod(t1, w[136], w[27]);
        mulmod(t2, w[136], w[27]);
        mulmod_constant(t2, t2, two);
        submod(w[542], t1, t2);
    }

    // XOR 77 438 -> 543
    {
        bn254fr_class t1, t2;
        addmod(t1, w[77], w[438]);
        mulmod(t2, w[77], w[438]);
        mulmod_constant(t2, t2, two);
        submod(w[543], t1, t2);
    }

    // AND 425 475 -> 544
    mulmod(w[544], w[425], w[475]);

    // INV 203 -> 545
    submod(w[545], one, w[203]);

    // XOR 200 410 -> 546
    {
        bn254fr_class t1, t2;
        addmod(t1, w[200], w[410]);
        mulmod(t2, w[200], w[410]);
        mulmod_constant(t2, t2, two);
        submod(w[546], t1, t2);
    }

    // XOR 4 49 -> 547
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4], w[49]);
        mulmod(t2, w[4], w[49]);
        mulmod_constant(t2, t2, two);
        submod(w[547], t1, t2);
    }

    // AND 71 467 -> 548
    mulmod(w[548], w[71], w[467]);

    // XOR 212 53 -> 549
    {
        bn254fr_class t1, t2;
        addmod(t1, w[212], w[53]);
        mulmod(t2, w[212], w[53]);
        mulmod_constant(t2, t2, two);
        submod(w[549], t1, t2);
    }

    // AND 224 235 -> 550
    mulmod(w[550], w[224], w[235]);

    // XOR 98 314 -> 551
    {
        bn254fr_class t1, t2;
        addmod(t1, w[98], w[314]);
        mulmod(t2, w[98], w[314]);
        mulmod_constant(t2, t2, two);
        submod(w[551], t1, t2);
    }

    // XOR 486 240 -> 552
    {
        bn254fr_class t1, t2;
        addmod(t1, w[486], w[240]);
        mulmod(t2, w[486], w[240]);
        mulmod_constant(t2, t2, two);
        submod(w[552], t1, t2);
    }

    // AND 156 312 -> 553
    mulmod(w[553], w[156], w[312]);

    // XOR 398 345 -> 554
    {
        bn254fr_class t1, t2;
        addmod(t1, w[398], w[345]);
        mulmod(t2, w[398], w[345]);
        mulmod_constant(t2, t2, two);
        submod(w[554], t1, t2);
    }

    // XOR 75 103 -> 555
    {
        bn254fr_class t1, t2;
        addmod(t1, w[75], w[103]);
        mulmod(t2, w[75], w[103]);
        mulmod_constant(t2, t2, two);
        submod(w[555], t1, t2);
    }

    // AND 293 481 -> 556
    mulmod(w[556], w[293], w[481]);

    // XOR 392 119 -> 557
    {
        bn254fr_class t1, t2;
        addmod(t1, w[392], w[119]);
        mulmod(t2, w[392], w[119]);
        mulmod_constant(t2, t2, two);
        submod(w[557], t1, t2);
    }

    // XOR 469 407 -> 558
    {
        bn254fr_class t1, t2;
        addmod(t1, w[469], w[407]);
        mulmod(t2, w[469], w[407]);
        mulmod_constant(t2, t2, two);
        submod(w[558], t1, t2);
    }

    // XOR 349 25 -> 559
    {
        bn254fr_class t1, t2;
        addmod(t1, w[349], w[25]);
        mulmod(t2, w[349], w[25]);
        mulmod_constant(t2, t2, two);
        submod(w[559], t1, t2);
    }

    // XOR 306 363 -> 560
    {
        bn254fr_class t1, t2;
        addmod(t1, w[306], w[363]);
        mulmod(t2, w[306], w[363]);
        mulmod_constant(t2, t2, two);
        submod(w[560], t1, t2);
    }

    // XOR 252 101 -> 561
    {
        bn254fr_class t1, t2;
        addmod(t1, w[252], w[101]);
        mulmod(t2, w[252], w[101]);
        mulmod_constant(t2, t2, two);
        submod(w[561], t1, t2);
    }

    // XOR 16 473 -> 562
    {
        bn254fr_class t1, t2;
        addmod(t1, w[16], w[473]);
        mulmod(t2, w[16], w[473]);
        mulmod_constant(t2, t2, two);
        submod(w[562], t1, t2);
    }

    // AND 434 129 -> 563
    mulmod(w[563], w[434], w[129]);

    // AND 121 485 -> 564
    mulmod(w[564], w[121], w[485]);

    // XOR 64 229 -> 565
    {
        bn254fr_class t1, t2;
        addmod(t1, w[64], w[229]);
        mulmod(t2, w[64], w[229]);
        mulmod_constant(t2, t2, two);
        submod(w[565], t1, t2);
    }

    // AND 220 154 -> 566
    mulmod(w[566], w[220], w[154]);

    // XOR 268 338 -> 567
    {
        bn254fr_class t1, t2;
        addmod(t1, w[268], w[338]);
        mulmod(t2, w[268], w[338]);
        mulmod_constant(t2, t2, two);
        submod(w[567], t1, t2);
    }

    // XOR 268 167 -> 568
    {
        bn254fr_class t1, t2;
        addmod(t1, w[268], w[167]);
        mulmod(t2, w[268], w[167]);
        mulmod_constant(t2, t2, two);
        submod(w[568], t1, t2);
    }

    // AND 23 11 -> 569
    mulmod(w[569], w[23], w[11]);

    // XOR 117 368 -> 570
    {
        bn254fr_class t1, t2;
        addmod(t1, w[117], w[368]);
        mulmod(t2, w[117], w[368]);
        mulmod_constant(t2, t2, two);
        submod(w[570], t1, t2);
    }

    // AND 214 49 -> 571
    mulmod(w[571], w[214], w[49]);

    // XOR 320 356 -> 572
    {
        bn254fr_class t1, t2;
        addmod(t1, w[320], w[356]);
        mulmod(t2, w[320], w[356]);
        mulmod_constant(t2, t2, two);
        submod(w[572], t1, t2);
    }

    // AND 290 352 -> 573
    mulmod(w[573], w[290], w[352]);

    // INV 129 -> 574
    submod(w[574], one, w[129]);

    // AND 410 194 -> 575
    mulmod(w[575], w[410], w[194]);

    // AND 284 170 -> 576
    mulmod(w[576], w[284], w[170]);

    // INV 350 -> 577
    submod(w[577], one, w[350]);

    // XOR 137 129 -> 578
    {
        bn254fr_class t1, t2;
        addmod(t1, w[137], w[129]);
        mulmod(t2, w[137], w[129]);
        mulmod_constant(t2, t2, two);
        submod(w[578], t1, t2);
    }

    // AND 412 325 -> 579
    mulmod(w[579], w[412], w[325]);

    // AND 130 308 -> 580
    mulmod(w[580], w[130], w[308]);

    // XOR 115 101 -> 581
    {
        bn254fr_class t1, t2;
        addmod(t1, w[115], w[101]);
        mulmod(t2, w[115], w[101]);
        mulmod_constant(t2, t2, two);
        submod(w[581], t1, t2);
    }

    // XOR 306 54 -> 582
    {
        bn254fr_class t1, t2;
        addmod(t1, w[306], w[54]);
        mulmod(t2, w[306], w[54]);
        mulmod_constant(t2, t2, two);
        submod(w[582], t1, t2);
    }

    // AND 88 416 -> 583
    mulmod(w[583], w[88], w[416]);

    // AND 410 26 -> 584
    mulmod(w[584], w[410], w[26]);

    // XOR 380 120 -> 585
    {
        bn254fr_class t1, t2;
        addmod(t1, w[380], w[120]);
        mulmod(t2, w[380], w[120]);
        mulmod_constant(t2, t2, two);
        submod(w[585], t1, t2);
    }

    // XOR 429 135 -> 586
    {
        bn254fr_class t1, t2;
        addmod(t1, w[429], w[135]);
        mulmod(t2, w[429], w[135]);
        mulmod_constant(t2, t2, two);
        submod(w[586], t1, t2);
    }

    // XOR 237 456 -> 587
    {
        bn254fr_class t1, t2;
        addmod(t1, w[237], w[456]);
        mulmod(t2, w[237], w[456]);
        mulmod_constant(t2, t2, two);
        submod(w[587], t1, t2);
    }

    // XOR 43 576 -> 588
    {
        bn254fr_class t1, t2;
        addmod(t1, w[43], w[576]);
        mulmod(t2, w[43], w[576]);
        mulmod_constant(t2, t2, two);
        submod(w[588], t1, t2);
    }

    // AND 437 367 -> 589
    mulmod(w[589], w[437], w[367]);

    // XOR 536 404 -> 590
    {
        bn254fr_class t1, t2;
        addmod(t1, w[536], w[404]);
        mulmod(t2, w[536], w[404]);
        mulmod_constant(t2, t2, two);
        submod(w[590], t1, t2);
    }

    // XOR 112 493 -> 591
    {
        bn254fr_class t1, t2;
        addmod(t1, w[112], w[493]);
        mulmod(t2, w[112], w[493]);
        mulmod_constant(t2, t2, two);
        submod(w[591], t1, t2);
    }

    // XOR 307 219 -> 592
    {
        bn254fr_class t1, t2;
        addmod(t1, w[307], w[219]);
        mulmod(t2, w[307], w[219]);
        mulmod_constant(t2, t2, two);
        submod(w[592], t1, t2);
    }

    // XOR 478 342 -> 593
    {
        bn254fr_class t1, t2;
        addmod(t1, w[478], w[342]);
        mulmod(t2, w[478], w[342]);
        mulmod_constant(t2, t2, two);
        submod(w[593], t1, t2);
    }

    // XOR 51 216 -> 594
    {
        bn254fr_class t1, t2;
        addmod(t1, w[51], w[216]);
        mulmod(t2, w[51], w[216]);
        mulmod_constant(t2, t2, two);
        submod(w[594], t1, t2);
    }

    // XOR 175 192 -> 595
    {
        bn254fr_class t1, t2;
        addmod(t1, w[175], w[192]);
        mulmod(t2, w[175], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[595], t1, t2);
    }

    // INV 290 -> 596
    submod(w[596], one, w[290]);

    // AND 374 321 -> 597
    mulmod(w[597], w[374], w[321]);

    // AND 500 553 -> 598
    mulmod(w[598], w[500], w[553]);

    // AND 367 251 -> 599
    mulmod(w[599], w[367], w[251]);

    // XOR 119 215 -> 600
    {
        bn254fr_class t1, t2;
        addmod(t1, w[119], w[215]);
        mulmod(t2, w[119], w[215]);
        mulmod_constant(t2, t2, two);
        submod(w[600], t1, t2);
    }

    // XOR 386 398 -> 601
    {
        bn254fr_class t1, t2;
        addmod(t1, w[386], w[398]);
        mulmod(t2, w[386], w[398]);
        mulmod_constant(t2, t2, two);
        submod(w[601], t1, t2);
    }

    // XOR 230 490 -> 602
    {
        bn254fr_class t1, t2;
        addmod(t1, w[230], w[490]);
        mulmod(t2, w[230], w[490]);
        mulmod_constant(t2, t2, two);
        submod(w[602], t1, t2);
    }

    // XOR 343 102 -> 603
    {
        bn254fr_class t1, t2;
        addmod(t1, w[343], w[102]);
        mulmod(t2, w[343], w[102]);
        mulmod_constant(t2, t2, two);
        submod(w[603], t1, t2);
    }

    // AND 556 193 -> 604
    mulmod(w[604], w[556], w[193]);

    // AND 481 423 -> 605
    mulmod(w[605], w[481], w[423]);

    // XOR 13 423 -> 606
    {
        bn254fr_class t1, t2;
        addmod(t1, w[13], w[423]);
        mulmod(t2, w[13], w[423]);
        mulmod_constant(t2, t2, two);
        submod(w[606], t1, t2);
    }

    // XOR 259 319 -> 607
    {
        bn254fr_class t1, t2;
        addmod(t1, w[259], w[319]);
        mulmod(t2, w[259], w[319]);
        mulmod_constant(t2, t2, two);
        submod(w[607], t1, t2);
    }

    // AND 218 351 -> 608
    mulmod(w[608], w[218], w[351]);

    // XOR 507 396 -> 609
    {
        bn254fr_class t1, t2;
        addmod(t1, w[507], w[396]);
        mulmod(t2, w[507], w[396]);
        mulmod_constant(t2, t2, two);
        submod(w[609], t1, t2);
    }

    // XOR 532 282 -> 610
    {
        bn254fr_class t1, t2;
        addmod(t1, w[532], w[282]);
        mulmod(t2, w[532], w[282]);
        mulmod_constant(t2, t2, two);
        submod(w[610], t1, t2);
    }

    // XOR 401 5 -> 611
    {
        bn254fr_class t1, t2;
        addmod(t1, w[401], w[5]);
        mulmod(t2, w[401], w[5]);
        mulmod_constant(t2, t2, two);
        submod(w[611], t1, t2);
    }

    // INV 285 -> 612
    submod(w[612], one, w[285]);

    // INV 17 -> 613
    submod(w[613], one, w[17]);

    // INV 202 -> 614
    submod(w[614], one, w[202]);

    // XOR 324 134 -> 615
    {
        bn254fr_class t1, t2;
        addmod(t1, w[324], w[134]);
        mulmod(t2, w[324], w[134]);
        mulmod_constant(t2, t2, two);
        submod(w[615], t1, t2);
    }

    // INV 365 -> 616
    submod(w[616], one, w[365]);

    // AND 168 299 -> 617
    mulmod(w[617], w[168], w[299]);

    // XOR 145 54 -> 618
    {
        bn254fr_class t1, t2;
        addmod(t1, w[145], w[54]);
        mulmod(t2, w[145], w[54]);
        mulmod_constant(t2, t2, two);
        submod(w[618], t1, t2);
    }

    // XOR 470 562 -> 619
    {
        bn254fr_class t1, t2;
        addmod(t1, w[470], w[562]);
        mulmod(t2, w[470], w[562]);
        mulmod_constant(t2, t2, two);
        submod(w[619], t1, t2);
    }

    // XOR 8 336 -> 620
    {
        bn254fr_class t1, t2;
        addmod(t1, w[8], w[336]);
        mulmod(t2, w[8], w[336]);
        mulmod_constant(t2, t2, two);
        submod(w[620], t1, t2);
    }

    // XOR 492 309 -> 621
    {
        bn254fr_class t1, t2;
        addmod(t1, w[492], w[309]);
        mulmod(t2, w[492], w[309]);
        mulmod_constant(t2, t2, two);
        submod(w[621], t1, t2);
    }

    // AND 419 128 -> 622
    mulmod(w[622], w[419], w[128]);

    // XOR 484 82 -> 623
    {
        bn254fr_class t1, t2;
        addmod(t1, w[484], w[82]);
        mulmod(t2, w[484], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[623], t1, t2);
    }

    // XOR 457 391 -> 624
    {
        bn254fr_class t1, t2;
        addmod(t1, w[457], w[391]);
        mulmod(t2, w[457], w[391]);
        mulmod_constant(t2, t2, two);
        submod(w[624], t1, t2);
    }

    // XOR 368 459 -> 625
    {
        bn254fr_class t1, t2;
        addmod(t1, w[368], w[459]);
        mulmod(t2, w[368], w[459]);
        mulmod_constant(t2, t2, two);
        submod(w[625], t1, t2);
    }

    // AND 252 162 -> 626
    mulmod(w[626], w[252], w[162]);

    // AND 277 236 -> 627
    mulmod(w[627], w[277], w[236]);

    // AND 209 199 -> 628
    mulmod(w[628], w[209], w[199]);

    // AND 379 350 -> 629
    mulmod(w[629], w[379], w[350]);

    // XOR 160 344 -> 630
    {
        bn254fr_class t1, t2;
        addmod(t1, w[160], w[344]);
        mulmod(t2, w[160], w[344]);
        mulmod_constant(t2, t2, two);
        submod(w[630], t1, t2);
    }

    // XOR 551 98 -> 631
    {
        bn254fr_class t1, t2;
        addmod(t1, w[551], w[98]);
        mulmod(t2, w[551], w[98]);
        mulmod_constant(t2, t2, two);
        submod(w[631], t1, t2);
    }

    // AND 9 135 -> 632
    mulmod(w[632], w[9], w[135]);

    // AND 145 400 -> 633
    mulmod(w[633], w[145], w[400]);

    // XOR 83 405 -> 634
    {
        bn254fr_class t1, t2;
        addmod(t1, w[83], w[405]);
        mulmod(t2, w[83], w[405]);
        mulmod_constant(t2, t2, two);
        submod(w[634], t1, t2);
    }

    // XOR 509 180 -> 635
    {
        bn254fr_class t1, t2;
        addmod(t1, w[509], w[180]);
        mulmod(t2, w[509], w[180]);
        mulmod_constant(t2, t2, two);
        submod(w[635], t1, t2);
    }

    // AND 109 483 -> 636
    mulmod(w[636], w[109], w[483]);

    // XOR 152 199 -> 637
    {
        bn254fr_class t1, t2;
        addmod(t1, w[152], w[199]);
        mulmod(t2, w[152], w[199]);
        mulmod_constant(t2, t2, two);
        submod(w[637], t1, t2);
    }

    // XOR 335 472 -> 638
    {
        bn254fr_class t1, t2;
        addmod(t1, w[335], w[472]);
        mulmod(t2, w[335], w[472]);
        mulmod_constant(t2, t2, two);
        submod(w[638], t1, t2);
    }

    // XOR 258 234 -> 639
    {
        bn254fr_class t1, t2;
        addmod(t1, w[258], w[234]);
        mulmod(t2, w[258], w[234]);
        mulmod_constant(t2, t2, two);
        submod(w[639], t1, t2);
    }

    // XOR 564 261 -> 640
    {
        bn254fr_class t1, t2;
        addmod(t1, w[564], w[261]);
        mulmod(t2, w[564], w[261]);
        mulmod_constant(t2, t2, two);
        submod(w[640], t1, t2);
    }

    // AND 406 553 -> 641
    mulmod(w[641], w[406], w[553]);

    // XOR 178 261 -> 642
    {
        bn254fr_class t1, t2;
        addmod(t1, w[178], w[261]);
        mulmod(t2, w[178], w[261]);
        mulmod_constant(t2, t2, two);
        submod(w[642], t1, t2);
    }

    // AND 323 542 -> 643
    mulmod(w[643], w[323], w[542]);

    // XOR 371 417 -> 644
    {
        bn254fr_class t1, t2;
        addmod(t1, w[371], w[417]);
        mulmod(t2, w[371], w[417]);
        mulmod_constant(t2, t2, two);
        submod(w[644], t1, t2);
    }

    // AND 97 98 -> 645
    mulmod(w[645], w[97], w[98]);

    // AND 427 376 -> 646
    mulmod(w[646], w[427], w[376]);

    // XOR 17 239 -> 647
    {
        bn254fr_class t1, t2;
        addmod(t1, w[17], w[239]);
        mulmod(t2, w[17], w[239]);
        mulmod_constant(t2, t2, two);
        submod(w[647], t1, t2);
    }

    // XOR 83 401 -> 648
    {
        bn254fr_class t1, t2;
        addmod(t1, w[83], w[401]);
        mulmod(t2, w[83], w[401]);
        mulmod_constant(t2, t2, two);
        submod(w[648], t1, t2);
    }

    // XOR 460 519 -> 649
    {
        bn254fr_class t1, t2;
        addmod(t1, w[460], w[519]);
        mulmod(t2, w[460], w[519]);
        mulmod_constant(t2, t2, two);
        submod(w[649], t1, t2);
    }

    // XOR 560 410 -> 650
    {
        bn254fr_class t1, t2;
        addmod(t1, w[560], w[410]);
        mulmod(t2, w[560], w[410]);
        mulmod_constant(t2, t2, two);
        submod(w[650], t1, t2);
    }

    // XOR 55 493 -> 651
    {
        bn254fr_class t1, t2;
        addmod(t1, w[55], w[493]);
        mulmod(t2, w[55], w[493]);
        mulmod_constant(t2, t2, two);
        submod(w[651], t1, t2);
    }

    // XOR 264 244 -> 652
    {
        bn254fr_class t1, t2;
        addmod(t1, w[264], w[244]);
        mulmod(t2, w[264], w[244]);
        mulmod_constant(t2, t2, two);
        submod(w[652], t1, t2);
    }

    // XOR 196 202 -> 653
    {
        bn254fr_class t1, t2;
        addmod(t1, w[196], w[202]);
        mulmod(t2, w[196], w[202]);
        mulmod_constant(t2, t2, two);
        submod(w[653], t1, t2);
    }

    // AND 377 422 -> 654
    mulmod(w[654], w[377], w[422]);

    // AND 165 577 -> 655
    mulmod(w[655], w[165], w[577]);

    // AND 70 237 -> 656
    mulmod(w[656], w[70], w[237]);

    // XOR 153 450 -> 657
    {
        bn254fr_class t1, t2;
        addmod(t1, w[153], w[450]);
        mulmod(t2, w[153], w[450]);
        mulmod_constant(t2, t2, two);
        submod(w[657], t1, t2);
    }

    // XOR 511 74 -> 658
    {
        bn254fr_class t1, t2;
        addmod(t1, w[511], w[74]);
        mulmod(t2, w[511], w[74]);
        mulmod_constant(t2, t2, two);
        submod(w[658], t1, t2);
    }

    // XOR 356 450 -> 659
    {
        bn254fr_class t1, t2;
        addmod(t1, w[356], w[450]);
        mulmod(t2, w[356], w[450]);
        mulmod_constant(t2, t2, two);
        submod(w[659], t1, t2);
    }

    // XOR 562 95 -> 660
    {
        bn254fr_class t1, t2;
        addmod(t1, w[562], w[95]);
        mulmod(t2, w[562], w[95]);
        mulmod_constant(t2, t2, two);
        submod(w[660], t1, t2);
    }

    // XOR 257 8 -> 661
    {
        bn254fr_class t1, t2;
        addmod(t1, w[257], w[8]);
        mulmod(t2, w[257], w[8]);
        mulmod_constant(t2, t2, two);
        submod(w[661], t1, t2);
    }

    // AND 472 254 -> 662
    mulmod(w[662], w[472], w[254]);

    // XOR 480 115 -> 663
    {
        bn254fr_class t1, t2;
        addmod(t1, w[480], w[115]);
        mulmod(t2, w[480], w[115]);
        mulmod_constant(t2, t2, two);
        submod(w[663], t1, t2);
    }

    // INV 247 -> 664
    submod(w[664], one, w[247]);

    // AND 34 13 -> 665
    mulmod(w[665], w[34], w[13]);

    // AND 139 295 -> 666
    mulmod(w[666], w[139], w[295]);

    // XOR 78 273 -> 667
    {
        bn254fr_class t1, t2;
        addmod(t1, w[78], w[273]);
        mulmod(t2, w[78], w[273]);
        mulmod_constant(t2, t2, two);
        submod(w[667], t1, t2);
    }

    // XOR 190 420 -> 668
    {
        bn254fr_class t1, t2;
        addmod(t1, w[190], w[420]);
        mulmod(t2, w[190], w[420]);
        mulmod_constant(t2, t2, two);
        submod(w[668], t1, t2);
    }

    // XOR 580 209 -> 669
    {
        bn254fr_class t1, t2;
        addmod(t1, w[580], w[209]);
        mulmod(t2, w[580], w[209]);
        mulmod_constant(t2, t2, two);
        submod(w[669], t1, t2);
    }

    // XOR 99 111 -> 670
    {
        bn254fr_class t1, t2;
        addmod(t1, w[99], w[111]);
        mulmod(t2, w[99], w[111]);
        mulmod_constant(t2, t2, two);
        submod(w[670], t1, t2);
    }

    // XOR 310 350 -> 671
    {
        bn254fr_class t1, t2;
        addmod(t1, w[310], w[350]);
        mulmod(t2, w[310], w[350]);
        mulmod_constant(t2, t2, two);
        submod(w[671], t1, t2);
    }

    // XOR 530 302 -> 672
    {
        bn254fr_class t1, t2;
        addmod(t1, w[530], w[302]);
        mulmod(t2, w[530], w[302]);
        mulmod_constant(t2, t2, two);
        submod(w[672], t1, t2);
    }

    // XOR 559 167 -> 673
    {
        bn254fr_class t1, t2;
        addmod(t1, w[559], w[167]);
        mulmod(t2, w[559], w[167]);
        mulmod_constant(t2, t2, two);
        submod(w[673], t1, t2);
    }

    // AND 130 15 -> 674
    mulmod(w[674], w[130], w[15]);

    // INV 269 -> 675
    submod(w[675], one, w[269]);

    // XOR 252 472 -> 676
    {
        bn254fr_class t1, t2;
        addmod(t1, w[252], w[472]);
        mulmod(t2, w[252], w[472]);
        mulmod_constant(t2, t2, two);
        submod(w[676], t1, t2);
    }

    // XOR 320 313 -> 677
    {
        bn254fr_class t1, t2;
        addmod(t1, w[320], w[313]);
        mulmod(t2, w[320], w[313]);
        mulmod_constant(t2, t2, two);
        submod(w[677], t1, t2);
    }

    // XOR 522 341 -> 678
    {
        bn254fr_class t1, t2;
        addmod(t1, w[522], w[341]);
        mulmod(t2, w[522], w[341]);
        mulmod_constant(t2, t2, two);
        submod(w[678], t1, t2);
    }

    // XOR 50 441 -> 679
    {
        bn254fr_class t1, t2;
        addmod(t1, w[50], w[441]);
        mulmod(t2, w[50], w[441]);
        mulmod_constant(t2, t2, two);
        submod(w[679], t1, t2);
    }

    // AND 8 465 -> 680
    mulmod(w[680], w[8], w[465]);

    // INV 258 -> 681
    submod(w[681], one, w[258]);

    // AND 387 438 -> 682
    mulmod(w[682], w[387], w[438]);

    // AND 199 18 -> 683
    mulmod(w[683], w[199], w[18]);

    // AND 216 68 -> 684
    mulmod(w[684], w[216], w[68]);

    // AND 145 507 -> 685
    mulmod(w[685], w[145], w[507]);

    // AND 258 105 -> 686
    mulmod(w[686], w[258], w[105]);

    // XOR 105 180 -> 687
    {
        bn254fr_class t1, t2;
        addmod(t1, w[105], w[180]);
        mulmod(t2, w[105], w[180]);
        mulmod_constant(t2, t2, two);
        submod(w[687], t1, t2);
    }

    // XOR 80 412 -> 688
    {
        bn254fr_class t1, t2;
        addmod(t1, w[80], w[412]);
        mulmod(t2, w[80], w[412]);
        mulmod_constant(t2, t2, two);
        submod(w[688], t1, t2);
    }

    // AND 393 346 -> 689
    mulmod(w[689], w[393], w[346]);

    // XOR 326 220 -> 690
    {
        bn254fr_class t1, t2;
        addmod(t1, w[326], w[220]);
        mulmod(t2, w[326], w[220]);
        mulmod_constant(t2, t2, two);
        submod(w[690], t1, t2);
    }

    // XOR 389 166 -> 691
    {
        bn254fr_class t1, t2;
        addmod(t1, w[389], w[166]);
        mulmod(t2, w[389], w[166]);
        mulmod_constant(t2, t2, two);
        submod(w[691], t1, t2);
    }

    // AND 287 428 -> 692
    mulmod(w[692], w[287], w[428]);

    // XOR 325 509 -> 693
    {
        bn254fr_class t1, t2;
        addmod(t1, w[325], w[509]);
        mulmod(t2, w[325], w[509]);
        mulmod_constant(t2, t2, two);
        submod(w[693], t1, t2);
    }

    // XOR 81 409 -> 694
    {
        bn254fr_class t1, t2;
        addmod(t1, w[81], w[409]);
        mulmod(t2, w[81], w[409]);
        mulmod_constant(t2, t2, two);
        submod(w[694], t1, t2);
    }

    // XOR 553 416 -> 695
    {
        bn254fr_class t1, t2;
        addmod(t1, w[553], w[416]);
        mulmod(t2, w[553], w[416]);
        mulmod_constant(t2, t2, two);
        submod(w[695], t1, t2);
    }

    // AND 402 295 -> 696
    mulmod(w[696], w[402], w[295]);

    // AND 504 385 -> 697
    mulmod(w[697], w[504], w[385]);

    // XOR 151 328 -> 698
    {
        bn254fr_class t1, t2;
        addmod(t1, w[151], w[328]);
        mulmod(t2, w[151], w[328]);
        mulmod_constant(t2, t2, two);
        submod(w[698], t1, t2);
    }

    // AND 128 228 -> 699
    mulmod(w[699], w[128], w[228]);

    // XOR 579 564 -> 700
    {
        bn254fr_class t1, t2;
        addmod(t1, w[579], w[564]);
        mulmod(t2, w[579], w[564]);
        mulmod_constant(t2, t2, two);
        submod(w[700], t1, t2);
    }

    // AND 193 268 -> 701
    mulmod(w[701], w[193], w[268]);

    // AND 37 129 -> 702
    mulmod(w[702], w[37], w[129]);

    // XOR 524 620 -> 703
    {
        bn254fr_class t1, t2;
        addmod(t1, w[524], w[620]);
        mulmod(t2, w[524], w[620]);
        mulmod_constant(t2, t2, two);
        submod(w[703], t1, t2);
    }

    // AND 206 546 -> 704
    mulmod(w[704], w[206], w[546]);

    // AND 621 574 -> 705
    mulmod(w[705], w[621], w[574]);

    // XOR 260 494 -> 706
    {
        bn254fr_class t1, t2;
        addmod(t1, w[260], w[494]);
        mulmod(t2, w[260], w[494]);
        mulmod_constant(t2, t2, two);
        submod(w[706], t1, t2);
    }

    // AND 382 479 -> 707
    mulmod(w[707], w[382], w[479]);

    // AND 56 601 -> 708
    mulmod(w[708], w[56], w[601]);

    // XOR 53 529 -> 709
    {
        bn254fr_class t1, t2;
        addmod(t1, w[53], w[529]);
        mulmod(t2, w[53], w[529]);
        mulmod_constant(t2, t2, two);
        submod(w[709], t1, t2);
    }

    // XOR 627 18 -> 710
    {
        bn254fr_class t1, t2;
        addmod(t1, w[627], w[18]);
        mulmod(t2, w[627], w[18]);
        mulmod_constant(t2, t2, two);
        submod(w[710], t1, t2);
    }

    // AND 379 686 -> 711
    mulmod(w[711], w[379], w[686]);

    // AND 282 435 -> 712
    mulmod(w[712], w[282], w[435]);

    // XOR 658 609 -> 713
    {
        bn254fr_class t1, t2;
        addmod(t1, w[658], w[609]);
        mulmod(t2, w[658], w[609]);
        mulmod_constant(t2, t2, two);
        submod(w[713], t1, t2);
    }

    // AND 579 101 -> 714
    mulmod(w[714], w[579], w[101]);

    // XOR 648 245 -> 715
    {
        bn254fr_class t1, t2;
        addmod(t1, w[648], w[245]);
        mulmod(t2, w[648], w[245]);
        mulmod_constant(t2, t2, two);
        submod(w[715], t1, t2);
    }

    // AND 415 449 -> 716
    mulmod(w[716], w[415], w[449]);

    // XOR 687 386 -> 717
    {
        bn254fr_class t1, t2;
        addmod(t1, w[687], w[386]);
        mulmod(t2, w[687], w[386]);
        mulmod_constant(t2, t2, two);
        submod(w[717], t1, t2);
    }

    // XOR 253 458 -> 718
    {
        bn254fr_class t1, t2;
        addmod(t1, w[253], w[458]);
        mulmod(t2, w[253], w[458]);
        mulmod_constant(t2, t2, two);
        submod(w[718], t1, t2);
    }

    // XOR 508 430 -> 719
    {
        bn254fr_class t1, t2;
        addmod(t1, w[508], w[430]);
        mulmod(t2, w[508], w[430]);
        mulmod_constant(t2, t2, two);
        submod(w[719], t1, t2);
    }

    // AND 187 548 -> 720
    mulmod(w[720], w[187], w[548]);

    // INV 116 -> 721
    submod(w[721], one, w[116]);

    // INV 49 -> 722
    submod(w[722], one, w[49]);

    // XOR 464 303 -> 723
    {
        bn254fr_class t1, t2;
        addmod(t1, w[464], w[303]);
        mulmod(t2, w[464], w[303]);
        mulmod_constant(t2, t2, two);
        submod(w[723], t1, t2);
    }

    // INV 463 -> 724
    submod(w[724], one, w[463]);

    // XOR 299 213 -> 725
    {
        bn254fr_class t1, t2;
        addmod(t1, w[299], w[213]);
        mulmod(t2, w[299], w[213]);
        mulmod_constant(t2, t2, two);
        submod(w[725], t1, t2);
    }

    // XOR 288 160 -> 726
    {
        bn254fr_class t1, t2;
        addmod(t1, w[288], w[160]);
        mulmod(t2, w[288], w[160]);
        mulmod_constant(t2, t2, two);
        submod(w[726], t1, t2);
    }

    // XOR 543 260 -> 727
    {
        bn254fr_class t1, t2;
        addmod(t1, w[543], w[260]);
        mulmod(t2, w[543], w[260]);
        mulmod_constant(t2, t2, two);
        submod(w[727], t1, t2);
    }

    // INV 526 -> 728
    submod(w[728], one, w[526]);

    // XOR 686 54 -> 729
    {
        bn254fr_class t1, t2;
        addmod(t1, w[686], w[54]);
        mulmod(t2, w[686], w[54]);
        mulmod_constant(t2, t2, two);
        submod(w[729], t1, t2);
    }

    // XOR 145 136 -> 730
    {
        bn254fr_class t1, t2;
        addmod(t1, w[145], w[136]);
        mulmod(t2, w[145], w[136]);
        mulmod_constant(t2, t2, two);
        submod(w[730], t1, t2);
    }

    // AND 30 633 -> 731
    mulmod(w[731], w[30], w[633]);

    // XOR 59 375 -> 732
    {
        bn254fr_class t1, t2;
        addmod(t1, w[59], w[375]);
        mulmod(t2, w[59], w[375]);
        mulmod_constant(t2, t2, two);
        submod(w[732], t1, t2);
    }

    // AND 425 365 -> 733
    mulmod(w[733], w[425], w[365]);

    // AND 653 85 -> 734
    mulmod(w[734], w[653], w[85]);

    // AND 72 71 -> 735
    mulmod(w[735], w[72], w[71]);

    // XOR 473 353 -> 736
    {
        bn254fr_class t1, t2;
        addmod(t1, w[473], w[353]);
        mulmod(t2, w[473], w[353]);
        mulmod_constant(t2, t2, two);
        submod(w[736], t1, t2);
    }

    // XOR 287 261 -> 737
    {
        bn254fr_class t1, t2;
        addmod(t1, w[287], w[261]);
        mulmod(t2, w[287], w[261]);
        mulmod_constant(t2, t2, two);
        submod(w[737], t1, t2);
    }

    // XOR 90 665 -> 738
    {
        bn254fr_class t1, t2;
        addmod(t1, w[90], w[665]);
        mulmod(t2, w[90], w[665]);
        mulmod_constant(t2, t2, two);
        submod(w[738], t1, t2);
    }

    // XOR 689 437 -> 739
    {
        bn254fr_class t1, t2;
        addmod(t1, w[689], w[437]);
        mulmod(t2, w[689], w[437]);
        mulmod_constant(t2, t2, two);
        submod(w[739], t1, t2);
    }

    // XOR 367 295 -> 740
    {
        bn254fr_class t1, t2;
        addmod(t1, w[367], w[295]);
        mulmod(t2, w[367], w[295]);
        mulmod_constant(t2, t2, two);
        submod(w[740], t1, t2);
    }

    // XOR 572 432 -> 741
    {
        bn254fr_class t1, t2;
        addmod(t1, w[572], w[432]);
        mulmod(t2, w[572], w[432]);
        mulmod_constant(t2, t2, two);
        submod(w[741], t1, t2);
    }

    // XOR 110 454 -> 742
    {
        bn254fr_class t1, t2;
        addmod(t1, w[110], w[454]);
        mulmod(t2, w[110], w[454]);
        mulmod_constant(t2, t2, two);
        submod(w[742], t1, t2);
    }

    // XOR 526 99 -> 743
    {
        bn254fr_class t1, t2;
        addmod(t1, w[526], w[99]);
        mulmod(t2, w[526], w[99]);
        mulmod_constant(t2, t2, two);
        submod(w[743], t1, t2);
    }

    // XOR 258 110 -> 744
    {
        bn254fr_class t1, t2;
        addmod(t1, w[258], w[110]);
        mulmod(t2, w[258], w[110]);
        mulmod_constant(t2, t2, two);
        submod(w[744], t1, t2);
    }

    // XOR 166 233 -> 745
    {
        bn254fr_class t1, t2;
        addmod(t1, w[166], w[233]);
        mulmod(t2, w[166], w[233]);
        mulmod_constant(t2, t2, two);
        submod(w[745], t1, t2);
    }

    // XOR 410 300 -> 746
    {
        bn254fr_class t1, t2;
        addmod(t1, w[410], w[300]);
        mulmod(t2, w[410], w[300]);
        mulmod_constant(t2, t2, two);
        submod(w[746], t1, t2);
    }

    // XOR 257 196 -> 747
    {
        bn254fr_class t1, t2;
        addmod(t1, w[257], w[196]);
        mulmod(t2, w[257], w[196]);
        mulmod_constant(t2, t2, two);
        submod(w[747], t1, t2);
    }

    // XOR 333 444 -> 748
    {
        bn254fr_class t1, t2;
        addmod(t1, w[333], w[444]);
        mulmod(t2, w[333], w[444]);
        mulmod_constant(t2, t2, two);
        submod(w[748], t1, t2);
    }

    // AND 599 248 -> 749
    mulmod(w[749], w[599], w[248]);

    // AND 638 368 -> 750
    mulmod(w[750], w[638], w[368]);

    // XOR 423 168 -> 751
    {
        bn254fr_class t1, t2;
        addmod(t1, w[423], w[168]);
        mulmod(t2, w[423], w[168]);
        mulmod_constant(t2, t2, two);
        submod(w[751], t1, t2);
    }

    // XOR 317 238 -> 752
    {
        bn254fr_class t1, t2;
        addmod(t1, w[317], w[238]);
        mulmod(t2, w[317], w[238]);
        mulmod_constant(t2, t2, two);
        submod(w[752], t1, t2);
    }

    // XOR 339 580 -> 753
    {
        bn254fr_class t1, t2;
        addmod(t1, w[339], w[580]);
        mulmod(t2, w[339], w[580]);
        mulmod_constant(t2, t2, two);
        submod(w[753], t1, t2);
    }

    // XOR 372 513 -> 754
    {
        bn254fr_class t1, t2;
        addmod(t1, w[372], w[513]);
        mulmod(t2, w[372], w[513]);
        mulmod_constant(t2, t2, two);
        submod(w[754], t1, t2);
    }

    // XOR 560 123 -> 755
    {
        bn254fr_class t1, t2;
        addmod(t1, w[560], w[123]);
        mulmod(t2, w[560], w[123]);
        mulmod_constant(t2, t2, two);
        submod(w[755], t1, t2);
    }

    // XOR 532 132 -> 756
    {
        bn254fr_class t1, t2;
        addmod(t1, w[532], w[132]);
        mulmod(t2, w[532], w[132]);
        mulmod_constant(t2, t2, two);
        submod(w[756], t1, t2);
    }

    // XOR 232 10 -> 757
    {
        bn254fr_class t1, t2;
        addmod(t1, w[232], w[10]);
        mulmod(t2, w[232], w[10]);
        mulmod_constant(t2, t2, two);
        submod(w[757], t1, t2);
    }

    // XOR 179 322 -> 758
    {
        bn254fr_class t1, t2;
        addmod(t1, w[179], w[322]);
        mulmod(t2, w[179], w[322]);
        mulmod_constant(t2, t2, two);
        submod(w[758], t1, t2);
    }

    // XOR 155 469 -> 759
    {
        bn254fr_class t1, t2;
        addmod(t1, w[155], w[469]);
        mulmod(t2, w[155], w[469]);
        mulmod_constant(t2, t2, two);
        submod(w[759], t1, t2);
    }

    // XOR 55 559 -> 760
    {
        bn254fr_class t1, t2;
        addmod(t1, w[55], w[559]);
        mulmod(t2, w[55], w[559]);
        mulmod_constant(t2, t2, two);
        submod(w[760], t1, t2);
    }

    // XOR 661 413 -> 761
    {
        bn254fr_class t1, t2;
        addmod(t1, w[661], w[413]);
        mulmod(t2, w[661], w[413]);
        mulmod_constant(t2, t2, two);
        submod(w[761], t1, t2);
    }

    // AND 8 359 -> 762
    mulmod(w[762], w[8], w[359]);

    // XOR 565 292 -> 763
    {
        bn254fr_class t1, t2;
        addmod(t1, w[565], w[292]);
        mulmod(t2, w[565], w[292]);
        mulmod_constant(t2, t2, two);
        submod(w[763], t1, t2);
    }

    // XOR 352 541 -> 764
    {
        bn254fr_class t1, t2;
        addmod(t1, w[352], w[541]);
        mulmod(t2, w[352], w[541]);
        mulmod_constant(t2, t2, two);
        submod(w[764], t1, t2);
    }

    // AND 361 41 -> 765
    mulmod(w[765], w[361], w[41]);

    // XOR 278 482 -> 766
    {
        bn254fr_class t1, t2;
        addmod(t1, w[278], w[482]);
        mulmod(t2, w[278], w[482]);
        mulmod_constant(t2, t2, two);
        submod(w[766], t1, t2);
    }

    // XOR 136 635 -> 767
    {
        bn254fr_class t1, t2;
        addmod(t1, w[136], w[635]);
        mulmod(t2, w[136], w[635]);
        mulmod_constant(t2, t2, two);
        submod(w[767], t1, t2);
    }

    // INV 145 -> 768
    submod(w[768], one, w[145]);

    // XOR 70 379 -> 769
    {
        bn254fr_class t1, t2;
        addmod(t1, w[70], w[379]);
        mulmod(t2, w[70], w[379]);
        mulmod_constant(t2, t2, two);
        submod(w[769], t1, t2);
    }

    // AND 619 504 -> 770
    mulmod(w[770], w[619], w[504]);

    // AND 365 7 -> 771
    mulmod(w[771], w[365], w[7]);

    // XOR 224 479 -> 772
    {
        bn254fr_class t1, t2;
        addmod(t1, w[224], w[479]);
        mulmod(t2, w[224], w[479]);
        mulmod_constant(t2, t2, two);
        submod(w[772], t1, t2);
    }

    // AND 498 591 -> 773
    mulmod(w[773], w[498], w[591]);

    // AND 562 317 -> 774
    mulmod(w[774], w[562], w[317]);

    // XOR 42 698 -> 775
    {
        bn254fr_class t1, t2;
        addmod(t1, w[42], w[698]);
        mulmod(t2, w[42], w[698]);
        mulmod_constant(t2, t2, two);
        submod(w[775], t1, t2);
    }

    // XOR 111 451 -> 776
    {
        bn254fr_class t1, t2;
        addmod(t1, w[111], w[451]);
        mulmod(t2, w[111], w[451]);
        mulmod_constant(t2, t2, two);
        submod(w[776], t1, t2);
    }

    // AND 207 91 -> 777
    mulmod(w[777], w[207], w[91]);

    // XOR 363 475 -> 778
    {
        bn254fr_class t1, t2;
        addmod(t1, w[363], w[475]);
        mulmod(t2, w[363], w[475]);
        mulmod_constant(t2, t2, two);
        submod(w[778], t1, t2);
    }

    // AND 95 598 -> 779
    mulmod(w[779], w[95], w[598]);

    // XOR 238 248 -> 780
    {
        bn254fr_class t1, t2;
        addmod(t1, w[238], w[248]);
        mulmod(t2, w[238], w[248]);
        mulmod_constant(t2, t2, two);
        submod(w[780], t1, t2);
    }

    // XOR 178 202 -> 781
    {
        bn254fr_class t1, t2;
        addmod(t1, w[178], w[202]);
        mulmod(t2, w[178], w[202]);
        mulmod_constant(t2, t2, two);
        submod(w[781], t1, t2);
    }

    // XOR 212 22 -> 782
    {
        bn254fr_class t1, t2;
        addmod(t1, w[212], w[22]);
        mulmod(t2, w[212], w[22]);
        mulmod_constant(t2, t2, two);
        submod(w[782], t1, t2);
    }

    // XOR 344 279 -> 783
    {
        bn254fr_class t1, t2;
        addmod(t1, w[344], w[279]);
        mulmod(t2, w[344], w[279]);
        mulmod_constant(t2, t2, two);
        submod(w[783], t1, t2);
    }

    // AND 387 672 -> 784
    mulmod(w[784], w[387], w[672]);

    // XOR 384 371 -> 785
    {
        bn254fr_class t1, t2;
        addmod(t1, w[384], w[371]);
        mulmod(t2, w[384], w[371]);
        mulmod_constant(t2, t2, two);
        submod(w[785], t1, t2);
    }

    // AND 67 213 -> 786
    mulmod(w[786], w[67], w[213]);

    // AND 492 114 -> 787
    mulmod(w[787], w[492], w[114]);

    // XOR 28 91 -> 788
    {
        bn254fr_class t1, t2;
        addmod(t1, w[28], w[91]);
        mulmod(t2, w[28], w[91]);
        mulmod_constant(t2, t2, two);
        submod(w[788], t1, t2);
    }

    // XOR 20 369 -> 789
    {
        bn254fr_class t1, t2;
        addmod(t1, w[20], w[369]);
        mulmod(t2, w[20], w[369]);
        mulmod_constant(t2, t2, two);
        submod(w[789], t1, t2);
    }

    // XOR 581 284 -> 790
    {
        bn254fr_class t1, t2;
        addmod(t1, w[581], w[284]);
        mulmod(t2, w[581], w[284]);
        mulmod_constant(t2, t2, two);
        submod(w[790], t1, t2);
    }

    // INV 269 -> 791
    submod(w[791], one, w[269]);

    // XOR 313 359 -> 792
    {
        bn254fr_class t1, t2;
        addmod(t1, w[313], w[359]);
        mulmod(t2, w[313], w[359]);
        mulmod_constant(t2, t2, two);
        submod(w[792], t1, t2);
    }

    // XOR 555 409 -> 793
    {
        bn254fr_class t1, t2;
        addmod(t1, w[555], w[409]);
        mulmod(t2, w[555], w[409]);
        mulmod_constant(t2, t2, two);
        submod(w[793], t1, t2);
    }

    // AND 273 125 -> 794
    mulmod(w[794], w[273], w[125]);

    // AND 579 681 -> 795
    mulmod(w[795], w[579], w[681]);

    // XOR 424 342 -> 796
    {
        bn254fr_class t1, t2;
        addmod(t1, w[424], w[342]);
        mulmod(t2, w[424], w[342]);
        mulmod_constant(t2, t2, two);
        submod(w[796], t1, t2);
    }

    // AND 179 481 -> 797
    mulmod(w[797], w[179], w[481]);

    // XOR 618 448 -> 798
    {
        bn254fr_class t1, t2;
        addmod(t1, w[618], w[448]);
        mulmod(t2, w[618], w[448]);
        mulmod_constant(t2, t2, two);
        submod(w[798], t1, t2);
    }

    // XOR 380 321 -> 799
    {
        bn254fr_class t1, t2;
        addmod(t1, w[380], w[321]);
        mulmod(t2, w[380], w[321]);
        mulmod_constant(t2, t2, two);
        submod(w[799], t1, t2);
    }

    // XOR 582 33 -> 800
    {
        bn254fr_class t1, t2;
        addmod(t1, w[582], w[33]);
        mulmod(t2, w[582], w[33]);
        mulmod_constant(t2, t2, two);
        submod(w[800], t1, t2);
    }

    // AND 381 343 -> 801
    mulmod(w[801], w[381], w[343]);

    // XOR 188 459 -> 802
    {
        bn254fr_class t1, t2;
        addmod(t1, w[188], w[459]);
        mulmod(t2, w[188], w[459]);
        mulmod_constant(t2, t2, two);
        submod(w[802], t1, t2);
    }

    // AND 384 543 -> 803
    mulmod(w[803], w[384], w[543]);

    // INV 442 -> 804
    submod(w[804], one, w[442]);

    // INV 90 -> 805
    submod(w[805], one, w[90]);

    // AND 571 147 -> 806
    mulmod(w[806], w[571], w[147]);

    // AND 177 56 -> 807
    mulmod(w[807], w[177], w[56]);

    // XOR 251 205 -> 808
    {
        bn254fr_class t1, t2;
        addmod(t1, w[251], w[205]);
        mulmod(t2, w[251], w[205]);
        mulmod_constant(t2, t2, two);
        submod(w[808], t1, t2);
    }

    // XOR 151 166 -> 809
    {
        bn254fr_class t1, t2;
        addmod(t1, w[151], w[166]);
        mulmod(t2, w[151], w[166]);
        mulmod_constant(t2, t2, two);
        submod(w[809], t1, t2);
    }

    // XOR 189 159 -> 810
    {
        bn254fr_class t1, t2;
        addmod(t1, w[189], w[159]);
        mulmod(t2, w[189], w[159]);
        mulmod_constant(t2, t2, two);
        submod(w[810], t1, t2);
    }

    // AND 218 689 -> 811
    mulmod(w[811], w[218], w[689]);

    // XOR 530 33 -> 812
    {
        bn254fr_class t1, t2;
        addmod(t1, w[530], w[33]);
        mulmod(t2, w[530], w[33]);
        mulmod_constant(t2, t2, two);
        submod(w[812], t1, t2);
    }

    // XOR 503 103 -> 813
    {
        bn254fr_class t1, t2;
        addmod(t1, w[503], w[103]);
        mulmod(t2, w[503], w[103]);
        mulmod_constant(t2, t2, two);
        submod(w[813], t1, t2);
    }

    // XOR 218 143 -> 814
    {
        bn254fr_class t1, t2;
        addmod(t1, w[218], w[143]);
        mulmod(t2, w[218], w[143]);
        mulmod_constant(t2, t2, two);
        submod(w[814], t1, t2);
    }

    // XOR 1 705 -> 815
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1], w[705]);
        mulmod(t2, w[1], w[705]);
        mulmod_constant(t2, t2, two);
        submod(w[815], t1, t2);
    }

    // AND 339 0 -> 816
    mulmod(w[816], w[339], w[0]);

    // XOR 266 806 -> 817
    {
        bn254fr_class t1, t2;
        addmod(t1, w[266], w[806]);
        mulmod(t2, w[266], w[806]);
        mulmod_constant(t2, t2, two);
        submod(w[817], t1, t2);
    }

    // XOR 659 478 -> 818
    {
        bn254fr_class t1, t2;
        addmod(t1, w[659], w[478]);
        mulmod(t2, w[659], w[478]);
        mulmod_constant(t2, t2, two);
        submod(w[818], t1, t2);
    }

    // AND 505 658 -> 819
    mulmod(w[819], w[505], w[658]);

    // AND 105 378 -> 820
    mulmod(w[820], w[105], w[378]);

    // XOR 337 90 -> 821
    {
        bn254fr_class t1, t2;
        addmod(t1, w[337], w[90]);
        mulmod(t2, w[337], w[90]);
        mulmod_constant(t2, t2, two);
        submod(w[821], t1, t2);
    }

    // XOR 145 44 -> 822
    {
        bn254fr_class t1, t2;
        addmod(t1, w[145], w[44]);
        mulmod(t2, w[145], w[44]);
        mulmod_constant(t2, t2, two);
        submod(w[822], t1, t2);
    }

    // XOR 378 718 -> 823
    {
        bn254fr_class t1, t2;
        addmod(t1, w[378], w[718]);
        mulmod(t2, w[378], w[718]);
        mulmod_constant(t2, t2, two);
        submod(w[823], t1, t2);
    }

    // AND 276 211 -> 824
    mulmod(w[824], w[276], w[211]);

    // XOR 190 588 -> 825
    {
        bn254fr_class t1, t2;
        addmod(t1, w[190], w[588]);
        mulmod(t2, w[190], w[588]);
        mulmod_constant(t2, t2, two);
        submod(w[825], t1, t2);
    }

    // XOR 171 363 -> 826
    {
        bn254fr_class t1, t2;
        addmod(t1, w[171], w[363]);
        mulmod(t2, w[171], w[363]);
        mulmod_constant(t2, t2, two);
        submod(w[826], t1, t2);
    }

    // AND 479 466 -> 827
    mulmod(w[827], w[479], w[466]);

    // XOR 81 190 -> 828
    {
        bn254fr_class t1, t2;
        addmod(t1, w[81], w[190]);
        mulmod(t2, w[81], w[190]);
        mulmod_constant(t2, t2, two);
        submod(w[828], t1, t2);
    }

    // XOR 725 499 -> 829
    {
        bn254fr_class t1, t2;
        addmod(t1, w[725], w[499]);
        mulmod(t2, w[725], w[499]);
        mulmod_constant(t2, t2, two);
        submod(w[829], t1, t2);
    }

    // AND 504 45 -> 830
    mulmod(w[830], w[504], w[45]);

    // XOR 612 196 -> 831
    {
        bn254fr_class t1, t2;
        addmod(t1, w[612], w[196]);
        mulmod(t2, w[612], w[196]);
        mulmod_constant(t2, t2, two);
        submod(w[831], t1, t2);
    }

    // XOR 89 525 -> 832
    {
        bn254fr_class t1, t2;
        addmod(t1, w[89], w[525]);
        mulmod(t2, w[89], w[525]);
        mulmod_constant(t2, t2, two);
        submod(w[832], t1, t2);
    }

    // XOR 77 676 -> 833
    {
        bn254fr_class t1, t2;
        addmod(t1, w[77], w[676]);
        mulmod(t2, w[77], w[676]);
        mulmod_constant(t2, t2, two);
        submod(w[833], t1, t2);
    }

    // AND 540 766 -> 834
    mulmod(w[834], w[540], w[766]);

    // AND 90 250 -> 835
    mulmod(w[835], w[90], w[250]);

    // INV 416 -> 836
    submod(w[836], one, w[416]);

    // AND 638 134 -> 837
    mulmod(w[837], w[638], w[134]);

    // AND 21 773 -> 838
    mulmod(w[838], w[21], w[773]);

    // XOR 545 223 -> 839
    {
        bn254fr_class t1, t2;
        addmod(t1, w[545], w[223]);
        mulmod(t2, w[545], w[223]);
        mulmod_constant(t2, t2, two);
        submod(w[839], t1, t2);
    }

    // XOR 172 170 -> 840
    {
        bn254fr_class t1, t2;
        addmod(t1, w[172], w[170]);
        mulmod(t2, w[172], w[170]);
        mulmod_constant(t2, t2, two);
        submod(w[840], t1, t2);
    }

    // XOR 348 650 -> 841
    {
        bn254fr_class t1, t2;
        addmod(t1, w[348], w[650]);
        mulmod(t2, w[348], w[650]);
        mulmod_constant(t2, t2, two);
        submod(w[841], t1, t2);
    }

    // XOR 330 441 -> 842
    {
        bn254fr_class t1, t2;
        addmod(t1, w[330], w[441]);
        mulmod(t2, w[330], w[441]);
        mulmod_constant(t2, t2, two);
        submod(w[842], t1, t2);
    }

    // XOR 403 160 -> 843
    {
        bn254fr_class t1, t2;
        addmod(t1, w[403], w[160]);
        mulmod(t2, w[403], w[160]);
        mulmod_constant(t2, t2, two);
        submod(w[843], t1, t2);
    }

    // XOR 82 161 -> 844
    {
        bn254fr_class t1, t2;
        addmod(t1, w[82], w[161]);
        mulmod(t2, w[82], w[161]);
        mulmod_constant(t2, t2, two);
        submod(w[844], t1, t2);
    }

    // INV 22 -> 845
    submod(w[845], one, w[22]);

    // XOR 784 337 -> 846
    {
        bn254fr_class t1, t2;
        addmod(t1, w[784], w[337]);
        mulmod(t2, w[784], w[337]);
        mulmod_constant(t2, t2, two);
        submod(w[846], t1, t2);
    }

    // INV 744 -> 847
    submod(w[847], one, w[744]);

    // XOR 40 470 -> 848
    {
        bn254fr_class t1, t2;
        addmod(t1, w[40], w[470]);
        mulmod(t2, w[40], w[470]);
        mulmod_constant(t2, t2, two);
        submod(w[848], t1, t2);
    }

    // XOR 110 573 -> 849
    {
        bn254fr_class t1, t2;
        addmod(t1, w[110], w[573]);
        mulmod(t2, w[110], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[849], t1, t2);
    }

    // XOR 234 15 -> 850
    {
        bn254fr_class t1, t2;
        addmod(t1, w[234], w[15]);
        mulmod(t2, w[234], w[15]);
        mulmod_constant(t2, t2, two);
        submod(w[850], t1, t2);
    }

    // XOR 757 226 -> 851
    {
        bn254fr_class t1, t2;
        addmod(t1, w[757], w[226]);
        mulmod(t2, w[757], w[226]);
        mulmod_constant(t2, t2, two);
        submod(w[851], t1, t2);
    }

    // XOR 184 643 -> 852
    {
        bn254fr_class t1, t2;
        addmod(t1, w[184], w[643]);
        mulmod(t2, w[184], w[643]);
        mulmod_constant(t2, t2, two);
        submod(w[852], t1, t2);
    }

    // XOR 250 245 -> 853
    {
        bn254fr_class t1, t2;
        addmod(t1, w[250], w[245]);
        mulmod(t2, w[250], w[245]);
        mulmod_constant(t2, t2, two);
        submod(w[853], t1, t2);
    }

    // INV 620 -> 854
    submod(w[854], one, w[620]);

    // XOR 88 1 -> 855
    {
        bn254fr_class t1, t2;
        addmod(t1, w[88], w[1]);
        mulmod(t2, w[88], w[1]);
        mulmod_constant(t2, t2, two);
        submod(w[855], t1, t2);
    }

    // AND 147 295 -> 856
    mulmod(w[856], w[147], w[295]);

    // XOR 488 108 -> 857
    {
        bn254fr_class t1, t2;
        addmod(t1, w[488], w[108]);
        mulmod(t2, w[488], w[108]);
        mulmod_constant(t2, t2, two);
        submod(w[857], t1, t2);
    }

    // XOR 134 408 -> 858
    {
        bn254fr_class t1, t2;
        addmod(t1, w[134], w[408]);
        mulmod(t2, w[134], w[408]);
        mulmod_constant(t2, t2, two);
        submod(w[858], t1, t2);
    }

    // INV 278 -> 859
    submod(w[859], one, w[278]);

    // AND 379 178 -> 860
    mulmod(w[860], w[379], w[178]);

    // AND 450 670 -> 861
    mulmod(w[861], w[450], w[670]);

    // XOR 757 167 -> 862
    {
        bn254fr_class t1, t2;
        addmod(t1, w[757], w[167]);
        mulmod(t2, w[757], w[167]);
        mulmod_constant(t2, t2, two);
        submod(w[862], t1, t2);
    }

    // AND 493 113 -> 863
    mulmod(w[863], w[493], w[113]);

    // AND 644 72 -> 864
    mulmod(w[864], w[644], w[72]);

    // AND 175 629 -> 865
    mulmod(w[865], w[175], w[629]);

    // AND 712 43 -> 866
    mulmod(w[866], w[712], w[43]);

    // XOR 171 574 -> 867
    {
        bn254fr_class t1, t2;
        addmod(t1, w[171], w[574]);
        mulmod(t2, w[171], w[574]);
        mulmod_constant(t2, t2, two);
        submod(w[867], t1, t2);
    }

    // XOR 7 712 -> 868
    {
        bn254fr_class t1, t2;
        addmod(t1, w[7], w[712]);
        mulmod(t2, w[7], w[712]);
        mulmod_constant(t2, t2, two);
        submod(w[868], t1, t2);
    }

    // XOR 211 372 -> 869
    {
        bn254fr_class t1, t2;
        addmod(t1, w[211], w[372]);
        mulmod(t2, w[211], w[372]);
        mulmod_constant(t2, t2, two);
        submod(w[869], t1, t2);
    }

    // XOR 674 262 -> 870
    {
        bn254fr_class t1, t2;
        addmod(t1, w[674], w[262]);
        mulmod(t2, w[674], w[262]);
        mulmod_constant(t2, t2, two);
        submod(w[870], t1, t2);
    }

    // INV 368 -> 871
    submod(w[871], one, w[368]);

    // XOR 492 794 -> 872
    {
        bn254fr_class t1, t2;
        addmod(t1, w[492], w[794]);
        mulmod(t2, w[492], w[794]);
        mulmod_constant(t2, t2, two);
        submod(w[872], t1, t2);
    }

    // AND 31 168 -> 873
    mulmod(w[873], w[31], w[168]);

    // AND 295 665 -> 874
    mulmod(w[874], w[295], w[665]);

    // XOR 32 498 -> 875
    {
        bn254fr_class t1, t2;
        addmod(t1, w[32], w[498]);
        mulmod(t2, w[32], w[498]);
        mulmod_constant(t2, t2, two);
        submod(w[875], t1, t2);
    }

    // AND 548 700 -> 876
    mulmod(w[876], w[548], w[700]);

    // AND 365 681 -> 877
    mulmod(w[877], w[365], w[681]);

    // XOR 761 237 -> 878
    {
        bn254fr_class t1, t2;
        addmod(t1, w[761], w[237]);
        mulmod(t2, w[761], w[237]);
        mulmod_constant(t2, t2, two);
        submod(w[878], t1, t2);
    }

    // AND 696 536 -> 879
    mulmod(w[879], w[696], w[536]);

    // XOR 184 352 -> 880
    {
        bn254fr_class t1, t2;
        addmod(t1, w[184], w[352]);
        mulmod(t2, w[184], w[352]);
        mulmod_constant(t2, t2, two);
        submod(w[880], t1, t2);
    }

    // XOR 175 637 -> 881
    {
        bn254fr_class t1, t2;
        addmod(t1, w[175], w[637]);
        mulmod(t2, w[175], w[637]);
        mulmod_constant(t2, t2, two);
        submod(w[881], t1, t2);
    }

    // AND 263 39 -> 882
    mulmod(w[882], w[263], w[39]);

    // XOR 326 633 -> 883
    {
        bn254fr_class t1, t2;
        addmod(t1, w[326], w[633]);
        mulmod(t2, w[326], w[633]);
        mulmod_constant(t2, t2, two);
        submod(w[883], t1, t2);
    }

    // XOR 19 591 -> 884
    {
        bn254fr_class t1, t2;
        addmod(t1, w[19], w[591]);
        mulmod(t2, w[19], w[591]);
        mulmod_constant(t2, t2, two);
        submod(w[884], t1, t2);
    }

    // XOR 518 175 -> 885
    {
        bn254fr_class t1, t2;
        addmod(t1, w[518], w[175]);
        mulmod(t2, w[518], w[175]);
        mulmod_constant(t2, t2, two);
        submod(w[885], t1, t2);
    }

    // AND 640 745 -> 886
    mulmod(w[886], w[640], w[745]);

    // XOR 55 357 -> 887
    {
        bn254fr_class t1, t2;
        addmod(t1, w[55], w[357]);
        mulmod(t2, w[55], w[357]);
        mulmod_constant(t2, t2, two);
        submod(w[887], t1, t2);
    }

    // XOR 456 804 -> 888
    {
        bn254fr_class t1, t2;
        addmod(t1, w[456], w[804]);
        mulmod(t2, w[456], w[804]);
        mulmod_constant(t2, t2, two);
        submod(w[888], t1, t2);
    }

    // XOR 125 543 -> 889
    {
        bn254fr_class t1, t2;
        addmod(t1, w[125], w[543]);
        mulmod(t2, w[125], w[543]);
        mulmod_constant(t2, t2, two);
        submod(w[889], t1, t2);
    }

    // XOR 700 32 -> 890
    {
        bn254fr_class t1, t2;
        addmod(t1, w[700], w[32]);
        mulmod(t2, w[700], w[32]);
        mulmod_constant(t2, t2, two);
        submod(w[890], t1, t2);
    }

    // XOR 684 62 -> 891
    {
        bn254fr_class t1, t2;
        addmod(t1, w[684], w[62]);
        mulmod(t2, w[684], w[62]);
        mulmod_constant(t2, t2, two);
        submod(w[891], t1, t2);
    }

    // XOR 565 699 -> 892
    {
        bn254fr_class t1, t2;
        addmod(t1, w[565], w[699]);
        mulmod(t2, w[565], w[699]);
        mulmod_constant(t2, t2, two);
        submod(w[892], t1, t2);
    }

    // XOR 402 536 -> 893
    {
        bn254fr_class t1, t2;
        addmod(t1, w[402], w[536]);
        mulmod(t2, w[402], w[536]);
        mulmod_constant(t2, t2, two);
        submod(w[893], t1, t2);
    }

    // AND 31 207 -> 894
    mulmod(w[894], w[31], w[207]);

    // AND 344 513 -> 895
    mulmod(w[895], w[344], w[513]);

    // XOR 271 397 -> 896
    {
        bn254fr_class t1, t2;
        addmod(t1, w[271], w[397]);
        mulmod(t2, w[271], w[397]);
        mulmod_constant(t2, t2, two);
        submod(w[896], t1, t2);
    }

    // INV 801 -> 897
    submod(w[897], one, w[801]);

    // XOR 788 588 -> 898
    {
        bn254fr_class t1, t2;
        addmod(t1, w[788], w[588]);
        mulmod(t2, w[788], w[588]);
        mulmod_constant(t2, t2, two);
        submod(w[898], t1, t2);
    }

    // XOR 633 527 -> 899
    {
        bn254fr_class t1, t2;
        addmod(t1, w[633], w[527]);
        mulmod(t2, w[633], w[527]);
        mulmod_constant(t2, t2, two);
        submod(w[899], t1, t2);
    }

    // XOR 512 275 -> 900
    {
        bn254fr_class t1, t2;
        addmod(t1, w[512], w[275]);
        mulmod(t2, w[512], w[275]);
        mulmod_constant(t2, t2, two);
        submod(w[900], t1, t2);
    }

    // INV 708 -> 901
    submod(w[901], one, w[708]);

    // XOR 789 179 -> 902
    {
        bn254fr_class t1, t2;
        addmod(t1, w[789], w[179]);
        mulmod(t2, w[789], w[179]);
        mulmod_constant(t2, t2, two);
        submod(w[902], t1, t2);
    }

    // XOR 384 13 -> 903
    {
        bn254fr_class t1, t2;
        addmod(t1, w[384], w[13]);
        mulmod(t2, w[384], w[13]);
        mulmod_constant(t2, t2, two);
        submod(w[903], t1, t2);
    }

    // XOR 172 504 -> 904
    {
        bn254fr_class t1, t2;
        addmod(t1, w[172], w[504]);
        mulmod(t2, w[172], w[504]);
        mulmod_constant(t2, t2, two);
        submod(w[904], t1, t2);
    }

    // XOR 468 444 -> 905
    {
        bn254fr_class t1, t2;
        addmod(t1, w[468], w[444]);
        mulmod(t2, w[468], w[444]);
        mulmod_constant(t2, t2, two);
        submod(w[905], t1, t2);
    }

    // AND 596 516 -> 906
    mulmod(w[906], w[596], w[516]);

    // AND 200 51 -> 907
    mulmod(w[907], w[200], w[51]);

    // AND 585 373 -> 908
    mulmod(w[908], w[585], w[373]);

    // XOR 321 97 -> 909
    {
        bn254fr_class t1, t2;
        addmod(t1, w[321], w[97]);
        mulmod(t2, w[321], w[97]);
        mulmod_constant(t2, t2, two);
        submod(w[909], t1, t2);
    }

    // AND 733 661 -> 910
    mulmod(w[910], w[733], w[661]);

    // XOR 681 173 -> 911
    {
        bn254fr_class t1, t2;
        addmod(t1, w[681], w[173]);
        mulmod(t2, w[681], w[173]);
        mulmod_constant(t2, t2, two);
        submod(w[911], t1, t2);
    }

    // INV 613 -> 912
    submod(w[912], one, w[613]);

    // INV 548 -> 913
    submod(w[913], one, w[548]);

    // XOR 100 601 -> 914
    {
        bn254fr_class t1, t2;
        addmod(t1, w[100], w[601]);
        mulmod(t2, w[100], w[601]);
        mulmod_constant(t2, t2, two);
        submod(w[914], t1, t2);
    }

    // AND 153 524 -> 915
    mulmod(w[915], w[153], w[524]);

    // AND 664 278 -> 916
    mulmod(w[916], w[664], w[278]);

    // XOR 84 167 -> 917
    {
        bn254fr_class t1, t2;
        addmod(t1, w[84], w[167]);
        mulmod(t2, w[84], w[167]);
        mulmod_constant(t2, t2, two);
        submod(w[917], t1, t2);
    }

    // XOR 389 227 -> 918
    {
        bn254fr_class t1, t2;
        addmod(t1, w[389], w[227]);
        mulmod(t2, w[389], w[227]);
        mulmod_constant(t2, t2, two);
        submod(w[918], t1, t2);
    }

    // XOR 744 548 -> 919
    {
        bn254fr_class t1, t2;
        addmod(t1, w[744], w[548]);
        mulmod(t2, w[744], w[548]);
        mulmod_constant(t2, t2, two);
        submod(w[919], t1, t2);
    }

    // XOR 357 246 -> 920
    {
        bn254fr_class t1, t2;
        addmod(t1, w[357], w[246]);
        mulmod(t2, w[357], w[246]);
        mulmod_constant(t2, t2, two);
        submod(w[920], t1, t2);
    }

    // AND 602 275 -> 921
    mulmod(w[921], w[602], w[275]);

    // AND 304 413 -> 922
    mulmod(w[922], w[304], w[413]);

    // XOR 172 11 -> 923
    {
        bn254fr_class t1, t2;
        addmod(t1, w[172], w[11]);
        mulmod(t2, w[172], w[11]);
        mulmod_constant(t2, t2, two);
        submod(w[923], t1, t2);
    }

    // XOR 764 908 -> 924
    {
        bn254fr_class t1, t2;
        addmod(t1, w[764], w[908]);
        mulmod(t2, w[764], w[908]);
        mulmod_constant(t2, t2, two);
        submod(w[924], t1, t2);
    }

    // XOR 418 240 -> 925
    {
        bn254fr_class t1, t2;
        addmod(t1, w[418], w[240]);
        mulmod(t2, w[418], w[240]);
        mulmod_constant(t2, t2, two);
        submod(w[925], t1, t2);
    }

    // XOR 539 228 -> 926
    {
        bn254fr_class t1, t2;
        addmod(t1, w[539], w[228]);
        mulmod(t2, w[539], w[228]);
        mulmod_constant(t2, t2, two);
        submod(w[926], t1, t2);
    }

    // AND 365 107 -> 927
    mulmod(w[927], w[365], w[107]);

    // XOR 306 463 -> 928
    {
        bn254fr_class t1, t2;
        addmod(t1, w[306], w[463]);
        mulmod(t2, w[306], w[463]);
        mulmod_constant(t2, t2, two);
        submod(w[928], t1, t2);
    }

    // AND 636 335 -> 929
    mulmod(w[929], w[636], w[335]);

    // AND 197 232 -> 930
    mulmod(w[930], w[197], w[232]);

    // XOR 333 743 -> 931
    {
        bn254fr_class t1, t2;
        addmod(t1, w[333], w[743]);
        mulmod(t2, w[333], w[743]);
        mulmod_constant(t2, t2, two);
        submod(w[931], t1, t2);
    }

    // XOR 462 65 -> 932
    {
        bn254fr_class t1, t2;
        addmod(t1, w[462], w[65]);
        mulmod(t2, w[462], w[65]);
        mulmod_constant(t2, t2, two);
        submod(w[932], t1, t2);
    }

    // XOR 406 264 -> 933
    {
        bn254fr_class t1, t2;
        addmod(t1, w[406], w[264]);
        mulmod(t2, w[406], w[264]);
        mulmod_constant(t2, t2, two);
        submod(w[933], t1, t2);
    }

    // XOR 552 414 -> 934
    {
        bn254fr_class t1, t2;
        addmod(t1, w[552], w[414]);
        mulmod(t2, w[552], w[414]);
        mulmod_constant(t2, t2, two);
        submod(w[934], t1, t2);
    }

    // XOR 460 698 -> 935
    {
        bn254fr_class t1, t2;
        addmod(t1, w[460], w[698]);
        mulmod(t2, w[460], w[698]);
        mulmod_constant(t2, t2, two);
        submod(w[935], t1, t2);
    }

    // AND 402 585 -> 936
    mulmod(w[936], w[402], w[585]);

    // AND 181 481 -> 937
    mulmod(w[937], w[181], w[481]);

    // AND 244 37 -> 938
    mulmod(w[938], w[244], w[37]);

    // AND 480 539 -> 939
    mulmod(w[939], w[480], w[539]);

    // XOR 653 874 -> 940
    {
        bn254fr_class t1, t2;
        addmod(t1, w[653], w[874]);
        mulmod(t2, w[653], w[874]);
        mulmod_constant(t2, t2, two);
        submod(w[940], t1, t2);
    }

    // AND 707 559 -> 941
    mulmod(w[941], w[707], w[559]);

    // AND 827 153 -> 942
    mulmod(w[942], w[827], w[153]);

    // XOR 829 763 -> 943
    {
        bn254fr_class t1, t2;
        addmod(t1, w[829], w[763]);
        mulmod(t2, w[829], w[763]);
        mulmod_constant(t2, t2, two);
        submod(w[943], t1, t2);
    }

    // AND 233 328 -> 944
    mulmod(w[944], w[233], w[328]);

    // AND 54 814 -> 945
    mulmod(w[945], w[54], w[814]);

    // XOR 62 227 -> 946
    {
        bn254fr_class t1, t2;
        addmod(t1, w[62], w[227]);
        mulmod(t2, w[62], w[227]);
        mulmod_constant(t2, t2, two);
        submod(w[946], t1, t2);
    }

    // AND 275 291 -> 947
    mulmod(w[947], w[275], w[291]);

    // AND 405 904 -> 948
    mulmod(w[948], w[405], w[904]);

    // XOR 310 646 -> 949
    {
        bn254fr_class t1, t2;
        addmod(t1, w[310], w[646]);
        mulmod(t2, w[310], w[646]);
        mulmod_constant(t2, t2, two);
        submod(w[949], t1, t2);
    }

    // INV 202 -> 950
    submod(w[950], one, w[202]);

    // XOR 310 269 -> 951
    {
        bn254fr_class t1, t2;
        addmod(t1, w[310], w[269]);
        mulmod(t2, w[310], w[269]);
        mulmod_constant(t2, t2, two);
        submod(w[951], t1, t2);
    }

    // XOR 759 475 -> 952
    {
        bn254fr_class t1, t2;
        addmod(t1, w[759], w[475]);
        mulmod(t2, w[759], w[475]);
        mulmod_constant(t2, t2, two);
        submod(w[952], t1, t2);
    }

    // AND 412 9 -> 953
    mulmod(w[953], w[412], w[9]);

    // AND 633 410 -> 954
    mulmod(w[954], w[633], w[410]);

    // XOR 687 706 -> 955
    {
        bn254fr_class t1, t2;
        addmod(t1, w[687], w[706]);
        mulmod(t2, w[687], w[706]);
        mulmod_constant(t2, t2, two);
        submod(w[955], t1, t2);
    }

    // INV 864 -> 956
    submod(w[956], one, w[864]);

    // XOR 308 17 -> 957
    {
        bn254fr_class t1, t2;
        addmod(t1, w[308], w[17]);
        mulmod(t2, w[308], w[17]);
        mulmod_constant(t2, t2, two);
        submod(w[957], t1, t2);
    }

    // AND 781 490 -> 958
    mulmod(w[958], w[781], w[490]);

    // XOR 491 850 -> 959
    {
        bn254fr_class t1, t2;
        addmod(t1, w[491], w[850]);
        mulmod(t2, w[491], w[850]);
        mulmod_constant(t2, t2, two);
        submod(w[959], t1, t2);
    }

    // XOR 638 660 -> 960
    {
        bn254fr_class t1, t2;
        addmod(t1, w[638], w[660]);
        mulmod(t2, w[638], w[660]);
        mulmod_constant(t2, t2, two);
        submod(w[960], t1, t2);
    }

    // AND 544 827 -> 961
    mulmod(w[961], w[544], w[827]);

    // XOR 325 322 -> 962
    {
        bn254fr_class t1, t2;
        addmod(t1, w[325], w[322]);
        mulmod(t2, w[325], w[322]);
        mulmod_constant(t2, t2, two);
        submod(w[962], t1, t2);
    }

    // XOR 357 8 -> 963
    {
        bn254fr_class t1, t2;
        addmod(t1, w[357], w[8]);
        mulmod(t2, w[357], w[8]);
        mulmod_constant(t2, t2, two);
        submod(w[963], t1, t2);
    }

    // XOR 209 298 -> 964
    {
        bn254fr_class t1, t2;
        addmod(t1, w[209], w[298]);
        mulmod(t2, w[209], w[298]);
        mulmod_constant(t2, t2, two);
        submod(w[964], t1, t2);
    }

    // XOR 482 436 -> 965
    {
        bn254fr_class t1, t2;
        addmod(t1, w[482], w[436]);
        mulmod(t2, w[482], w[436]);
        mulmod_constant(t2, t2, two);
        submod(w[965], t1, t2);
    }

    // XOR 40 323 -> 966
    {
        bn254fr_class t1, t2;
        addmod(t1, w[40], w[323]);
        mulmod(t2, w[40], w[323]);
        mulmod_constant(t2, t2, two);
        submod(w[966], t1, t2);
    }

    // XOR 476 553 -> 967
    {
        bn254fr_class t1, t2;
        addmod(t1, w[476], w[553]);
        mulmod(t2, w[476], w[553]);
        mulmod_constant(t2, t2, two);
        submod(w[967], t1, t2);
    }

    // AND 430 893 -> 968
    mulmod(w[968], w[430], w[893]);

    // INV 661 -> 969
    submod(w[969], one, w[661]);

    // XOR 460 916 -> 970
    {
        bn254fr_class t1, t2;
        addmod(t1, w[460], w[916]);
        mulmod(t2, w[460], w[916]);
        mulmod_constant(t2, t2, two);
        submod(w[970], t1, t2);
    }

    // AND 705 814 -> 971
    mulmod(w[971], w[705], w[814]);

    // XOR 402 832 -> 972
    {
        bn254fr_class t1, t2;
        addmod(t1, w[402], w[832]);
        mulmod(t2, w[402], w[832]);
        mulmod_constant(t2, t2, two);
        submod(w[972], t1, t2);
    }

    // XOR 779 882 -> 973
    {
        bn254fr_class t1, t2;
        addmod(t1, w[779], w[882]);
        mulmod(t2, w[779], w[882]);
        mulmod_constant(t2, t2, two);
        submod(w[973], t1, t2);
    }

    // XOR 392 184 -> 974
    {
        bn254fr_class t1, t2;
        addmod(t1, w[392], w[184]);
        mulmod(t2, w[392], w[184]);
        mulmod_constant(t2, t2, two);
        submod(w[974], t1, t2);
    }

    // XOR 786 463 -> 975
    {
        bn254fr_class t1, t2;
        addmod(t1, w[786], w[463]);
        mulmod(t2, w[786], w[463]);
        mulmod_constant(t2, t2, two);
        submod(w[975], t1, t2);
    }

    // XOR 236 358 -> 976
    {
        bn254fr_class t1, t2;
        addmod(t1, w[236], w[358]);
        mulmod(t2, w[236], w[358]);
        mulmod_constant(t2, t2, two);
        submod(w[976], t1, t2);
    }

    // AND 0 740 -> 977
    mulmod(w[977], w[0], w[740]);

    // INV 268 -> 978
    submod(w[978], one, w[268]);

    // AND 460 109 -> 979
    mulmod(w[979], w[460], w[109]);

    // XOR 221 400 -> 980
    {
        bn254fr_class t1, t2;
        addmod(t1, w[221], w[400]);
        mulmod(t2, w[221], w[400]);
        mulmod_constant(t2, t2, two);
        submod(w[980], t1, t2);
    }

    // XOR 531 405 -> 981
    {
        bn254fr_class t1, t2;
        addmod(t1, w[531], w[405]);
        mulmod(t2, w[531], w[405]);
        mulmod_constant(t2, t2, two);
        submod(w[981], t1, t2);
    }

    // XOR 462 259 -> 982
    {
        bn254fr_class t1, t2;
        addmod(t1, w[462], w[259]);
        mulmod(t2, w[462], w[259]);
        mulmod_constant(t2, t2, two);
        submod(w[982], t1, t2);
    }

    // AND 504 604 -> 983
    mulmod(w[983], w[504], w[604]);

    // AND 394 421 -> 984
    mulmod(w[984], w[394], w[421]);

    // INV 459 -> 985
    submod(w[985], one, w[459]);

    // XOR 562 161 -> 986
    {
        bn254fr_class t1, t2;
        addmod(t1, w[562], w[161]);
        mulmod(t2, w[562], w[161]);
        mulmod_constant(t2, t2, two);
        submod(w[986], t1, t2);
    }

    // XOR 496 524 -> 987
    {
        bn254fr_class t1, t2;
        addmod(t1, w[496], w[524]);
        mulmod(t2, w[496], w[524]);
        mulmod_constant(t2, t2, two);
        submod(w[987], t1, t2);
    }

    // XOR 560 767 -> 988
    {
        bn254fr_class t1, t2;
        addmod(t1, w[560], w[767]);
        mulmod(t2, w[560], w[767]);
        mulmod_constant(t2, t2, two);
        submod(w[988], t1, t2);
    }

    // XOR 695 362 -> 989
    {
        bn254fr_class t1, t2;
        addmod(t1, w[695], w[362]);
        mulmod(t2, w[695], w[362]);
        mulmod_constant(t2, t2, two);
        submod(w[989], t1, t2);
    }

    // AND 746 404 -> 990
    mulmod(w[990], w[746], w[404]);

    // XOR 43 383 -> 991
    {
        bn254fr_class t1, t2;
        addmod(t1, w[43], w[383]);
        mulmod(t2, w[43], w[383]);
        mulmod_constant(t2, t2, two);
        submod(w[991], t1, t2);
    }

    // XOR 113 190 -> 992
    {
        bn254fr_class t1, t2;
        addmod(t1, w[113], w[190]);
        mulmod(t2, w[113], w[190]);
        mulmod_constant(t2, t2, two);
        submod(w[992], t1, t2);
    }

    // AND 98 250 -> 993
    mulmod(w[993], w[98], w[250]);

    // AND 454 903 -> 994
    mulmod(w[994], w[454], w[903]);

    // AND 363 159 -> 995
    mulmod(w[995], w[363], w[159]);

    // XOR 626 602 -> 996
    {
        bn254fr_class t1, t2;
        addmod(t1, w[626], w[602]);
        mulmod(t2, w[626], w[602]);
        mulmod_constant(t2, t2, two);
        submod(w[996], t1, t2);
    }

    // XOR 541 150 -> 997
    {
        bn254fr_class t1, t2;
        addmod(t1, w[541], w[150]);
        mulmod(t2, w[541], w[150]);
        mulmod_constant(t2, t2, two);
        submod(w[997], t1, t2);
    }

    // XOR 326 696 -> 998
    {
        bn254fr_class t1, t2;
        addmod(t1, w[326], w[696]);
        mulmod(t2, w[326], w[696]);
        mulmod_constant(t2, t2, two);
        submod(w[998], t1, t2);
    }

    // AND 498 875 -> 999
    mulmod(w[999], w[498], w[875]);

    // XOR 797 574 -> 1000
    {
        bn254fr_class t1, t2;
        addmod(t1, w[797], w[574]);
        mulmod(t2, w[797], w[574]);
        mulmod_constant(t2, t2, two);
        submod(w[1000], t1, t2);
    }

    // XOR 451 18 -> 1001
    {
        bn254fr_class t1, t2;
        addmod(t1, w[451], w[18]);
        mulmod(t2, w[451], w[18]);
        mulmod_constant(t2, t2, two);
        submod(w[1001], t1, t2);
    }

    // AND 640 528 -> 1002
    mulmod(w[1002], w[640], w[528]);

    // XOR 807 356 -> 1003
    {
        bn254fr_class t1, t2;
        addmod(t1, w[807], w[356]);
        mulmod(t2, w[807], w[356]);
        mulmod_constant(t2, t2, two);
        submod(w[1003], t1, t2);
    }

    // AND 569 787 -> 1004
    mulmod(w[1004], w[569], w[787]);

    // AND 313 898 -> 1005
    mulmod(w[1005], w[313], w[898]);

    // XOR 106 95 -> 1006
    {
        bn254fr_class t1, t2;
        addmod(t1, w[106], w[95]);
        mulmod(t2, w[106], w[95]);
        mulmod_constant(t2, t2, two);
        submod(w[1006], t1, t2);
    }

    // AND 192 693 -> 1007
    mulmod(w[1007], w[192], w[693]);

    // XOR 77 340 -> 1008
    {
        bn254fr_class t1, t2;
        addmod(t1, w[77], w[340]);
        mulmod(t2, w[77], w[340]);
        mulmod_constant(t2, t2, two);
        submod(w[1008], t1, t2);
    }

    // INV 177 -> 1009
    submod(w[1009], one, w[177]);

    // AND 343 546 -> 1010
    mulmod(w[1010], w[343], w[546]);

    // XOR 725 816 -> 1011
    {
        bn254fr_class t1, t2;
        addmod(t1, w[725], w[816]);
        mulmod(t2, w[725], w[816]);
        mulmod_constant(t2, t2, two);
        submod(w[1011], t1, t2);
    }

    // XOR 713 655 -> 1012
    {
        bn254fr_class t1, t2;
        addmod(t1, w[713], w[655]);
        mulmod(t2, w[713], w[655]);
        mulmod_constant(t2, t2, two);
        submod(w[1012], t1, t2);
    }

    // XOR 165 190 -> 1013
    {
        bn254fr_class t1, t2;
        addmod(t1, w[165], w[190]);
        mulmod(t2, w[165], w[190]);
        mulmod_constant(t2, t2, two);
        submod(w[1013], t1, t2);
    }

    // XOR 320 252 -> 1014
    {
        bn254fr_class t1, t2;
        addmod(t1, w[320], w[252]);
        mulmod(t2, w[320], w[252]);
        mulmod_constant(t2, t2, two);
        submod(w[1014], t1, t2);
    }

    // XOR 208 20 -> 1015
    {
        bn254fr_class t1, t2;
        addmod(t1, w[208], w[20]);
        mulmod(t2, w[208], w[20]);
        mulmod_constant(t2, t2, two);
        submod(w[1015], t1, t2);
    }

    // AND 484 430 -> 1016
    mulmod(w[1016], w[484], w[430]);

    // XOR 33 18 -> 1017
    {
        bn254fr_class t1, t2;
        addmod(t1, w[33], w[18]);
        mulmod(t2, w[33], w[18]);
        mulmod_constant(t2, t2, two);
        submod(w[1017], t1, t2);
    }

    // AND 863 450 -> 1018
    mulmod(w[1018], w[863], w[450]);

    // INV 263 -> 1019
    submod(w[1019], one, w[263]);

    // XOR 558 536 -> 1020
    {
        bn254fr_class t1, t2;
        addmod(t1, w[558], w[536]);
        mulmod(t2, w[558], w[536]);
        mulmod_constant(t2, t2, two);
        submod(w[1020], t1, t2);
    }

    // XOR 219 398 -> 1021
    {
        bn254fr_class t1, t2;
        addmod(t1, w[219], w[398]);
        mulmod(t2, w[219], w[398]);
        mulmod_constant(t2, t2, two);
        submod(w[1021], t1, t2);
    }

    // XOR 852 46 -> 1022
    {
        bn254fr_class t1, t2;
        addmod(t1, w[852], w[46]);
        mulmod(t2, w[852], w[46]);
        mulmod_constant(t2, t2, two);
        submod(w[1022], t1, t2);
    }

    // XOR 670 586 -> 1023
    {
        bn254fr_class t1, t2;
        addmod(t1, w[670], w[586]);
        mulmod(t2, w[670], w[586]);
        mulmod_constant(t2, t2, two);
        submod(w[1023], t1, t2);
    }

    // XOR 466 365 -> 1024
    {
        bn254fr_class t1, t2;
        addmod(t1, w[466], w[365]);
        mulmod(t2, w[466], w[365]);
        mulmod_constant(t2, t2, two);
        submod(w[1024], t1, t2);
    }

    // XOR 90 1 -> 1025
    {
        bn254fr_class t1, t2;
        addmod(t1, w[90], w[1]);
        mulmod(t2, w[90], w[1]);
        mulmod_constant(t2, t2, two);
        submod(w[1025], t1, t2);
    }

    // AND 695 483 -> 1026
    mulmod(w[1026], w[695], w[483]);

    // AND 713 298 -> 1027
    mulmod(w[1027], w[713], w[298]);

    // AND 638 16 -> 1028
    mulmod(w[1028], w[638], w[16]);

    // XOR 891 338 -> 1029
    {
        bn254fr_class t1, t2;
        addmod(t1, w[891], w[338]);
        mulmod(t2, w[891], w[338]);
        mulmod_constant(t2, t2, two);
        submod(w[1029], t1, t2);
    }

    // AND 713 182 -> 1030
    mulmod(w[1030], w[713], w[182]);

    // XOR 733 207 -> 1031
    {
        bn254fr_class t1, t2;
        addmod(t1, w[733], w[207]);
        mulmod(t2, w[733], w[207]);
        mulmod_constant(t2, t2, two);
        submod(w[1031], t1, t2);
    }

    // AND 693 701 -> 1032
    mulmod(w[1032], w[693], w[701]);

    // AND 861 822 -> 1033
    mulmod(w[1033], w[861], w[822]);

    // AND 572 484 -> 1034
    mulmod(w[1034], w[572], w[484]);

    // XOR 382 431 -> 1035
    {
        bn254fr_class t1, t2;
        addmod(t1, w[382], w[431]);
        mulmod(t2, w[382], w[431]);
        mulmod_constant(t2, t2, two);
        submod(w[1035], t1, t2);
    }

    // XOR 499 42 -> 1036
    {
        bn254fr_class t1, t2;
        addmod(t1, w[499], w[42]);
        mulmod(t2, w[499], w[42]);
        mulmod_constant(t2, t2, two);
        submod(w[1036], t1, t2);
    }

    // XOR 53 324 -> 1037
    {
        bn254fr_class t1, t2;
        addmod(t1, w[53], w[324]);
        mulmod(t2, w[53], w[324]);
        mulmod_constant(t2, t2, two);
        submod(w[1037], t1, t2);
    }

    // INV 576 -> 1038
    submod(w[1038], one, w[576]);

    // XOR 796 615 -> 1039
    {
        bn254fr_class t1, t2;
        addmod(t1, w[796], w[615]);
        mulmod(t2, w[796], w[615]);
        mulmod_constant(t2, t2, two);
        submod(w[1039], t1, t2);
    }

    // XOR 193 426 -> 1040
    {
        bn254fr_class t1, t2;
        addmod(t1, w[193], w[426]);
        mulmod(t2, w[193], w[426]);
        mulmod_constant(t2, t2, two);
        submod(w[1040], t1, t2);
    }

    // XOR 472 114 -> 1041
    {
        bn254fr_class t1, t2;
        addmod(t1, w[472], w[114]);
        mulmod(t2, w[472], w[114]);
        mulmod_constant(t2, t2, two);
        submod(w[1041], t1, t2);
    }

    // XOR 820 860 -> 1042
    {
        bn254fr_class t1, t2;
        addmod(t1, w[820], w[860]);
        mulmod(t2, w[820], w[860]);
        mulmod_constant(t2, t2, two);
        submod(w[1042], t1, t2);
    }

    // XOR 871 503 -> 1043
    {
        bn254fr_class t1, t2;
        addmod(t1, w[871], w[503]);
        mulmod(t2, w[871], w[503]);
        mulmod_constant(t2, t2, two);
        submod(w[1043], t1, t2);
    }

    // XOR 16 460 -> 1044
    {
        bn254fr_class t1, t2;
        addmod(t1, w[16], w[460]);
        mulmod(t2, w[16], w[460]);
        mulmod_constant(t2, t2, two);
        submod(w[1044], t1, t2);
    }

    // XOR 789 771 -> 1045
    {
        bn254fr_class t1, t2;
        addmod(t1, w[789], w[771]);
        mulmod(t2, w[789], w[771]);
        mulmod_constant(t2, t2, two);
        submod(w[1045], t1, t2);
    }

    // XOR 862 466 -> 1046
    {
        bn254fr_class t1, t2;
        addmod(t1, w[862], w[466]);
        mulmod(t2, w[862], w[466]);
        mulmod_constant(t2, t2, two);
        submod(w[1046], t1, t2);
    }

    // AND 225 293 -> 1047
    mulmod(w[1047], w[225], w[293]);

    // AND 476 868 -> 1048
    mulmod(w[1048], w[476], w[868]);

    // AND 701 381 -> 1049
    mulmod(w[1049], w[701], w[381]);

    // INV 114 -> 1050
    submod(w[1050], one, w[114]);

    // AND 258 574 -> 1051
    mulmod(w[1051], w[258], w[574]);

    // AND 290 114 -> 1052
    mulmod(w[1052], w[290], w[114]);

    // INV 938 -> 1053
    submod(w[1053], one, w[938]);

    // AND 722 21 -> 1054
    mulmod(w[1054], w[722], w[21]);

    // AND 581 730 -> 1055
    mulmod(w[1055], w[581], w[730]);

    // XOR 75 590 -> 1056
    {
        bn254fr_class t1, t2;
        addmod(t1, w[75], w[590]);
        mulmod(t2, w[75], w[590]);
        mulmod_constant(t2, t2, two);
        submod(w[1056], t1, t2);
    }

    // AND 704 358 -> 1057
    mulmod(w[1057], w[704], w[358]);

    // AND 232 52 -> 1058
    mulmod(w[1058], w[232], w[52]);

    // XOR 445 760 -> 1059
    {
        bn254fr_class t1, t2;
        addmod(t1, w[445], w[760]);
        mulmod(t2, w[445], w[760]);
        mulmod_constant(t2, t2, two);
        submod(w[1059], t1, t2);
    }

    // XOR 768 177 -> 1060
    {
        bn254fr_class t1, t2;
        addmod(t1, w[768], w[177]);
        mulmod(t2, w[768], w[177]);
        mulmod_constant(t2, t2, two);
        submod(w[1060], t1, t2);
    }

    // XOR 737 150 -> 1061
    {
        bn254fr_class t1, t2;
        addmod(t1, w[737], w[150]);
        mulmod(t2, w[737], w[150]);
        mulmod_constant(t2, t2, two);
        submod(w[1061], t1, t2);
    }

    // INV 991 -> 1062
    submod(w[1062], one, w[991]);

    // XOR 886 480 -> 1063
    {
        bn254fr_class t1, t2;
        addmod(t1, w[886], w[480]);
        mulmod(t2, w[886], w[480]);
        mulmod_constant(t2, t2, two);
        submod(w[1063], t1, t2);
    }

    // AND 506 842 -> 1064
    mulmod(w[1064], w[506], w[842]);

    // XOR 668 156 -> 1065
    {
        bn254fr_class t1, t2;
        addmod(t1, w[668], w[156]);
        mulmod(t2, w[668], w[156]);
        mulmod_constant(t2, t2, two);
        submod(w[1065], t1, t2);
    }

    // INV 434 -> 1066
    submod(w[1066], one, w[434]);

    // AND 638 484 -> 1067
    mulmod(w[1067], w[638], w[484]);

    // XOR 445 462 -> 1068
    {
        bn254fr_class t1, t2;
        addmod(t1, w[445], w[462]);
        mulmod(t2, w[445], w[462]);
        mulmod_constant(t2, t2, two);
        submod(w[1068], t1, t2);
    }

    // AND 958 837 -> 1069
    mulmod(w[1069], w[958], w[837]);

    // AND 1035 506 -> 1070
    mulmod(w[1070], w[1035], w[506]);

    // XOR 708 1003 -> 1071
    {
        bn254fr_class t1, t2;
        addmod(t1, w[708], w[1003]);
        mulmod(t2, w[708], w[1003]);
        mulmod_constant(t2, t2, two);
        submod(w[1071], t1, t2);
    }

    // AND 257 1025 -> 1072
    mulmod(w[1072], w[257], w[1025]);

    // XOR 15 360 -> 1073
    {
        bn254fr_class t1, t2;
        addmod(t1, w[15], w[360]);
        mulmod(t2, w[15], w[360]);
        mulmod_constant(t2, t2, two);
        submod(w[1073], t1, t2);
    }

    // XOR 1015 285 -> 1074
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1015], w[285]);
        mulmod(t2, w[1015], w[285]);
        mulmod_constant(t2, t2, two);
        submod(w[1074], t1, t2);
    }

    // AND 627 263 -> 1075
    mulmod(w[1075], w[627], w[263]);

    // AND 962 468 -> 1076
    mulmod(w[1076], w[962], w[468]);

    // XOR 494 1024 -> 1077
    {
        bn254fr_class t1, t2;
        addmod(t1, w[494], w[1024]);
        mulmod(t2, w[494], w[1024]);
        mulmod_constant(t2, t2, two);
        submod(w[1077], t1, t2);
    }

    // XOR 997 682 -> 1078
    {
        bn254fr_class t1, t2;
        addmod(t1, w[997], w[682]);
        mulmod(t2, w[997], w[682]);
        mulmod_constant(t2, t2, two);
        submod(w[1078], t1, t2);
    }

    // AND 362 706 -> 1079
    mulmod(w[1079], w[362], w[706]);

    // AND 90 898 -> 1080
    mulmod(w[1080], w[90], w[898]);

    // INV 572 -> 1081
    submod(w[1081], one, w[572]);

    // AND 302 586 -> 1082
    mulmod(w[1082], w[302], w[586]);

    // XOR 118 565 -> 1083
    {
        bn254fr_class t1, t2;
        addmod(t1, w[118], w[565]);
        mulmod(t2, w[118], w[565]);
        mulmod_constant(t2, t2, two);
        submod(w[1083], t1, t2);
    }

    // XOR 347 26 -> 1084
    {
        bn254fr_class t1, t2;
        addmod(t1, w[347], w[26]);
        mulmod(t2, w[347], w[26]);
        mulmod_constant(t2, t2, two);
        submod(w[1084], t1, t2);
    }

    // XOR 274 416 -> 1085
    {
        bn254fr_class t1, t2;
        addmod(t1, w[274], w[416]);
        mulmod(t2, w[274], w[416]);
        mulmod_constant(t2, t2, two);
        submod(w[1085], t1, t2);
    }

    // XOR 775 194 -> 1086
    {
        bn254fr_class t1, t2;
        addmod(t1, w[775], w[194]);
        mulmod(t2, w[775], w[194]);
        mulmod_constant(t2, t2, two);
        submod(w[1086], t1, t2);
    }

    // XOR 461 157 -> 1087
    {
        bn254fr_class t1, t2;
        addmod(t1, w[461], w[157]);
        mulmod(t2, w[461], w[157]);
        mulmod_constant(t2, t2, two);
        submod(w[1087], t1, t2);
    }

    // AND 979 455 -> 1088
    mulmod(w[1088], w[979], w[455]);

    // INV 644 -> 1089
    submod(w[1089], one, w[644]);

    // AND 159 847 -> 1090
    mulmod(w[1090], w[159], w[847]);

    // XOR 334 754 -> 1091
    {
        bn254fr_class t1, t2;
        addmod(t1, w[334], w[754]);
        mulmod(t2, w[334], w[754]);
        mulmod_constant(t2, t2, two);
        submod(w[1091], t1, t2);
    }

    // XOR 77 515 -> 1092
    {
        bn254fr_class t1, t2;
        addmod(t1, w[77], w[515]);
        mulmod(t2, w[77], w[515]);
        mulmod_constant(t2, t2, two);
        submod(w[1092], t1, t2);
    }

    // XOR 533 72 -> 1093
    {
        bn254fr_class t1, t2;
        addmod(t1, w[533], w[72]);
        mulmod(t2, w[533], w[72]);
        mulmod_constant(t2, t2, two);
        submod(w[1093], t1, t2);
    }

    // AND 102 269 -> 1094
    mulmod(w[1094], w[102], w[269]);

    // XOR 858 185 -> 1095
    {
        bn254fr_class t1, t2;
        addmod(t1, w[858], w[185]);
        mulmod(t2, w[858], w[185]);
        mulmod_constant(t2, t2, two);
        submod(w[1095], t1, t2);
    }

    // AND 540 881 -> 1096
    mulmod(w[1096], w[540], w[881]);

    // XOR 497 606 -> 1097
    {
        bn254fr_class t1, t2;
        addmod(t1, w[497], w[606]);
        mulmod(t2, w[497], w[606]);
        mulmod_constant(t2, t2, two);
        submod(w[1097], t1, t2);
    }

    // INV 7 -> 1098
    submod(w[1098], one, w[7]);

    // XOR 751 322 -> 1099
    {
        bn254fr_class t1, t2;
        addmod(t1, w[751], w[322]);
        mulmod(t2, w[751], w[322]);
        mulmod_constant(t2, t2, two);
        submod(w[1099], t1, t2);
    }

    // XOR 704 737 -> 1100
    {
        bn254fr_class t1, t2;
        addmod(t1, w[704], w[737]);
        mulmod(t2, w[704], w[737]);
        mulmod_constant(t2, t2, two);
        submod(w[1100], t1, t2);
    }

    // XOR 161 331 -> 1101
    {
        bn254fr_class t1, t2;
        addmod(t1, w[161], w[331]);
        mulmod(t2, w[161], w[331]);
        mulmod_constant(t2, t2, two);
        submod(w[1101], t1, t2);
    }

    // XOR 952 49 -> 1102
    {
        bn254fr_class t1, t2;
        addmod(t1, w[952], w[49]);
        mulmod(t2, w[952], w[49]);
        mulmod_constant(t2, t2, two);
        submod(w[1102], t1, t2);
    }

    // INV 215 -> 1103
    submod(w[1103], one, w[215]);

    // AND 463 13 -> 1104
    mulmod(w[1104], w[463], w[13]);

    // INV 672 -> 1105
    submod(w[1105], one, w[672]);

    // AND 622 603 -> 1106
    mulmod(w[1106], w[622], w[603]);

    // AND 58 368 -> 1107
    mulmod(w[1107], w[58], w[368]);

    // AND 314 726 -> 1108
    mulmod(w[1108], w[314], w[726]);

    // AND 404 168 -> 1109
    mulmod(w[1109], w[404], w[168]);

    // XOR 321 905 -> 1110
    {
        bn254fr_class t1, t2;
        addmod(t1, w[321], w[905]);
        mulmod(t2, w[321], w[905]);
        mulmod_constant(t2, t2, two);
        submod(w[1110], t1, t2);
    }

    // AND 886 602 -> 1111
    mulmod(w[1111], w[886], w[602]);

    // AND 7 472 -> 1112
    mulmod(w[1112], w[7], w[472]);

    // AND 816 771 -> 1113
    mulmod(w[1113], w[816], w[771]);

    // XOR 810 1003 -> 1114
    {
        bn254fr_class t1, t2;
        addmod(t1, w[810], w[1003]);
        mulmod(t2, w[810], w[1003]);
        mulmod_constant(t2, t2, two);
        submod(w[1114], t1, t2);
    }

    // XOR 712 191 -> 1115
    {
        bn254fr_class t1, t2;
        addmod(t1, w[712], w[191]);
        mulmod(t2, w[712], w[191]);
        mulmod_constant(t2, t2, two);
        submod(w[1115], t1, t2);
    }

    // XOR 669 747 -> 1116
    {
        bn254fr_class t1, t2;
        addmod(t1, w[669], w[747]);
        mulmod(t2, w[669], w[747]);
        mulmod_constant(t2, t2, two);
        submod(w[1116], t1, t2);
    }

    // AND 884 16 -> 1117
    mulmod(w[1117], w[884], w[16]);

    // INV 469 -> 1118
    submod(w[1118], one, w[469]);

    // XOR 850 222 -> 1119
    {
        bn254fr_class t1, t2;
        addmod(t1, w[850], w[222]);
        mulmod(t2, w[850], w[222]);
        mulmod_constant(t2, t2, two);
        submod(w[1119], t1, t2);
    }

    // XOR 245 91 -> 1120
    {
        bn254fr_class t1, t2;
        addmod(t1, w[245], w[91]);
        mulmod(t2, w[245], w[91]);
        mulmod_constant(t2, t2, two);
        submod(w[1120], t1, t2);
    }

    // AND 870 984 -> 1121
    mulmod(w[1121], w[870], w[984]);

    // AND 855 517 -> 1122
    mulmod(w[1122], w[855], w[517]);

    // XOR 86 448 -> 1123
    {
        bn254fr_class t1, t2;
        addmod(t1, w[86], w[448]);
        mulmod(t2, w[86], w[448]);
        mulmod_constant(t2, t2, two);
        submod(w[1123], t1, t2);
    }

    // AND 687 94 -> 1124
    mulmod(w[1124], w[687], w[94]);

    // XOR 157 760 -> 1125
    {
        bn254fr_class t1, t2;
        addmod(t1, w[157], w[760]);
        mulmod(t2, w[157], w[760]);
        mulmod_constant(t2, t2, two);
        submod(w[1125], t1, t2);
    }

    // AND 754 399 -> 1126
    mulmod(w[1126], w[754], w[399]);

    // AND 765 138 -> 1127
    mulmod(w[1127], w[765], w[138]);

    // AND 492 108 -> 1128
    mulmod(w[1128], w[492], w[108]);

    // AND 752 1016 -> 1129
    mulmod(w[1129], w[752], w[1016]);

    // AND 147 800 -> 1130
    mulmod(w[1130], w[147], w[800]);

    // XOR 48 756 -> 1131
    {
        bn254fr_class t1, t2;
        addmod(t1, w[48], w[756]);
        mulmod(t2, w[48], w[756]);
        mulmod_constant(t2, t2, two);
        submod(w[1131], t1, t2);
    }

    // AND 528 921 -> 1132
    mulmod(w[1132], w[528], w[921]);

    // XOR 403 937 -> 1133
    {
        bn254fr_class t1, t2;
        addmod(t1, w[403], w[937]);
        mulmod(t2, w[403], w[937]);
        mulmod_constant(t2, t2, two);
        submod(w[1133], t1, t2);
    }

    // AND 523 932 -> 1134
    mulmod(w[1134], w[523], w[932]);

    // XOR 710 66 -> 1135
    {
        bn254fr_class t1, t2;
        addmod(t1, w[710], w[66]);
        mulmod(t2, w[710], w[66]);
        mulmod_constant(t2, t2, two);
        submod(w[1135], t1, t2);
    }

    // AND 936 936 -> 1136
    mulmod(w[1136], w[936], w[936]);

    // INV 932 -> 1137
    submod(w[1137], one, w[932]);

    // XOR 897 676 -> 1138
    {
        bn254fr_class t1, t2;
        addmod(t1, w[897], w[676]);
        mulmod(t2, w[897], w[676]);
        mulmod_constant(t2, t2, two);
        submod(w[1138], t1, t2);
    }

    // XOR 500 416 -> 1139
    {
        bn254fr_class t1, t2;
        addmod(t1, w[500], w[416]);
        mulmod(t2, w[500], w[416]);
        mulmod_constant(t2, t2, two);
        submod(w[1139], t1, t2);
    }

    // XOR 116 832 -> 1140
    {
        bn254fr_class t1, t2;
        addmod(t1, w[116], w[832]);
        mulmod(t2, w[116], w[832]);
        mulmod_constant(t2, t2, two);
        submod(w[1140], t1, t2);
    }

    // AND 429 806 -> 1141
    mulmod(w[1141], w[429], w[806]);

    // XOR 223 45 -> 1142
    {
        bn254fr_class t1, t2;
        addmod(t1, w[223], w[45]);
        mulmod(t2, w[223], w[45]);
        mulmod_constant(t2, t2, two);
        submod(w[1142], t1, t2);
    }

    // XOR 750 298 -> 1143
    {
        bn254fr_class t1, t2;
        addmod(t1, w[750], w[298]);
        mulmod(t2, w[750], w[298]);
        mulmod_constant(t2, t2, two);
        submod(w[1143], t1, t2);
    }

    // XOR 1093 356 -> 1144
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1093], w[356]);
        mulmod(t2, w[1093], w[356]);
        mulmod_constant(t2, t2, two);
        submod(w[1144], t1, t2);
    }

    // XOR 898 963 -> 1145
    {
        bn254fr_class t1, t2;
        addmod(t1, w[898], w[963]);
        mulmod(t2, w[898], w[963]);
        mulmod_constant(t2, t2, two);
        submod(w[1145], t1, t2);
    }

    // XOR 613 299 -> 1146
    {
        bn254fr_class t1, t2;
        addmod(t1, w[613], w[299]);
        mulmod(t2, w[613], w[299]);
        mulmod_constant(t2, t2, two);
        submod(w[1146], t1, t2);
    }

    // AND 277 927 -> 1147
    mulmod(w[1147], w[277], w[927]);

    // AND 1001 551 -> 1148
    mulmod(w[1148], w[1001], w[551]);

    // XOR 937 276 -> 1149
    {
        bn254fr_class t1, t2;
        addmod(t1, w[937], w[276]);
        mulmod(t2, w[937], w[276]);
        mulmod_constant(t2, t2, two);
        submod(w[1149], t1, t2);
    }

    // XOR 81 881 -> 1150
    {
        bn254fr_class t1, t2;
        addmod(t1, w[81], w[881]);
        mulmod(t2, w[81], w[881]);
        mulmod_constant(t2, t2, two);
        submod(w[1150], t1, t2);
    }

    // XOR 151 565 -> 1151
    {
        bn254fr_class t1, t2;
        addmod(t1, w[151], w[565]);
        mulmod(t2, w[151], w[565]);
        mulmod_constant(t2, t2, two);
        submod(w[1151], t1, t2);
    }

    // XOR 1096 823 -> 1152
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1096], w[823]);
        mulmod(t2, w[1096], w[823]);
        mulmod_constant(t2, t2, two);
        submod(w[1152], t1, t2);
    }

    // AND 1032 744 -> 1153
    mulmod(w[1153], w[1032], w[744]);

    // AND 296 47 -> 1154
    mulmod(w[1154], w[296], w[47]);

    // XOR 362 619 -> 1155
    {
        bn254fr_class t1, t2;
        addmod(t1, w[362], w[619]);
        mulmod(t2, w[362], w[619]);
        mulmod_constant(t2, t2, two);
        submod(w[1155], t1, t2);
    }

    // XOR 456 788 -> 1156
    {
        bn254fr_class t1, t2;
        addmod(t1, w[456], w[788]);
        mulmod(t2, w[456], w[788]);
        mulmod_constant(t2, t2, two);
        submod(w[1156], t1, t2);
    }

    // XOR 1000 719 -> 1157
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1000], w[719]);
        mulmod(t2, w[1000], w[719]);
        mulmod_constant(t2, t2, two);
        submod(w[1157], t1, t2);
    }

    // AND 588 157 -> 1158
    mulmod(w[1158], w[588], w[157]);

    // XOR 781 619 -> 1159
    {
        bn254fr_class t1, t2;
        addmod(t1, w[781], w[619]);
        mulmod(t2, w[781], w[619]);
        mulmod_constant(t2, t2, two);
        submod(w[1159], t1, t2);
    }

    // AND 601 59 -> 1160
    mulmod(w[1160], w[601], w[59]);

    // XOR 422 333 -> 1161
    {
        bn254fr_class t1, t2;
        addmod(t1, w[422], w[333]);
        mulmod(t2, w[422], w[333]);
        mulmod_constant(t2, t2, two);
        submod(w[1161], t1, t2);
    }

    // AND 392 327 -> 1162
    mulmod(w[1162], w[392], w[327]);

    // AND 4 909 -> 1163
    mulmod(w[1163], w[4], w[909]);

    // XOR 247 229 -> 1164
    {
        bn254fr_class t1, t2;
        addmod(t1, w[247], w[229]);
        mulmod(t2, w[247], w[229]);
        mulmod_constant(t2, t2, two);
        submod(w[1164], t1, t2);
    }

    // XOR 503 1062 -> 1165
    {
        bn254fr_class t1, t2;
        addmod(t1, w[503], w[1062]);
        mulmod(t2, w[503], w[1062]);
        mulmod_constant(t2, t2, two);
        submod(w[1165], t1, t2);
    }

    // AND 600 633 -> 1166
    mulmod(w[1166], w[600], w[633]);

    // AND 761 413 -> 1167
    mulmod(w[1167], w[761], w[413]);

    // XOR 595 989 -> 1168
    {
        bn254fr_class t1, t2;
        addmod(t1, w[595], w[989]);
        mulmod(t2, w[595], w[989]);
        mulmod_constant(t2, t2, two);
        submod(w[1168], t1, t2);
    }

    // INV 795 -> 1169
    submod(w[1169], one, w[795]);

    // INV 686 -> 1170
    submod(w[1170], one, w[686]);

    // AND 17 1125 -> 1171
    mulmod(w[1171], w[17], w[1125]);

    // XOR 331 338 -> 1172
    {
        bn254fr_class t1, t2;
        addmod(t1, w[331], w[338]);
        mulmod(t2, w[331], w[338]);
        mulmod_constant(t2, t2, two);
        submod(w[1172], t1, t2);
    }

    // AND 287 272 -> 1173
    mulmod(w[1173], w[287], w[272]);

    // AND 303 1005 -> 1174
    mulmod(w[1174], w[303], w[1005]);

    // AND 49 1099 -> 1175
    mulmod(w[1175], w[49], w[1099]);

    // XOR 993 701 -> 1176
    {
        bn254fr_class t1, t2;
        addmod(t1, w[993], w[701]);
        mulmod(t2, w[993], w[701]);
        mulmod_constant(t2, t2, two);
        submod(w[1176], t1, t2);
    }

    // AND 458 254 -> 1177
    mulmod(w[1177], w[458], w[254]);

    // INV 677 -> 1178
    submod(w[1178], one, w[677]);

    // INV 976 -> 1179
    submod(w[1179], one, w[976]);

    // XOR 810 359 -> 1180
    {
        bn254fr_class t1, t2;
        addmod(t1, w[810], w[359]);
        mulmod(t2, w[810], w[359]);
        mulmod_constant(t2, t2, two);
        submod(w[1180], t1, t2);
    }

    // XOR 27 349 -> 1181
    {
        bn254fr_class t1, t2;
        addmod(t1, w[27], w[349]);
        mulmod(t2, w[27], w[349]);
        mulmod_constant(t2, t2, two);
        submod(w[1181], t1, t2);
    }

    // XOR 783 541 -> 1182
    {
        bn254fr_class t1, t2;
        addmod(t1, w[783], w[541]);
        mulmod(t2, w[783], w[541]);
        mulmod_constant(t2, t2, two);
        submod(w[1182], t1, t2);
    }

    // AND 1035 356 -> 1183
    mulmod(w[1183], w[1035], w[356]);

    // XOR 675 921 -> 1184
    {
        bn254fr_class t1, t2;
        addmod(t1, w[675], w[921]);
        mulmod(t2, w[675], w[921]);
        mulmod_constant(t2, t2, two);
        submod(w[1184], t1, t2);
    }

    // XOR 377 1103 -> 1185
    {
        bn254fr_class t1, t2;
        addmod(t1, w[377], w[1103]);
        mulmod(t2, w[377], w[1103]);
        mulmod_constant(t2, t2, two);
        submod(w[1185], t1, t2);
    }

    // XOR 1034 938 -> 1186
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1034], w[938]);
        mulmod(t2, w[1034], w[938]);
        mulmod_constant(t2, t2, two);
        submod(w[1186], t1, t2);
    }

    // AND 167 562 -> 1187
    mulmod(w[1187], w[167], w[562]);

    // XOR 726 179 -> 1188
    {
        bn254fr_class t1, t2;
        addmod(t1, w[726], w[179]);
        mulmod(t2, w[726], w[179]);
        mulmod_constant(t2, t2, two);
        submod(w[1188], t1, t2);
    }

    // XOR 705 618 -> 1189
    {
        bn254fr_class t1, t2;
        addmod(t1, w[705], w[618]);
        mulmod(t2, w[705], w[618]);
        mulmod_constant(t2, t2, two);
        submod(w[1189], t1, t2);
    }

    // AND 497 252 -> 1190
    mulmod(w[1190], w[497], w[252]);

    // INV 1091 -> 1191
    submod(w[1191], one, w[1091]);

    // AND 535 4 -> 1192
    mulmod(w[1192], w[535], w[4]);

    // AND 263 537 -> 1193
    mulmod(w[1193], w[263], w[537]);

    // INV 148 -> 1194
    submod(w[1194], one, w[148]);

    // AND 766 1010 -> 1195
    mulmod(w[1195], w[766], w[1010]);

    // XOR 105 722 -> 1196
    {
        bn254fr_class t1, t2;
        addmod(t1, w[105], w[722]);
        mulmod(t2, w[105], w[722]);
        mulmod_constant(t2, t2, two);
        submod(w[1196], t1, t2);
    }

    // XOR 661 5 -> 1197
    {
        bn254fr_class t1, t2;
        addmod(t1, w[661], w[5]);
        mulmod(t2, w[661], w[5]);
        mulmod_constant(t2, t2, two);
        submod(w[1197], t1, t2);
    }

    // AND 394 22 -> 1198
    mulmod(w[1198], w[394], w[22]);

    // XOR 227 106 -> 1199
    {
        bn254fr_class t1, t2;
        addmod(t1, w[227], w[106]);
        mulmod(t2, w[227], w[106]);
        mulmod_constant(t2, t2, two);
        submod(w[1199], t1, t2);
    }

    // AND 935 723 -> 1200
    mulmod(w[1200], w[935], w[723]);

    // XOR 587 855 -> 1201
    {
        bn254fr_class t1, t2;
        addmod(t1, w[587], w[855]);
        mulmod(t2, w[587], w[855]);
        mulmod_constant(t2, t2, two);
        submod(w[1201], t1, t2);
    }

    // XOR 798 869 -> 1202
    {
        bn254fr_class t1, t2;
        addmod(t1, w[798], w[869]);
        mulmod(t2, w[798], w[869]);
        mulmod_constant(t2, t2, two);
        submod(w[1202], t1, t2);
    }

    // XOR 624 348 -> 1203
    {
        bn254fr_class t1, t2;
        addmod(t1, w[624], w[348]);
        mulmod(t2, w[624], w[348]);
        mulmod_constant(t2, t2, two);
        submod(w[1203], t1, t2);
    }

    // XOR 43 834 -> 1204
    {
        bn254fr_class t1, t2;
        addmod(t1, w[43], w[834]);
        mulmod(t2, w[43], w[834]);
        mulmod_constant(t2, t2, two);
        submod(w[1204], t1, t2);
    }

    // XOR 781 355 -> 1205
    {
        bn254fr_class t1, t2;
        addmod(t1, w[781], w[355]);
        mulmod(t2, w[781], w[355]);
        mulmod_constant(t2, t2, two);
        submod(w[1205], t1, t2);
    }

    // XOR 768 362 -> 1206
    {
        bn254fr_class t1, t2;
        addmod(t1, w[768], w[362]);
        mulmod(t2, w[768], w[362]);
        mulmod_constant(t2, t2, two);
        submod(w[1206], t1, t2);
    }

    // AND 94 43 -> 1207
    mulmod(w[1207], w[94], w[43]);

    // XOR 463 1134 -> 1208
    {
        bn254fr_class t1, t2;
        addmod(t1, w[463], w[1134]);
        mulmod(t2, w[463], w[1134]);
        mulmod_constant(t2, t2, two);
        submod(w[1208], t1, t2);
    }

    // AND 333 7 -> 1209
    mulmod(w[1209], w[333], w[7]);

    // AND 795 651 -> 1210
    mulmod(w[1210], w[795], w[651]);

    // XOR 944 875 -> 1211
    {
        bn254fr_class t1, t2;
        addmod(t1, w[944], w[875]);
        mulmod(t2, w[944], w[875]);
        mulmod_constant(t2, t2, two);
        submod(w[1211], t1, t2);
    }

    // AND 236 377 -> 1212
    mulmod(w[1212], w[236], w[377]);

    // XOR 568 508 -> 1213
    {
        bn254fr_class t1, t2;
        addmod(t1, w[568], w[508]);
        mulmod(t2, w[568], w[508]);
        mulmod_constant(t2, t2, two);
        submod(w[1213], t1, t2);
    }

    // XOR 633 247 -> 1214
    {
        bn254fr_class t1, t2;
        addmod(t1, w[633], w[247]);
        mulmod(t2, w[633], w[247]);
        mulmod_constant(t2, t2, two);
        submod(w[1214], t1, t2);
    }

    // AND 969 967 -> 1215
    mulmod(w[1215], w[969], w[967]);

    // AND 746 650 -> 1216
    mulmod(w[1216], w[746], w[650]);

    // AND 335 1026 -> 1217
    mulmod(w[1217], w[335], w[1026]);

    // XOR 969 340 -> 1218
    {
        bn254fr_class t1, t2;
        addmod(t1, w[969], w[340]);
        mulmod(t2, w[969], w[340]);
        mulmod_constant(t2, t2, two);
        submod(w[1218], t1, t2);
    }

    // AND 633 694 -> 1219
    mulmod(w[1219], w[633], w[694]);

    // XOR 124 877 -> 1220
    {
        bn254fr_class t1, t2;
        addmod(t1, w[124], w[877]);
        mulmod(t2, w[124], w[877]);
        mulmod_constant(t2, t2, two);
        submod(w[1220], t1, t2);
    }

    // XOR 73 428 -> 1221
    {
        bn254fr_class t1, t2;
        addmod(t1, w[73], w[428]);
        mulmod(t2, w[73], w[428]);
        mulmod_constant(t2, t2, two);
        submod(w[1221], t1, t2);
    }

    // AND 126 633 -> 1222
    mulmod(w[1222], w[126], w[633]);

    // AND 517 989 -> 1223
    mulmod(w[1223], w[517], w[989]);

    // XOR 448 488 -> 1224
    {
        bn254fr_class t1, t2;
        addmod(t1, w[448], w[488]);
        mulmod(t2, w[448], w[488]);
        mulmod_constant(t2, t2, two);
        submod(w[1224], t1, t2);
    }

    // XOR 311 1119 -> 1225
    {
        bn254fr_class t1, t2;
        addmod(t1, w[311], w[1119]);
        mulmod(t2, w[311], w[1119]);
        mulmod_constant(t2, t2, two);
        submod(w[1225], t1, t2);
    }

    // XOR 246 60 -> 1226
    {
        bn254fr_class t1, t2;
        addmod(t1, w[246], w[60]);
        mulmod(t2, w[246], w[60]);
        mulmod_constant(t2, t2, two);
        submod(w[1226], t1, t2);
    }

    // XOR 999 947 -> 1227
    {
        bn254fr_class t1, t2;
        addmod(t1, w[999], w[947]);
        mulmod(t2, w[999], w[947]);
        mulmod_constant(t2, t2, two);
        submod(w[1227], t1, t2);
    }

    // XOR 88 901 -> 1228
    {
        bn254fr_class t1, t2;
        addmod(t1, w[88], w[901]);
        mulmod(t2, w[88], w[901]);
        mulmod_constant(t2, t2, two);
        submod(w[1228], t1, t2);
    }

    // XOR 686 1074 -> 1229
    {
        bn254fr_class t1, t2;
        addmod(t1, w[686], w[1074]);
        mulmod(t2, w[686], w[1074]);
        mulmod_constant(t2, t2, two);
        submod(w[1229], t1, t2);
    }

    // AND 134 213 -> 1230
    mulmod(w[1230], w[134], w[213]);

    // XOR 551 265 -> 1231
    {
        bn254fr_class t1, t2;
        addmod(t1, w[551], w[265]);
        mulmod(t2, w[551], w[265]);
        mulmod_constant(t2, t2, two);
        submod(w[1231], t1, t2);
    }

    // XOR 207 538 -> 1232
    {
        bn254fr_class t1, t2;
        addmod(t1, w[207], w[538]);
        mulmod(t2, w[207], w[538]);
        mulmod_constant(t2, t2, two);
        submod(w[1232], t1, t2);
    }

    // AND 703 916 -> 1233
    mulmod(w[1233], w[703], w[916]);

    // XOR 369 895 -> 1234
    {
        bn254fr_class t1, t2;
        addmod(t1, w[369], w[895]);
        mulmod(t2, w[369], w[895]);
        mulmod_constant(t2, t2, two);
        submod(w[1234], t1, t2);
    }

    // XOR 324 219 -> 1235
    {
        bn254fr_class t1, t2;
        addmod(t1, w[324], w[219]);
        mulmod(t2, w[324], w[219]);
        mulmod_constant(t2, t2, two);
        submod(w[1235], t1, t2);
    }

    // AND 507 1053 -> 1236
    mulmod(w[1236], w[507], w[1053]);

    // AND 1164 227 -> 1237
    mulmod(w[1237], w[1164], w[227]);

    // XOR 1064 447 -> 1238
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1064], w[447]);
        mulmod(t2, w[1064], w[447]);
        mulmod_constant(t2, t2, two);
        submod(w[1238], t1, t2);
    }

    // AND 616 709 -> 1239
    mulmod(w[1239], w[616], w[709]);

    // INV 1183 -> 1240
    submod(w[1240], one, w[1183]);

    // AND 1005 1033 -> 1241
    mulmod(w[1241], w[1005], w[1033]);

    // AND 118 280 -> 1242
    mulmod(w[1242], w[118], w[280]);

    // XOR 216 739 -> 1243
    {
        bn254fr_class t1, t2;
        addmod(t1, w[216], w[739]);
        mulmod(t2, w[216], w[739]);
        mulmod_constant(t2, t2, two);
        submod(w[1243], t1, t2);
    }

    // AND 1195 733 -> 1244
    mulmod(w[1244], w[1195], w[733]);

    // XOR 412 596 -> 1245
    {
        bn254fr_class t1, t2;
        addmod(t1, w[412], w[596]);
        mulmod(t2, w[412], w[596]);
        mulmod_constant(t2, t2, two);
        submod(w[1245], t1, t2);
    }

    // INV 1121 -> 1246
    submod(w[1246], one, w[1121]);

    // AND 782 76 -> 1247
    mulmod(w[1247], w[782], w[76]);

    // XOR 1232 470 -> 1248
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1232], w[470]);
        mulmod(t2, w[1232], w[470]);
        mulmod_constant(t2, t2, two);
        submod(w[1248], t1, t2);
    }

    // XOR 367 285 -> 1249
    {
        bn254fr_class t1, t2;
        addmod(t1, w[367], w[285]);
        mulmod(t2, w[367], w[285]);
        mulmod_constant(t2, t2, two);
        submod(w[1249], t1, t2);
    }

    // AND 956 612 -> 1250
    mulmod(w[1250], w[956], w[612]);

    // XOR 94 763 -> 1251
    {
        bn254fr_class t1, t2;
        addmod(t1, w[94], w[763]);
        mulmod(t2, w[94], w[763]);
        mulmod_constant(t2, t2, two);
        submod(w[1251], t1, t2);
    }

    // AND 1027 673 -> 1252
    mulmod(w[1252], w[1027], w[673]);

    // XOR 285 450 -> 1253
    {
        bn254fr_class t1, t2;
        addmod(t1, w[285], w[450]);
        mulmod(t2, w[285], w[450]);
        mulmod_constant(t2, t2, two);
        submod(w[1253], t1, t2);
    }

    // AND 312 147 -> 1254
    mulmod(w[1254], w[312], w[147]);

    // XOR 743 905 -> 1255
    {
        bn254fr_class t1, t2;
        addmod(t1, w[743], w[905]);
        mulmod(t2, w[743], w[905]);
        mulmod_constant(t2, t2, two);
        submod(w[1255], t1, t2);
    }

    // XOR 29 937 -> 1256
    {
        bn254fr_class t1, t2;
        addmod(t1, w[29], w[937]);
        mulmod(t2, w[29], w[937]);
        mulmod_constant(t2, t2, two);
        submod(w[1256], t1, t2);
    }

    // XOR 741 865 -> 1257
    {
        bn254fr_class t1, t2;
        addmod(t1, w[741], w[865]);
        mulmod(t2, w[741], w[865]);
        mulmod_constant(t2, t2, two);
        submod(w[1257], t1, t2);
    }

    // AND 530 258 -> 1258
    mulmod(w[1258], w[530], w[258]);

    // AND 839 554 -> 1259
    mulmod(w[1259], w[839], w[554]);

    // AND 634 1009 -> 1260
    mulmod(w[1260], w[634], w[1009]);

    // XOR 1003 281 -> 1261
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1003], w[281]);
        mulmod(t2, w[1003], w[281]);
        mulmod_constant(t2, t2, two);
        submod(w[1261], t1, t2);
    }

    // INV 186 -> 1262
    submod(w[1262], one, w[186]);

    // XOR 631 348 -> 1263
    {
        bn254fr_class t1, t2;
        addmod(t1, w[631], w[348]);
        mulmod(t2, w[631], w[348]);
        mulmod_constant(t2, t2, two);
        submod(w[1263], t1, t2);
    }

    // AND 367 1026 -> 1264
    mulmod(w[1264], w[367], w[1026]);

    // AND 631 357 -> 1265
    mulmod(w[1265], w[631], w[357]);

    // AND 1081 740 -> 1266
    mulmod(w[1266], w[1081], w[740]);

    // INV 580 -> 1267
    submod(w[1267], one, w[580]);

    // AND 189 996 -> 1268
    mulmod(w[1268], w[189], w[996]);

    // XOR 288 185 -> 1269
    {
        bn254fr_class t1, t2;
        addmod(t1, w[288], w[185]);
        mulmod(t2, w[288], w[185]);
        mulmod_constant(t2, t2, two);
        submod(w[1269], t1, t2);
    }

    // XOR 262 738 -> 1270
    {
        bn254fr_class t1, t2;
        addmod(t1, w[262], w[738]);
        mulmod(t2, w[262], w[738]);
        mulmod_constant(t2, t2, two);
        submod(w[1270], t1, t2);
    }

    // XOR 488 1044 -> 1271
    {
        bn254fr_class t1, t2;
        addmod(t1, w[488], w[1044]);
        mulmod(t2, w[488], w[1044]);
        mulmod_constant(t2, t2, two);
        submod(w[1271], t1, t2);
    }

    // XOR 971 157 -> 1272
    {
        bn254fr_class t1, t2;
        addmod(t1, w[971], w[157]);
        mulmod(t2, w[971], w[157]);
        mulmod_constant(t2, t2, two);
        submod(w[1272], t1, t2);
    }

    // XOR 1049 24 -> 1273
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1049], w[24]);
        mulmod(t2, w[1049], w[24]);
        mulmod_constant(t2, t2, two);
        submod(w[1273], t1, t2);
    }

    // XOR 956 1143 -> 1274
    {
        bn254fr_class t1, t2;
        addmod(t1, w[956], w[1143]);
        mulmod(t2, w[956], w[1143]);
        mulmod_constant(t2, t2, two);
        submod(w[1274], t1, t2);
    }

    // XOR 1197 777 -> 1275
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1197], w[777]);
        mulmod(t2, w[1197], w[777]);
        mulmod_constant(t2, t2, two);
        submod(w[1275], t1, t2);
    }

    // AND 1210 174 -> 1276
    mulmod(w[1276], w[1210], w[174]);

    // XOR 800 1171 -> 1277
    {
        bn254fr_class t1, t2;
        addmod(t1, w[800], w[1171]);
        mulmod(t2, w[800], w[1171]);
        mulmod_constant(t2, t2, two);
        submod(w[1277], t1, t2);
    }

    // AND 332 867 -> 1278
    mulmod(w[1278], w[332], w[867]);

    // XOR 329 898 -> 1279
    {
        bn254fr_class t1, t2;
        addmod(t1, w[329], w[898]);
        mulmod(t2, w[329], w[898]);
        mulmod_constant(t2, t2, two);
        submod(w[1279], t1, t2);
    }

    // XOR 112 557 -> 1280
    {
        bn254fr_class t1, t2;
        addmod(t1, w[112], w[557]);
        mulmod(t2, w[112], w[557]);
        mulmod_constant(t2, t2, two);
        submod(w[1280], t1, t2);
    }

    // AND 26 1080 -> 1281
    mulmod(w[1281], w[26], w[1080]);

    // AND 735 77 -> 1282
    mulmod(w[1282], w[735], w[77]);

    // XOR 532 896 -> 1283
    {
        bn254fr_class t1, t2;
        addmod(t1, w[532], w[896]);
        mulmod(t2, w[532], w[896]);
        mulmod_constant(t2, t2, two);
        submod(w[1283], t1, t2);
    }

    // XOR 501 308 -> 1284
    {
        bn254fr_class t1, t2;
        addmod(t1, w[501], w[308]);
        mulmod(t2, w[501], w[308]);
        mulmod_constant(t2, t2, two);
        submod(w[1284], t1, t2);
    }

    // XOR 330 949 -> 1285
    {
        bn254fr_class t1, t2;
        addmod(t1, w[330], w[949]);
        mulmod(t2, w[330], w[949]);
        mulmod_constant(t2, t2, two);
        submod(w[1285], t1, t2);
    }

    // XOR 413 189 -> 1286
    {
        bn254fr_class t1, t2;
        addmod(t1, w[413], w[189]);
        mulmod(t2, w[413], w[189]);
        mulmod_constant(t2, t2, two);
        submod(w[1286], t1, t2);
    }

    // XOR 1001 599 -> 1287
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1001], w[599]);
        mulmod(t2, w[1001], w[599]);
        mulmod_constant(t2, t2, two);
        submod(w[1287], t1, t2);
    }

    // XOR 1182 600 -> 1288
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1182], w[600]);
        mulmod(t2, w[1182], w[600]);
        mulmod_constant(t2, t2, two);
        submod(w[1288], t1, t2);
    }

    // XOR 934 757 -> 1289
    {
        bn254fr_class t1, t2;
        addmod(t1, w[934], w[757]);
        mulmod(t2, w[934], w[757]);
        mulmod_constant(t2, t2, two);
        submod(w[1289], t1, t2);
    }

    // AND 981 636 -> 1290
    mulmod(w[1290], w[981], w[636]);

    // XOR 202 321 -> 1291
    {
        bn254fr_class t1, t2;
        addmod(t1, w[202], w[321]);
        mulmod(t2, w[202], w[321]);
        mulmod_constant(t2, t2, two);
        submod(w[1291], t1, t2);
    }

    // AND 452 24 -> 1292
    mulmod(w[1292], w[452], w[24]);

    // AND 638 1169 -> 1293
    mulmod(w[1293], w[638], w[1169]);

    // XOR 1211 434 -> 1294
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1211], w[434]);
        mulmod(t2, w[1211], w[434]);
        mulmod_constant(t2, t2, two);
        submod(w[1294], t1, t2);
    }

    // XOR 433 696 -> 1295
    {
        bn254fr_class t1, t2;
        addmod(t1, w[433], w[696]);
        mulmod(t2, w[433], w[696]);
        mulmod_constant(t2, t2, two);
        submod(w[1295], t1, t2);
    }

    // XOR 515 140 -> 1296
    {
        bn254fr_class t1, t2;
        addmod(t1, w[515], w[140]);
        mulmod(t2, w[515], w[140]);
        mulmod_constant(t2, t2, two);
        submod(w[1296], t1, t2);
    }

    // XOR 835 383 -> 1297
    {
        bn254fr_class t1, t2;
        addmod(t1, w[835], w[383]);
        mulmod(t2, w[835], w[383]);
        mulmod_constant(t2, t2, two);
        submod(w[1297], t1, t2);
    }

    // XOR 288 484 -> 1298
    {
        bn254fr_class t1, t2;
        addmod(t1, w[288], w[484]);
        mulmod(t2, w[288], w[484]);
        mulmod_constant(t2, t2, two);
        submod(w[1298], t1, t2);
    }

    // XOR 45 1070 -> 1299
    {
        bn254fr_class t1, t2;
        addmod(t1, w[45], w[1070]);
        mulmod(t2, w[45], w[1070]);
        mulmod_constant(t2, t2, two);
        submod(w[1299], t1, t2);
    }

    // XOR 822 1126 -> 1300
    {
        bn254fr_class t1, t2;
        addmod(t1, w[822], w[1126]);
        mulmod(t2, w[822], w[1126]);
        mulmod_constant(t2, t2, two);
        submod(w[1300], t1, t2);
    }

    // AND 540 545 -> 1301
    mulmod(w[1301], w[540], w[545]);

    // AND 840 11 -> 1302
    mulmod(w[1302], w[840], w[11]);

    // XOR 369 685 -> 1303
    {
        bn254fr_class t1, t2;
        addmod(t1, w[369], w[685]);
        mulmod(t2, w[369], w[685]);
        mulmod_constant(t2, t2, two);
        submod(w[1303], t1, t2);
    }

    // XOR 665 255 -> 1304
    {
        bn254fr_class t1, t2;
        addmod(t1, w[665], w[255]);
        mulmod(t2, w[665], w[255]);
        mulmod_constant(t2, t2, two);
        submod(w[1304], t1, t2);
    }

    // XOR 1223 536 -> 1305
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1223], w[536]);
        mulmod(t2, w[1223], w[536]);
        mulmod_constant(t2, t2, two);
        submod(w[1305], t1, t2);
    }

    // INV 84 -> 1306
    submod(w[1306], one, w[84]);

    // AND 807 429 -> 1307
    mulmod(w[1307], w[807], w[429]);

    // XOR 67 423 -> 1308
    {
        bn254fr_class t1, t2;
        addmod(t1, w[67], w[423]);
        mulmod(t2, w[67], w[423]);
        mulmod_constant(t2, t2, two);
        submod(w[1308], t1, t2);
    }

    // XOR 161 1109 -> 1309
    {
        bn254fr_class t1, t2;
        addmod(t1, w[161], w[1109]);
        mulmod(t2, w[161], w[1109]);
        mulmod_constant(t2, t2, two);
        submod(w[1309], t1, t2);
    }

    // AND 1090 796 -> 1310
    mulmod(w[1310], w[1090], w[796]);

    // AND 654 502 -> 1311
    mulmod(w[1311], w[654], w[502]);

    // XOR 790 1132 -> 1312
    {
        bn254fr_class t1, t2;
        addmod(t1, w[790], w[1132]);
        mulmod(t2, w[790], w[1132]);
        mulmod_constant(t2, t2, two);
        submod(w[1312], t1, t2);
    }

    // XOR 1008 1062 -> 1313
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1008], w[1062]);
        mulmod(t2, w[1008], w[1062]);
        mulmod_constant(t2, t2, two);
        submod(w[1313], t1, t2);
    }

    // AND 483 119 -> 1314
    mulmod(w[1314], w[483], w[119]);

    // XOR 693 351 -> 1315
    {
        bn254fr_class t1, t2;
        addmod(t1, w[693], w[351]);
        mulmod(t2, w[693], w[351]);
        mulmod_constant(t2, t2, two);
        submod(w[1315], t1, t2);
    }

    // AND 962 331 -> 1316
    mulmod(w[1316], w[962], w[331]);

    // XOR 756 1164 -> 1317
    {
        bn254fr_class t1, t2;
        addmod(t1, w[756], w[1164]);
        mulmod(t2, w[756], w[1164]);
        mulmod_constant(t2, t2, two);
        submod(w[1317], t1, t2);
    }

    // XOR 898 711 -> 1318
    {
        bn254fr_class t1, t2;
        addmod(t1, w[898], w[711]);
        mulmod(t2, w[898], w[711]);
        mulmod_constant(t2, t2, two);
        submod(w[1318], t1, t2);
    }

    // INV 86 -> 1319
    submod(w[1319], one, w[86]);

    // XOR 363 285 -> 1320
    {
        bn254fr_class t1, t2;
        addmod(t1, w[363], w[285]);
        mulmod(t2, w[363], w[285]);
        mulmod_constant(t2, t2, two);
        submod(w[1320], t1, t2);
    }

    // XOR 259 570 -> 1321
    {
        bn254fr_class t1, t2;
        addmod(t1, w[259], w[570]);
        mulmod(t2, w[259], w[570]);
        mulmod_constant(t2, t2, two);
        submod(w[1321], t1, t2);
    }

    // XOR 1094 694 -> 1322
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1094], w[694]);
        mulmod(t2, w[1094], w[694]);
        mulmod_constant(t2, t2, two);
        submod(w[1322], t1, t2);
    }

    // INV 1210 -> 1323
    submod(w[1323], one, w[1210]);

    // AND 482 727 -> 1324
    mulmod(w[1324], w[482], w[727]);

    // AND 411 571 -> 1325
    mulmod(w[1325], w[411], w[571]);

    // AND 965 218 -> 1326
    mulmod(w[1326], w[965], w[218]);

    // XOR 118 253 -> 1327
    {
        bn254fr_class t1, t2;
        addmod(t1, w[118], w[253]);
        mulmod(t2, w[118], w[253]);
        mulmod_constant(t2, t2, two);
        submod(w[1327], t1, t2);
    }

    // XOR 740 419 -> 1328
    {
        bn254fr_class t1, t2;
        addmod(t1, w[740], w[419]);
        mulmod(t2, w[740], w[419]);
        mulmod_constant(t2, t2, two);
        submod(w[1328], t1, t2);
    }

    // AND 734 6 -> 1329
    mulmod(w[1329], w[734], w[6]);

    // XOR 1103 587 -> 1330
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1103], w[587]);
        mulmod(t2, w[1103], w[587]);
        mulmod_constant(t2, t2, two);
        submod(w[1330], t1, t2);
    }

    // XOR 1307 252 -> 1331
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1307], w[252]);
        mulmod(t2, w[1307], w[252]);
        mulmod_constant(t2, t2, two);
        submod(w[1331], t1, t2);
    }

    // AND 1221 363 -> 1332
    mulmod(w[1332], w[1221], w[363]);

    // XOR 546 999 -> 1333
    {
        bn254fr_class t1, t2;
        addmod(t1, w[546], w[999]);
        mulmod(t2, w[546], w[999]);
        mulmod_constant(t2, t2, two);
        submod(w[1333], t1, t2);
    }

    // XOR 203 1320 -> 1334
    {
        bn254fr_class t1, t2;
        addmod(t1, w[203], w[1320]);
        mulmod(t2, w[203], w[1320]);
        mulmod_constant(t2, t2, two);
        submod(w[1334], t1, t2);
    }

    // AND 926 725 -> 1335
    mulmod(w[1335], w[926], w[725]);

    // XOR 448 1236 -> 1336
    {
        bn254fr_class t1, t2;
        addmod(t1, w[448], w[1236]);
        mulmod(t2, w[448], w[1236]);
        mulmod_constant(t2, t2, two);
        submod(w[1336], t1, t2);
    }

    // XOR 815 474 -> 1337
    {
        bn254fr_class t1, t2;
        addmod(t1, w[815], w[474]);
        mulmod(t2, w[815], w[474]);
        mulmod_constant(t2, t2, two);
        submod(w[1337], t1, t2);
    }

    // XOR 1080 295 -> 1338
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1080], w[295]);
        mulmod(t2, w[1080], w[295]);
        mulmod_constant(t2, t2, two);
        submod(w[1338], t1, t2);
    }

    // AND 872 777 -> 1339
    mulmod(w[1339], w[872], w[777]);

    // AND 928 917 -> 1340
    mulmod(w[1340], w[928], w[917]);

    // XOR 915 1005 -> 1341
    {
        bn254fr_class t1, t2;
        addmod(t1, w[915], w[1005]);
        mulmod(t2, w[915], w[1005]);
        mulmod_constant(t2, t2, two);
        submod(w[1341], t1, t2);
    }

    // XOR 921 206 -> 1342
    {
        bn254fr_class t1, t2;
        addmod(t1, w[921], w[206]);
        mulmod(t2, w[921], w[206]);
        mulmod_constant(t2, t2, two);
        submod(w[1342], t1, t2);
    }

    // AND 533 1029 -> 1343
    mulmod(w[1343], w[533], w[1029]);

    // XOR 459 983 -> 1344
    {
        bn254fr_class t1, t2;
        addmod(t1, w[459], w[983]);
        mulmod(t2, w[459], w[983]);
        mulmod_constant(t2, t2, two);
        submod(w[1344], t1, t2);
    }

    // INV 679 -> 1345
    submod(w[1345], one, w[679]);

    // INV 723 -> 1346
    submod(w[1346], one, w[723]);

    // XOR 534 44 -> 1347
    {
        bn254fr_class t1, t2;
        addmod(t1, w[534], w[44]);
        mulmod(t2, w[534], w[44]);
        mulmod_constant(t2, t2, two);
        submod(w[1347], t1, t2);
    }

    // XOR 1284 1159 -> 1348
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1284], w[1159]);
        mulmod(t2, w[1284], w[1159]);
        mulmod_constant(t2, t2, two);
        submod(w[1348], t1, t2);
    }

    // XOR 1272 85 -> 1349
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1272], w[85]);
        mulmod(t2, w[1272], w[85]);
        mulmod_constant(t2, t2, two);
        submod(w[1349], t1, t2);
    }

    // INV 286 -> 1350
    submod(w[1350], one, w[286]);

    // INV 1326 -> 1351
    submod(w[1351], one, w[1326]);

    // AND 1001 61 -> 1352
    mulmod(w[1352], w[1001], w[61]);

    // INV 1189 -> 1353
    submod(w[1353], one, w[1189]);

    // AND 110 884 -> 1354
    mulmod(w[1354], w[110], w[884]);

    // XOR 634 233 -> 1355
    {
        bn254fr_class t1, t2;
        addmod(t1, w[634], w[233]);
        mulmod(t2, w[634], w[233]);
        mulmod_constant(t2, t2, two);
        submod(w[1355], t1, t2);
    }

    // AND 1125 263 -> 1356
    mulmod(w[1356], w[1125], w[263]);

    // XOR 655 862 -> 1357
    {
        bn254fr_class t1, t2;
        addmod(t1, w[655], w[862]);
        mulmod(t2, w[655], w[862]);
        mulmod_constant(t2, t2, two);
        submod(w[1357], t1, t2);
    }

    // AND 62 516 -> 1358
    mulmod(w[1358], w[62], w[516]);

    // XOR 983 192 -> 1359
    {
        bn254fr_class t1, t2;
        addmod(t1, w[983], w[192]);
        mulmod(t2, w[983], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[1359], t1, t2);
    }

    // INV 360 -> 1360
    submod(w[1360], one, w[360]);

    // XOR 69 777 -> 1361
    {
        bn254fr_class t1, t2;
        addmod(t1, w[69], w[777]);
        mulmod(t2, w[69], w[777]);
        mulmod_constant(t2, t2, two);
        submod(w[1361], t1, t2);
    }

    // XOR 1286 669 -> 1362
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1286], w[669]);
        mulmod(t2, w[1286], w[669]);
        mulmod_constant(t2, t2, two);
        submod(w[1362], t1, t2);
    }

    // XOR 1135 858 -> 1363
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1135], w[858]);
        mulmod(t2, w[1135], w[858]);
        mulmod_constant(t2, t2, two);
        submod(w[1363], t1, t2);
    }

    // AND 331 326 -> 1364
    mulmod(w[1364], w[331], w[326]);

    // XOR 677 502 -> 1365
    {
        bn254fr_class t1, t2;
        addmod(t1, w[677], w[502]);
        mulmod(t2, w[677], w[502]);
        mulmod_constant(t2, t2, two);
        submod(w[1365], t1, t2);
    }

    // AND 1033 653 -> 1366
    mulmod(w[1366], w[1033], w[653]);

    // XOR 35 752 -> 1367
    {
        bn254fr_class t1, t2;
        addmod(t1, w[35], w[752]);
        mulmod(t2, w[35], w[752]);
        mulmod_constant(t2, t2, two);
        submod(w[1367], t1, t2);
    }

    // INV 487 -> 1368
    submod(w[1368], one, w[487]);

    // AND 902 323 -> 1369
    mulmod(w[1369], w[902], w[323]);

    // XOR 1128 1127 -> 1370
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1128], w[1127]);
        mulmod(t2, w[1128], w[1127]);
        mulmod_constant(t2, t2, two);
        submod(w[1370], t1, t2);
    }

    // AND 790 90 -> 1371
    mulmod(w[1371], w[790], w[90]);

    // XOR 498 1243 -> 1372
    {
        bn254fr_class t1, t2;
        addmod(t1, w[498], w[1243]);
        mulmod(t2, w[498], w[1243]);
        mulmod_constant(t2, t2, two);
        submod(w[1372], t1, t2);
    }

    // AND 1185 377 -> 1373
    mulmod(w[1373], w[1185], w[377]);

    // XOR 728 369 -> 1374
    {
        bn254fr_class t1, t2;
        addmod(t1, w[728], w[369]);
        mulmod(t2, w[728], w[369]);
        mulmod_constant(t2, t2, two);
        submod(w[1374], t1, t2);
    }

    // XOR 916 295 -> 1375
    {
        bn254fr_class t1, t2;
        addmod(t1, w[916], w[295]);
        mulmod(t2, w[916], w[295]);
        mulmod_constant(t2, t2, two);
        submod(w[1375], t1, t2);
    }

    // AND 34 82 -> 1376
    mulmod(w[1376], w[34], w[82]);

    // XOR 995 201 -> 1377
    {
        bn254fr_class t1, t2;
        addmod(t1, w[995], w[201]);
        mulmod(t2, w[995], w[201]);
        mulmod_constant(t2, t2, two);
        submod(w[1377], t1, t2);
    }

    // AND 613 1207 -> 1378
    mulmod(w[1378], w[613], w[1207]);

    // XOR 888 1003 -> 1379
    {
        bn254fr_class t1, t2;
        addmod(t1, w[888], w[1003]);
        mulmod(t2, w[888], w[1003]);
        mulmod_constant(t2, t2, two);
        submod(w[1379], t1, t2);
    }

    // XOR 184 544 -> 1380
    {
        bn254fr_class t1, t2;
        addmod(t1, w[184], w[544]);
        mulmod(t2, w[184], w[544]);
        mulmod_constant(t2, t2, two);
        submod(w[1380], t1, t2);
    }

    // XOR 295 1317 -> 1381
    {
        bn254fr_class t1, t2;
        addmod(t1, w[295], w[1317]);
        mulmod(t2, w[295], w[1317]);
        mulmod_constant(t2, t2, two);
        submod(w[1381], t1, t2);
    }

    // XOR 688 372 -> 1382
    {
        bn254fr_class t1, t2;
        addmod(t1, w[688], w[372]);
        mulmod(t2, w[688], w[372]);
        mulmod_constant(t2, t2, two);
        submod(w[1382], t1, t2);
    }

    // XOR 932 14 -> 1383
    {
        bn254fr_class t1, t2;
        addmod(t1, w[932], w[14]);
        mulmod(t2, w[932], w[14]);
        mulmod_constant(t2, t2, two);
        submod(w[1383], t1, t2);
    }

    // AND 841 1243 -> 1384
    mulmod(w[1384], w[841], w[1243]);

    // AND 26 1082 -> 1385
    mulmod(w[1385], w[26], w[1082]);

    // INV 813 -> 1386
    submod(w[1386], one, w[813]);

    // AND 920 815 -> 1387
    mulmod(w[1387], w[920], w[815]);

    // AND 427 1069 -> 1388
    mulmod(w[1388], w[427], w[1069]);

    // AND 596 219 -> 1389
    mulmod(w[1389], w[596], w[219]);

    // XOR 1127 592 -> 1390
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1127], w[592]);
        mulmod(t2, w[1127], w[592]);
        mulmod_constant(t2, t2, two);
        submod(w[1390], t1, t2);
    }

    // XOR 786 990 -> 1391
    {
        bn254fr_class t1, t2;
        addmod(t1, w[786], w[990]);
        mulmod(t2, w[786], w[990]);
        mulmod_constant(t2, t2, two);
        submod(w[1391], t1, t2);
    }

    // XOR 649 544 -> 1392
    {
        bn254fr_class t1, t2;
        addmod(t1, w[649], w[544]);
        mulmod(t2, w[649], w[544]);
        mulmod_constant(t2, t2, two);
        submod(w[1392], t1, t2);
    }

    // XOR 559 60 -> 1393
    {
        bn254fr_class t1, t2;
        addmod(t1, w[559], w[60]);
        mulmod(t2, w[559], w[60]);
        mulmod_constant(t2, t2, two);
        submod(w[1393], t1, t2);
    }

    // AND 845 822 -> 1394
    mulmod(w[1394], w[845], w[822]);

    // INV 1159 -> 1395
    submod(w[1395], one, w[1159]);

    // XOR 272 1022 -> 1396
    {
        bn254fr_class t1, t2;
        addmod(t1, w[272], w[1022]);
        mulmod(t2, w[272], w[1022]);
        mulmod_constant(t2, t2, two);
        submod(w[1396], t1, t2);
    }

    // XOR 321 185 -> 1397
    {
        bn254fr_class t1, t2;
        addmod(t1, w[321], w[185]);
        mulmod(t2, w[321], w[185]);
        mulmod_constant(t2, t2, two);
        submod(w[1397], t1, t2);
    }

    // AND 375 345 -> 1398
    mulmod(w[1398], w[375], w[345]);

    // XOR 891 553 -> 1399
    {
        bn254fr_class t1, t2;
        addmod(t1, w[891], w[553]);
        mulmod(t2, w[891], w[553]);
        mulmod_constant(t2, t2, two);
        submod(w[1399], t1, t2);
    }

    // XOR 806 150 -> 1400
    {
        bn254fr_class t1, t2;
        addmod(t1, w[806], w[150]);
        mulmod(t2, w[806], w[150]);
        mulmod_constant(t2, t2, two);
        submod(w[1400], t1, t2);
    }

    // XOR 1292 316 -> 1401
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1292], w[316]);
        mulmod(t2, w[1292], w[316]);
        mulmod_constant(t2, t2, two);
        submod(w[1401], t1, t2);
    }

    // XOR 82 351 -> 1402
    {
        bn254fr_class t1, t2;
        addmod(t1, w[82], w[351]);
        mulmod(t2, w[82], w[351]);
        mulmod_constant(t2, t2, two);
        submod(w[1402], t1, t2);
    }

    // AND 149 542 -> 1403
    mulmod(w[1403], w[149], w[542]);

    // XOR 804 756 -> 1404
    {
        bn254fr_class t1, t2;
        addmod(t1, w[804], w[756]);
        mulmod(t2, w[804], w[756]);
        mulmod_constant(t2, t2, two);
        submod(w[1404], t1, t2);
    }

    // AND 1167 470 -> 1405
    mulmod(w[1405], w[1167], w[470]);

    // AND 50 414 -> 1406
    mulmod(w[1406], w[50], w[414]);

    // XOR 1186 423 -> 1407
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1186], w[423]);
        mulmod(t2, w[1186], w[423]);
        mulmod_constant(t2, t2, two);
        submod(w[1407], t1, t2);
    }

    // AND 971 161 -> 1408
    mulmod(w[1408], w[971], w[161]);

    // AND 800 1200 -> 1409
    mulmod(w[1409], w[800], w[1200]);

    // INV 200 -> 1410
    submod(w[1410], one, w[200]);

    // XOR 207 615 -> 1411
    {
        bn254fr_class t1, t2;
        addmod(t1, w[207], w[615]);
        mulmod(t2, w[207], w[615]);
        mulmod_constant(t2, t2, two);
        submod(w[1411], t1, t2);
    }

    // XOR 115 1235 -> 1412
    {
        bn254fr_class t1, t2;
        addmod(t1, w[115], w[1235]);
        mulmod(t2, w[115], w[1235]);
        mulmod_constant(t2, t2, two);
        submod(w[1412], t1, t2);
    }

    // AND 283 194 -> 1413
    mulmod(w[1413], w[283], w[194]);

    // AND 24 937 -> 1414
    mulmod(w[1414], w[24], w[937]);

    // AND 768 502 -> 1415
    mulmod(w[1415], w[768], w[502]);

    // AND 1141 945 -> 1416
    mulmod(w[1416], w[1141], w[945]);

    // INV 510 -> 1417
    submod(w[1417], one, w[510]);

    // XOR 481 696 -> 1418
    {
        bn254fr_class t1, t2;
        addmod(t1, w[481], w[696]);
        mulmod(t2, w[481], w[696]);
        mulmod_constant(t2, t2, two);
        submod(w[1418], t1, t2);
    }

    // AND 943 126 -> 1419
    mulmod(w[1419], w[943], w[126]);

    // XOR 260 1277 -> 1420
    {
        bn254fr_class t1, t2;
        addmod(t1, w[260], w[1277]);
        mulmod(t2, w[260], w[1277]);
        mulmod_constant(t2, t2, two);
        submod(w[1420], t1, t2);
    }

    // AND 1080 1257 -> 1421
    mulmod(w[1421], w[1080], w[1257]);

    // AND 650 696 -> 1422
    mulmod(w[1422], w[650], w[696]);

    // XOR 31 566 -> 1423
    {
        bn254fr_class t1, t2;
        addmod(t1, w[31], w[566]);
        mulmod(t2, w[31], w[566]);
        mulmod_constant(t2, t2, two);
        submod(w[1423], t1, t2);
    }

    // XOR 125 1008 -> 1424
    {
        bn254fr_class t1, t2;
        addmod(t1, w[125], w[1008]);
        mulmod(t2, w[125], w[1008]);
        mulmod_constant(t2, t2, two);
        submod(w[1424], t1, t2);
    }

    // XOR 470 678 -> 1425
    {
        bn254fr_class t1, t2;
        addmod(t1, w[470], w[678]);
        mulmod(t2, w[470], w[678]);
        mulmod_constant(t2, t2, two);
        submod(w[1425], t1, t2);
    }

    // AND 41 398 -> 1426
    mulmod(w[1426], w[41], w[398]);

    // AND 362 1127 -> 1427
    mulmod(w[1427], w[362], w[1127]);

    // AND 58 517 -> 1428
    mulmod(w[1428], w[58], w[517]);

    // XOR 1407 1043 -> 1429
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1407], w[1043]);
        mulmod(t2, w[1407], w[1043]);
        mulmod_constant(t2, t2, two);
        submod(w[1429], t1, t2);
    }

    // XOR 944 172 -> 1430
    {
        bn254fr_class t1, t2;
        addmod(t1, w[944], w[172]);
        mulmod(t2, w[944], w[172]);
        mulmod_constant(t2, t2, two);
        submod(w[1430], t1, t2);
    }

    // XOR 306 319 -> 1431
    {
        bn254fr_class t1, t2;
        addmod(t1, w[306], w[319]);
        mulmod(t2, w[306], w[319]);
        mulmod_constant(t2, t2, two);
        submod(w[1431], t1, t2);
    }

    // AND 179 740 -> 1432
    mulmod(w[1432], w[179], w[740]);

    // XOR 1151 384 -> 1433
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1151], w[384]);
        mulmod(t2, w[1151], w[384]);
        mulmod_constant(t2, t2, two);
        submod(w[1433], t1, t2);
    }

    // XOR 250 1414 -> 1434
    {
        bn254fr_class t1, t2;
        addmod(t1, w[250], w[1414]);
        mulmod(t2, w[250], w[1414]);
        mulmod_constant(t2, t2, two);
        submod(w[1434], t1, t2);
    }

    // XOR 1410 475 -> 1435
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1410], w[475]);
        mulmod(t2, w[1410], w[475]);
        mulmod_constant(t2, t2, two);
        submod(w[1435], t1, t2);
    }

    // INV 642 -> 1436
    submod(w[1436], one, w[642]);

    // XOR 1369 1280 -> 1437
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1369], w[1280]);
        mulmod(t2, w[1369], w[1280]);
        mulmod_constant(t2, t2, two);
        submod(w[1437], t1, t2);
    }

    // XOR 801 1011 -> 1438
    {
        bn254fr_class t1, t2;
        addmod(t1, w[801], w[1011]);
        mulmod(t2, w[801], w[1011]);
        mulmod_constant(t2, t2, two);
        submod(w[1438], t1, t2);
    }

    // XOR 17 960 -> 1439
    {
        bn254fr_class t1, t2;
        addmod(t1, w[17], w[960]);
        mulmod(t2, w[17], w[960]);
        mulmod_constant(t2, t2, two);
        submod(w[1439], t1, t2);
    }

    // AND 1356 603 -> 1440
    mulmod(w[1440], w[1356], w[603]);

    // AND 704 514 -> 1441
    mulmod(w[1441], w[704], w[514]);

    // XOR 475 624 -> 1442
    {
        bn254fr_class t1, t2;
        addmod(t1, w[475], w[624]);
        mulmod(t2, w[475], w[624]);
        mulmod_constant(t2, t2, two);
        submod(w[1442], t1, t2);
    }

    // XOR 952 1137 -> 1443
    {
        bn254fr_class t1, t2;
        addmod(t1, w[952], w[1137]);
        mulmod(t2, w[952], w[1137]);
        mulmod_constant(t2, t2, two);
        submod(w[1443], t1, t2);
    }

    // INV 254 -> 1444
    submod(w[1444], one, w[254]);

    // AND 428 693 -> 1445
    mulmod(w[1445], w[428], w[693]);

    // XOR 70 194 -> 1446
    {
        bn254fr_class t1, t2;
        addmod(t1, w[70], w[194]);
        mulmod(t2, w[70], w[194]);
        mulmod_constant(t2, t2, two);
        submod(w[1446], t1, t2);
    }

    // XOR 151 937 -> 1447
    {
        bn254fr_class t1, t2;
        addmod(t1, w[151], w[937]);
        mulmod(t2, w[151], w[937]);
        mulmod_constant(t2, t2, two);
        submod(w[1447], t1, t2);
    }

    // XOR 952 706 -> 1448
    {
        bn254fr_class t1, t2;
        addmod(t1, w[952], w[706]);
        mulmod(t2, w[952], w[706]);
        mulmod_constant(t2, t2, two);
        submod(w[1448], t1, t2);
    }

    // XOR 350 1133 -> 1449
    {
        bn254fr_class t1, t2;
        addmod(t1, w[350], w[1133]);
        mulmod(t2, w[350], w[1133]);
        mulmod_constant(t2, t2, two);
        submod(w[1449], t1, t2);
    }

    // XOR 790 296 -> 1450
    {
        bn254fr_class t1, t2;
        addmod(t1, w[790], w[296]);
        mulmod(t2, w[790], w[296]);
        mulmod_constant(t2, t2, two);
        submod(w[1450], t1, t2);
    }

    // XOR 107 367 -> 1451
    {
        bn254fr_class t1, t2;
        addmod(t1, w[107], w[367]);
        mulmod(t2, w[107], w[367]);
        mulmod_constant(t2, t2, two);
        submod(w[1451], t1, t2);
    }

    // AND 262 821 -> 1452
    mulmod(w[1452], w[262], w[821]);

    // XOR 412 860 -> 1453
    {
        bn254fr_class t1, t2;
        addmod(t1, w[412], w[860]);
        mulmod(t2, w[412], w[860]);
        mulmod_constant(t2, t2, two);
        submod(w[1453], t1, t2);
    }

    // XOR 28 240 -> 1454
    {
        bn254fr_class t1, t2;
        addmod(t1, w[28], w[240]);
        mulmod(t2, w[28], w[240]);
        mulmod_constant(t2, t2, two);
        submod(w[1454], t1, t2);
    }

    // INV 579 -> 1455
    submod(w[1455], one, w[579]);

    // AND 938 619 -> 1456
    mulmod(w[1456], w[938], w[619]);

    // AND 805 227 -> 1457
    mulmod(w[1457], w[805], w[227]);

    // AND 243 733 -> 1458
    mulmod(w[1458], w[243], w[733]);

    // XOR 233 1106 -> 1459
    {
        bn254fr_class t1, t2;
        addmod(t1, w[233], w[1106]);
        mulmod(t2, w[233], w[1106]);
        mulmod_constant(t2, t2, two);
        submod(w[1459], t1, t2);
    }

    // XOR 148 7 -> 1460
    {
        bn254fr_class t1, t2;
        addmod(t1, w[148], w[7]);
        mulmod(t2, w[148], w[7]);
        mulmod_constant(t2, t2, two);
        submod(w[1460], t1, t2);
    }

    // XOR 436 725 -> 1461
    {
        bn254fr_class t1, t2;
        addmod(t1, w[436], w[725]);
        mulmod(t2, w[436], w[725]);
        mulmod_constant(t2, t2, two);
        submod(w[1461], t1, t2);
    }

    // XOR 75 1289 -> 1462
    {
        bn254fr_class t1, t2;
        addmod(t1, w[75], w[1289]);
        mulmod(t2, w[75], w[1289]);
        mulmod_constant(t2, t2, two);
        submod(w[1462], t1, t2);
    }

    // AND 1334 1139 -> 1463
    mulmod(w[1463], w[1334], w[1139]);

    // XOR 568 747 -> 1464
    {
        bn254fr_class t1, t2;
        addmod(t1, w[568], w[747]);
        mulmod(t2, w[568], w[747]);
        mulmod_constant(t2, t2, two);
        submod(w[1464], t1, t2);
    }

    // AND 1146 1060 -> 1465
    mulmod(w[1465], w[1146], w[1060]);

    // XOR 1158 1293 -> 1466
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1158], w[1293]);
        mulmod(t2, w[1158], w[1293]);
        mulmod_constant(t2, t2, two);
        submod(w[1466], t1, t2);
    }

    // AND 1257 680 -> 1467
    mulmod(w[1467], w[1257], w[680]);

    // AND 486 1278 -> 1468
    mulmod(w[1468], w[486], w[1278]);

    // INV 704 -> 1469
    submod(w[1469], one, w[704]);

    // AND 653 1037 -> 1470
    mulmod(w[1470], w[653], w[1037]);

    // AND 154 1350 -> 1471
    mulmod(w[1471], w[154], w[1350]);

    // AND 881 729 -> 1472
    mulmod(w[1472], w[881], w[729]);

    // INV 997 -> 1473
    submod(w[1473], one, w[997]);

    // XOR 290 384 -> 1474
    {
        bn254fr_class t1, t2;
        addmod(t1, w[290], w[384]);
        mulmod(t2, w[290], w[384]);
        mulmod_constant(t2, t2, two);
        submod(w[1474], t1, t2);
    }

    // XOR 322 896 -> 1475
    {
        bn254fr_class t1, t2;
        addmod(t1, w[322], w[896]);
        mulmod(t2, w[322], w[896]);
        mulmod_constant(t2, t2, two);
        submod(w[1475], t1, t2);
    }

    // XOR 1422 192 -> 1476
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1422], w[192]);
        mulmod(t2, w[1422], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[1476], t1, t2);
    }

    // AND 242 913 -> 1477
    mulmod(w[1477], w[242], w[913]);

    // XOR 1010 647 -> 1478
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1010], w[647]);
        mulmod(t2, w[1010], w[647]);
        mulmod_constant(t2, t2, two);
        submod(w[1478], t1, t2);
    }

    // XOR 445 645 -> 1479
    {
        bn254fr_class t1, t2;
        addmod(t1, w[445], w[645]);
        mulmod(t2, w[445], w[645]);
        mulmod_constant(t2, t2, two);
        submod(w[1479], t1, t2);
    }

    // XOR 997 335 -> 1480
    {
        bn254fr_class t1, t2;
        addmod(t1, w[997], w[335]);
        mulmod(t2, w[997], w[335]);
        mulmod_constant(t2, t2, two);
        submod(w[1480], t1, t2);
    }

    // AND 1238 436 -> 1481
    mulmod(w[1481], w[1238], w[436]);

    // XOR 523 619 -> 1482
    {
        bn254fr_class t1, t2;
        addmod(t1, w[523], w[619]);
        mulmod(t2, w[523], w[619]);
        mulmod_constant(t2, t2, two);
        submod(w[1482], t1, t2);
    }

    // XOR 763 798 -> 1483
    {
        bn254fr_class t1, t2;
        addmod(t1, w[763], w[798]);
        mulmod(t2, w[763], w[798]);
        mulmod_constant(t2, t2, two);
        submod(w[1483], t1, t2);
    }

    // XOR 435 1187 -> 1484
    {
        bn254fr_class t1, t2;
        addmod(t1, w[435], w[1187]);
        mulmod(t2, w[435], w[1187]);
        mulmod_constant(t2, t2, two);
        submod(w[1484], t1, t2);
    }

    // XOR 491 252 -> 1485
    {
        bn254fr_class t1, t2;
        addmod(t1, w[491], w[252]);
        mulmod(t2, w[491], w[252]);
        mulmod_constant(t2, t2, two);
        submod(w[1485], t1, t2);
    }

    // XOR 1152 390 -> 1486
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1152], w[390]);
        mulmod(t2, w[1152], w[390]);
        mulmod_constant(t2, t2, two);
        submod(w[1486], t1, t2);
    }

    // XOR 762 1394 -> 1487
    {
        bn254fr_class t1, t2;
        addmod(t1, w[762], w[1394]);
        mulmod(t2, w[762], w[1394]);
        mulmod_constant(t2, t2, two);
        submod(w[1487], t1, t2);
    }

    // XOR 491 1189 -> 1488
    {
        bn254fr_class t1, t2;
        addmod(t1, w[491], w[1189]);
        mulmod(t2, w[491], w[1189]);
        mulmod_constant(t2, t2, two);
        submod(w[1488], t1, t2);
    }

    // XOR 1195 358 -> 1489
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1195], w[358]);
        mulmod(t2, w[1195], w[358]);
        mulmod_constant(t2, t2, two);
        submod(w[1489], t1, t2);
    }

    // AND 1262 252 -> 1490
    mulmod(w[1490], w[1262], w[252]);

    // XOR 1084 622 -> 1491
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1084], w[622]);
        mulmod(t2, w[1084], w[622]);
        mulmod_constant(t2, t2, two);
        submod(w[1491], t1, t2);
    }

    // XOR 174 313 -> 1492
    {
        bn254fr_class t1, t2;
        addmod(t1, w[174], w[313]);
        mulmod(t2, w[174], w[313]);
        mulmod_constant(t2, t2, two);
        submod(w[1492], t1, t2);
    }

    // XOR 101 1171 -> 1493
    {
        bn254fr_class t1, t2;
        addmod(t1, w[101], w[1171]);
        mulmod(t2, w[101], w[1171]);
        mulmod_constant(t2, t2, two);
        submod(w[1493], t1, t2);
    }

    // AND 619 1342 -> 1494
    mulmod(w[1494], w[619], w[1342]);

    // XOR 1245 6 -> 1495
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1245], w[6]);
        mulmod(t2, w[1245], w[6]);
        mulmod_constant(t2, t2, two);
        submod(w[1495], t1, t2);
    }

    // XOR 1234 666 -> 1496
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1234], w[666]);
        mulmod(t2, w[1234], w[666]);
        mulmod_constant(t2, t2, two);
        submod(w[1496], t1, t2);
    }

    // AND 1005 642 -> 1497
    mulmod(w[1497], w[1005], w[642]);

    // AND 289 1181 -> 1498
    mulmod(w[1498], w[289], w[1181]);

    // AND 1338 70 -> 1499
    mulmod(w[1499], w[1338], w[70]);

    // INV 123 -> 1500
    submod(w[1500], one, w[123]);

    // XOR 1379 897 -> 1501
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1379], w[897]);
        mulmod(t2, w[1379], w[897]);
        mulmod_constant(t2, t2, two);
        submod(w[1501], t1, t2);
    }

    // AND 285 896 -> 1502
    mulmod(w[1502], w[285], w[896]);

    // AND 518 1200 -> 1503
    mulmod(w[1503], w[518], w[1200]);

    // XOR 348 123 -> 1504
    {
        bn254fr_class t1, t2;
        addmod(t1, w[348], w[123]);
        mulmod(t2, w[348], w[123]);
        mulmod_constant(t2, t2, two);
        submod(w[1504], t1, t2);
    }

    // AND 972 459 -> 1505
    mulmod(w[1505], w[972], w[459]);

    // XOR 806 1195 -> 1506
    {
        bn254fr_class t1, t2;
        addmod(t1, w[806], w[1195]);
        mulmod(t2, w[806], w[1195]);
        mulmod_constant(t2, t2, two);
        submod(w[1506], t1, t2);
    }

    // XOR 561 944 -> 1507
    {
        bn254fr_class t1, t2;
        addmod(t1, w[561], w[944]);
        mulmod(t2, w[561], w[944]);
        mulmod_constant(t2, t2, two);
        submod(w[1507], t1, t2);
    }

    // XOR 238 436 -> 1508
    {
        bn254fr_class t1, t2;
        addmod(t1, w[238], w[436]);
        mulmod(t2, w[238], w[436]);
        mulmod_constant(t2, t2, two);
        submod(w[1508], t1, t2);
    }

    // XOR 179 917 -> 1509
    {
        bn254fr_class t1, t2;
        addmod(t1, w[179], w[917]);
        mulmod(t2, w[179], w[917]);
        mulmod_constant(t2, t2, two);
        submod(w[1509], t1, t2);
    }

    // XOR 1250 642 -> 1510
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1250], w[642]);
        mulmod(t2, w[1250], w[642]);
        mulmod_constant(t2, t2, two);
        submod(w[1510], t1, t2);
    }

    // XOR 297 275 -> 1511
    {
        bn254fr_class t1, t2;
        addmod(t1, w[297], w[275]);
        mulmod(t2, w[297], w[275]);
        mulmod_constant(t2, t2, two);
        submod(w[1511], t1, t2);
    }

    // AND 1172 629 -> 1512
    mulmod(w[1512], w[1172], w[629]);

    // AND 1411 1502 -> 1513
    mulmod(w[1513], w[1411], w[1502]);

    // XOR 2 291 -> 1514
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2], w[291]);
        mulmod(t2, w[2], w[291]);
        mulmod_constant(t2, t2, two);
        submod(w[1514], t1, t2);
    }

    // INV 707 -> 1515
    submod(w[1515], one, w[707]);

    // XOR 1094 611 -> 1516
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1094], w[611]);
        mulmod(t2, w[1094], w[611]);
        mulmod_constant(t2, t2, two);
        submod(w[1516], t1, t2);
    }

    // AND 123 138 -> 1517
    mulmod(w[1517], w[123], w[138]);

    // XOR 578 1233 -> 1518
    {
        bn254fr_class t1, t2;
        addmod(t1, w[578], w[1233]);
        mulmod(t2, w[578], w[1233]);
        mulmod_constant(t2, t2, two);
        submod(w[1518], t1, t2);
    }

    // AND 692 762 -> 1519
    mulmod(w[1519], w[692], w[762]);

    // XOR 570 121 -> 1520
    {
        bn254fr_class t1, t2;
        addmod(t1, w[570], w[121]);
        mulmod(t2, w[570], w[121]);
        mulmod_constant(t2, t2, two);
        submod(w[1520], t1, t2);
    }

    // INV 401 -> 1521
    submod(w[1521], one, w[401]);

    // AND 1091 17 -> 1522
    mulmod(w[1522], w[1091], w[17]);

    // AND 599 761 -> 1523
    mulmod(w[1523], w[599], w[761]);

    // XOR 798 33 -> 1524
    {
        bn254fr_class t1, t2;
        addmod(t1, w[798], w[33]);
        mulmod(t2, w[798], w[33]);
        mulmod_constant(t2, t2, two);
        submod(w[1524], t1, t2);
    }

    // INV 678 -> 1525
    submod(w[1525], one, w[678]);

    // XOR 1189 1055 -> 1526
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1189], w[1055]);
        mulmod(t2, w[1189], w[1055]);
        mulmod_constant(t2, t2, two);
        submod(w[1526], t1, t2);
    }

    // XOR 1234 603 -> 1527
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1234], w[603]);
        mulmod(t2, w[1234], w[603]);
        mulmod_constant(t2, t2, two);
        submod(w[1527], t1, t2);
    }

    // XOR 835 965 -> 1528
    {
        bn254fr_class t1, t2;
        addmod(t1, w[835], w[965]);
        mulmod(t2, w[835], w[965]);
        mulmod_constant(t2, t2, two);
        submod(w[1528], t1, t2);
    }

    // XOR 291 1052 -> 1529
    {
        bn254fr_class t1, t2;
        addmod(t1, w[291], w[1052]);
        mulmod(t2, w[291], w[1052]);
        mulmod_constant(t2, t2, two);
        submod(w[1529], t1, t2);
    }

    // XOR 1044 117 -> 1530
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1044], w[117]);
        mulmod(t2, w[1044], w[117]);
        mulmod_constant(t2, t2, two);
        submod(w[1530], t1, t2);
    }

    // AND 781 1031 -> 1531
    mulmod(w[1531], w[781], w[1031]);

    // XOR 1397 1493 -> 1532
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1397], w[1493]);
        mulmod(t2, w[1397], w[1493]);
        mulmod_constant(t2, t2, two);
        submod(w[1532], t1, t2);
    }

    // XOR 1178 567 -> 1533
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1178], w[567]);
        mulmod(t2, w[1178], w[567]);
        mulmod_constant(t2, t2, two);
        submod(w[1533], t1, t2);
    }

    // XOR 727 1196 -> 1534
    {
        bn254fr_class t1, t2;
        addmod(t1, w[727], w[1196]);
        mulmod(t2, w[727], w[1196]);
        mulmod_constant(t2, t2, two);
        submod(w[1534], t1, t2);
    }

    // AND 418 893 -> 1535
    mulmod(w[1535], w[418], w[893]);

    // AND 1258 1494 -> 1536
    mulmod(w[1536], w[1258], w[1494]);

    // XOR 1006 347 -> 1537
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1006], w[347]);
        mulmod(t2, w[1006], w[347]);
        mulmod_constant(t2, t2, two);
        submod(w[1537], t1, t2);
    }

    // AND 12 182 -> 1538
    mulmod(w[1538], w[12], w[182]);

    // XOR 249 1217 -> 1539
    {
        bn254fr_class t1, t2;
        addmod(t1, w[249], w[1217]);
        mulmod(t2, w[249], w[1217]);
        mulmod_constant(t2, t2, two);
        submod(w[1539], t1, t2);
    }

    // XOR 975 944 -> 1540
    {
        bn254fr_class t1, t2;
        addmod(t1, w[975], w[944]);
        mulmod(t2, w[975], w[944]);
        mulmod_constant(t2, t2, two);
        submod(w[1540], t1, t2);
    }

    // AND 816 929 -> 1541
    mulmod(w[1541], w[816], w[929]);

    // XOR 1373 1260 -> 1542
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1373], w[1260]);
        mulmod(t2, w[1373], w[1260]);
        mulmod_constant(t2, t2, two);
        submod(w[1542], t1, t2);
    }

    // XOR 880 392 -> 1543
    {
        bn254fr_class t1, t2;
        addmod(t1, w[880], w[392]);
        mulmod(t2, w[880], w[392]);
        mulmod_constant(t2, t2, two);
        submod(w[1543], t1, t2);
    }

    // AND 46 333 -> 1544
    mulmod(w[1544], w[46], w[333]);

    // INV 645 -> 1545
    submod(w[1545], one, w[645]);

    // XOR 303 632 -> 1546
    {
        bn254fr_class t1, t2;
        addmod(t1, w[303], w[632]);
        mulmod(t2, w[303], w[632]);
        mulmod_constant(t2, t2, two);
        submod(w[1546], t1, t2);
    }

    // XOR 1287 1303 -> 1547
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1287], w[1303]);
        mulmod(t2, w[1287], w[1303]);
        mulmod_constant(t2, t2, two);
        submod(w[1547], t1, t2);
    }

    // XOR 78 1511 -> 1548
    {
        bn254fr_class t1, t2;
        addmod(t1, w[78], w[1511]);
        mulmod(t2, w[78], w[1511]);
        mulmod_constant(t2, t2, two);
        submod(w[1548], t1, t2);
    }

    // AND 1162 581 -> 1549
    mulmod(w[1549], w[1162], w[581]);

    // AND 428 105 -> 1550
    mulmod(w[1550], w[428], w[105]);

    // XOR 1301 1116 -> 1551
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1301], w[1116]);
        mulmod(t2, w[1301], w[1116]);
        mulmod_constant(t2, t2, two);
        submod(w[1551], t1, t2);
    }

    // XOR 166 82 -> 1552
    {
        bn254fr_class t1, t2;
        addmod(t1, w[166], w[82]);
        mulmod(t2, w[166], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[1552], t1, t2);
    }

    // XOR 148 121 -> 1553
    {
        bn254fr_class t1, t2;
        addmod(t1, w[148], w[121]);
        mulmod(t2, w[148], w[121]);
        mulmod_constant(t2, t2, two);
        submod(w[1553], t1, t2);
    }

    // AND 429 649 -> 1554
    mulmod(w[1554], w[429], w[649]);

    // AND 451 475 -> 1555
    mulmod(w[1555], w[451], w[475]);

    // XOR 947 986 -> 1556
    {
        bn254fr_class t1, t2;
        addmod(t1, w[947], w[986]);
        mulmod(t2, w[947], w[986]);
        mulmod_constant(t2, t2, two);
        submod(w[1556], t1, t2);
    }

    // AND 182 610 -> 1557
    mulmod(w[1557], w[182], w[610]);

    // XOR 52 752 -> 1558
    {
        bn254fr_class t1, t2;
        addmod(t1, w[52], w[752]);
        mulmod(t2, w[52], w[752]);
        mulmod_constant(t2, t2, two);
        submod(w[1558], t1, t2);
    }

    // AND 1192 709 -> 1559
    mulmod(w[1559], w[1192], w[709]);

    // XOR 1147 1211 -> 1560
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1147], w[1211]);
        mulmod(t2, w[1147], w[1211]);
        mulmod_constant(t2, t2, two);
        submod(w[1560], t1, t2);
    }

    // AND 927 43 -> 1561
    mulmod(w[1561], w[927], w[43]);

    // XOR 749 881 -> 1562
    {
        bn254fr_class t1, t2;
        addmod(t1, w[749], w[881]);
        mulmod(t2, w[749], w[881]);
        mulmod_constant(t2, t2, two);
        submod(w[1562], t1, t2);
    }

    // AND 1055 1201 -> 1563
    mulmod(w[1563], w[1055], w[1201]);

    // XOR 543 1321 -> 1564
    {
        bn254fr_class t1, t2;
        addmod(t1, w[543], w[1321]);
        mulmod(t2, w[543], w[1321]);
        mulmod_constant(t2, t2, two);
        submod(w[1564], t1, t2);
    }

    // AND 954 1196 -> 1565
    mulmod(w[1565], w[954], w[1196]);

    // XOR 1511 506 -> 1566
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1511], w[506]);
        mulmod(t2, w[1511], w[506]);
        mulmod_constant(t2, t2, two);
        submod(w[1566], t1, t2);
    }

    // XOR 846 1069 -> 1567
    {
        bn254fr_class t1, t2;
        addmod(t1, w[846], w[1069]);
        mulmod(t2, w[846], w[1069]);
        mulmod_constant(t2, t2, two);
        submod(w[1567], t1, t2);
    }

    // XOR 522 1157 -> 1568
    {
        bn254fr_class t1, t2;
        addmod(t1, w[522], w[1157]);
        mulmod(t2, w[522], w[1157]);
        mulmod_constant(t2, t2, two);
        submod(w[1568], t1, t2);
    }

    // XOR 1153 622 -> 1569
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1153], w[622]);
        mulmod(t2, w[1153], w[622]);
        mulmod_constant(t2, t2, two);
        submod(w[1569], t1, t2);
    }

    // AND 1481 1000 -> 1570
    mulmod(w[1570], w[1481], w[1000]);

    // XOR 166 320 -> 1571
    {
        bn254fr_class t1, t2;
        addmod(t1, w[166], w[320]);
        mulmod(t2, w[166], w[320]);
        mulmod_constant(t2, t2, two);
        submod(w[1571], t1, t2);
    }

    // XOR 14 1497 -> 1572
    {
        bn254fr_class t1, t2;
        addmod(t1, w[14], w[1497]);
        mulmod(t2, w[14], w[1497]);
        mulmod_constant(t2, t2, two);
        submod(w[1572], t1, t2);
    }

    // INV 1005 -> 1573
    submod(w[1573], one, w[1005]);

    // XOR 746 782 -> 1574
    {
        bn254fr_class t1, t2;
        addmod(t1, w[746], w[782]);
        mulmod(t2, w[746], w[782]);
        mulmod_constant(t2, t2, two);
        submod(w[1574], t1, t2);
    }

    // XOR 779 818 -> 1575
    {
        bn254fr_class t1, t2;
        addmod(t1, w[779], w[818]);
        mulmod(t2, w[779], w[818]);
        mulmod_constant(t2, t2, two);
        submod(w[1575], t1, t2);
    }

    // XOR 1326 943 -> 1576
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1326], w[943]);
        mulmod(t2, w[1326], w[943]);
        mulmod_constant(t2, t2, two);
        submod(w[1576], t1, t2);
    }

    // XOR 794 830 -> 1577
    {
        bn254fr_class t1, t2;
        addmod(t1, w[794], w[830]);
        mulmod(t2, w[794], w[830]);
        mulmod_constant(t2, t2, two);
        submod(w[1577], t1, t2);
    }

    // XOR 299 1143 -> 1578
    {
        bn254fr_class t1, t2;
        addmod(t1, w[299], w[1143]);
        mulmod(t2, w[299], w[1143]);
        mulmod_constant(t2, t2, two);
        submod(w[1578], t1, t2);
    }

    // AND 409 887 -> 1579
    mulmod(w[1579], w[409], w[887]);

    // INV 740 -> 1580
    submod(w[1580], one, w[740]);

    // XOR 195 1424 -> 1581
    {
        bn254fr_class t1, t2;
        addmod(t1, w[195], w[1424]);
        mulmod(t2, w[195], w[1424]);
        mulmod_constant(t2, t2, two);
        submod(w[1581], t1, t2);
    }

    // XOR 1271 1507 -> 1582
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1271], w[1507]);
        mulmod(t2, w[1271], w[1507]);
        mulmod_constant(t2, t2, two);
        submod(w[1582], t1, t2);
    }

    // XOR 507 330 -> 1583
    {
        bn254fr_class t1, t2;
        addmod(t1, w[507], w[330]);
        mulmod(t2, w[507], w[330]);
        mulmod_constant(t2, t2, two);
        submod(w[1583], t1, t2);
    }

    // XOR 271 999 -> 1584
    {
        bn254fr_class t1, t2;
        addmod(t1, w[271], w[999]);
        mulmod(t2, w[271], w[999]);
        mulmod_constant(t2, t2, two);
        submod(w[1584], t1, t2);
    }

    // XOR 880 584 -> 1585
    {
        bn254fr_class t1, t2;
        addmod(t1, w[880], w[584]);
        mulmod(t2, w[880], w[584]);
        mulmod_constant(t2, t2, two);
        submod(w[1585], t1, t2);
    }

    // XOR 1018 995 -> 1586
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1018], w[995]);
        mulmod(t2, w[1018], w[995]);
        mulmod_constant(t2, t2, two);
        submod(w[1586], t1, t2);
    }

    // XOR 252 67 -> 1587
    {
        bn254fr_class t1, t2;
        addmod(t1, w[252], w[67]);
        mulmod(t2, w[252], w[67]);
        mulmod_constant(t2, t2, two);
        submod(w[1587], t1, t2);
    }

    // XOR 1015 911 -> 1588
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1015], w[911]);
        mulmod(t2, w[1015], w[911]);
        mulmod_constant(t2, t2, two);
        submod(w[1588], t1, t2);
    }

    // AND 330 906 -> 1589
    mulmod(w[1589], w[330], w[906]);

    // AND 1473 1189 -> 1590
    mulmod(w[1590], w[1473], w[1189]);

    // AND 585 744 -> 1591
    mulmod(w[1591], w[585], w[744]);

    // AND 1414 425 -> 1592
    mulmod(w[1592], w[1414], w[425]);

    // AND 111 1396 -> 1593
    mulmod(w[1593], w[111], w[1396]);

    // XOR 861 173 -> 1594
    {
        bn254fr_class t1, t2;
        addmod(t1, w[861], w[173]);
        mulmod(t2, w[861], w[173]);
        mulmod_constant(t2, t2, two);
        submod(w[1594], t1, t2);
    }

    // XOR 3 1085 -> 1595
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3], w[1085]);
        mulmod(t2, w[3], w[1085]);
        mulmod_constant(t2, t2, two);
        submod(w[1595], t1, t2);
    }

    // XOR 1485 866 -> 1596
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1485], w[866]);
        mulmod(t2, w[1485], w[866]);
        mulmod_constant(t2, t2, two);
        submod(w[1596], t1, t2);
    }

    // XOR 808 827 -> 1597
    {
        bn254fr_class t1, t2;
        addmod(t1, w[808], w[827]);
        mulmod(t2, w[808], w[827]);
        mulmod_constant(t2, t2, two);
        submod(w[1597], t1, t2);
    }

    // XOR 1175 1477 -> 1598
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1175], w[1477]);
        mulmod(t2, w[1175], w[1477]);
        mulmod_constant(t2, t2, two);
        submod(w[1598], t1, t2);
    }

    // XOR 1222 745 -> 1599
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1222], w[745]);
        mulmod(t2, w[1222], w[745]);
        mulmod_constant(t2, t2, two);
        submod(w[1599], t1, t2);
    }

    // XOR 193 1235 -> 1600
    {
        bn254fr_class t1, t2;
        addmod(t1, w[193], w[1235]);
        mulmod(t2, w[193], w[1235]);
        mulmod_constant(t2, t2, two);
        submod(w[1600], t1, t2);
    }

    // XOR 414 1421 -> 1601
    {
        bn254fr_class t1, t2;
        addmod(t1, w[414], w[1421]);
        mulmod(t2, w[414], w[1421]);
        mulmod_constant(t2, t2, two);
        submod(w[1601], t1, t2);
    }

    // XOR 951 1248 -> 1602
    {
        bn254fr_class t1, t2;
        addmod(t1, w[951], w[1248]);
        mulmod(t2, w[951], w[1248]);
        mulmod_constant(t2, t2, two);
        submod(w[1602], t1, t2);
    }

    // AND 1274 30 -> 1603
    mulmod(w[1603], w[1274], w[30]);

    // AND 551 953 -> 1604
    mulmod(w[1604], w[551], w[953]);

    // XOR 579 1110 -> 1605
    {
        bn254fr_class t1, t2;
        addmod(t1, w[579], w[1110]);
        mulmod(t2, w[579], w[1110]);
        mulmod_constant(t2, t2, two);
        submod(w[1605], t1, t2);
    }

    // INV 370 -> 1606
    submod(w[1606], one, w[370]);

    // AND 642 610 -> 1607
    mulmod(w[1607], w[642], w[610]);

    // AND 1198 401 -> 1608
    mulmod(w[1608], w[1198], w[401]);

    // INV 232 -> 1609
    submod(w[1609], one, w[232]);

    // XOR 1480 933 -> 1610
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1480], w[933]);
        mulmod(t2, w[1480], w[933]);
        mulmod_constant(t2, t2, two);
        submod(w[1610], t1, t2);
    }

    // AND 120 352 -> 1611
    mulmod(w[1611], w[120], w[352]);

    // AND 824 268 -> 1612
    mulmod(w[1612], w[824], w[268]);

    // XOR 406 1114 -> 1613
    {
        bn254fr_class t1, t2;
        addmod(t1, w[406], w[1114]);
        mulmod(t2, w[406], w[1114]);
        mulmod_constant(t2, t2, two);
        submod(w[1613], t1, t2);
    }

    // AND 1227 1017 -> 1614
    mulmod(w[1614], w[1227], w[1017]);

    // XOR 301 892 -> 1615
    {
        bn254fr_class t1, t2;
        addmod(t1, w[301], w[892]);
        mulmod(t2, w[301], w[892]);
        mulmod_constant(t2, t2, two);
        submod(w[1615], t1, t2);
    }

    // XOR 68 482 -> 1616
    {
        bn254fr_class t1, t2;
        addmod(t1, w[68], w[482]);
        mulmod(t2, w[68], w[482]);
        mulmod_constant(t2, t2, two);
        submod(w[1616], t1, t2);
    }

    // XOR 159 216 -> 1617
    {
        bn254fr_class t1, t2;
        addmod(t1, w[159], w[216]);
        mulmod(t2, w[159], w[216]);
        mulmod_constant(t2, t2, two);
        submod(w[1617], t1, t2);
    }

    // XOR 125 343 -> 1618
    {
        bn254fr_class t1, t2;
        addmod(t1, w[125], w[343]);
        mulmod(t2, w[125], w[343]);
        mulmod_constant(t2, t2, two);
        submod(w[1618], t1, t2);
    }

    // XOR 1442 311 -> 1619
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1442], w[311]);
        mulmod(t2, w[1442], w[311]);
        mulmod_constant(t2, t2, two);
        submod(w[1619], t1, t2);
    }

    // XOR 9 1055 -> 1620
    {
        bn254fr_class t1, t2;
        addmod(t1, w[9], w[1055]);
        mulmod(t2, w[9], w[1055]);
        mulmod_constant(t2, t2, two);
        submod(w[1620], t1, t2);
    }

    // XOR 1312 421 -> 1621
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1312], w[421]);
        mulmod(t2, w[1312], w[421]);
        mulmod_constant(t2, t2, two);
        submod(w[1621], t1, t2);
    }

    // XOR 1006 790 -> 1622
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1006], w[790]);
        mulmod(t2, w[1006], w[790]);
        mulmod_constant(t2, t2, two);
        submod(w[1622], t1, t2);
    }

    // AND 806 1166 -> 1623
    mulmod(w[1623], w[806], w[1166]);

    // AND 306 1589 -> 1624
    mulmod(w[1624], w[306], w[1589]);

    // XOR 1270 561 -> 1625
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1270], w[561]);
        mulmod(t2, w[1270], w[561]);
        mulmod_constant(t2, t2, two);
        submod(w[1625], t1, t2);
    }

    // AND 555 1437 -> 1626
    mulmod(w[1626], w[555], w[1437]);

    // XOR 995 1299 -> 1627
    {
        bn254fr_class t1, t2;
        addmod(t1, w[995], w[1299]);
        mulmod(t2, w[995], w[1299]);
        mulmod_constant(t2, t2, two);
        submod(w[1627], t1, t2);
    }

    // AND 859 1372 -> 1628
    mulmod(w[1628], w[859], w[1372]);

    // XOR 1077 48 -> 1629
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1077], w[48]);
        mulmod(t2, w[1077], w[48]);
        mulmod_constant(t2, t2, two);
        submod(w[1629], t1, t2);
    }

    // AND 268 377 -> 1630
    mulmod(w[1630], w[268], w[377]);

    // AND 359 473 -> 1631
    mulmod(w[1631], w[359], w[473]);

    // XOR 1578 1493 -> 1632
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1578], w[1493]);
        mulmod(t2, w[1578], w[1493]);
        mulmod_constant(t2, t2, two);
        submod(w[1632], t1, t2);
    }

    // XOR 1546 165 -> 1633
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1546], w[165]);
        mulmod(t2, w[1546], w[165]);
        mulmod_constant(t2, t2, two);
        submod(w[1633], t1, t2);
    }

    // XOR 468 869 -> 1634
    {
        bn254fr_class t1, t2;
        addmod(t1, w[468], w[869]);
        mulmod(t2, w[468], w[869]);
        mulmod_constant(t2, t2, two);
        submod(w[1634], t1, t2);
    }

    // AND 247 1333 -> 1635
    mulmod(w[1635], w[247], w[1333]);

    // AND 57 1512 -> 1636
    mulmod(w[1636], w[57], w[1512]);

    // XOR 229 75 -> 1637
    {
        bn254fr_class t1, t2;
        addmod(t1, w[229], w[75]);
        mulmod(t2, w[229], w[75]);
        mulmod_constant(t2, t2, two);
        submod(w[1637], t1, t2);
    }

    // XOR 162 184 -> 1638
    {
        bn254fr_class t1, t2;
        addmod(t1, w[162], w[184]);
        mulmod(t2, w[162], w[184]);
        mulmod_constant(t2, t2, two);
        submod(w[1638], t1, t2);
    }

    // AND 296 16 -> 1639
    mulmod(w[1639], w[296], w[16]);

    // AND 745 1539 -> 1640
    mulmod(w[1640], w[745], w[1539]);

    // AND 320 844 -> 1641
    mulmod(w[1641], w[320], w[844]);

    // XOR 474 318 -> 1642
    {
        bn254fr_class t1, t2;
        addmod(t1, w[474], w[318]);
        mulmod(t2, w[474], w[318]);
        mulmod_constant(t2, t2, two);
        submod(w[1642], t1, t2);
    }

    // AND 152 64 -> 1643
    mulmod(w[1643], w[152], w[64]);

    // INV 715 -> 1644
    submod(w[1644], one, w[715]);

    // AND 882 1068 -> 1645
    mulmod(w[1645], w[882], w[1068]);

    // AND 348 980 -> 1646
    mulmod(w[1646], w[348], w[980]);

    // XOR 1081 605 -> 1647
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1081], w[605]);
        mulmod(t2, w[1081], w[605]);
        mulmod_constant(t2, t2, two);
        submod(w[1647], t1, t2);
    }

    // XOR 1400 1326 -> 1648
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1400], w[1326]);
        mulmod(t2, w[1400], w[1326]);
        mulmod_constant(t2, t2, two);
        submod(w[1648], t1, t2);
    }

    // XOR 979 588 -> 1649
    {
        bn254fr_class t1, t2;
        addmod(t1, w[979], w[588]);
        mulmod(t2, w[979], w[588]);
        mulmod_constant(t2, t2, two);
        submod(w[1649], t1, t2);
    }

    // XOR 877 976 -> 1650
    {
        bn254fr_class t1, t2;
        addmod(t1, w[877], w[976]);
        mulmod(t2, w[877], w[976]);
        mulmod_constant(t2, t2, two);
        submod(w[1650], t1, t2);
    }

    // XOR 596 1245 -> 1651
    {
        bn254fr_class t1, t2;
        addmod(t1, w[596], w[1245]);
        mulmod(t2, w[596], w[1245]);
        mulmod_constant(t2, t2, two);
        submod(w[1651], t1, t2);
    }

    // XOR 1562 832 -> 1652
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1562], w[832]);
        mulmod(t2, w[1562], w[832]);
        mulmod_constant(t2, t2, two);
        submod(w[1652], t1, t2);
    }

    // AND 93 726 -> 1653
    mulmod(w[1653], w[93], w[726]);

    // INV 989 -> 1654
    submod(w[1654], one, w[989]);

    // XOR 501 553 -> 1655
    {
        bn254fr_class t1, t2;
        addmod(t1, w[501], w[553]);
        mulmod(t2, w[501], w[553]);
        mulmod_constant(t2, t2, two);
        submod(w[1655], t1, t2);
    }

    // XOR 1067 1068 -> 1656
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1067], w[1068]);
        mulmod(t2, w[1067], w[1068]);
        mulmod_constant(t2, t2, two);
        submod(w[1656], t1, t2);
    }

    // INV 1427 -> 1657
    submod(w[1657], one, w[1427]);

    // AND 632 60 -> 1658
    mulmod(w[1658], w[632], w[60]);

    // XOR 140 141 -> 1659
    {
        bn254fr_class t1, t2;
        addmod(t1, w[140], w[141]);
        mulmod(t2, w[140], w[141]);
        mulmod_constant(t2, t2, two);
        submod(w[1659], t1, t2);
    }

    // XOR 1320 255 -> 1660
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1320], w[255]);
        mulmod(t2, w[1320], w[255]);
        mulmod_constant(t2, t2, two);
        submod(w[1660], t1, t2);
    }

    // XOR 564 525 -> 1661
    {
        bn254fr_class t1, t2;
        addmod(t1, w[564], w[525]);
        mulmod(t2, w[564], w[525]);
        mulmod_constant(t2, t2, two);
        submod(w[1661], t1, t2);
    }

    // AND 777 1071 -> 1662
    mulmod(w[1662], w[777], w[1071]);

    // AND 590 29 -> 1663
    mulmod(w[1663], w[590], w[29]);

    // AND 280 1334 -> 1664
    mulmod(w[1664], w[280], w[1334]);

    // XOR 1341 372 -> 1665
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1341], w[372]);
        mulmod(t2, w[1341], w[372]);
        mulmod_constant(t2, t2, two);
        submod(w[1665], t1, t2);
    }

    // AND 83 69 -> 1666
    mulmod(w[1666], w[83], w[69]);

    // AND 903 468 -> 1667
    mulmod(w[1667], w[903], w[468]);

    // XOR 835 721 -> 1668
    {
        bn254fr_class t1, t2;
        addmod(t1, w[835], w[721]);
        mulmod(t2, w[835], w[721]);
        mulmod_constant(t2, t2, two);
        submod(w[1668], t1, t2);
    }

    // XOR 1267 752 -> 1669
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1267], w[752]);
        mulmod(t2, w[1267], w[752]);
        mulmod_constant(t2, t2, two);
        submod(w[1669], t1, t2);
    }

    // XOR 744 764 -> 1670
    {
        bn254fr_class t1, t2;
        addmod(t1, w[744], w[764]);
        mulmod(t2, w[744], w[764]);
        mulmod_constant(t2, t2, two);
        submod(w[1670], t1, t2);
    }

    // XOR 968 490 -> 1671
    {
        bn254fr_class t1, t2;
        addmod(t1, w[968], w[490]);
        mulmod(t2, w[968], w[490]);
        mulmod_constant(t2, t2, two);
        submod(w[1671], t1, t2);
    }

    // XOR 979 1420 -> 1672
    {
        bn254fr_class t1, t2;
        addmod(t1, w[979], w[1420]);
        mulmod(t2, w[979], w[1420]);
        mulmod_constant(t2, t2, two);
        submod(w[1672], t1, t2);
    }

    // XOR 162 1101 -> 1673
    {
        bn254fr_class t1, t2;
        addmod(t1, w[162], w[1101]);
        mulmod(t2, w[162], w[1101]);
        mulmod_constant(t2, t2, two);
        submod(w[1673], t1, t2);
    }

    // XOR 403 82 -> 1674
    {
        bn254fr_class t1, t2;
        addmod(t1, w[403], w[82]);
        mulmod(t2, w[403], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[1674], t1, t2);
    }

    // AND 1008 290 -> 1675
    mulmod(w[1675], w[1008], w[290]);

    // XOR 1565 85 -> 1676
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1565], w[85]);
        mulmod(t2, w[1565], w[85]);
        mulmod_constant(t2, t2, two);
        submod(w[1676], t1, t2);
    }

    // XOR 1434 567 -> 1677
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1434], w[567]);
        mulmod(t2, w[1434], w[567]);
        mulmod_constant(t2, t2, two);
        submod(w[1677], t1, t2);
    }

    // XOR 1072 1561 -> 1678
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1072], w[1561]);
        mulmod(t2, w[1072], w[1561]);
        mulmod_constant(t2, t2, two);
        submod(w[1678], t1, t2);
    }

    // AND 451 1206 -> 1679
    mulmod(w[1679], w[451], w[1206]);

    // AND 113 1382 -> 1680
    mulmod(w[1680], w[113], w[1382]);

    // XOR 997 539 -> 1681
    {
        bn254fr_class t1, t2;
        addmod(t1, w[997], w[539]);
        mulmod(t2, w[997], w[539]);
        mulmod_constant(t2, t2, two);
        submod(w[1681], t1, t2);
    }

    // XOR 364 571 -> 1682
    {
        bn254fr_class t1, t2;
        addmod(t1, w[364], w[571]);
        mulmod(t2, w[364], w[571]);
        mulmod_constant(t2, t2, two);
        submod(w[1682], t1, t2);
    }

    // AND 122 403 -> 1683
    mulmod(w[1683], w[122], w[403]);

    // XOR 60 1063 -> 1684
    {
        bn254fr_class t1, t2;
        addmod(t1, w[60], w[1063]);
        mulmod(t2, w[60], w[1063]);
        mulmod_constant(t2, t2, two);
        submod(w[1684], t1, t2);
    }

    // AND 1581 831 -> 1685
    mulmod(w[1685], w[1581], w[831]);

    // AND 440 1612 -> 1686
    mulmod(w[1686], w[440], w[1612]);

    // AND 1563 333 -> 1687
    mulmod(w[1687], w[1563], w[333]);

    // XOR 574 596 -> 1688
    {
        bn254fr_class t1, t2;
        addmod(t1, w[574], w[596]);
        mulmod(t2, w[574], w[596]);
        mulmod_constant(t2, t2, two);
        submod(w[1688], t1, t2);
    }

    // XOR 449 1406 -> 1689
    {
        bn254fr_class t1, t2;
        addmod(t1, w[449], w[1406]);
        mulmod(t2, w[449], w[1406]);
        mulmod_constant(t2, t2, two);
        submod(w[1689], t1, t2);
    }

    // XOR 458 466 -> 1690
    {
        bn254fr_class t1, t2;
        addmod(t1, w[458], w[466]);
        mulmod(t2, w[458], w[466]);
        mulmod_constant(t2, t2, two);
        submod(w[1690], t1, t2);
    }

    // INV 649 -> 1691
    submod(w[1691], one, w[649]);

    // XOR 1436 1420 -> 1692
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1436], w[1420]);
        mulmod(t2, w[1436], w[1420]);
        mulmod_constant(t2, t2, two);
        submod(w[1692], t1, t2);
    }

    // XOR 941 879 -> 1693
    {
        bn254fr_class t1, t2;
        addmod(t1, w[941], w[879]);
        mulmod(t2, w[941], w[879]);
        mulmod_constant(t2, t2, two);
        submod(w[1693], t1, t2);
    }

    // INV 992 -> 1694
    submod(w[1694], one, w[992]);

    // AND 827 874 -> 1695
    mulmod(w[1695], w[827], w[874]);

    // XOR 732 525 -> 1696
    {
        bn254fr_class t1, t2;
        addmod(t1, w[732], w[525]);
        mulmod(t2, w[732], w[525]);
        mulmod_constant(t2, t2, two);
        submod(w[1696], t1, t2);
    }

    // AND 425 230 -> 1697
    mulmod(w[1697], w[425], w[230]);

    // XOR 1497 560 -> 1698
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1497], w[560]);
        mulmod(t2, w[1497], w[560]);
        mulmod_constant(t2, t2, two);
        submod(w[1698], t1, t2);
    }

    // XOR 778 456 -> 1699
    {
        bn254fr_class t1, t2;
        addmod(t1, w[778], w[456]);
        mulmod(t2, w[778], w[456]);
        mulmod_constant(t2, t2, two);
        submod(w[1699], t1, t2);
    }

    // AND 1561 480 -> 1700
    mulmod(w[1700], w[1561], w[480]);

    // AND 7 1108 -> 1701
    mulmod(w[1701], w[7], w[1108]);

    // AND 779 1550 -> 1702
    mulmod(w[1702], w[779], w[1550]);

    // AND 1109 1321 -> 1703
    mulmod(w[1703], w[1109], w[1321]);

    // XOR 1278 730 -> 1704
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1278], w[730]);
        mulmod(t2, w[1278], w[730]);
        mulmod_constant(t2, t2, two);
        submod(w[1704], t1, t2);
    }

    // XOR 346 211 -> 1705
    {
        bn254fr_class t1, t2;
        addmod(t1, w[346], w[211]);
        mulmod(t2, w[346], w[211]);
        mulmod_constant(t2, t2, two);
        submod(w[1705], t1, t2);
    }

    // XOR 1573 968 -> 1706
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1573], w[968]);
        mulmod(t2, w[1573], w[968]);
        mulmod_constant(t2, t2, two);
        submod(w[1706], t1, t2);
    }

    // XOR 997 284 -> 1707
    {
        bn254fr_class t1, t2;
        addmod(t1, w[997], w[284]);
        mulmod(t2, w[997], w[284]);
        mulmod_constant(t2, t2, two);
        submod(w[1707], t1, t2);
    }

    // AND 414 244 -> 1708
    mulmod(w[1708], w[414], w[244]);

    // AND 382 118 -> 1709
    mulmod(w[1709], w[382], w[118]);

    // AND 554 1203 -> 1710
    mulmod(w[1710], w[554], w[1203]);

    // AND 1190 1545 -> 1711
    mulmod(w[1711], w[1190], w[1545]);

    // AND 1323 278 -> 1712
    mulmod(w[1712], w[1323], w[278]);

    // XOR 470 1337 -> 1713
    {
        bn254fr_class t1, t2;
        addmod(t1, w[470], w[1337]);
        mulmod(t2, w[470], w[1337]);
        mulmod_constant(t2, t2, two);
        submod(w[1713], t1, t2);
    }

    // XOR 250 1405 -> 1714
    {
        bn254fr_class t1, t2;
        addmod(t1, w[250], w[1405]);
        mulmod(t2, w[250], w[1405]);
        mulmod_constant(t2, t2, two);
        submod(w[1714], t1, t2);
    }

    // AND 203 1060 -> 1715
    mulmod(w[1715], w[203], w[1060]);

    // AND 127 1136 -> 1716
    mulmod(w[1716], w[127], w[1136]);

    // AND 1212 1457 -> 1717
    mulmod(w[1717], w[1212], w[1457]);

    // AND 965 748 -> 1718
    mulmod(w[1718], w[965], w[748]);

    // AND 760 1572 -> 1719
    mulmod(w[1719], w[760], w[1572]);

    // AND 225 1226 -> 1720
    mulmod(w[1720], w[225], w[1226]);

    // XOR 1154 982 -> 1721
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1154], w[982]);
        mulmod(t2, w[1154], w[982]);
        mulmod_constant(t2, t2, two);
        submod(w[1721], t1, t2);
    }

    // XOR 730 1135 -> 1722
    {
        bn254fr_class t1, t2;
        addmod(t1, w[730], w[1135]);
        mulmod(t2, w[730], w[1135]);
        mulmod_constant(t2, t2, two);
        submod(w[1722], t1, t2);
    }

    // INV 1087 -> 1723
    submod(w[1723], one, w[1087]);

    // XOR 374 1072 -> 1724
    {
        bn254fr_class t1, t2;
        addmod(t1, w[374], w[1072]);
        mulmod(t2, w[374], w[1072]);
        mulmod_constant(t2, t2, two);
        submod(w[1724], t1, t2);
    }

    // XOR 27 666 -> 1725
    {
        bn254fr_class t1, t2;
        addmod(t1, w[27], w[666]);
        mulmod(t2, w[27], w[666]);
        mulmod_constant(t2, t2, two);
        submod(w[1725], t1, t2);
    }

    // INV 862 -> 1726
    submod(w[1726], one, w[862]);

    // XOR 763 343 -> 1727
    {
        bn254fr_class t1, t2;
        addmod(t1, w[763], w[343]);
        mulmod(t2, w[763], w[343]);
        mulmod_constant(t2, t2, two);
        submod(w[1727], t1, t2);
    }

    // XOR 610 232 -> 1728
    {
        bn254fr_class t1, t2;
        addmod(t1, w[610], w[232]);
        mulmod(t2, w[610], w[232]);
        mulmod_constant(t2, t2, two);
        submod(w[1728], t1, t2);
    }

    // XOR 842 1185 -> 1729
    {
        bn254fr_class t1, t2;
        addmod(t1, w[842], w[1185]);
        mulmod(t2, w[842], w[1185]);
        mulmod_constant(t2, t2, two);
        submod(w[1729], t1, t2);
    }

    // XOR 371 900 -> 1730
    {
        bn254fr_class t1, t2;
        addmod(t1, w[371], w[900]);
        mulmod(t2, w[371], w[900]);
        mulmod_constant(t2, t2, two);
        submod(w[1730], t1, t2);
    }

    // XOR 754 1399 -> 1731
    {
        bn254fr_class t1, t2;
        addmod(t1, w[754], w[1399]);
        mulmod(t2, w[754], w[1399]);
        mulmod_constant(t2, t2, two);
        submod(w[1731], t1, t2);
    }

    // XOR 918 1042 -> 1732
    {
        bn254fr_class t1, t2;
        addmod(t1, w[918], w[1042]);
        mulmod(t2, w[918], w[1042]);
        mulmod_constant(t2, t2, two);
        submod(w[1732], t1, t2);
    }

    // AND 1368 262 -> 1733
    mulmod(w[1733], w[1368], w[262]);

    // AND 546 49 -> 1734
    mulmod(w[1734], w[546], w[49]);

    // XOR 707 952 -> 1735
    {
        bn254fr_class t1, t2;
        addmod(t1, w[707], w[952]);
        mulmod(t2, w[707], w[952]);
        mulmod_constant(t2, t2, two);
        submod(w[1735], t1, t2);
    }

    // XOR 224 114 -> 1736
    {
        bn254fr_class t1, t2;
        addmod(t1, w[224], w[114]);
        mulmod(t2, w[224], w[114]);
        mulmod_constant(t2, t2, two);
        submod(w[1736], t1, t2);
    }

    // AND 622 1362 -> 1737
    mulmod(w[1737], w[622], w[1362]);

    // AND 707 1426 -> 1738
    mulmod(w[1738], w[707], w[1426]);

    // AND 293 850 -> 1739
    mulmod(w[1739], w[293], w[850]);

    // XOR 1177 44 -> 1740
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1177], w[44]);
        mulmod(t2, w[1177], w[44]);
        mulmod_constant(t2, t2, two);
        submod(w[1740], t1, t2);
    }

    // AND 534 567 -> 1741
    mulmod(w[1741], w[534], w[567]);

    // XOR 162 1624 -> 1742
    {
        bn254fr_class t1, t2;
        addmod(t1, w[162], w[1624]);
        mulmod(t2, w[162], w[1624]);
        mulmod_constant(t2, t2, two);
        submod(w[1742], t1, t2);
    }

    // AND 975 534 -> 1743
    mulmod(w[1743], w[975], w[534]);

    // XOR 1454 150 -> 1744
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1454], w[150]);
        mulmod(t2, w[1454], w[150]);
        mulmod_constant(t2, t2, two);
        submod(w[1744], t1, t2);
    }

    // XOR 638 1171 -> 1745
    {
        bn254fr_class t1, t2;
        addmod(t1, w[638], w[1171]);
        mulmod(t2, w[638], w[1171]);
        mulmod_constant(t2, t2, two);
        submod(w[1745], t1, t2);
    }

    // XOR 137 435 -> 1746
    {
        bn254fr_class t1, t2;
        addmod(t1, w[137], w[435]);
        mulmod(t2, w[137], w[435]);
        mulmod_constant(t2, t2, two);
        submod(w[1746], t1, t2);
    }

    // XOR 733 650 -> 1747
    {
        bn254fr_class t1, t2;
        addmod(t1, w[733], w[650]);
        mulmod(t2, w[733], w[650]);
        mulmod_constant(t2, t2, two);
        submod(w[1747], t1, t2);
    }

    // AND 439 1268 -> 1748
    mulmod(w[1748], w[439], w[1268]);

    // XOR 611 1664 -> 1749
    {
        bn254fr_class t1, t2;
        addmod(t1, w[611], w[1664]);
        mulmod(t2, w[611], w[1664]);
        mulmod_constant(t2, t2, two);
        submod(w[1749], t1, t2);
    }

    // AND 387 1145 -> 1750
    mulmod(w[1750], w[387], w[1145]);

    // XOR 1110 1011 -> 1751
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1110], w[1011]);
        mulmod(t2, w[1110], w[1011]);
        mulmod_constant(t2, t2, two);
        submod(w[1751], t1, t2);
    }

    // AND 1447 987 -> 1752
    mulmod(w[1752], w[1447], w[987]);

    // AND 1051 1245 -> 1753
    mulmod(w[1753], w[1051], w[1245]);

    // AND 533 350 -> 1754
    mulmod(w[1754], w[533], w[350]);

    // AND 47 157 -> 1755
    mulmod(w[1755], w[47], w[157]);

    // AND 464 1075 -> 1756
    mulmod(w[1756], w[464], w[1075]);

    // INV 795 -> 1757
    submod(w[1757], one, w[795]);

    // AND 554 1457 -> 1758
    mulmod(w[1758], w[554], w[1457]);

    // AND 412 1206 -> 1759
    mulmod(w[1759], w[412], w[1206]);

    // AND 108 804 -> 1760
    mulmod(w[1760], w[108], w[804]);

    // INV 1724 -> 1761
    submod(w[1761], one, w[1724]);

    // XOR 1581 1068 -> 1762
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1581], w[1068]);
        mulmod(t2, w[1581], w[1068]);
        mulmod_constant(t2, t2, two);
        submod(w[1762], t1, t2);
    }

    // XOR 262 1439 -> 1763
    {
        bn254fr_class t1, t2;
        addmod(t1, w[262], w[1439]);
        mulmod(t2, w[262], w[1439]);
        mulmod_constant(t2, t2, two);
        submod(w[1763], t1, t2);
    }

    // INV 1048 -> 1764
    submod(w[1764], one, w[1048]);

    // XOR 1081 456 -> 1765
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1081], w[456]);
        mulmod(t2, w[1081], w[456]);
        mulmod_constant(t2, t2, two);
        submod(w[1765], t1, t2);
    }

    // AND 595 665 -> 1766
    mulmod(w[1766], w[595], w[665]);

    // INV 1508 -> 1767
    submod(w[1767], one, w[1508]);

    // INV 497 -> 1768
    submod(w[1768], one, w[497]);

    // XOR 1551 663 -> 1769
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1551], w[663]);
        mulmod(t2, w[1551], w[663]);
        mulmod_constant(t2, t2, two);
        submod(w[1769], t1, t2);
    }

    // XOR 517 1611 -> 1770
    {
        bn254fr_class t1, t2;
        addmod(t1, w[517], w[1611]);
        mulmod(t2, w[517], w[1611]);
        mulmod_constant(t2, t2, two);
        submod(w[1770], t1, t2);
    }

    // XOR 144 746 -> 1771
    {
        bn254fr_class t1, t2;
        addmod(t1, w[144], w[746]);
        mulmod(t2, w[144], w[746]);
        mulmod_constant(t2, t2, two);
        submod(w[1771], t1, t2);
    }

    // INV 878 -> 1772
    submod(w[1772], one, w[878]);

    // XOR 1031 565 -> 1773
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1031], w[565]);
        mulmod(t2, w[1031], w[565]);
        mulmod_constant(t2, t2, two);
        submod(w[1773], t1, t2);
    }

    // AND 1473 1444 -> 1774
    mulmod(w[1774], w[1473], w[1444]);

    // AND 189 1143 -> 1775
    mulmod(w[1775], w[189], w[1143]);

    // XOR 1229 1343 -> 1776
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1229], w[1343]);
        mulmod(t2, w[1229], w[1343]);
        mulmod_constant(t2, t2, two);
        submod(w[1776], t1, t2);
    }

    // INV 996 -> 1777
    submod(w[1777], one, w[996]);

    // AND 751 436 -> 1778
    mulmod(w[1778], w[751], w[436]);

    // XOR 1563 845 -> 1779
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1563], w[845]);
        mulmod(t2, w[1563], w[845]);
        mulmod_constant(t2, t2, two);
        submod(w[1779], t1, t2);
    }

    // XOR 730 112 -> 1780
    {
        bn254fr_class t1, t2;
        addmod(t1, w[730], w[112]);
        mulmod(t2, w[730], w[112]);
        mulmod_constant(t2, t2, two);
        submod(w[1780], t1, t2);
    }

    // XOR 467 295 -> 1781
    {
        bn254fr_class t1, t2;
        addmod(t1, w[467], w[295]);
        mulmod(t2, w[467], w[295]);
        mulmod_constant(t2, t2, two);
        submod(w[1781], t1, t2);
    }

    // XOR 950 779 -> 1782
    {
        bn254fr_class t1, t2;
        addmod(t1, w[950], w[779]);
        mulmod(t2, w[950], w[779]);
        mulmod_constant(t2, t2, two);
        submod(w[1782], t1, t2);
    }

    // XOR 1579 619 -> 1783
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1579], w[619]);
        mulmod(t2, w[1579], w[619]);
        mulmod_constant(t2, t2, two);
        submod(w[1783], t1, t2);
    }

    // INV 1259 -> 1784
    submod(w[1784], one, w[1259]);

    // XOR 407 1197 -> 1785
    {
        bn254fr_class t1, t2;
        addmod(t1, w[407], w[1197]);
        mulmod(t2, w[407], w[1197]);
        mulmod_constant(t2, t2, two);
        submod(w[1785], t1, t2);
    }

    // XOR 827 786 -> 1786
    {
        bn254fr_class t1, t2;
        addmod(t1, w[827], w[786]);
        mulmod(t2, w[827], w[786]);
        mulmod_constant(t2, t2, two);
        submod(w[1786], t1, t2);
    }

    // XOR 1377 1519 -> 1787
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1377], w[1519]);
        mulmod(t2, w[1377], w[1519]);
        mulmod_constant(t2, t2, two);
        submod(w[1787], t1, t2);
    }

    // AND 419 483 -> 1788
    mulmod(w[1788], w[419], w[483]);

    // AND 280 1459 -> 1789
    mulmod(w[1789], w[280], w[1459]);

    // XOR 468 1424 -> 1790
    {
        bn254fr_class t1, t2;
        addmod(t1, w[468], w[1424]);
        mulmod(t2, w[468], w[1424]);
        mulmod_constant(t2, t2, two);
        submod(w[1790], t1, t2);
    }

    // INV 1110 -> 1791
    submod(w[1791], one, w[1110]);

    // XOR 345 1399 -> 1792
    {
        bn254fr_class t1, t2;
        addmod(t1, w[345], w[1399]);
        mulmod(t2, w[345], w[1399]);
        mulmod_constant(t2, t2, two);
        submod(w[1792], t1, t2);
    }

    // AND 96 1402 -> 1793
    mulmod(w[1793], w[96], w[1402]);

    // XOR 418 1439 -> 1794
    {
        bn254fr_class t1, t2;
        addmod(t1, w[418], w[1439]);
        mulmod(t2, w[418], w[1439]);
        mulmod_constant(t2, t2, two);
        submod(w[1794], t1, t2);
    }

    // AND 550 140 -> 1795
    mulmod(w[1795], w[550], w[140]);

    // XOR 88 711 -> 1796
    {
        bn254fr_class t1, t2;
        addmod(t1, w[88], w[711]);
        mulmod(t2, w[88], w[711]);
        mulmod_constant(t2, t2, two);
        submod(w[1796], t1, t2);
    }

    // XOR 1147 517 -> 1797
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1147], w[517]);
        mulmod(t2, w[1147], w[517]);
        mulmod_constant(t2, t2, two);
        submod(w[1797], t1, t2);
    }

    // AND 450 1071 -> 1798
    mulmod(w[1798], w[450], w[1071]);

    // AND 431 529 -> 1799
    mulmod(w[1799], w[431], w[529]);

    // XOR 971 1433 -> 1800
    {
        bn254fr_class t1, t2;
        addmod(t1, w[971], w[1433]);
        mulmod(t2, w[971], w[1433]);
        mulmod_constant(t2, t2, two);
        submod(w[1800], t1, t2);
    }

    // XOR 1269 1241 -> 1801
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1269], w[1241]);
        mulmod(t2, w[1269], w[1241]);
        mulmod_constant(t2, t2, two);
        submod(w[1801], t1, t2);
    }

    // XOR 1021 211 -> 1802
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1021], w[211]);
        mulmod(t2, w[1021], w[211]);
        mulmod_constant(t2, t2, two);
        submod(w[1802], t1, t2);
    }

    // AND 773 1442 -> 1803
    mulmod(w[1803], w[773], w[1442]);

    // XOR 737 467 -> 1804
    {
        bn254fr_class t1, t2;
        addmod(t1, w[737], w[467]);
        mulmod(t2, w[737], w[467]);
        mulmod_constant(t2, t2, two);
        submod(w[1804], t1, t2);
    }

    // XOR 152 1416 -> 1805
    {
        bn254fr_class t1, t2;
        addmod(t1, w[152], w[1416]);
        mulmod(t2, w[152], w[1416]);
        mulmod_constant(t2, t2, two);
        submod(w[1805], t1, t2);
    }

    // AND 465 1165 -> 1806
    mulmod(w[1806], w[465], w[1165]);

    // XOR 1712 1066 -> 1807
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1712], w[1066]);
        mulmod(t2, w[1712], w[1066]);
        mulmod_constant(t2, t2, two);
        submod(w[1807], t1, t2);
    }

    // AND 1543 1176 -> 1808
    mulmod(w[1808], w[1543], w[1176]);

    // XOR 124 76 -> 1809
    {
        bn254fr_class t1, t2;
        addmod(t1, w[124], w[76]);
        mulmod(t2, w[124], w[76]);
        mulmod_constant(t2, t2, two);
        submod(w[1809], t1, t2);
    }

    // XOR 1644 1319 -> 1810
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1644], w[1319]);
        mulmod(t2, w[1644], w[1319]);
        mulmod_constant(t2, t2, two);
        submod(w[1810], t1, t2);
    }

    // XOR 1366 1522 -> 1811
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1366], w[1522]);
        mulmod(t2, w[1366], w[1522]);
        mulmod_constant(t2, t2, two);
        submod(w[1811], t1, t2);
    }

    // AND 1092 768 -> 1812
    mulmod(w[1812], w[1092], w[768]);

    // AND 1521 462 -> 1813
    mulmod(w[1813], w[1521], w[462]);

    // AND 505 852 -> 1814
    mulmod(w[1814], w[505], w[852]);

    // AND 1092 1181 -> 1815
    mulmod(w[1815], w[1092], w[1181]);

    // XOR 1622 1702 -> 1816
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1622], w[1702]);
        mulmod(t2, w[1622], w[1702]);
        mulmod_constant(t2, t2, two);
        submod(w[1816], t1, t2);
    }

    // XOR 1632 49 -> 1817
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1632], w[49]);
        mulmod(t2, w[1632], w[49]);
        mulmod_constant(t2, t2, two);
        submod(w[1817], t1, t2);
    }

    // XOR 556 1522 -> 1818
    {
        bn254fr_class t1, t2;
        addmod(t1, w[556], w[1522]);
        mulmod(t2, w[556], w[1522]);
        mulmod_constant(t2, t2, two);
        submod(w[1818], t1, t2);
    }

    // XOR 22 124 -> 1819
    {
        bn254fr_class t1, t2;
        addmod(t1, w[22], w[124]);
        mulmod(t2, w[22], w[124]);
        mulmod_constant(t2, t2, two);
        submod(w[1819], t1, t2);
    }

    // AND 218 800 -> 1820
    mulmod(w[1820], w[218], w[800]);

    // INV 1685 -> 1821
    submod(w[1821], one, w[1685]);

    // XOR 336 1193 -> 1822
    {
        bn254fr_class t1, t2;
        addmod(t1, w[336], w[1193]);
        mulmod(t2, w[336], w[1193]);
        mulmod_constant(t2, t2, two);
        submod(w[1822], t1, t2);
    }

    // AND 1684 1006 -> 1823
    mulmod(w[1823], w[1684], w[1006]);

    // AND 171 601 -> 1824
    mulmod(w[1824], w[171], w[601]);

    // AND 778 38 -> 1825
    mulmod(w[1825], w[778], w[38]);

    // XOR 1015 217 -> 1826
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1015], w[217]);
        mulmod(t2, w[1015], w[217]);
        mulmod_constant(t2, t2, two);
        submod(w[1826], t1, t2);
    }

    // AND 833 1012 -> 1827
    mulmod(w[1827], w[833], w[1012]);

    // INV 1141 -> 1828
    submod(w[1828], one, w[1141]);

    // XOR 692 1081 -> 1829
    {
        bn254fr_class t1, t2;
        addmod(t1, w[692], w[1081]);
        mulmod(t2, w[692], w[1081]);
        mulmod_constant(t2, t2, two);
        submod(w[1829], t1, t2);
    }

    // XOR 126 187 -> 1830
    {
        bn254fr_class t1, t2;
        addmod(t1, w[126], w[187]);
        mulmod(t2, w[126], w[187]);
        mulmod_constant(t2, t2, two);
        submod(w[1830], t1, t2);
    }

    // INV 569 -> 1831
    submod(w[1831], one, w[569]);

    // XOR 108 353 -> 1832
    {
        bn254fr_class t1, t2;
        addmod(t1, w[108], w[353]);
        mulmod(t2, w[108], w[353]);
        mulmod_constant(t2, t2, two);
        submod(w[1832], t1, t2);
    }

    // XOR 634 1404 -> 1833
    {
        bn254fr_class t1, t2;
        addmod(t1, w[634], w[1404]);
        mulmod(t2, w[634], w[1404]);
        mulmod_constant(t2, t2, two);
        submod(w[1833], t1, t2);
    }

    // XOR 1378 1452 -> 1834
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1378], w[1452]);
        mulmod(t2, w[1378], w[1452]);
        mulmod_constant(t2, t2, two);
        submod(w[1834], t1, t2);
    }

    // XOR 730 1441 -> 1835
    {
        bn254fr_class t1, t2;
        addmod(t1, w[730], w[1441]);
        mulmod(t2, w[730], w[1441]);
        mulmod_constant(t2, t2, two);
        submod(w[1835], t1, t2);
    }

    // INV 1764 -> 1836
    submod(w[1836], one, w[1764]);

    // AND 296 468 -> 1837
    mulmod(w[1837], w[296], w[468]);

    // XOR 1133 1515 -> 1838
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1133], w[1515]);
        mulmod(t2, w[1133], w[1515]);
        mulmod_constant(t2, t2, two);
        submod(w[1838], t1, t2);
    }

    // AND 1430 709 -> 1839
    mulmod(w[1839], w[1430], w[709]);

    // AND 350 1364 -> 1840
    mulmod(w[1840], w[350], w[1364]);

    // XOR 1056 1620 -> 1841
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1056], w[1620]);
        mulmod(t2, w[1056], w[1620]);
        mulmod_constant(t2, t2, two);
        submod(w[1841], t1, t2);
    }

    // XOR 1812 1033 -> 1842
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1812], w[1033]);
        mulmod(t2, w[1812], w[1033]);
        mulmod_constant(t2, t2, two);
        submod(w[1842], t1, t2);
    }

    // AND 710 1060 -> 1843
    mulmod(w[1843], w[710], w[1060]);

    // AND 1364 705 -> 1844
    mulmod(w[1844], w[1364], w[705]);

    // XOR 1417 568 -> 1845
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1417], w[568]);
        mulmod(t2, w[1417], w[568]);
        mulmod_constant(t2, t2, two);
        submod(w[1845], t1, t2);
    }

    // AND 1541 881 -> 1846
    mulmod(w[1846], w[1541], w[881]);

    // XOR 726 513 -> 1847
    {
        bn254fr_class t1, t2;
        addmod(t1, w[726], w[513]);
        mulmod(t2, w[726], w[513]);
        mulmod_constant(t2, t2, two);
        submod(w[1847], t1, t2);
    }

    // XOR 1557 228 -> 1848
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1557], w[228]);
        mulmod(t2, w[1557], w[228]);
        mulmod_constant(t2, t2, two);
        submod(w[1848], t1, t2);
    }

    // XOR 781 901 -> 1849
    {
        bn254fr_class t1, t2;
        addmod(t1, w[781], w[901]);
        mulmod(t2, w[781], w[901]);
        mulmod_constant(t2, t2, two);
        submod(w[1849], t1, t2);
    }

    // AND 1151 1145 -> 1850
    mulmod(w[1850], w[1151], w[1145]);

    // AND 25 427 -> 1851
    mulmod(w[1851], w[25], w[427]);

    // XOR 41 298 -> 1852
    {
        bn254fr_class t1, t2;
        addmod(t1, w[41], w[298]);
        mulmod(t2, w[41], w[298]);
        mulmod_constant(t2, t2, two);
        submod(w[1852], t1, t2);
    }

    // XOR 1182 609 -> 1853
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1182], w[609]);
        mulmod(t2, w[1182], w[609]);
        mulmod_constant(t2, t2, two);
        submod(w[1853], t1, t2);
    }

    // XOR 1211 573 -> 1854
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1211], w[573]);
        mulmod(t2, w[1211], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[1854], t1, t2);
    }

    // XOR 776 770 -> 1855
    {
        bn254fr_class t1, t2;
        addmod(t1, w[776], w[770]);
        mulmod(t2, w[776], w[770]);
        mulmod_constant(t2, t2, two);
        submod(w[1855], t1, t2);
    }

    // AND 1100 995 -> 1856
    mulmod(w[1856], w[1100], w[995]);

    // XOR 230 686 -> 1857
    {
        bn254fr_class t1, t2;
        addmod(t1, w[230], w[686]);
        mulmod(t2, w[230], w[686]);
        mulmod_constant(t2, t2, two);
        submod(w[1857], t1, t2);
    }

    // XOR 426 638 -> 1858
    {
        bn254fr_class t1, t2;
        addmod(t1, w[426], w[638]);
        mulmod(t2, w[426], w[638]);
        mulmod_constant(t2, t2, two);
        submod(w[1858], t1, t2);
    }

    // XOR 1305 340 -> 1859
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1305], w[340]);
        mulmod(t2, w[1305], w[340]);
        mulmod_constant(t2, t2, two);
        submod(w[1859], t1, t2);
    }

    // AND 718 252 -> 1860
    mulmod(w[1860], w[718], w[252]);

    // XOR 1229 1073 -> 1861
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1229], w[1073]);
        mulmod(t2, w[1229], w[1073]);
        mulmod_constant(t2, t2, two);
        submod(w[1861], t1, t2);
    }

    // XOR 1528 760 -> 1862
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1528], w[760]);
        mulmod(t2, w[1528], w[760]);
        mulmod_constant(t2, t2, two);
        submod(w[1862], t1, t2);
    }

    // AND 1578 1365 -> 1863
    mulmod(w[1863], w[1578], w[1365]);

    // AND 1820 190 -> 1864
    mulmod(w[1864], w[1820], w[190]);

    // AND 1645 71 -> 1865
    mulmod(w[1865], w[1645], w[71]);

    // XOR 460 892 -> 1866
    {
        bn254fr_class t1, t2;
        addmod(t1, w[460], w[892]);
        mulmod(t2, w[460], w[892]);
        mulmod_constant(t2, t2, two);
        submod(w[1866], t1, t2);
    }

    // AND 1410 1383 -> 1867
    mulmod(w[1867], w[1410], w[1383]);

    // XOR 1560 509 -> 1868
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1560], w[509]);
        mulmod(t2, w[1560], w[509]);
        mulmod_constant(t2, t2, two);
        submod(w[1868], t1, t2);
    }

    // AND 1587 553 -> 1869
    mulmod(w[1869], w[1587], w[553]);

    // AND 284 1820 -> 1870
    mulmod(w[1870], w[284], w[1820]);

    // XOR 696 613 -> 1871
    {
        bn254fr_class t1, t2;
        addmod(t1, w[696], w[613]);
        mulmod(t2, w[696], w[613]);
        mulmod_constant(t2, t2, two);
        submod(w[1871], t1, t2);
    }

    // AND 1481 917 -> 1872
    mulmod(w[1872], w[1481], w[917]);

    // XOR 1777 1413 -> 1873
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1777], w[1413]);
        mulmod(t2, w[1777], w[1413]);
        mulmod_constant(t2, t2, two);
        submod(w[1873], t1, t2);
    }

    // INV 1166 -> 1874
    submod(w[1874], one, w[1166]);

    // XOR 1566 43 -> 1875
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1566], w[43]);
        mulmod(t2, w[1566], w[43]);
        mulmod_constant(t2, t2, two);
        submod(w[1875], t1, t2);
    }

    // AND 747 1676 -> 1876
    mulmod(w[1876], w[747], w[1676]);

    // AND 725 1732 -> 1877
    mulmod(w[1877], w[725], w[1732]);

    // XOR 9 326 -> 1878
    {
        bn254fr_class t1, t2;
        addmod(t1, w[9], w[326]);
        mulmod(t2, w[9], w[326]);
        mulmod_constant(t2, t2, two);
        submod(w[1878], t1, t2);
    }

    // AND 1524 14 -> 1879
    mulmod(w[1879], w[1524], w[14]);

    // AND 1779 1390 -> 1880
    mulmod(w[1880], w[1779], w[1390]);

    // XOR 539 772 -> 1881
    {
        bn254fr_class t1, t2;
        addmod(t1, w[539], w[772]);
        mulmod(t2, w[539], w[772]);
        mulmod_constant(t2, t2, two);
        submod(w[1881], t1, t2);
    }

    // AND 525 1346 -> 1882
    mulmod(w[1882], w[525], w[1346]);

    // AND 666 939 -> 1883
    mulmod(w[1883], w[666], w[939]);

    // XOR 256 1581 -> 1884
    {
        bn254fr_class t1, t2;
        addmod(t1, w[256], w[1581]);
        mulmod(t2, w[256], w[1581]);
        mulmod_constant(t2, t2, two);
        submod(w[1884], t1, t2);
    }

    // XOR 1328 1369 -> 1885
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1328], w[1369]);
        mulmod(t2, w[1328], w[1369]);
        mulmod_constant(t2, t2, two);
        submod(w[1885], t1, t2);
    }

    // XOR 1803 1622 -> 1886
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1803], w[1622]);
        mulmod(t2, w[1803], w[1622]);
        mulmod_constant(t2, t2, two);
        submod(w[1886], t1, t2);
    }

    // INV 1127 -> 1887
    submod(w[1887], one, w[1127]);

    // XOR 1177 1523 -> 1888
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1177], w[1523]);
        mulmod(t2, w[1177], w[1523]);
        mulmod_constant(t2, t2, two);
        submod(w[1888], t1, t2);
    }

    // XOR 1287 912 -> 1889
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1287], w[912]);
        mulmod(t2, w[1287], w[912]);
        mulmod_constant(t2, t2, two);
        submod(w[1889], t1, t2);
    }

    // XOR 229 1776 -> 1890
    {
        bn254fr_class t1, t2;
        addmod(t1, w[229], w[1776]);
        mulmod(t2, w[229], w[1776]);
        mulmod_constant(t2, t2, two);
        submod(w[1890], t1, t2);
    }

    // AND 849 1492 -> 1891
    mulmod(w[1891], w[849], w[1492]);

    // XOR 1458 1223 -> 1892
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1458], w[1223]);
        mulmod(t2, w[1458], w[1223]);
        mulmod_constant(t2, t2, two);
        submod(w[1892], t1, t2);
    }

    // AND 642 1761 -> 1893
    mulmod(w[1893], w[642], w[1761]);

    // XOR 103 401 -> 1894
    {
        bn254fr_class t1, t2;
        addmod(t1, w[103], w[401]);
        mulmod(t2, w[103], w[401]);
        mulmod_constant(t2, t2, two);
        submod(w[1894], t1, t2);
    }

    // AND 1527 1101 -> 1895
    mulmod(w[1895], w[1527], w[1101]);

    // INV 955 -> 1896
    submod(w[1896], one, w[955]);

    // XOR 1602 599 -> 1897
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1602], w[599]);
        mulmod(t2, w[1602], w[599]);
        mulmod_constant(t2, t2, two);
        submod(w[1897], t1, t2);
    }

    // XOR 698 850 -> 1898
    {
        bn254fr_class t1, t2;
        addmod(t1, w[698], w[850]);
        mulmod(t2, w[698], w[850]);
        mulmod_constant(t2, t2, two);
        submod(w[1898], t1, t2);
    }

    // XOR 454 413 -> 1899
    {
        bn254fr_class t1, t2;
        addmod(t1, w[454], w[413]);
        mulmod(t2, w[454], w[413]);
        mulmod_constant(t2, t2, two);
        submod(w[1899], t1, t2);
    }

    // AND 1500 54 -> 1900
    mulmod(w[1900], w[1500], w[54]);

    // AND 810 410 -> 1901
    mulmod(w[1901], w[810], w[410]);

    // XOR 1443 610 -> 1902
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1443], w[610]);
        mulmod(t2, w[1443], w[610]);
        mulmod_constant(t2, t2, two);
        submod(w[1902], t1, t2);
    }

    // XOR 1016 130 -> 1903
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1016], w[130]);
        mulmod(t2, w[1016], w[130]);
        mulmod_constant(t2, t2, two);
        submod(w[1903], t1, t2);
    }

    // XOR 201 850 -> 1904
    {
        bn254fr_class t1, t2;
        addmod(t1, w[201], w[850]);
        mulmod(t2, w[201], w[850]);
        mulmod_constant(t2, t2, two);
        submod(w[1904], t1, t2);
    }

    // XOR 1082 184 -> 1905
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1082], w[184]);
        mulmod(t2, w[1082], w[184]);
        mulmod_constant(t2, t2, two);
        submod(w[1905], t1, t2);
    }

    // AND 1579 1229 -> 1906
    mulmod(w[1906], w[1579], w[1229]);

    // XOR 459 944 -> 1907
    {
        bn254fr_class t1, t2;
        addmod(t1, w[459], w[944]);
        mulmod(t2, w[459], w[944]);
        mulmod_constant(t2, t2, two);
        submod(w[1907], t1, t2);
    }

    // AND 63 879 -> 1908
    mulmod(w[1908], w[63], w[879]);

    // XOR 304 735 -> 1909
    {
        bn254fr_class t1, t2;
        addmod(t1, w[304], w[735]);
        mulmod(t2, w[304], w[735]);
        mulmod_constant(t2, t2, two);
        submod(w[1909], t1, t2);
    }

    // AND 1356 1197 -> 1910
    mulmod(w[1910], w[1356], w[1197]);

    // XOR 153 859 -> 1911
    {
        bn254fr_class t1, t2;
        addmod(t1, w[153], w[859]);
        mulmod(t2, w[153], w[859]);
        mulmod_constant(t2, t2, two);
        submod(w[1911], t1, t2);
    }

    // AND 922 239 -> 1912
    mulmod(w[1912], w[922], w[239]);

    // XOR 1619 1814 -> 1913
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1619], w[1814]);
        mulmod(t2, w[1619], w[1814]);
        mulmod_constant(t2, t2, two);
        submod(w[1913], t1, t2);
    }

    // AND 175 3 -> 1914
    mulmod(w[1914], w[175], w[3]);

    // AND 1781 144 -> 1915
    mulmod(w[1915], w[1781], w[144]);

    // XOR 1606 663 -> 1916
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1606], w[663]);
        mulmod(t2, w[1606], w[663]);
        mulmod_constant(t2, t2, two);
        submod(w[1916], t1, t2);
    }

    // AND 160 1017 -> 1917
    mulmod(w[1917], w[160], w[1017]);

    // XOR 1479 1560 -> 1918
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1479], w[1560]);
        mulmod(t2, w[1479], w[1560]);
        mulmod_constant(t2, t2, two);
        submod(w[1918], t1, t2);
    }

    // XOR 540 568 -> 1919
    {
        bn254fr_class t1, t2;
        addmod(t1, w[540], w[568]);
        mulmod(t2, w[540], w[568]);
        mulmod_constant(t2, t2, two);
        submod(w[1919], t1, t2);
    }

    // INV 221 -> 1920
    submod(w[1920], one, w[221]);

    // XOR 54 529 -> 1921
    {
        bn254fr_class t1, t2;
        addmod(t1, w[54], w[529]);
        mulmod(t2, w[54], w[529]);
        mulmod_constant(t2, t2, two);
        submod(w[1921], t1, t2);
    }

    // XOR 400 799 -> 1922
    {
        bn254fr_class t1, t2;
        addmod(t1, w[400], w[799]);
        mulmod(t2, w[400], w[799]);
        mulmod_constant(t2, t2, two);
        submod(w[1922], t1, t2);
    }

    // XOR 343 1477 -> 1923
    {
        bn254fr_class t1, t2;
        addmod(t1, w[343], w[1477]);
        mulmod(t2, w[343], w[1477]);
        mulmod_constant(t2, t2, two);
        submod(w[1923], t1, t2);
    }

    // XOR 615 1304 -> 1924
    {
        bn254fr_class t1, t2;
        addmod(t1, w[615], w[1304]);
        mulmod(t2, w[615], w[1304]);
        mulmod_constant(t2, t2, two);
        submod(w[1924], t1, t2);
    }

    // AND 225 838 -> 1925
    mulmod(w[1925], w[225], w[838]);

    // XOR 975 671 -> 1926
    {
        bn254fr_class t1, t2;
        addmod(t1, w[975], w[671]);
        mulmod(t2, w[975], w[671]);
        mulmod_constant(t2, t2, two);
        submod(w[1926], t1, t2);
    }

    // XOR 325 530 -> 1927
    {
        bn254fr_class t1, t2;
        addmod(t1, w[325], w[530]);
        mulmod(t2, w[325], w[530]);
        mulmod_constant(t2, t2, two);
        submod(w[1927], t1, t2);
    }

    // XOR 519 1327 -> 1928
    {
        bn254fr_class t1, t2;
        addmod(t1, w[519], w[1327]);
        mulmod(t2, w[519], w[1327]);
        mulmod_constant(t2, t2, two);
        submod(w[1928], t1, t2);
    }

    // XOR 1406 1314 -> 1929
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1406], w[1314]);
        mulmod(t2, w[1406], w[1314]);
        mulmod_constant(t2, t2, two);
        submod(w[1929], t1, t2);
    }

    // XOR 1347 192 -> 1930
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1347], w[192]);
        mulmod(t2, w[1347], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[1930], t1, t2);
    }

    // AND 605 1442 -> 1931
    mulmod(w[1931], w[605], w[1442]);

    // XOR 1127 438 -> 1932
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1127], w[438]);
        mulmod(t2, w[1127], w[438]);
        mulmod_constant(t2, t2, two);
        submod(w[1932], t1, t2);
    }

    // AND 1113 1442 -> 1933
    mulmod(w[1933], w[1113], w[1442]);

    // AND 492 273 -> 1934
    mulmod(w[1934], w[492], w[273]);

    // AND 307 1158 -> 1935
    mulmod(w[1935], w[307], w[1158]);

    // XOR 1811 434 -> 1936
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1811], w[434]);
        mulmod(t2, w[1811], w[434]);
        mulmod_constant(t2, t2, two);
        submod(w[1936], t1, t2);
    }

    // AND 878 368 -> 1937
    mulmod(w[1937], w[878], w[368]);

    // XOR 1391 211 -> 1938
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1391], w[211]);
        mulmod(t2, w[1391], w[211]);
        mulmod_constant(t2, t2, two);
        submod(w[1938], t1, t2);
    }

    // AND 1326 15 -> 1939
    mulmod(w[1939], w[1326], w[15]);

    // XOR 1729 975 -> 1940
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1729], w[975]);
        mulmod(t2, w[1729], w[975]);
        mulmod_constant(t2, t2, two);
        submod(w[1940], t1, t2);
    }

    // XOR 808 1392 -> 1941
    {
        bn254fr_class t1, t2;
        addmod(t1, w[808], w[1392]);
        mulmod(t2, w[808], w[1392]);
        mulmod_constant(t2, t2, two);
        submod(w[1941], t1, t2);
    }

    // XOR 220 327 -> 1942
    {
        bn254fr_class t1, t2;
        addmod(t1, w[220], w[327]);
        mulmod(t2, w[220], w[327]);
        mulmod_constant(t2, t2, two);
        submod(w[1942], t1, t2);
    }

    // XOR 674 295 -> 1943
    {
        bn254fr_class t1, t2;
        addmod(t1, w[674], w[295]);
        mulmod(t2, w[674], w[295]);
        mulmod_constant(t2, t2, two);
        submod(w[1943], t1, t2);
    }

    // XOR 1197 670 -> 1944
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1197], w[670]);
        mulmod(t2, w[1197], w[670]);
        mulmod_constant(t2, t2, two);
        submod(w[1944], t1, t2);
    }

    // AND 1370 702 -> 1945
    mulmod(w[1945], w[1370], w[702]);

    // AND 214 336 -> 1946
    mulmod(w[1946], w[214], w[336]);

    // AND 463 1370 -> 1947
    mulmod(w[1947], w[463], w[1370]);

    // AND 120 1601 -> 1948
    mulmod(w[1948], w[120], w[1601]);

    // AND 1786 458 -> 1949
    mulmod(w[1949], w[1786], w[458]);

    // AND 178 306 -> 1950
    mulmod(w[1950], w[178], w[306]);

    // XOR 588 498 -> 1951
    {
        bn254fr_class t1, t2;
        addmod(t1, w[588], w[498]);
        mulmod(t2, w[588], w[498]);
        mulmod_constant(t2, t2, two);
        submod(w[1951], t1, t2);
    }

    // AND 1763 1542 -> 1952
    mulmod(w[1952], w[1763], w[1542]);

    // XOR 853 310 -> 1953
    {
        bn254fr_class t1, t2;
        addmod(t1, w[853], w[310]);
        mulmod(t2, w[853], w[310]);
        mulmod_constant(t2, t2, two);
        submod(w[1953], t1, t2);
    }

    // XOR 1022 1039 -> 1954
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1022], w[1039]);
        mulmod(t2, w[1022], w[1039]);
        mulmod_constant(t2, t2, two);
        submod(w[1954], t1, t2);
    }

    // XOR 1068 1414 -> 1955
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1068], w[1414]);
        mulmod(t2, w[1068], w[1414]);
        mulmod_constant(t2, t2, two);
        submod(w[1955], t1, t2);
    }

    // XOR 160 713 -> 1956
    {
        bn254fr_class t1, t2;
        addmod(t1, w[160], w[713]);
        mulmod(t2, w[160], w[713]);
        mulmod_constant(t2, t2, two);
        submod(w[1956], t1, t2);
    }

    // XOR 973 1028 -> 1957
    {
        bn254fr_class t1, t2;
        addmod(t1, w[973], w[1028]);
        mulmod(t2, w[973], w[1028]);
        mulmod_constant(t2, t2, two);
        submod(w[1957], t1, t2);
    }

    // INV 318 -> 1958
    submod(w[1958], one, w[318]);

    // AND 12 88 -> 1959
    mulmod(w[1959], w[12], w[88]);

    // AND 1047 559 -> 1960
    mulmod(w[1960], w[1047], w[559]);

    // XOR 388 1323 -> 1961
    {
        bn254fr_class t1, t2;
        addmod(t1, w[388], w[1323]);
        mulmod(t2, w[388], w[1323]);
        mulmod_constant(t2, t2, two);
        submod(w[1961], t1, t2);
    }

    // XOR 630 567 -> 1962
    {
        bn254fr_class t1, t2;
        addmod(t1, w[630], w[567]);
        mulmod(t2, w[630], w[567]);
        mulmod_constant(t2, t2, two);
        submod(w[1962], t1, t2);
    }

    // XOR 707 1603 -> 1963
    {
        bn254fr_class t1, t2;
        addmod(t1, w[707], w[1603]);
        mulmod(t2, w[707], w[1603]);
        mulmod_constant(t2, t2, two);
        submod(w[1963], t1, t2);
    }

    // AND 27 1070 -> 1964
    mulmod(w[1964], w[27], w[1070]);

    // XOR 269 1520 -> 1965
    {
        bn254fr_class t1, t2;
        addmod(t1, w[269], w[1520]);
        mulmod(t2, w[269], w[1520]);
        mulmod_constant(t2, t2, two);
        submod(w[1965], t1, t2);
    }

    // XOR 1538 862 -> 1966
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1538], w[862]);
        mulmod(t2, w[1538], w[862]);
        mulmod_constant(t2, t2, two);
        submod(w[1966], t1, t2);
    }

    // XOR 1344 1346 -> 1967
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1344], w[1346]);
        mulmod(t2, w[1344], w[1346]);
        mulmod_constant(t2, t2, two);
        submod(w[1967], t1, t2);
    }

    // INV 1754 -> 1968
    submod(w[1968], one, w[1754]);

    // XOR 440 733 -> 1969
    {
        bn254fr_class t1, t2;
        addmod(t1, w[440], w[733]);
        mulmod(t2, w[440], w[733]);
        mulmod_constant(t2, t2, two);
        submod(w[1969], t1, t2);
    }

    // XOR 1559 228 -> 1970
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1559], w[228]);
        mulmod(t2, w[1559], w[228]);
        mulmod_constant(t2, t2, two);
        submod(w[1970], t1, t2);
    }

    // AND 1738 1466 -> 1971
    mulmod(w[1971], w[1738], w[1466]);

    // XOR 1683 238 -> 1972
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1683], w[238]);
        mulmod(t2, w[1683], w[238]);
        mulmod_constant(t2, t2, two);
        submod(w[1972], t1, t2);
    }

    // AND 664 1847 -> 1973
    mulmod(w[1973], w[664], w[1847]);

    // XOR 175 180 -> 1974
    {
        bn254fr_class t1, t2;
        addmod(t1, w[175], w[180]);
        mulmod(t2, w[175], w[180]);
        mulmod_constant(t2, t2, two);
        submod(w[1974], t1, t2);
    }

    // XOR 415 437 -> 1975
    {
        bn254fr_class t1, t2;
        addmod(t1, w[415], w[437]);
        mulmod(t2, w[415], w[437]);
        mulmod_constant(t2, t2, two);
        submod(w[1975], t1, t2);
    }

    // AND 842 1424 -> 1976
    mulmod(w[1976], w[842], w[1424]);

    // AND 1766 1367 -> 1977
    mulmod(w[1977], w[1766], w[1367]);

    // XOR 267 110 -> 1978
    {
        bn254fr_class t1, t2;
        addmod(t1, w[267], w[110]);
        mulmod(t2, w[267], w[110]);
        mulmod_constant(t2, t2, two);
        submod(w[1978], t1, t2);
    }

    // INV 127 -> 1979
    submod(w[1979], one, w[127]);

    // XOR 710 345 -> 1980
    {
        bn254fr_class t1, t2;
        addmod(t1, w[710], w[345]);
        mulmod(t2, w[710], w[345]);
        mulmod_constant(t2, t2, two);
        submod(w[1980], t1, t2);
    }

    // AND 429 783 -> 1981
    mulmod(w[1981], w[429], w[783]);

    // XOR 1756 1280 -> 1982
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1756], w[1280]);
        mulmod(t2, w[1756], w[1280]);
        mulmod_constant(t2, t2, two);
        submod(w[1982], t1, t2);
    }

    // XOR 716 183 -> 1983
    {
        bn254fr_class t1, t2;
        addmod(t1, w[716], w[183]);
        mulmod(t2, w[716], w[183]);
        mulmod_constant(t2, t2, two);
        submod(w[1983], t1, t2);
    }

    // XOR 348 1197 -> 1984
    {
        bn254fr_class t1, t2;
        addmod(t1, w[348], w[1197]);
        mulmod(t2, w[348], w[1197]);
        mulmod_constant(t2, t2, two);
        submod(w[1984], t1, t2);
    }

    // AND 454 673 -> 1985
    mulmod(w[1985], w[454], w[673]);

    // AND 17 83 -> 1986
    mulmod(w[1986], w[17], w[83]);

    // XOR 1079 1280 -> 1987
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1079], w[1280]);
        mulmod(t2, w[1079], w[1280]);
        mulmod_constant(t2, t2, two);
        submod(w[1987], t1, t2);
    }

    // XOR 846 283 -> 1988
    {
        bn254fr_class t1, t2;
        addmod(t1, w[846], w[283]);
        mulmod(t2, w[846], w[283]);
        mulmod_constant(t2, t2, two);
        submod(w[1988], t1, t2);
    }

    // AND 738 445 -> 1989
    mulmod(w[1989], w[738], w[445]);

    // XOR 1751 70 -> 1990
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1751], w[70]);
        mulmod(t2, w[1751], w[70]);
        mulmod_constant(t2, t2, two);
        submod(w[1990], t1, t2);
    }

    // AND 1523 1661 -> 1991
    mulmod(w[1991], w[1523], w[1661]);

    // AND 1697 1471 -> 1992
    mulmod(w[1992], w[1697], w[1471]);

    // XOR 24 1075 -> 1993
    {
        bn254fr_class t1, t2;
        addmod(t1, w[24], w[1075]);
        mulmod(t2, w[24], w[1075]);
        mulmod_constant(t2, t2, two);
        submod(w[1993], t1, t2);
    }

    // XOR 1422 238 -> 1994
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1422], w[238]);
        mulmod(t2, w[1422], w[238]);
        mulmod_constant(t2, t2, two);
        submod(w[1994], t1, t2);
    }

    // XOR 245 574 -> 1995
    {
        bn254fr_class t1, t2;
        addmod(t1, w[245], w[574]);
        mulmod(t2, w[245], w[574]);
        mulmod_constant(t2, t2, two);
        submod(w[1995], t1, t2);
    }

    // AND 1843 147 -> 1996
    mulmod(w[1996], w[1843], w[147]);

    // XOR 1157 1151 -> 1997
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1157], w[1151]);
        mulmod(t2, w[1157], w[1151]);
        mulmod_constant(t2, t2, two);
        submod(w[1997], t1, t2);
    }

    // AND 1318 359 -> 1998
    mulmod(w[1998], w[1318], w[359]);

    // XOR 700 1362 -> 1999
    {
        bn254fr_class t1, t2;
        addmod(t1, w[700], w[1362]);
        mulmod(t2, w[700], w[1362]);
        mulmod_constant(t2, t2, two);
        submod(w[1999], t1, t2);
    }

    // AND 1487 1755 -> 2000
    mulmod(w[2000], w[1487], w[1755]);

    // XOR 649 375 -> 2001
    {
        bn254fr_class t1, t2;
        addmod(t1, w[649], w[375]);
        mulmod(t2, w[649], w[375]);
        mulmod_constant(t2, t2, two);
        submod(w[2001], t1, t2);
    }

    // AND 603 946 -> 2002
    mulmod(w[2002], w[603], w[946]);

    // XOR 981 192 -> 2003
    {
        bn254fr_class t1, t2;
        addmod(t1, w[981], w[192]);
        mulmod(t2, w[981], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[2003], t1, t2);
    }

    // INV 1017 -> 2004
    submod(w[2004], one, w[1017]);

    // XOR 1502 447 -> 2005
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1502], w[447]);
        mulmod(t2, w[1502], w[447]);
        mulmod_constant(t2, t2, two);
        submod(w[2005], t1, t2);
    }

    // AND 1651 1342 -> 2006
    mulmod(w[2006], w[1651], w[1342]);

    // AND 1084 566 -> 2007
    mulmod(w[2007], w[1084], w[566]);

    // XOR 156 1890 -> 2008
    {
        bn254fr_class t1, t2;
        addmod(t1, w[156], w[1890]);
        mulmod(t2, w[156], w[1890]);
        mulmod_constant(t2, t2, two);
        submod(w[2008], t1, t2);
    }

    // AND 1642 669 -> 2009
    mulmod(w[2009], w[1642], w[669]);

    // XOR 940 413 -> 2010
    {
        bn254fr_class t1, t2;
        addmod(t1, w[940], w[413]);
        mulmod(t2, w[940], w[413]);
        mulmod_constant(t2, t2, two);
        submod(w[2010], t1, t2);
    }

    // XOR 1042 344 -> 2011
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1042], w[344]);
        mulmod(t2, w[1042], w[344]);
        mulmod_constant(t2, t2, two);
        submod(w[2011], t1, t2);
    }

    // XOR 1281 215 -> 2012
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1281], w[215]);
        mulmod(t2, w[1281], w[215]);
        mulmod_constant(t2, t2, two);
        submod(w[2012], t1, t2);
    }

    // XOR 543 1066 -> 2013
    {
        bn254fr_class t1, t2;
        addmod(t1, w[543], w[1066]);
        mulmod(t2, w[543], w[1066]);
        mulmod_constant(t2, t2, two);
        submod(w[2013], t1, t2);
    }

    // AND 331 31 -> 2014
    mulmod(w[2014], w[331], w[31]);

    // XOR 409 626 -> 2015
    {
        bn254fr_class t1, t2;
        addmod(t1, w[409], w[626]);
        mulmod(t2, w[409], w[626]);
        mulmod_constant(t2, t2, two);
        submod(w[2015], t1, t2);
    }

    // INV 1751 -> 2016
    submod(w[2016], one, w[1751]);

    // XOR 665 1592 -> 2017
    {
        bn254fr_class t1, t2;
        addmod(t1, w[665], w[1592]);
        mulmod(t2, w[665], w[1592]);
        mulmod_constant(t2, t2, two);
        submod(w[2017], t1, t2);
    }

    // XOR 1686 1391 -> 2018
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1686], w[1391]);
        mulmod(t2, w[1686], w[1391]);
        mulmod_constant(t2, t2, two);
        submod(w[2018], t1, t2);
    }

    // AND 1197 383 -> 2019
    mulmod(w[2019], w[1197], w[383]);

    // AND 1382 1461 -> 2020
    mulmod(w[2020], w[1382], w[1461]);

    // XOR 534 1157 -> 2021
    {
        bn254fr_class t1, t2;
        addmod(t1, w[534], w[1157]);
        mulmod(t2, w[534], w[1157]);
        mulmod_constant(t2, t2, two);
        submod(w[2021], t1, t2);
    }

    // XOR 1823 881 -> 2022
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1823], w[881]);
        mulmod(t2, w[1823], w[881]);
        mulmod_constant(t2, t2, two);
        submod(w[2022], t1, t2);
    }

    // AND 1822 1107 -> 2023
    mulmod(w[2023], w[1822], w[1107]);

    // AND 1779 781 -> 2024
    mulmod(w[2024], w[1779], w[781]);

    // INV 1299 -> 2025
    submod(w[2025], one, w[1299]);

    // XOR 868 294 -> 2026
    {
        bn254fr_class t1, t2;
        addmod(t1, w[868], w[294]);
        mulmod(t2, w[868], w[294]);
        mulmod_constant(t2, t2, two);
        submod(w[2026], t1, t2);
    }

    // XOR 276 856 -> 2027
    {
        bn254fr_class t1, t2;
        addmod(t1, w[276], w[856]);
        mulmod(t2, w[276], w[856]);
        mulmod_constant(t2, t2, two);
        submod(w[2027], t1, t2);
    }

    // AND 944 117 -> 2028
    mulmod(w[2028], w[944], w[117]);

    // AND 1150 326 -> 2029
    mulmod(w[2029], w[1150], w[326]);

    // XOR 880 1526 -> 2030
    {
        bn254fr_class t1, t2;
        addmod(t1, w[880], w[1526]);
        mulmod(t2, w[880], w[1526]);
        mulmod_constant(t2, t2, two);
        submod(w[2030], t1, t2);
    }

    // XOR 1646 1259 -> 2031
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1646], w[1259]);
        mulmod(t2, w[1646], w[1259]);
        mulmod_constant(t2, t2, two);
        submod(w[2031], t1, t2);
    }

    // INV 502 -> 2032
    submod(w[2032], one, w[502]);

    // AND 1049 839 -> 2033
    mulmod(w[2033], w[1049], w[839]);

    // XOR 1533 1902 -> 2034
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1533], w[1902]);
        mulmod(t2, w[1533], w[1902]);
        mulmod_constant(t2, t2, two);
        submod(w[2034], t1, t2);
    }

    // INV 1859 -> 2035
    submod(w[2035], one, w[1859]);

    // XOR 1434 413 -> 2036
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1434], w[413]);
        mulmod(t2, w[1434], w[413]);
        mulmod_constant(t2, t2, two);
        submod(w[2036], t1, t2);
    }

    // AND 731 519 -> 2037
    mulmod(w[2037], w[731], w[519]);

    // AND 629 1867 -> 2038
    mulmod(w[2038], w[629], w[1867]);

    // XOR 37 1658 -> 2039
    {
        bn254fr_class t1, t2;
        addmod(t1, w[37], w[1658]);
        mulmod(t2, w[37], w[1658]);
        mulmod_constant(t2, t2, two);
        submod(w[2039], t1, t2);
    }

    // XOR 131 1690 -> 2040
    {
        bn254fr_class t1, t2;
        addmod(t1, w[131], w[1690]);
        mulmod(t2, w[131], w[1690]);
        mulmod_constant(t2, t2, two);
        submod(w[2040], t1, t2);
    }

    // INV 959 -> 2041
    submod(w[2041], one, w[959]);

    // XOR 775 293 -> 2042
    {
        bn254fr_class t1, t2;
        addmod(t1, w[775], w[293]);
        mulmod(t2, w[775], w[293]);
        mulmod_constant(t2, t2, two);
        submod(w[2042], t1, t2);
    }

    // XOR 1477 117 -> 2043
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1477], w[117]);
        mulmod(t2, w[1477], w[117]);
        mulmod_constant(t2, t2, two);
        submod(w[2043], t1, t2);
    }

    // INV 477 -> 2044
    submod(w[2044], one, w[477]);

    // XOR 274 1319 -> 2045
    {
        bn254fr_class t1, t2;
        addmod(t1, w[274], w[1319]);
        mulmod(t2, w[274], w[1319]);
        mulmod_constant(t2, t2, two);
        submod(w[2045], t1, t2);
    }

    // XOR 1125 718 -> 2046
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1125], w[718]);
        mulmod(t2, w[1125], w[718]);
        mulmod_constant(t2, t2, two);
        submod(w[2046], t1, t2);
    }

    // XOR 1009 573 -> 2047
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1009], w[573]);
        mulmod(t2, w[1009], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[2047], t1, t2);
    }

    // XOR 642 1076 -> 2048
    {
        bn254fr_class t1, t2;
        addmod(t1, w[642], w[1076]);
        mulmod(t2, w[642], w[1076]);
        mulmod_constant(t2, t2, two);
        submod(w[2048], t1, t2);
    }

    // AND 802 1185 -> 2049
    mulmod(w[2049], w[802], w[1185]);

    // XOR 836 135 -> 2050
    {
        bn254fr_class t1, t2;
        addmod(t1, w[836], w[135]);
        mulmod(t2, w[836], w[135]);
        mulmod_constant(t2, t2, two);
        submod(w[2050], t1, t2);
    }

    // AND 769 1805 -> 2051
    mulmod(w[2051], w[769], w[1805]);

    // XOR 840 757 -> 2052
    {
        bn254fr_class t1, t2;
        addmod(t1, w[840], w[757]);
        mulmod(t2, w[840], w[757]);
        mulmod_constant(t2, t2, two);
        submod(w[2052], t1, t2);
    }

    // XOR 142 1187 -> 2053
    {
        bn254fr_class t1, t2;
        addmod(t1, w[142], w[1187]);
        mulmod(t2, w[142], w[1187]);
        mulmod_constant(t2, t2, two);
        submod(w[2053], t1, t2);
    }

    // INV 1863 -> 2054
    submod(w[2054], one, w[1863]);

    // XOR 1118 1136 -> 2055
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1118], w[1136]);
        mulmod(t2, w[1118], w[1136]);
        mulmod_constant(t2, t2, two);
        submod(w[2055], t1, t2);
    }

    // XOR 1196 1419 -> 2056
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1196], w[1419]);
        mulmod(t2, w[1196], w[1419]);
        mulmod_constant(t2, t2, two);
        submod(w[2056], t1, t2);
    }

    // XOR 919 1902 -> 2057
    {
        bn254fr_class t1, t2;
        addmod(t1, w[919], w[1902]);
        mulmod(t2, w[919], w[1902]);
        mulmod_constant(t2, t2, two);
        submod(w[2057], t1, t2);
    }

    // XOR 517 1331 -> 2058
    {
        bn254fr_class t1, t2;
        addmod(t1, w[517], w[1331]);
        mulmod(t2, w[517], w[1331]);
        mulmod_constant(t2, t2, two);
        submod(w[2058], t1, t2);
    }

    // XOR 567 124 -> 2059
    {
        bn254fr_class t1, t2;
        addmod(t1, w[567], w[124]);
        mulmod(t2, w[567], w[124]);
        mulmod_constant(t2, t2, two);
        submod(w[2059], t1, t2);
    }

    // AND 54 1430 -> 2060
    mulmod(w[2060], w[54], w[1430]);

    // XOR 607 1534 -> 2061
    {
        bn254fr_class t1, t2;
        addmod(t1, w[607], w[1534]);
        mulmod(t2, w[607], w[1534]);
        mulmod_constant(t2, t2, two);
        submod(w[2061], t1, t2);
    }

    // XOR 1807 1845 -> 2062
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1807], w[1845]);
        mulmod(t2, w[1807], w[1845]);
        mulmod_constant(t2, t2, two);
        submod(w[2062], t1, t2);
    }

    // AND 581 1430 -> 2063
    mulmod(w[2063], w[581], w[1430]);

    // XOR 1164 1487 -> 2064
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1164], w[1487]);
        mulmod(t2, w[1164], w[1487]);
        mulmod_constant(t2, t2, two);
        submod(w[2064], t1, t2);
    }

    // XOR 1268 2052 -> 2065
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1268], w[2052]);
        mulmod(t2, w[1268], w[2052]);
        mulmod_constant(t2, t2, two);
        submod(w[2065], t1, t2);
    }

    // INV 1484 -> 2066
    submod(w[2066], one, w[1484]);

    // INV 1683 -> 2067
    submod(w[2067], one, w[1683]);

    // XOR 843 992 -> 2068
    {
        bn254fr_class t1, t2;
        addmod(t1, w[843], w[992]);
        mulmod(t2, w[843], w[992]);
        mulmod_constant(t2, t2, two);
        submod(w[2068], t1, t2);
    }

    // XOR 655 1000 -> 2069
    {
        bn254fr_class t1, t2;
        addmod(t1, w[655], w[1000]);
        mulmod(t2, w[655], w[1000]);
        mulmod_constant(t2, t2, two);
        submod(w[2069], t1, t2);
    }

    // XOR 87 199 -> 2070
    {
        bn254fr_class t1, t2;
        addmod(t1, w[87], w[199]);
        mulmod(t2, w[87], w[199]);
        mulmod_constant(t2, t2, two);
        submod(w[2070], t1, t2);
    }

    // XOR 1028 2011 -> 2071
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1028], w[2011]);
        mulmod(t2, w[1028], w[2011]);
        mulmod_constant(t2, t2, two);
        submod(w[2071], t1, t2);
    }

    // AND 708 2021 -> 2072
    mulmod(w[2072], w[708], w[2021]);

    // XOR 52 1776 -> 2073
    {
        bn254fr_class t1, t2;
        addmod(t1, w[52], w[1776]);
        mulmod(t2, w[52], w[1776]);
        mulmod_constant(t2, t2, two);
        submod(w[2073], t1, t2);
    }

    // AND 1023 396 -> 2074
    mulmod(w[2074], w[1023], w[396]);

    // XOR 746 315 -> 2075
    {
        bn254fr_class t1, t2;
        addmod(t1, w[746], w[315]);
        mulmod(t2, w[746], w[315]);
        mulmod_constant(t2, t2, two);
        submod(w[2075], t1, t2);
    }

    // XOR 669 838 -> 2076
    {
        bn254fr_class t1, t2;
        addmod(t1, w[669], w[838]);
        mulmod(t2, w[669], w[838]);
        mulmod_constant(t2, t2, two);
        submod(w[2076], t1, t2);
    }

    // AND 1940 1919 -> 2077
    mulmod(w[2077], w[1940], w[1919]);

    // XOR 1500 400 -> 2078
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1500], w[400]);
        mulmod(t2, w[1500], w[400]);
        mulmod_constant(t2, t2, two);
        submod(w[2078], t1, t2);
    }

    // AND 984 165 -> 2079
    mulmod(w[2079], w[984], w[165]);

    // XOR 813 600 -> 2080
    {
        bn254fr_class t1, t2;
        addmod(t1, w[813], w[600]);
        mulmod(t2, w[813], w[600]);
        mulmod_constant(t2, t2, two);
        submod(w[2080], t1, t2);
    }

    // XOR 451 1096 -> 2081
    {
        bn254fr_class t1, t2;
        addmod(t1, w[451], w[1096]);
        mulmod(t2, w[451], w[1096]);
        mulmod_constant(t2, t2, two);
        submod(w[2081], t1, t2);
    }

    // AND 885 1912 -> 2082
    mulmod(w[2082], w[885], w[1912]);

    // INV 938 -> 2083
    submod(w[2083], one, w[938]);

    // AND 626 1386 -> 2084
    mulmod(w[2084], w[626], w[1386]);

    // AND 196 934 -> 2085
    mulmod(w[2085], w[196], w[934]);

    // XOR 1517 1053 -> 2086
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1517], w[1053]);
        mulmod(t2, w[1517], w[1053]);
        mulmod_constant(t2, t2, two);
        submod(w[2086], t1, t2);
    }

    // XOR 651 875 -> 2087
    {
        bn254fr_class t1, t2;
        addmod(t1, w[651], w[875]);
        mulmod(t2, w[651], w[875]);
        mulmod_constant(t2, t2, two);
        submod(w[2087], t1, t2);
    }

    // INV 1536 -> 2088
    submod(w[2088], one, w[1536]);

    // XOR 1909 460 -> 2089
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1909], w[460]);
        mulmod(t2, w[1909], w[460]);
        mulmod_constant(t2, t2, two);
        submod(w[2089], t1, t2);
    }

    // XOR 211 1570 -> 2090
    {
        bn254fr_class t1, t2;
        addmod(t1, w[211], w[1570]);
        mulmod(t2, w[211], w[1570]);
        mulmod_constant(t2, t2, two);
        submod(w[2090], t1, t2);
    }

    // XOR 1522 418 -> 2091
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1522], w[418]);
        mulmod(t2, w[1522], w[418]);
        mulmod_constant(t2, t2, two);
        submod(w[2091], t1, t2);
    }

    // AND 1733 1636 -> 2092
    mulmod(w[2092], w[1733], w[1636]);

    // INV 17 -> 2093
    submod(w[2093], one, w[17]);

    // AND 587 1216 -> 2094
    mulmod(w[2094], w[587], w[1216]);

    // XOR 336 1786 -> 2095
    {
        bn254fr_class t1, t2;
        addmod(t1, w[336], w[1786]);
        mulmod(t2, w[336], w[1786]);
        mulmod_constant(t2, t2, two);
        submod(w[2095], t1, t2);
    }

    // AND 115 1330 -> 2096
    mulmod(w[2096], w[115], w[1330]);

    // AND 1068 224 -> 2097
    mulmod(w[2097], w[1068], w[224]);

    // XOR 940 2 -> 2098
    {
        bn254fr_class t1, t2;
        addmod(t1, w[940], w[2]);
        mulmod(t2, w[940], w[2]);
        mulmod_constant(t2, t2, two);
        submod(w[2098], t1, t2);
    }

    // XOR 1666 273 -> 2099
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1666], w[273]);
        mulmod(t2, w[1666], w[273]);
        mulmod_constant(t2, t2, two);
        submod(w[2099], t1, t2);
    }

    // AND 817 495 -> 2100
    mulmod(w[2100], w[817], w[495]);

    // AND 1548 1989 -> 2101
    mulmod(w[2101], w[1548], w[1989]);

    // AND 794 1149 -> 2102
    mulmod(w[2102], w[794], w[1149]);

    // INV 1643 -> 2103
    submod(w[2103], one, w[1643]);

    // AND 669 1474 -> 2104
    mulmod(w[2104], w[669], w[1474]);

    // XOR 516 282 -> 2105
    {
        bn254fr_class t1, t2;
        addmod(t1, w[516], w[282]);
        mulmod(t2, w[516], w[282]);
        mulmod_constant(t2, t2, two);
        submod(w[2105], t1, t2);
    }

    // XOR 387 1837 -> 2106
    {
        bn254fr_class t1, t2;
        addmod(t1, w[387], w[1837]);
        mulmod(t2, w[387], w[1837]);
        mulmod_constant(t2, t2, two);
        submod(w[2106], t1, t2);
    }

    // AND 439 776 -> 2107
    mulmod(w[2107], w[439], w[776]);

    // XOR 1278 1965 -> 2108
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1278], w[1965]);
        mulmod(t2, w[1278], w[1965]);
        mulmod_constant(t2, t2, two);
        submod(w[2108], t1, t2);
    }

    // XOR 881 358 -> 2109
    {
        bn254fr_class t1, t2;
        addmod(t1, w[881], w[358]);
        mulmod(t2, w[881], w[358]);
        mulmod_constant(t2, t2, two);
        submod(w[2109], t1, t2);
    }

    // AND 1877 1758 -> 2110
    mulmod(w[2110], w[1877], w[1758]);

    // XOR 494 1558 -> 2111
    {
        bn254fr_class t1, t2;
        addmod(t1, w[494], w[1558]);
        mulmod(t2, w[494], w[1558]);
        mulmod_constant(t2, t2, two);
        submod(w[2111], t1, t2);
    }

    // INV 32 -> 2112
    submod(w[2112], one, w[32]);

    // XOR 2028 75 -> 2113
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2028], w[75]);
        mulmod(t2, w[2028], w[75]);
        mulmod_constant(t2, t2, two);
        submod(w[2113], t1, t2);
    }

    // AND 54 1201 -> 2114
    mulmod(w[2114], w[54], w[1201]);

    // XOR 304 1455 -> 2115
    {
        bn254fr_class t1, t2;
        addmod(t1, w[304], w[1455]);
        mulmod(t2, w[304], w[1455]);
        mulmod_constant(t2, t2, two);
        submod(w[2115], t1, t2);
    }

    // AND 908 473 -> 2116
    mulmod(w[2116], w[908], w[473]);

    // XOR 211 1927 -> 2117
    {
        bn254fr_class t1, t2;
        addmod(t1, w[211], w[1927]);
        mulmod(t2, w[211], w[1927]);
        mulmod_constant(t2, t2, two);
        submod(w[2117], t1, t2);
    }

    // XOR 1664 1803 -> 2118
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1664], w[1803]);
        mulmod(t2, w[1664], w[1803]);
        mulmod_constant(t2, t2, two);
        submod(w[2118], t1, t2);
    }

    // XOR 1168 1676 -> 2119
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1168], w[1676]);
        mulmod(t2, w[1168], w[1676]);
        mulmod_constant(t2, t2, two);
        submod(w[2119], t1, t2);
    }

    // AND 1561 543 -> 2120
    mulmod(w[2120], w[1561], w[543]);

    // XOR 734 1191 -> 2121
    {
        bn254fr_class t1, t2;
        addmod(t1, w[734], w[1191]);
        mulmod(t2, w[734], w[1191]);
        mulmod_constant(t2, t2, two);
        submod(w[2121], t1, t2);
    }

    // AND 1645 1557 -> 2122
    mulmod(w[2122], w[1645], w[1557]);

    // XOR 1042 775 -> 2123
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1042], w[775]);
        mulmod(t2, w[1042], w[775]);
        mulmod_constant(t2, t2, two);
        submod(w[2123], t1, t2);
    }

    // AND 703 1716 -> 2124
    mulmod(w[2124], w[703], w[1716]);

    // AND 658 872 -> 2125
    mulmod(w[2125], w[658], w[872]);

    // XOR 500 1537 -> 2126
    {
        bn254fr_class t1, t2;
        addmod(t1, w[500], w[1537]);
        mulmod(t2, w[500], w[1537]);
        mulmod_constant(t2, t2, two);
        submod(w[2126], t1, t2);
    }

    // AND 218 781 -> 2127
    mulmod(w[2127], w[218], w[781]);

    // XOR 1547 734 -> 2128
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1547], w[734]);
        mulmod(t2, w[1547], w[734]);
        mulmod_constant(t2, t2, two);
        submod(w[2128], t1, t2);
    }

    // XOR 494 1422 -> 2129
    {
        bn254fr_class t1, t2;
        addmod(t1, w[494], w[1422]);
        mulmod(t2, w[494], w[1422]);
        mulmod_constant(t2, t2, two);
        submod(w[2129], t1, t2);
    }

    // AND 1879 1344 -> 2130
    mulmod(w[2130], w[1879], w[1344]);

    // XOR 1157 878 -> 2131
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1157], w[878]);
        mulmod(t2, w[1157], w[878]);
        mulmod_constant(t2, t2, two);
        submod(w[2131], t1, t2);
    }

    // XOR 1733 1293 -> 2132
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1733], w[1293]);
        mulmod(t2, w[1733], w[1293]);
        mulmod_constant(t2, t2, two);
        submod(w[2132], t1, t2);
    }

    // XOR 570 443 -> 2133
    {
        bn254fr_class t1, t2;
        addmod(t1, w[570], w[443]);
        mulmod(t2, w[570], w[443]);
        mulmod_constant(t2, t2, two);
        submod(w[2133], t1, t2);
    }

    // XOR 276 588 -> 2134
    {
        bn254fr_class t1, t2;
        addmod(t1, w[276], w[588]);
        mulmod(t2, w[276], w[588]);
        mulmod_constant(t2, t2, two);
        submod(w[2134], t1, t2);
    }

    // AND 1675 1065 -> 2135
    mulmod(w[2135], w[1675], w[1065]);

    // XOR 1513 119 -> 2136
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1513], w[119]);
        mulmod(t2, w[1513], w[119]);
        mulmod_constant(t2, t2, two);
        submod(w[2136], t1, t2);
    }

    // XOR 1369 927 -> 2137
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1369], w[927]);
        mulmod(t2, w[1369], w[927]);
        mulmod_constant(t2, t2, two);
        submod(w[2137], t1, t2);
    }

    // INV 1295 -> 2138
    submod(w[2138], one, w[1295]);

    // XOR 667 62 -> 2139
    {
        bn254fr_class t1, t2;
        addmod(t1, w[667], w[62]);
        mulmod(t2, w[667], w[62]);
        mulmod_constant(t2, t2, two);
        submod(w[2139], t1, t2);
    }

    // AND 973 178 -> 2140
    mulmod(w[2140], w[973], w[178]);

    // AND 1304 723 -> 2141
    mulmod(w[2141], w[1304], w[723]);

    // XOR 1478 353 -> 2142
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1478], w[353]);
        mulmod(t2, w[1478], w[353]);
        mulmod_constant(t2, t2, two);
        submod(w[2142], t1, t2);
    }

    // XOR 1154 1779 -> 2143
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1154], w[1779]);
        mulmod(t2, w[1154], w[1779]);
        mulmod_constant(t2, t2, two);
        submod(w[2143], t1, t2);
    }

    // XOR 1403 1507 -> 2144
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1403], w[1507]);
        mulmod(t2, w[1403], w[1507]);
        mulmod_constant(t2, t2, two);
        submod(w[2144], t1, t2);
    }

    // XOR 1923 1802 -> 2145
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1923], w[1802]);
        mulmod(t2, w[1923], w[1802]);
        mulmod_constant(t2, t2, two);
        submod(w[2145], t1, t2);
    }

    // INV 880 -> 2146
    submod(w[2146], one, w[880]);

    // AND 821 1353 -> 2147
    mulmod(w[2147], w[821], w[1353]);

    // AND 1956 1471 -> 2148
    mulmod(w[2148], w[1956], w[1471]);

    // AND 1906 959 -> 2149
    mulmod(w[2149], w[1906], w[959]);

    // AND 1952 666 -> 2150
    mulmod(w[2150], w[1952], w[666]);

    // INV 1673 -> 2151
    submod(w[2151], one, w[1673]);

    // AND 977 1908 -> 2152
    mulmod(w[2152], w[977], w[1908]);

    // XOR 1475 29 -> 2153
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1475], w[29]);
        mulmod(t2, w[1475], w[29]);
        mulmod_constant(t2, t2, two);
        submod(w[2153], t1, t2);
    }

    // AND 1634 976 -> 2154
    mulmod(w[2154], w[1634], w[976]);

    // XOR 2019 1553 -> 2155
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2019], w[1553]);
        mulmod(t2, w[2019], w[1553]);
        mulmod_constant(t2, t2, two);
        submod(w[2155], t1, t2);
    }

    // AND 1067 912 -> 2156
    mulmod(w[2156], w[1067], w[912]);

    // XOR 1903 1817 -> 2157
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1903], w[1817]);
        mulmod(t2, w[1903], w[1817]);
        mulmod_constant(t2, t2, two);
        submod(w[2157], t1, t2);
    }

    // AND 1967 576 -> 2158
    mulmod(w[2158], w[1967], w[576]);

    // INV 668 -> 2159
    submod(w[2159], one, w[668]);

    // AND 752 421 -> 2160
    mulmod(w[2160], w[752], w[421]);

    // XOR 701 821 -> 2161
    {
        bn254fr_class t1, t2;
        addmod(t1, w[701], w[821]);
        mulmod(t2, w[701], w[821]);
        mulmod_constant(t2, t2, two);
        submod(w[2161], t1, t2);
    }

    // XOR 995 704 -> 2162
    {
        bn254fr_class t1, t2;
        addmod(t1, w[995], w[704]);
        mulmod(t2, w[995], w[704]);
        mulmod_constant(t2, t2, two);
        submod(w[2162], t1, t2);
    }

    // AND 209 1408 -> 2163
    mulmod(w[2163], w[209], w[1408]);

    // XOR 1902 734 -> 2164
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1902], w[734]);
        mulmod(t2, w[1902], w[734]);
        mulmod_constant(t2, t2, two);
        submod(w[2164], t1, t2);
    }

    // XOR 511 140 -> 2165
    {
        bn254fr_class t1, t2;
        addmod(t1, w[511], w[140]);
        mulmod(t2, w[511], w[140]);
        mulmod_constant(t2, t2, two);
        submod(w[2165], t1, t2);
    }

    // AND 1133 1773 -> 2166
    mulmod(w[2166], w[1133], w[1773]);

    // XOR 1300 1429 -> 2167
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1300], w[1429]);
        mulmod(t2, w[1300], w[1429]);
        mulmod_constant(t2, t2, two);
        submod(w[2167], t1, t2);
    }

    // XOR 1442 1234 -> 2168
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1442], w[1234]);
        mulmod(t2, w[1442], w[1234]);
        mulmod_constant(t2, t2, two);
        submod(w[2168], t1, t2);
    }

    // INV 911 -> 2169
    submod(w[2169], one, w[911]);

    // XOR 1275 967 -> 2170
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1275], w[967]);
        mulmod(t2, w[1275], w[967]);
        mulmod_constant(t2, t2, two);
        submod(w[2170], t1, t2);
    }

    // INV 113 -> 2171
    submod(w[2171], one, w[113]);

    // AND 396 1057 -> 2172
    mulmod(w[2172], w[396], w[1057]);

    // XOR 319 403 -> 2173
    {
        bn254fr_class t1, t2;
        addmod(t1, w[319], w[403]);
        mulmod(t2, w[319], w[403]);
        mulmod_constant(t2, t2, two);
        submod(w[2173], t1, t2);
    }

    // AND 209 1991 -> 2174
    mulmod(w[2174], w[209], w[1991]);

    // XOR 1566 1569 -> 2175
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1566], w[1569]);
        mulmod(t2, w[1566], w[1569]);
        mulmod_constant(t2, t2, two);
        submod(w[2175], t1, t2);
    }

    // AND 197 187 -> 2176
    mulmod(w[2176], w[197], w[187]);

    // AND 1181 120 -> 2177
    mulmod(w[2177], w[1181], w[120]);

    // XOR 128 1906 -> 2178
    {
        bn254fr_class t1, t2;
        addmod(t1, w[128], w[1906]);
        mulmod(t2, w[128], w[1906]);
        mulmod_constant(t2, t2, two);
        submod(w[2178], t1, t2);
    }

    // AND 936 1613 -> 2179
    mulmod(w[2179], w[936], w[1613]);

    // XOR 2046 325 -> 2180
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2046], w[325]);
        mulmod(t2, w[2046], w[325]);
        mulmod_constant(t2, t2, two);
        submod(w[2180], t1, t2);
    }

    // XOR 1783 1031 -> 2181
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1783], w[1031]);
        mulmod(t2, w[1783], w[1031]);
        mulmod_constant(t2, t2, two);
        submod(w[2181], t1, t2);
    }

    // XOR 1777 340 -> 2182
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1777], w[340]);
        mulmod(t2, w[1777], w[340]);
        mulmod_constant(t2, t2, two);
        submod(w[2182], t1, t2);
    }

    // AND 1882 1855 -> 2183
    mulmod(w[2183], w[1882], w[1855]);

    // XOR 641 1917 -> 2184
    {
        bn254fr_class t1, t2;
        addmod(t1, w[641], w[1917]);
        mulmod(t2, w[641], w[1917]);
        mulmod_constant(t2, t2, two);
        submod(w[2184], t1, t2);
    }

    // XOR 20 385 -> 2185
    {
        bn254fr_class t1, t2;
        addmod(t1, w[20], w[385]);
        mulmod(t2, w[20], w[385]);
        mulmod_constant(t2, t2, two);
        submod(w[2185], t1, t2);
    }

    // XOR 1805 212 -> 2186
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1805], w[212]);
        mulmod(t2, w[1805], w[212]);
        mulmod_constant(t2, t2, two);
        submod(w[2186], t1, t2);
    }

    // XOR 1436 614 -> 2187
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1436], w[614]);
        mulmod(t2, w[1436], w[614]);
        mulmod_constant(t2, t2, two);
        submod(w[2187], t1, t2);
    }

    // AND 912 1884 -> 2188
    mulmod(w[2188], w[912], w[1884]);

    // XOR 1716 1267 -> 2189
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1716], w[1267]);
        mulmod(t2, w[1716], w[1267]);
        mulmod_constant(t2, t2, two);
        submod(w[2189], t1, t2);
    }

    // AND 1535 880 -> 2190
    mulmod(w[2190], w[1535], w[880]);

    // AND 131 423 -> 2191
    mulmod(w[2191], w[131], w[423]);

    // AND 1476 1025 -> 2192
    mulmod(w[2192], w[1476], w[1025]);

    // AND 1981 1646 -> 2193
    mulmod(w[2193], w[1981], w[1646]);

    // XOR 946 1327 -> 2194
    {
        bn254fr_class t1, t2;
        addmod(t1, w[946], w[1327]);
        mulmod(t2, w[946], w[1327]);
        mulmod_constant(t2, t2, two);
        submod(w[2194], t1, t2);
    }

    // AND 263 975 -> 2195
    mulmod(w[2195], w[263], w[975]);

    // AND 1052 1711 -> 2196
    mulmod(w[2196], w[1052], w[1711]);

    // XOR 1547 1517 -> 2197
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1547], w[1517]);
        mulmod(t2, w[1547], w[1517]);
        mulmod_constant(t2, t2, two);
        submod(w[2197], t1, t2);
    }

    // INV 2154 -> 2198
    submod(w[2198], one, w[2154]);

    // AND 119 1345 -> 2199
    mulmod(w[2199], w[119], w[1345]);

    // XOR 888 1000 -> 2200
    {
        bn254fr_class t1, t2;
        addmod(t1, w[888], w[1000]);
        mulmod(t2, w[888], w[1000]);
        mulmod_constant(t2, t2, two);
        submod(w[2200], t1, t2);
    }

    // XOR 1995 524 -> 2201
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1995], w[524]);
        mulmod(t2, w[1995], w[524]);
        mulmod_constant(t2, t2, two);
        submod(w[2201], t1, t2);
    }

    // XOR 1854 217 -> 2202
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1854], w[217]);
        mulmod(t2, w[1854], w[217]);
        mulmod_constant(t2, t2, two);
        submod(w[2202], t1, t2);
    }

    // INV 1196 -> 2203
    submod(w[2203], one, w[1196]);

    // XOR 753 838 -> 2204
    {
        bn254fr_class t1, t2;
        addmod(t1, w[753], w[838]);
        mulmod(t2, w[753], w[838]);
        mulmod_constant(t2, t2, two);
        submod(w[2204], t1, t2);
    }

    // XOR 1473 571 -> 2205
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1473], w[571]);
        mulmod(t2, w[1473], w[571]);
        mulmod_constant(t2, t2, two);
        submod(w[2205], t1, t2);
    }

    // XOR 1078 1929 -> 2206
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1078], w[1929]);
        mulmod(t2, w[1078], w[1929]);
        mulmod_constant(t2, t2, two);
        submod(w[2206], t1, t2);
    }

    // XOR 159 2000 -> 2207
    {
        bn254fr_class t1, t2;
        addmod(t1, w[159], w[2000]);
        mulmod(t2, w[159], w[2000]);
        mulmod_constant(t2, t2, two);
        submod(w[2207], t1, t2);
    }

    // AND 1311 1793 -> 2208
    mulmod(w[2208], w[1311], w[1793]);

    // XOR 1533 266 -> 2209
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1533], w[266]);
        mulmod(t2, w[1533], w[266]);
        mulmod_constant(t2, t2, two);
        submod(w[2209], t1, t2);
    }

    // XOR 1734 1834 -> 2210
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1734], w[1834]);
        mulmod(t2, w[1734], w[1834]);
        mulmod_constant(t2, t2, two);
        submod(w[2210], t1, t2);
    }

    // AND 1618 787 -> 2211
    mulmod(w[2211], w[1618], w[787]);

    // AND 546 999 -> 2212
    mulmod(w[2212], w[546], w[999]);

    // XOR 1366 1478 -> 2213
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1366], w[1478]);
        mulmod(t2, w[1366], w[1478]);
        mulmod_constant(t2, t2, two);
        submod(w[2213], t1, t2);
    }

    // XOR 847 1318 -> 2214
    {
        bn254fr_class t1, t2;
        addmod(t1, w[847], w[1318]);
        mulmod(t2, w[847], w[1318]);
        mulmod_constant(t2, t2, two);
        submod(w[2214], t1, t2);
    }

    // XOR 1271 36 -> 2215
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1271], w[36]);
        mulmod(t2, w[1271], w[36]);
        mulmod_constant(t2, t2, two);
        submod(w[2215], t1, t2);
    }

    // INV 1326 -> 2216
    submod(w[2216], one, w[1326]);

    // AND 1496 217 -> 2217
    mulmod(w[2217], w[1496], w[217]);

    // XOR 785 279 -> 2218
    {
        bn254fr_class t1, t2;
        addmod(t1, w[785], w[279]);
        mulmod(t2, w[785], w[279]);
        mulmod_constant(t2, t2, two);
        submod(w[2218], t1, t2);
    }

    // AND 224 1685 -> 2219
    mulmod(w[2219], w[224], w[1685]);

    // INV 1448 -> 2220
    submod(w[2220], one, w[1448]);

    // XOR 1164 1877 -> 2221
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1164], w[1877]);
        mulmod(t2, w[1164], w[1877]);
        mulmod_constant(t2, t2, two);
        submod(w[2221], t1, t2);
    }

    // XOR 1184 1498 -> 2222
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1184], w[1498]);
        mulmod(t2, w[1184], w[1498]);
        mulmod_constant(t2, t2, two);
        submod(w[2222], t1, t2);
    }

    // INV 380 -> 2223
    submod(w[2223], one, w[380]);

    // XOR 1447 1382 -> 2224
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1447], w[1382]);
        mulmod(t2, w[1447], w[1382]);
        mulmod_constant(t2, t2, two);
        submod(w[2224], t1, t2);
    }

    // AND 1501 1165 -> 2225
    mulmod(w[2225], w[1501], w[1165]);

    // XOR 1293 1722 -> 2226
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1293], w[1722]);
        mulmod(t2, w[1293], w[1722]);
        mulmod_constant(t2, t2, two);
        submod(w[2226], t1, t2);
    }

    // XOR 1623 1516 -> 2227
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1623], w[1516]);
        mulmod(t2, w[1623], w[1516]);
        mulmod_constant(t2, t2, two);
        submod(w[2227], t1, t2);
    }

    // INV 1699 -> 2228
    submod(w[2228], one, w[1699]);

    // AND 103 1075 -> 2229
    mulmod(w[2229], w[103], w[1075]);

    // XOR 695 806 -> 2230
    {
        bn254fr_class t1, t2;
        addmod(t1, w[695], w[806]);
        mulmod(t2, w[695], w[806]);
        mulmod_constant(t2, t2, two);
        submod(w[2230], t1, t2);
    }

    // XOR 1491 815 -> 2231
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1491], w[815]);
        mulmod(t2, w[1491], w[815]);
        mulmod_constant(t2, t2, two);
        submod(w[2231], t1, t2);
    }

    // XOR 1748 174 -> 2232
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1748], w[174]);
        mulmod(t2, w[1748], w[174]);
        mulmod_constant(t2, t2, two);
        submod(w[2232], t1, t2);
    }

    // XOR 272 2135 -> 2233
    {
        bn254fr_class t1, t2;
        addmod(t1, w[272], w[2135]);
        mulmod(t2, w[272], w[2135]);
        mulmod_constant(t2, t2, two);
        submod(w[2233], t1, t2);
    }

    // AND 477 1751 -> 2234
    mulmod(w[2234], w[477], w[1751]);

    // AND 1273 542 -> 2235
    mulmod(w[2235], w[1273], w[542]);

    // XOR 1706 1889 -> 2236
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1706], w[1889]);
        mulmod(t2, w[1706], w[1889]);
        mulmod_constant(t2, t2, two);
        submod(w[2236], t1, t2);
    }

    // AND 695 1245 -> 2237
    mulmod(w[2237], w[695], w[1245]);

    // INV 381 -> 2238
    submod(w[2238], one, w[381]);

    // AND 1934 605 -> 2239
    mulmod(w[2239], w[1934], w[605]);

    // AND 263 1251 -> 2240
    mulmod(w[2240], w[263], w[1251]);

    // AND 201 390 -> 2241
    mulmod(w[2241], w[201], w[390]);

    // XOR 686 2060 -> 2242
    {
        bn254fr_class t1, t2;
        addmod(t1, w[686], w[2060]);
        mulmod(t2, w[686], w[2060]);
        mulmod_constant(t2, t2, two);
        submod(w[2242], t1, t2);
    }

    // XOR 1196 1159 -> 2243
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1196], w[1159]);
        mulmod(t2, w[1196], w[1159]);
        mulmod_constant(t2, t2, two);
        submod(w[2243], t1, t2);
    }

    // XOR 723 1211 -> 2244
    {
        bn254fr_class t1, t2;
        addmod(t1, w[723], w[1211]);
        mulmod(t2, w[723], w[1211]);
        mulmod_constant(t2, t2, two);
        submod(w[2244], t1, t2);
    }

    // XOR 36 703 -> 2245
    {
        bn254fr_class t1, t2;
        addmod(t1, w[36], w[703]);
        mulmod(t2, w[36], w[703]);
        mulmod_constant(t2, t2, two);
        submod(w[2245], t1, t2);
    }

    // AND 190 1870 -> 2246
    mulmod(w[2246], w[190], w[1870]);

    // XOR 1226 1639 -> 2247
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1226], w[1639]);
        mulmod(t2, w[1226], w[1639]);
        mulmod_constant(t2, t2, two);
        submod(w[2247], t1, t2);
    }

    // XOR 942 1278 -> 2248
    {
        bn254fr_class t1, t2;
        addmod(t1, w[942], w[1278]);
        mulmod(t2, w[942], w[1278]);
        mulmod_constant(t2, t2, two);
        submod(w[2248], t1, t2);
    }

    // XOR 121 1228 -> 2249
    {
        bn254fr_class t1, t2;
        addmod(t1, w[121], w[1228]);
        mulmod(t2, w[121], w[1228]);
        mulmod_constant(t2, t2, two);
        submod(w[2249], t1, t2);
    }

    // XOR 694 647 -> 2250
    {
        bn254fr_class t1, t2;
        addmod(t1, w[694], w[647]);
        mulmod(t2, w[694], w[647]);
        mulmod_constant(t2, t2, two);
        submod(w[2250], t1, t2);
    }

    // AND 1954 1419 -> 2251
    mulmod(w[2251], w[1954], w[1419]);

    // XOR 1990 1443 -> 2252
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1990], w[1443]);
        mulmod(t2, w[1990], w[1443]);
        mulmod_constant(t2, t2, two);
        submod(w[2252], t1, t2);
    }

    // XOR 398 340 -> 2253
    {
        bn254fr_class t1, t2;
        addmod(t1, w[398], w[340]);
        mulmod(t2, w[398], w[340]);
        mulmod_constant(t2, t2, two);
        submod(w[2253], t1, t2);
    }

    // INV 1444 -> 2254
    submod(w[2254], one, w[1444]);

    // INV 1778 -> 2255
    submod(w[2255], one, w[1778]);

    // XOR 1607 133 -> 2256
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1607], w[133]);
        mulmod(t2, w[1607], w[133]);
        mulmod_constant(t2, t2, two);
        submod(w[2256], t1, t2);
    }

    // XOR 2067 1075 -> 2257
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2067], w[1075]);
        mulmod(t2, w[2067], w[1075]);
        mulmod_constant(t2, t2, two);
        submod(w[2257], t1, t2);
    }

    // AND 1278 60 -> 2258
    mulmod(w[2258], w[1278], w[60]);

    // AND 2078 1822 -> 2259
    mulmod(w[2259], w[2078], w[1822]);

    // AND 1533 2083 -> 2260
    mulmod(w[2260], w[1533], w[2083]);

    // XOR 270 435 -> 2261
    {
        bn254fr_class t1, t2;
        addmod(t1, w[270], w[435]);
        mulmod(t2, w[270], w[435]);
        mulmod_constant(t2, t2, two);
        submod(w[2261], t1, t2);
    }

    // XOR 543 2049 -> 2262
    {
        bn254fr_class t1, t2;
        addmod(t1, w[543], w[2049]);
        mulmod(t2, w[543], w[2049]);
        mulmod_constant(t2, t2, two);
        submod(w[2262], t1, t2);
    }

    // INV 1152 -> 2263
    submod(w[2263], one, w[1152]);

    // AND 212 1903 -> 2264
    mulmod(w[2264], w[212], w[1903]);

    // AND 2015 1573 -> 2265
    mulmod(w[2265], w[2015], w[1573]);

    // AND 251 1681 -> 2266
    mulmod(w[2266], w[251], w[1681]);

    // XOR 274 810 -> 2267
    {
        bn254fr_class t1, t2;
        addmod(t1, w[274], w[810]);
        mulmod(t2, w[274], w[810]);
        mulmod_constant(t2, t2, two);
        submod(w[2267], t1, t2);
    }

    // XOR 1801 1421 -> 2268
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1801], w[1421]);
        mulmod(t2, w[1801], w[1421]);
        mulmod_constant(t2, t2, two);
        submod(w[2268], t1, t2);
    }

    // XOR 1206 1522 -> 2269
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1206], w[1522]);
        mulmod(t2, w[1206], w[1522]);
        mulmod_constant(t2, t2, two);
        submod(w[2269], t1, t2);
    }

    // AND 1401 1505 -> 2270
    mulmod(w[2270], w[1401], w[1505]);

    // AND 465 615 -> 2271
    mulmod(w[2271], w[465], w[615]);

    // AND 125 495 -> 2272
    mulmod(w[2272], w[125], w[495]);

    // XOR 911 1736 -> 2273
    {
        bn254fr_class t1, t2;
        addmod(t1, w[911], w[1736]);
        mulmod(t2, w[911], w[1736]);
        mulmod_constant(t2, t2, two);
        submod(w[2273], t1, t2);
    }

    // XOR 289 1605 -> 2274
    {
        bn254fr_class t1, t2;
        addmod(t1, w[289], w[1605]);
        mulmod(t2, w[289], w[1605]);
        mulmod_constant(t2, t2, two);
        submod(w[2274], t1, t2);
    }

    // AND 1912 1452 -> 2275
    mulmod(w[2275], w[1912], w[1452]);

    // XOR 1978 634 -> 2276
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1978], w[634]);
        mulmod(t2, w[1978], w[634]);
        mulmod_constant(t2, t2, two);
        submod(w[2276], t1, t2);
    }

    // XOR 966 689 -> 2277
    {
        bn254fr_class t1, t2;
        addmod(t1, w[966], w[689]);
        mulmod(t2, w[966], w[689]);
        mulmod_constant(t2, t2, two);
        submod(w[2277], t1, t2);
    }

    // AND 1127 758 -> 2278
    mulmod(w[2278], w[1127], w[758]);

    // AND 6 17 -> 2279
    mulmod(w[2279], w[6], w[17]);

    // XOR 939 1267 -> 2280
    {
        bn254fr_class t1, t2;
        addmod(t1, w[939], w[1267]);
        mulmod(t2, w[939], w[1267]);
        mulmod_constant(t2, t2, two);
        submod(w[2280], t1, t2);
    }

    // XOR 1033 298 -> 2281
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1033], w[298]);
        mulmod(t2, w[1033], w[298]);
        mulmod_constant(t2, t2, two);
        submod(w[2281], t1, t2);
    }

    // XOR 1119 592 -> 2282
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1119], w[592]);
        mulmod(t2, w[1119], w[592]);
        mulmod_constant(t2, t2, two);
        submod(w[2282], t1, t2);
    }

    // XOR 1089 396 -> 2283
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1089], w[396]);
        mulmod(t2, w[1089], w[396]);
        mulmod_constant(t2, t2, two);
        submod(w[2283], t1, t2);
    }

    // XOR 1047 297 -> 2284
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1047], w[297]);
        mulmod(t2, w[1047], w[297]);
        mulmod_constant(t2, t2, two);
        submod(w[2284], t1, t2);
    }

    // AND 326 1720 -> 2285
    mulmod(w[2285], w[326], w[1720]);

    // AND 1177 2013 -> 2286
    mulmod(w[2286], w[1177], w[2013]);

    // AND 1444 182 -> 2287
    mulmod(w[2287], w[1444], w[182]);

    // XOR 1765 2011 -> 2288
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1765], w[2011]);
        mulmod(t2, w[1765], w[2011]);
        mulmod_constant(t2, t2, two);
        submod(w[2288], t1, t2);
    }

    // AND 1749 1771 -> 2289
    mulmod(w[2289], w[1749], w[1771]);

    // XOR 1730 181 -> 2290
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1730], w[181]);
        mulmod(t2, w[1730], w[181]);
        mulmod_constant(t2, t2, two);
        submod(w[2290], t1, t2);
    }

    // AND 542 1385 -> 2291
    mulmod(w[2291], w[542], w[1385]);

    // AND 802 27 -> 2292
    mulmod(w[2292], w[802], w[27]);

    // XOR 610 1831 -> 2293
    {
        bn254fr_class t1, t2;
        addmod(t1, w[610], w[1831]);
        mulmod(t2, w[610], w[1831]);
        mulmod_constant(t2, t2, two);
        submod(w[2293], t1, t2);
    }

    // XOR 684 1057 -> 2294
    {
        bn254fr_class t1, t2;
        addmod(t1, w[684], w[1057]);
        mulmod(t2, w[684], w[1057]);
        mulmod_constant(t2, t2, two);
        submod(w[2294], t1, t2);
    }

    // AND 1328 937 -> 2295
    mulmod(w[2295], w[1328], w[937]);

    // XOR 1876 1891 -> 2296
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1876], w[1891]);
        mulmod(t2, w[1876], w[1891]);
        mulmod_constant(t2, t2, two);
        submod(w[2296], t1, t2);
    }

    // XOR 1511 720 -> 2297
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1511], w[720]);
        mulmod(t2, w[1511], w[720]);
        mulmod_constant(t2, t2, two);
        submod(w[2297], t1, t2);
    }

    // AND 1132 1063 -> 2298
    mulmod(w[2298], w[1132], w[1063]);

    // INV 1068 -> 2299
    submod(w[2299], one, w[1068]);

    // AND 1535 1094 -> 2300
    mulmod(w[2300], w[1535], w[1094]);

    // XOR 812 713 -> 2301
    {
        bn254fr_class t1, t2;
        addmod(t1, w[812], w[713]);
        mulmod(t2, w[812], w[713]);
        mulmod_constant(t2, t2, two);
        submod(w[2301], t1, t2);
    }

    // AND 2242 777 -> 2302
    mulmod(w[2302], w[2242], w[777]);

    // AND 1730 33 -> 2303
    mulmod(w[2303], w[1730], w[33]);

    // AND 421 246 -> 2304
    mulmod(w[2304], w[421], w[246]);

    // XOR 502 1414 -> 2305
    {
        bn254fr_class t1, t2;
        addmod(t1, w[502], w[1414]);
        mulmod(t2, w[502], w[1414]);
        mulmod_constant(t2, t2, two);
        submod(w[2305], t1, t2);
    }

    // XOR 1460 1726 -> 2306
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1460], w[1726]);
        mulmod(t2, w[1460], w[1726]);
        mulmod_constant(t2, t2, two);
        submod(w[2306], t1, t2);
    }

    // AND 1174 629 -> 2307
    mulmod(w[2307], w[1174], w[629]);

    // INV 409 -> 2308
    submod(w[2308], one, w[409]);

    // AND 1956 1457 -> 2309
    mulmod(w[2309], w[1956], w[1457]);

    // XOR 1922 1775 -> 2310
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1922], w[1775]);
        mulmod(t2, w[1922], w[1775]);
        mulmod_constant(t2, t2, two);
        submod(w[2310], t1, t2);
    }

    // XOR 900 1849 -> 2311
    {
        bn254fr_class t1, t2;
        addmod(t1, w[900], w[1849]);
        mulmod(t2, w[900], w[1849]);
        mulmod_constant(t2, t2, two);
        submod(w[2311], t1, t2);
    }

    // XOR 780 573 -> 2312
    {
        bn254fr_class t1, t2;
        addmod(t1, w[780], w[573]);
        mulmod(t2, w[780], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[2312], t1, t2);
    }

    // XOR 961 366 -> 2313
    {
        bn254fr_class t1, t2;
        addmod(t1, w[961], w[366]);
        mulmod(t2, w[961], w[366]);
        mulmod_constant(t2, t2, two);
        submod(w[2313], t1, t2);
    }

    // AND 1547 660 -> 2314
    mulmod(w[2314], w[1547], w[660]);

    // XOR 505 782 -> 2315
    {
        bn254fr_class t1, t2;
        addmod(t1, w[505], w[782]);
        mulmod(t2, w[505], w[782]);
        mulmod_constant(t2, t2, two);
        submod(w[2315], t1, t2);
    }

    // INV 1087 -> 2316
    submod(w[2316], one, w[1087]);

    // XOR 1665 1588 -> 2317
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1665], w[1588]);
        mulmod(t2, w[1665], w[1588]);
        mulmod_constant(t2, t2, two);
        submod(w[2317], t1, t2);
    }

    // AND 1417 1397 -> 2318
    mulmod(w[2318], w[1417], w[1397]);

    // AND 1031 2254 -> 2319
    mulmod(w[2319], w[1031], w[2254]);

    // XOR 781 937 -> 2320
    {
        bn254fr_class t1, t2;
        addmod(t1, w[781], w[937]);
        mulmod(t2, w[781], w[937]);
        mulmod_constant(t2, t2, two);
        submod(w[2320], t1, t2);
    }

    // AND 784 1508 -> 2321
    mulmod(w[2321], w[784], w[1508]);

    // AND 2111 1835 -> 2322
    mulmod(w[2322], w[2111], w[1835]);

    // INV 179 -> 2323
    submod(w[2323], one, w[179]);

    // XOR 1478 1211 -> 2324
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1478], w[1211]);
        mulmod(t2, w[1478], w[1211]);
        mulmod_constant(t2, t2, two);
        submod(w[2324], t1, t2);
    }

    // XOR 1289 1672 -> 2325
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1289], w[1672]);
        mulmod(t2, w[1289], w[1672]);
        mulmod_constant(t2, t2, two);
        submod(w[2325], t1, t2);
    }

    // XOR 977 1523 -> 2326
    {
        bn254fr_class t1, t2;
        addmod(t1, w[977], w[1523]);
        mulmod(t2, w[977], w[1523]);
        mulmod_constant(t2, t2, two);
        submod(w[2326], t1, t2);
    }

    // AND 1649 1133 -> 2327
    mulmod(w[2327], w[1649], w[1133]);

    // XOR 535 63 -> 2328
    {
        bn254fr_class t1, t2;
        addmod(t1, w[535], w[63]);
        mulmod(t2, w[535], w[63]);
        mulmod_constant(t2, t2, two);
        submod(w[2328], t1, t2);
    }

    // INV 102 -> 2329
    submod(w[2329], one, w[102]);

    // AND 1089 1177 -> 2330
    mulmod(w[2330], w[1089], w[1177]);

    // INV 466 -> 2331
    submod(w[2331], one, w[466]);

    // XOR 756 1586 -> 2332
    {
        bn254fr_class t1, t2;
        addmod(t1, w[756], w[1586]);
        mulmod(t2, w[756], w[1586]);
        mulmod_constant(t2, t2, two);
        submod(w[2332], t1, t2);
    }

    // XOR 1501 1470 -> 2333
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1501], w[1470]);
        mulmod(t2, w[1501], w[1470]);
        mulmod_constant(t2, t2, two);
        submod(w[2333], t1, t2);
    }

    // AND 39 1865 -> 2334
    mulmod(w[2334], w[39], w[1865]);

    // XOR 600 165 -> 2335
    {
        bn254fr_class t1, t2;
        addmod(t1, w[600], w[165]);
        mulmod(t2, w[600], w[165]);
        mulmod_constant(t2, t2, two);
        submod(w[2335], t1, t2);
    }

    // XOR 1637 1624 -> 2336
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1637], w[1624]);
        mulmod(t2, w[1637], w[1624]);
        mulmod_constant(t2, t2, two);
        submod(w[2336], t1, t2);
    }

    // XOR 2108 1300 -> 2337
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2108], w[1300]);
        mulmod(t2, w[2108], w[1300]);
        mulmod_constant(t2, t2, two);
        submod(w[2337], t1, t2);
    }

    // XOR 565 1609 -> 2338
    {
        bn254fr_class t1, t2;
        addmod(t1, w[565], w[1609]);
        mulmod(t2, w[565], w[1609]);
        mulmod_constant(t2, t2, two);
        submod(w[2338], t1, t2);
    }

    // INV 969 -> 2339
    submod(w[2339], one, w[969]);

    // AND 2174 415 -> 2340
    mulmod(w[2340], w[2174], w[415]);

    // XOR 773 452 -> 2341
    {
        bn254fr_class t1, t2;
        addmod(t1, w[773], w[452]);
        mulmod(t2, w[773], w[452]);
        mulmod_constant(t2, t2, two);
        submod(w[2341], t1, t2);
    }

    // XOR 1127 686 -> 2342
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1127], w[686]);
        mulmod(t2, w[1127], w[686]);
        mulmod_constant(t2, t2, two);
        submod(w[2342], t1, t2);
    }

    // INV 1310 -> 2343
    submod(w[2343], one, w[1310]);

    // XOR 409 347 -> 2344
    {
        bn254fr_class t1, t2;
        addmod(t1, w[409], w[347]);
        mulmod(t2, w[409], w[347]);
        mulmod_constant(t2, t2, two);
        submod(w[2344], t1, t2);
    }

    // AND 1936 630 -> 2345
    mulmod(w[2345], w[1936], w[630]);

    // AND 580 1303 -> 2346
    mulmod(w[2346], w[580], w[1303]);

    // XOR 1727 2156 -> 2347
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1727], w[2156]);
        mulmod(t2, w[1727], w[2156]);
        mulmod_constant(t2, t2, two);
        submod(w[2347], t1, t2);
    }

    // XOR 1446 1674 -> 2348
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1446], w[1674]);
        mulmod(t2, w[1446], w[1674]);
        mulmod_constant(t2, t2, two);
        submod(w[2348], t1, t2);
    }

    // XOR 1474 1708 -> 2349
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1474], w[1708]);
        mulmod(t2, w[1474], w[1708]);
        mulmod_constant(t2, t2, two);
        submod(w[2349], t1, t2);
    }

    // XOR 1546 2223 -> 2350
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1546], w[2223]);
        mulmod(t2, w[1546], w[2223]);
        mulmod_constant(t2, t2, two);
        submod(w[2350], t1, t2);
    }

    // XOR 830 1521 -> 2351
    {
        bn254fr_class t1, t2;
        addmod(t1, w[830], w[1521]);
        mulmod(t2, w[830], w[1521]);
        mulmod_constant(t2, t2, two);
        submod(w[2351], t1, t2);
    }

    // XOR 2017 404 -> 2352
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2017], w[404]);
        mulmod(t2, w[2017], w[404]);
        mulmod_constant(t2, t2, two);
        submod(w[2352], t1, t2);
    }

    // AND 216 341 -> 2353
    mulmod(w[2353], w[216], w[341]);

    // AND 656 1358 -> 2354
    mulmod(w[2354], w[656], w[1358]);

    // AND 800 1963 -> 2355
    mulmod(w[2355], w[800], w[1963]);

    // XOR 83 2129 -> 2356
    {
        bn254fr_class t1, t2;
        addmod(t1, w[83], w[2129]);
        mulmod(t2, w[83], w[2129]);
        mulmod_constant(t2, t2, two);
        submod(w[2356], t1, t2);
    }

    // AND 1052 349 -> 2357
    mulmod(w[2357], w[1052], w[349]);

    // AND 484 1206 -> 2358
    mulmod(w[2358], w[484], w[1206]);

    // AND 1689 476 -> 2359
    mulmod(w[2359], w[1689], w[476]);

    // XOR 939 511 -> 2360
    {
        bn254fr_class t1, t2;
        addmod(t1, w[939], w[511]);
        mulmod(t2, w[939], w[511]);
        mulmod_constant(t2, t2, two);
        submod(w[2360], t1, t2);
    }

    // AND 2114 1816 -> 2361
    mulmod(w[2361], w[2114], w[1816]);

    // XOR 85 1649 -> 2362
    {
        bn254fr_class t1, t2;
        addmod(t1, w[85], w[1649]);
        mulmod(t2, w[85], w[1649]);
        mulmod_constant(t2, t2, two);
        submod(w[2362], t1, t2);
    }

    // XOR 1335 1747 -> 2363
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1335], w[1747]);
        mulmod(t2, w[1335], w[1747]);
        mulmod_constant(t2, t2, two);
        submod(w[2363], t1, t2);
    }

    // AND 1104 1019 -> 2364
    mulmod(w[2364], w[1104], w[1019]);

    // XOR 579 2102 -> 2365
    {
        bn254fr_class t1, t2;
        addmod(t1, w[579], w[2102]);
        mulmod(t2, w[579], w[2102]);
        mulmod_constant(t2, t2, two);
        submod(w[2365], t1, t2);
    }

    // AND 14 515 -> 2366
    mulmod(w[2366], w[14], w[515]);

    // XOR 174 621 -> 2367
    {
        bn254fr_class t1, t2;
        addmod(t1, w[174], w[621]);
        mulmod(t2, w[174], w[621]);
        mulmod_constant(t2, t2, two);
        submod(w[2367], t1, t2);
    }

    // AND 353 1629 -> 2368
    mulmod(w[2368], w[353], w[1629]);

    // AND 21 687 -> 2369
    mulmod(w[2369], w[21], w[687]);

    // AND 42 1330 -> 2370
    mulmod(w[2370], w[42], w[1330]);

    // AND 1801 371 -> 2371
    mulmod(w[2371], w[1801], w[371]);

    // XOR 1723 2099 -> 2372
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1723], w[2099]);
        mulmod(t2, w[1723], w[2099]);
        mulmod_constant(t2, t2, two);
        submod(w[2372], t1, t2);
    }

    // XOR 742 852 -> 2373
    {
        bn254fr_class t1, t2;
        addmod(t1, w[742], w[852]);
        mulmod(t2, w[742], w[852]);
        mulmod_constant(t2, t2, two);
        submod(w[2373], t1, t2);
    }

    // AND 1346 1263 -> 2374
    mulmod(w[2374], w[1346], w[1263]);

    // XOR 199 771 -> 2375
    {
        bn254fr_class t1, t2;
        addmod(t1, w[199], w[771]);
        mulmod(t2, w[199], w[771]);
        mulmod_constant(t2, t2, two);
        submod(w[2375], t1, t2);
    }

    // XOR 527 1217 -> 2376
    {
        bn254fr_class t1, t2;
        addmod(t1, w[527], w[1217]);
        mulmod(t2, w[527], w[1217]);
        mulmod_constant(t2, t2, two);
        submod(w[2376], t1, t2);
    }

    // AND 310 1762 -> 2377
    mulmod(w[2377], w[310], w[1762]);

    // AND 1080 152 -> 2378
    mulmod(w[2378], w[1080], w[152]);

    // AND 549 1416 -> 2379
    mulmod(w[2379], w[549], w[1416]);

    // XOR 1677 1222 -> 2380
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1677], w[1222]);
        mulmod(t2, w[1677], w[1222]);
        mulmod_constant(t2, t2, two);
        submod(w[2380], t1, t2);
    }

    // XOR 1371 82 -> 2381
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1371], w[82]);
        mulmod(t2, w[1371], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[2381], t1, t2);
    }

    // XOR 2053 1477 -> 2382
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2053], w[1477]);
        mulmod(t2, w[2053], w[1477]);
        mulmod_constant(t2, t2, two);
        submod(w[2382], t1, t2);
    }

    // AND 794 1157 -> 2383
    mulmod(w[2383], w[794], w[1157]);

    // XOR 1856 2046 -> 2384
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1856], w[2046]);
        mulmod(t2, w[1856], w[2046]);
        mulmod_constant(t2, t2, two);
        submod(w[2384], t1, t2);
    }

    // INV 933 -> 2385
    submod(w[2385], one, w[933]);

    // AND 397 1161 -> 2386
    mulmod(w[2386], w[397], w[1161]);

    // INV 693 -> 2387
    submod(w[2387], one, w[693]);

    // XOR 983 828 -> 2388
    {
        bn254fr_class t1, t2;
        addmod(t1, w[983], w[828]);
        mulmod(t2, w[983], w[828]);
        mulmod_constant(t2, t2, two);
        submod(w[2388], t1, t2);
    }

    // AND 1177 401 -> 2389
    mulmod(w[2389], w[1177], w[401]);

    // AND 1836 269 -> 2390
    mulmod(w[2390], w[1836], w[269]);

    // XOR 463 1714 -> 2391
    {
        bn254fr_class t1, t2;
        addmod(t1, w[463], w[1714]);
        mulmod(t2, w[463], w[1714]);
        mulmod_constant(t2, t2, two);
        submod(w[2391], t1, t2);
    }

    // AND 773 1962 -> 2392
    mulmod(w[2392], w[773], w[1962]);

    // AND 129 1536 -> 2393
    mulmod(w[2393], w[129], w[1536]);

    // XOR 1595 899 -> 2394
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1595], w[899]);
        mulmod(t2, w[1595], w[899]);
        mulmod_constant(t2, t2, two);
        submod(w[2394], t1, t2);
    }

    // AND 2306 446 -> 2395
    mulmod(w[2395], w[2306], w[446]);

    // XOR 48 1870 -> 2396
    {
        bn254fr_class t1, t2;
        addmod(t1, w[48], w[1870]);
        mulmod(t2, w[48], w[1870]);
        mulmod_constant(t2, t2, two);
        submod(w[2396], t1, t2);
    }

    // AND 1548 1857 -> 2397
    mulmod(w[2397], w[1548], w[1857]);

    // XOR 2282 348 -> 2398
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2282], w[348]);
        mulmod(t2, w[2282], w[348]);
        mulmod_constant(t2, t2, two);
        submod(w[2398], t1, t2);
    }

    // AND 1300 327 -> 2399
    mulmod(w[2399], w[1300], w[327]);

    // INV 2277 -> 2400
    submod(w[2400], one, w[2277]);

    // XOR 502 736 -> 2401
    {
        bn254fr_class t1, t2;
        addmod(t1, w[502], w[736]);
        mulmod(t2, w[502], w[736]);
        mulmod_constant(t2, t2, two);
        submod(w[2401], t1, t2);
    }

    // AND 1998 1541 -> 2402
    mulmod(w[2402], w[1998], w[1541]);

    // XOR 2050 674 -> 2403
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2050], w[674]);
        mulmod(t2, w[2050], w[674]);
        mulmod_constant(t2, t2, two);
        submod(w[2403], t1, t2);
    }

    // XOR 130 471 -> 2404
    {
        bn254fr_class t1, t2;
        addmod(t1, w[130], w[471]);
        mulmod(t2, w[130], w[471]);
        mulmod_constant(t2, t2, two);
        submod(w[2404], t1, t2);
    }

    // INV 948 -> 2405
    submod(w[2405], one, w[948]);

    // XOR 2019 817 -> 2406
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2019], w[817]);
        mulmod(t2, w[2019], w[817]);
        mulmod_constant(t2, t2, two);
        submod(w[2406], t1, t2);
    }

    // XOR 726 624 -> 2407
    {
        bn254fr_class t1, t2;
        addmod(t1, w[726], w[624]);
        mulmod(t2, w[726], w[624]);
        mulmod_constant(t2, t2, two);
        submod(w[2407], t1, t2);
    }

    // AND 190 2271 -> 2408
    mulmod(w[2408], w[190], w[2271]);

    // XOR 2282 573 -> 2409
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2282], w[573]);
        mulmod(t2, w[2282], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[2409], t1, t2);
    }

    // AND 1936 1562 -> 2410
    mulmod(w[2410], w[1936], w[1562]);

    // XOR 2350 1294 -> 2411
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2350], w[1294]);
        mulmod(t2, w[2350], w[1294]);
        mulmod_constant(t2, t2, two);
        submod(w[2411], t1, t2);
    }

    // XOR 779 13 -> 2412
    {
        bn254fr_class t1, t2;
        addmod(t1, w[779], w[13]);
        mulmod(t2, w[779], w[13]);
        mulmod_constant(t2, t2, two);
        submod(w[2412], t1, t2);
    }

    // XOR 1232 1310 -> 2413
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1232], w[1310]);
        mulmod(t2, w[1232], w[1310]);
        mulmod_constant(t2, t2, two);
        submod(w[2413], t1, t2);
    }

    // AND 1705 1006 -> 2414
    mulmod(w[2414], w[1705], w[1006]);

    // XOR 259 1813 -> 2415
    {
        bn254fr_class t1, t2;
        addmod(t1, w[259], w[1813]);
        mulmod(t2, w[259], w[1813]);
        mulmod_constant(t2, t2, two);
        submod(w[2415], t1, t2);
    }

    // XOR 1500 525 -> 2416
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1500], w[525]);
        mulmod(t2, w[1500], w[525]);
        mulmod_constant(t2, t2, two);
        submod(w[2416], t1, t2);
    }

    // XOR 54 306 -> 2417
    {
        bn254fr_class t1, t2;
        addmod(t1, w[54], w[306]);
        mulmod(t2, w[54], w[306]);
        mulmod_constant(t2, t2, two);
        submod(w[2417], t1, t2);
    }

    // INV 2140 -> 2418
    submod(w[2418], one, w[2140]);

    // XOR 664 1307 -> 2419
    {
        bn254fr_class t1, t2;
        addmod(t1, w[664], w[1307]);
        mulmod(t2, w[664], w[1307]);
        mulmod_constant(t2, t2, two);
        submod(w[2419], t1, t2);
    }

    // XOR 2341 536 -> 2420
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2341], w[536]);
        mulmod(t2, w[2341], w[536]);
        mulmod_constant(t2, t2, two);
        submod(w[2420], t1, t2);
    }

    // INV 1729 -> 2421
    submod(w[2421], one, w[1729]);

    // XOR 2041 1364 -> 2422
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2041], w[1364]);
        mulmod(t2, w[2041], w[1364]);
        mulmod_constant(t2, t2, two);
        submod(w[2422], t1, t2);
    }

    // INV 713 -> 2423
    submod(w[2423], one, w[713]);

    // XOR 1901 1262 -> 2424
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1901], w[1262]);
        mulmod(t2, w[1901], w[1262]);
        mulmod_constant(t2, t2, two);
        submod(w[2424], t1, t2);
    }

    // AND 544 1788 -> 2425
    mulmod(w[2425], w[544], w[1788]);

    // AND 1601 2131 -> 2426
    mulmod(w[2426], w[1601], w[2131]);

    // AND 37 474 -> 2427
    mulmod(w[2427], w[37], w[474]);

    // AND 1076 2127 -> 2428
    mulmod(w[2428], w[1076], w[2127]);

    // AND 1382 234 -> 2429
    mulmod(w[2429], w[1382], w[234]);

    // XOR 888 963 -> 2430
    {
        bn254fr_class t1, t2;
        addmod(t1, w[888], w[963]);
        mulmod(t2, w[888], w[963]);
        mulmod_constant(t2, t2, two);
        submod(w[2430], t1, t2);
    }

    // AND 463 1608 -> 2431
    mulmod(w[2431], w[463], w[1608]);

    // XOR 445 28 -> 2432
    {
        bn254fr_class t1, t2;
        addmod(t1, w[445], w[28]);
        mulmod(t2, w[445], w[28]);
        mulmod_constant(t2, t2, two);
        submod(w[2432], t1, t2);
    }

    // XOR 719 529 -> 2433
    {
        bn254fr_class t1, t2;
        addmod(t1, w[719], w[529]);
        mulmod(t2, w[719], w[529]);
        mulmod_constant(t2, t2, two);
        submod(w[2433], t1, t2);
    }

    // XOR 7 1080 -> 2434
    {
        bn254fr_class t1, t2;
        addmod(t1, w[7], w[1080]);
        mulmod(t2, w[7], w[1080]);
        mulmod_constant(t2, t2, two);
        submod(w[2434], t1, t2);
    }

    // XOR 2204 1591 -> 2435
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2204], w[1591]);
        mulmod(t2, w[2204], w[1591]);
        mulmod_constant(t2, t2, two);
        submod(w[2435], t1, t2);
    }

    // XOR 26 813 -> 2436
    {
        bn254fr_class t1, t2;
        addmod(t1, w[26], w[813]);
        mulmod(t2, w[26], w[813]);
        mulmod_constant(t2, t2, two);
        submod(w[2436], t1, t2);
    }

    // AND 2344 636 -> 2437
    mulmod(w[2437], w[2344], w[636]);

    // XOR 673 1976 -> 2438
    {
        bn254fr_class t1, t2;
        addmod(t1, w[673], w[1976]);
        mulmod(t2, w[673], w[1976]);
        mulmod_constant(t2, t2, two);
        submod(w[2438], t1, t2);
    }

    // AND 2352 139 -> 2439
    mulmod(w[2439], w[2352], w[139]);

    // INV 1678 -> 2440
    submod(w[2440], one, w[1678]);

    // XOR 328 912 -> 2441
    {
        bn254fr_class t1, t2;
        addmod(t1, w[328], w[912]);
        mulmod(t2, w[328], w[912]);
        mulmod_constant(t2, t2, two);
        submod(w[2441], t1, t2);
    }

    // INV 1216 -> 2442
    submod(w[2442], one, w[1216]);

    // XOR 2301 1515 -> 2443
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2301], w[1515]);
        mulmod(t2, w[2301], w[1515]);
        mulmod_constant(t2, t2, two);
        submod(w[2443], t1, t2);
    }

    // XOR 660 1533 -> 2444
    {
        bn254fr_class t1, t2;
        addmod(t1, w[660], w[1533]);
        mulmod(t2, w[660], w[1533]);
        mulmod_constant(t2, t2, two);
        submod(w[2444], t1, t2);
    }

    // AND 1207 993 -> 2445
    mulmod(w[2445], w[1207], w[993]);

    // XOR 354 83 -> 2446
    {
        bn254fr_class t1, t2;
        addmod(t1, w[354], w[83]);
        mulmod(t2, w[354], w[83]);
        mulmod_constant(t2, t2, two);
        submod(w[2446], t1, t2);
    }

    // AND 623 218 -> 2447
    mulmod(w[2447], w[623], w[218]);

    // INV 216 -> 2448
    submod(w[2448], one, w[216]);

    // XOR 728 532 -> 2449
    {
        bn254fr_class t1, t2;
        addmod(t1, w[728], w[532]);
        mulmod(t2, w[728], w[532]);
        mulmod_constant(t2, t2, two);
        submod(w[2449], t1, t2);
    }

    // INV 1621 -> 2450
    submod(w[2450], one, w[1621]);

    // XOR 1352 2346 -> 2451
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1352], w[2346]);
        mulmod(t2, w[1352], w[2346]);
        mulmod_constant(t2, t2, two);
        submod(w[2451], t1, t2);
    }

    // AND 1350 1534 -> 2452
    mulmod(w[2452], w[1350], w[1534]);

    // AND 1316 569 -> 2453
    mulmod(w[2453], w[1316], w[569]);

    // XOR 2356 1785 -> 2454
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2356], w[1785]);
        mulmod(t2, w[2356], w[1785]);
        mulmod_constant(t2, t2, two);
        submod(w[2454], t1, t2);
    }

    // AND 1123 522 -> 2455
    mulmod(w[2455], w[1123], w[522]);

    // AND 1453 1898 -> 2456
    mulmod(w[2456], w[1453], w[1898]);

    // AND 520 992 -> 2457
    mulmod(w[2457], w[520], w[992]);

    // XOR 1120 1475 -> 2458
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1120], w[1475]);
        mulmod(t2, w[1120], w[1475]);
        mulmod_constant(t2, t2, two);
        submod(w[2458], t1, t2);
    }

    // XOR 1131 1794 -> 2459
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1131], w[1794]);
        mulmod(t2, w[1131], w[1794]);
        mulmod_constant(t2, t2, two);
        submod(w[2459], t1, t2);
    }

    // XOR 1128 1402 -> 2460
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1128], w[1402]);
        mulmod(t2, w[1128], w[1402]);
        mulmod_constant(t2, t2, two);
        submod(w[2460], t1, t2);
    }

    // XOR 523 2074 -> 2461
    {
        bn254fr_class t1, t2;
        addmod(t1, w[523], w[2074]);
        mulmod(t2, w[523], w[2074]);
        mulmod_constant(t2, t2, two);
        submod(w[2461], t1, t2);
    }

    // XOR 587 1710 -> 2462
    {
        bn254fr_class t1, t2;
        addmod(t1, w[587], w[1710]);
        mulmod(t2, w[587], w[1710]);
        mulmod_constant(t2, t2, two);
        submod(w[2462], t1, t2);
    }

    // XOR 2030 153 -> 2463
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2030], w[153]);
        mulmod(t2, w[2030], w[153]);
        mulmod_constant(t2, t2, two);
        submod(w[2463], t1, t2);
    }

    // AND 2087 2142 -> 2464
    mulmod(w[2464], w[2087], w[2142]);

    // AND 1347 537 -> 2465
    mulmod(w[2465], w[1347], w[537]);

    // INV 1460 -> 2466
    submod(w[2466], one, w[1460]);

    // AND 793 1827 -> 2467
    mulmod(w[2467], w[793], w[1827]);

    // XOR 1951 525 -> 2468
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1951], w[525]);
        mulmod(t2, w[1951], w[525]);
        mulmod_constant(t2, t2, two);
        submod(w[2468], t1, t2);
    }

    // XOR 1187 1452 -> 2469
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1187], w[1452]);
        mulmod(t2, w[1187], w[1452]);
        mulmod_constant(t2, t2, two);
        submod(w[2469], t1, t2);
    }

    // AND 2267 2054 -> 2470
    mulmod(w[2470], w[2267], w[2054]);

    // AND 467 1008 -> 2471
    mulmod(w[2471], w[467], w[1008]);

    // XOR 1508 1560 -> 2472
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1508], w[1560]);
        mulmod(t2, w[1508], w[1560]);
        mulmod_constant(t2, t2, two);
        submod(w[2472], t1, t2);
    }

    // XOR 1398 333 -> 2473
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1398], w[333]);
        mulmod(t2, w[1398], w[333]);
        mulmod_constant(t2, t2, two);
        submod(w[2473], t1, t2);
    }

    // XOR 1024 1529 -> 2474
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1024], w[1529]);
        mulmod(t2, w[1024], w[1529]);
        mulmod_constant(t2, t2, two);
        submod(w[2474], t1, t2);
    }

    // AND 1074 879 -> 2475
    mulmod(w[2475], w[1074], w[879]);

    // AND 198 648 -> 2476
    mulmod(w[2476], w[198], w[648]);

    // AND 354 190 -> 2477
    mulmod(w[2477], w[354], w[190]);

    // AND 1883 1241 -> 2478
    mulmod(w[2478], w[1883], w[1241]);

    // XOR 640 2221 -> 2479
    {
        bn254fr_class t1, t2;
        addmod(t1, w[640], w[2221]);
        mulmod(t2, w[640], w[2221]);
        mulmod_constant(t2, t2, two);
        submod(w[2479], t1, t2);
    }

    // XOR 516 504 -> 2480
    {
        bn254fr_class t1, t2;
        addmod(t1, w[516], w[504]);
        mulmod(t2, w[516], w[504]);
        mulmod_constant(t2, t2, two);
        submod(w[2480], t1, t2);
    }

    // INV 2156 -> 2481
    submod(w[2481], one, w[2156]);

    // AND 2310 35 -> 2482
    mulmod(w[2482], w[2310], w[35]);

    // XOR 1403 1577 -> 2483
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1403], w[1577]);
        mulmod(t2, w[1403], w[1577]);
        mulmod_constant(t2, t2, two);
        submod(w[2483], t1, t2);
    }

    // XOR 2245 582 -> 2484
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2245], w[582]);
        mulmod(t2, w[2245], w[582]);
        mulmod_constant(t2, t2, two);
        submod(w[2484], t1, t2);
    }

    // AND 1610 1499 -> 2485
    mulmod(w[2485], w[1610], w[1499]);

    // AND 1690 112 -> 2486
    mulmod(w[2486], w[1690], w[112]);

    // XOR 2193 1517 -> 2487
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2193], w[1517]);
        mulmod(t2, w[2193], w[1517]);
        mulmod_constant(t2, t2, two);
        submod(w[2487], t1, t2);
    }

    // AND 626 939 -> 2488
    mulmod(w[2488], w[626], w[939]);

    // INV 2373 -> 2489
    submod(w[2489], one, w[2373]);

    // XOR 752 430 -> 2490
    {
        bn254fr_class t1, t2;
        addmod(t1, w[752], w[430]);
        mulmod(t2, w[752], w[430]);
        mulmod_constant(t2, t2, two);
        submod(w[2490], t1, t2);
    }

    // XOR 698 1481 -> 2491
    {
        bn254fr_class t1, t2;
        addmod(t1, w[698], w[1481]);
        mulmod(t2, w[698], w[1481]);
        mulmod_constant(t2, t2, two);
        submod(w[2491], t1, t2);
    }

    // AND 1423 2198 -> 2492
    mulmod(w[2492], w[1423], w[2198]);

    // AND 222 1600 -> 2493
    mulmod(w[2493], w[222], w[1600]);

    // XOR 621 2052 -> 2494
    {
        bn254fr_class t1, t2;
        addmod(t1, w[621], w[2052]);
        mulmod(t2, w[621], w[2052]);
        mulmod_constant(t2, t2, two);
        submod(w[2494], t1, t2);
    }

    // XOR 1326 319 -> 2495
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1326], w[319]);
        mulmod(t2, w[1326], w[319]);
        mulmod_constant(t2, t2, two);
        submod(w[2495], t1, t2);
    }

    // INV 2280 -> 2496
    submod(w[2496], one, w[2280]);

    // XOR 436 1686 -> 2497
    {
        bn254fr_class t1, t2;
        addmod(t1, w[436], w[1686]);
        mulmod(t2, w[436], w[1686]);
        mulmod_constant(t2, t2, two);
        submod(w[2497], t1, t2);
    }

    // XOR 2150 2092 -> 2498
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2150], w[2092]);
        mulmod(t2, w[2150], w[2092]);
        mulmod_constant(t2, t2, two);
        submod(w[2498], t1, t2);
    }

    // AND 2155 1623 -> 2499
    mulmod(w[2499], w[2155], w[1623]);

    // AND 1326 406 -> 2500
    mulmod(w[2500], w[1326], w[406]);

    // XOR 352 431 -> 2501
    {
        bn254fr_class t1, t2;
        addmod(t1, w[352], w[431]);
        mulmod(t2, w[352], w[431]);
        mulmod_constant(t2, t2, two);
        submod(w[2501], t1, t2);
    }

    // XOR 1066 67 -> 2502
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1066], w[67]);
        mulmod(t2, w[1066], w[67]);
        mulmod_constant(t2, t2, two);
        submod(w[2502], t1, t2);
    }

    // AND 2071 2273 -> 2503
    mulmod(w[2503], w[2071], w[2273]);

    // AND 766 935 -> 2504
    mulmod(w[2504], w[766], w[935]);

    // INV 1711 -> 2505
    submod(w[2505], one, w[1711]);

    // AND 1303 1216 -> 2506
    mulmod(w[2506], w[1303], w[1216]);

    // XOR 1771 1441 -> 2507
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1771], w[1441]);
        mulmod(t2, w[1771], w[1441]);
        mulmod_constant(t2, t2, two);
        submod(w[2507], t1, t2);
    }

    // AND 2117 1034 -> 2508
    mulmod(w[2508], w[2117], w[1034]);

    // AND 2485 2395 -> 2509
    mulmod(w[2509], w[2485], w[2395]);

    // XOR 2162 937 -> 2510
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2162], w[937]);
        mulmod(t2, w[2162], w[937]);
        mulmod_constant(t2, t2, two);
        submod(w[2510], t1, t2);
    }

    // XOR 982 1478 -> 2511
    {
        bn254fr_class t1, t2;
        addmod(t1, w[982], w[1478]);
        mulmod(t2, w[982], w[1478]);
        mulmod_constant(t2, t2, two);
        submod(w[2511], t1, t2);
    }

    // XOR 1354 1354 -> 2512
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1354], w[1354]);
        mulmod(t2, w[1354], w[1354]);
        mulmod_constant(t2, t2, two);
        submod(w[2512], t1, t2);
    }

    // INV 2408 -> 2513
    submod(w[2513], one, w[2408]);

    // INV 1061 -> 2514
    submod(w[2514], one, w[1061]);

    // AND 1798 892 -> 2515
    mulmod(w[2515], w[1798], w[892]);

    // AND 620 442 -> 2516
    mulmod(w[2516], w[620], w[442]);

    // AND 513 463 -> 2517
    mulmod(w[2517], w[513], w[463]);

    // AND 513 1247 -> 2518
    mulmod(w[2518], w[513], w[1247]);

    // XOR 243 1440 -> 2519
    {
        bn254fr_class t1, t2;
        addmod(t1, w[243], w[1440]);
        mulmod(t2, w[243], w[1440]);
        mulmod_constant(t2, t2, two);
        submod(w[2519], t1, t2);
    }

    // AND 2123 1739 -> 2520
    mulmod(w[2520], w[2123], w[1739]);

    // XOR 2284 1421 -> 2521
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2284], w[1421]);
        mulmod(t2, w[2284], w[1421]);
        mulmod_constant(t2, t2, two);
        submod(w[2521], t1, t2);
    }

    // XOR 1161 1294 -> 2522
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1161], w[1294]);
        mulmod(t2, w[1161], w[1294]);
        mulmod_constant(t2, t2, two);
        submod(w[2522], t1, t2);
    }

    // AND 8 1499 -> 2523
    mulmod(w[2523], w[8], w[1499]);

    // AND 611 1869 -> 2524
    mulmod(w[2524], w[611], w[1869]);

    // AND 2078 352 -> 2525
    mulmod(w[2525], w[2078], w[352]);

    // XOR 49 459 -> 2526
    {
        bn254fr_class t1, t2;
        addmod(t1, w[49], w[459]);
        mulmod(t2, w[49], w[459]);
        mulmod_constant(t2, t2, two);
        submod(w[2526], t1, t2);
    }

    // XOR 2276 957 -> 2527
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2276], w[957]);
        mulmod(t2, w[2276], w[957]);
        mulmod_constant(t2, t2, two);
        submod(w[2527], t1, t2);
    }

    // XOR 2113 1308 -> 2528
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2113], w[1308]);
        mulmod(t2, w[2113], w[1308]);
        mulmod_constant(t2, t2, two);
        submod(w[2528], t1, t2);
    }

    // XOR 591 426 -> 2529
    {
        bn254fr_class t1, t2;
        addmod(t1, w[591], w[426]);
        mulmod(t2, w[591], w[426]);
        mulmod_constant(t2, t2, two);
        submod(w[2529], t1, t2);
    }

    // XOR 91 1308 -> 2530
    {
        bn254fr_class t1, t2;
        addmod(t1, w[91], w[1308]);
        mulmod(t2, w[91], w[1308]);
        mulmod_constant(t2, t2, two);
        submod(w[2530], t1, t2);
    }

    // XOR 1220 1174 -> 2531
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1220], w[1174]);
        mulmod(t2, w[1220], w[1174]);
        mulmod_constant(t2, t2, two);
        submod(w[2531], t1, t2);
    }

    // INV 466 -> 2532
    submod(w[2532], one, w[466]);

    // AND 1151 431 -> 2533
    mulmod(w[2533], w[1151], w[431]);

    // AND 1111 2340 -> 2534
    mulmod(w[2534], w[1111], w[2340]);

    // AND 1944 1148 -> 2535
    mulmod(w[2535], w[1944], w[1148]);

    // XOR 1273 889 -> 2536
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1273], w[889]);
        mulmod(t2, w[1273], w[889]);
        mulmod_constant(t2, t2, two);
        submod(w[2536], t1, t2);
    }

    // AND 1388 970 -> 2537
    mulmod(w[2537], w[1388], w[970]);

    // AND 214 393 -> 2538
    mulmod(w[2538], w[214], w[393]);

    // XOR 1842 263 -> 2539
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1842], w[263]);
        mulmod(t2, w[1842], w[263]);
        mulmod_constant(t2, t2, two);
        submod(w[2539], t1, t2);
    }

    // AND 414 1021 -> 2540
    mulmod(w[2540], w[414], w[1021]);

    // XOR 837 391 -> 2541
    {
        bn254fr_class t1, t2;
        addmod(t1, w[837], w[391]);
        mulmod(t2, w[837], w[391]);
        mulmod_constant(t2, t2, two);
        submod(w[2541], t1, t2);
    }

    // AND 2093 21 -> 2542
    mulmod(w[2542], w[2093], w[21]);

    // INV 1694 -> 2543
    submod(w[2543], one, w[1694]);

    // AND 1995 1952 -> 2544
    mulmod(w[2544], w[1995], w[1952]);

    // XOR 1865 2382 -> 2545
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1865], w[2382]);
        mulmod(t2, w[1865], w[2382]);
        mulmod_constant(t2, t2, two);
        submod(w[2545], t1, t2);
    }

    // XOR 105 917 -> 2546
    {
        bn254fr_class t1, t2;
        addmod(t1, w[105], w[917]);
        mulmod(t2, w[105], w[917]);
        mulmod_constant(t2, t2, two);
        submod(w[2546], t1, t2);
    }

    // AND 2195 330 -> 2547
    mulmod(w[2547], w[2195], w[330]);

    // AND 1860 2180 -> 2548
    mulmod(w[2548], w[1860], w[2180]);

    // AND 1804 1663 -> 2549
    mulmod(w[2549], w[1804], w[1663]);

    // XOR 801 539 -> 2550
    {
        bn254fr_class t1, t2;
        addmod(t1, w[801], w[539]);
        mulmod(t2, w[801], w[539]);
        mulmod_constant(t2, t2, two);
        submod(w[2550], t1, t2);
    }

    // AND 1717 706 -> 2551
    mulmod(w[2551], w[1717], w[706]);

    // AND 361 29 -> 2552
    mulmod(w[2552], w[361], w[29]);

    // XOR 1697 1674 -> 2553
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1697], w[1674]);
        mulmod(t2, w[1697], w[1674]);
        mulmod_constant(t2, t2, two);
        submod(w[2553], t1, t2);
    }

    // XOR 1617 1674 -> 2554
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1617], w[1674]);
        mulmod(t2, w[1617], w[1674]);
        mulmod_constant(t2, t2, two);
        submod(w[2554], t1, t2);
    }

    // AND 1304 1049 -> 2555
    mulmod(w[2555], w[1304], w[1049]);

    // XOR 1430 1832 -> 2556
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1430], w[1832]);
        mulmod(t2, w[1430], w[1832]);
        mulmod_constant(t2, t2, two);
        submod(w[2556], t1, t2);
    }

    // XOR 1757 2310 -> 2557
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1757], w[2310]);
        mulmod(t2, w[1757], w[2310]);
        mulmod_constant(t2, t2, two);
        submod(w[2557], t1, t2);
    }

    // XOR 462 555 -> 2558
    {
        bn254fr_class t1, t2;
        addmod(t1, w[462], w[555]);
        mulmod(t2, w[462], w[555]);
        mulmod_constant(t2, t2, two);
        submod(w[2558], t1, t2);
    }

    // INV 994 -> 2559
    submod(w[2559], one, w[994]);

    // INV 100 -> 2560
    submod(w[2560], one, w[100]);

    // INV 2011 -> 2561
    submod(w[2561], one, w[2011]);

    // XOR 447 1319 -> 2562
    {
        bn254fr_class t1, t2;
        addmod(t1, w[447], w[1319]);
        mulmod(t2, w[447], w[1319]);
        mulmod_constant(t2, t2, two);
        submod(w[2562], t1, t2);
    }

    // AND 1941 678 -> 2563
    mulmod(w[2563], w[1941], w[678]);

    // INV 2100 -> 2564
    submod(w[2564], one, w[2100]);

    // XOR 2034 75 -> 2565
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2034], w[75]);
        mulmod(t2, w[2034], w[75]);
        mulmod_constant(t2, t2, two);
        submod(w[2565], t1, t2);
    }

    // INV 652 -> 2566
    submod(w[2566], one, w[652]);

    // AND 1669 1483 -> 2567
    mulmod(w[2567], w[1669], w[1483]);

    // XOR 167 606 -> 2568
    {
        bn254fr_class t1, t2;
        addmod(t1, w[167], w[606]);
        mulmod(t2, w[167], w[606]);
        mulmod_constant(t2, t2, two);
        submod(w[2568], t1, t2);
    }

    // XOR 1541 1730 -> 2569
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1541], w[1730]);
        mulmod(t2, w[1541], w[1730]);
        mulmod_constant(t2, t2, two);
        submod(w[2569], t1, t2);
    }

    // XOR 1743 407 -> 2570
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1743], w[407]);
        mulmod(t2, w[1743], w[407]);
        mulmod_constant(t2, t2, two);
        submod(w[2570], t1, t2);
    }

    // XOR 2248 1545 -> 2571
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2248], w[1545]);
        mulmod(t2, w[2248], w[1545]);
        mulmod_constant(t2, t2, two);
        submod(w[2571], t1, t2);
    }

    // XOR 1405 1915 -> 2572
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1405], w[1915]);
        mulmod(t2, w[1405], w[1915]);
        mulmod_constant(t2, t2, two);
        submod(w[2572], t1, t2);
    }

    // INV 453 -> 2573
    submod(w[2573], one, w[453]);

    // INV 137 -> 2574
    submod(w[2574], one, w[137]);

    // AND 1926 1668 -> 2575
    mulmod(w[2575], w[1926], w[1668]);

    // INV 318 -> 2576
    submod(w[2576], one, w[318]);

    // AND 2059 822 -> 2577
    mulmod(w[2577], w[2059], w[822]);

    // AND 855 2346 -> 2578
    mulmod(w[2578], w[855], w[2346]);

    // AND 1092 2053 -> 2579
    mulmod(w[2579], w[1092], w[2053]);

    // XOR 2075 628 -> 2580
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2075], w[628]);
        mulmod(t2, w[2075], w[628]);
        mulmod_constant(t2, t2, two);
        submod(w[2580], t1, t2);
    }

    // XOR 1403 1479 -> 2581
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1403], w[1479]);
        mulmod(t2, w[1403], w[1479]);
        mulmod_constant(t2, t2, two);
        submod(w[2581], t1, t2);
    }

    // XOR 1893 1092 -> 2582
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1893], w[1092]);
        mulmod(t2, w[1893], w[1092]);
        mulmod_constant(t2, t2, two);
        submod(w[2582], t1, t2);
    }

    // XOR 149 303 -> 2583
    {
        bn254fr_class t1, t2;
        addmod(t1, w[149], w[303]);
        mulmod(t2, w[149], w[303]);
        mulmod_constant(t2, t2, two);
        submod(w[2583], t1, t2);
    }

    // XOR 446 1414 -> 2584
    {
        bn254fr_class t1, t2;
        addmod(t1, w[446], w[1414]);
        mulmod(t2, w[446], w[1414]);
        mulmod_constant(t2, t2, two);
        submod(w[2584], t1, t2);
    }

    // XOR 1795 1403 -> 2585
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1795], w[1403]);
        mulmod(t2, w[1795], w[1403]);
        mulmod_constant(t2, t2, two);
        submod(w[2585], t1, t2);
    }

    // AND 1317 65 -> 2586
    mulmod(w[2586], w[1317], w[65]);

    // AND 2012 1078 -> 2587
    mulmod(w[2587], w[2012], w[1078]);

    // XOR 1772 2383 -> 2588
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1772], w[2383]);
        mulmod(t2, w[1772], w[2383]);
        mulmod_constant(t2, t2, two);
        submod(w[2588], t1, t2);
    }

    // AND 1748 2425 -> 2589
    mulmod(w[2589], w[1748], w[2425]);

    // AND 1949 1007 -> 2590
    mulmod(w[2590], w[1949], w[1007]);

    // XOR 378 599 -> 2591
    {
        bn254fr_class t1, t2;
        addmod(t1, w[378], w[599]);
        mulmod(t2, w[378], w[599]);
        mulmod_constant(t2, t2, two);
        submod(w[2591], t1, t2);
    }

    // AND 1711 1806 -> 2592
    mulmod(w[2592], w[1711], w[1806]);

    // AND 1502 1221 -> 2593
    mulmod(w[2593], w[1502], w[1221]);

    // XOR 2062 2467 -> 2594
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2062], w[2467]);
        mulmod(t2, w[2062], w[2467]);
        mulmod_constant(t2, t2, two);
        submod(w[2594], t1, t2);
    }

    // XOR 2136 918 -> 2595
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2136], w[918]);
        mulmod(t2, w[2136], w[918]);
        mulmod_constant(t2, t2, two);
        submod(w[2595], t1, t2);
    }

    // AND 714 87 -> 2596
    mulmod(w[2596], w[714], w[87]);

    // XOR 174 1326 -> 2597
    {
        bn254fr_class t1, t2;
        addmod(t1, w[174], w[1326]);
        mulmod(t2, w[174], w[1326]);
        mulmod_constant(t2, t2, two);
        submod(w[2597], t1, t2);
    }

    // INV 1090 -> 2598
    submod(w[2598], one, w[1090]);

    // AND 2100 910 -> 2599
    mulmod(w[2599], w[2100], w[910]);

    // XOR 1177 512 -> 2600
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1177], w[512]);
        mulmod(t2, w[1177], w[512]);
        mulmod_constant(t2, t2, two);
        submod(w[2600], t1, t2);
    }

    // AND 94 1450 -> 2601
    mulmod(w[2601], w[94], w[1450]);

    // AND 1000 1924 -> 2602
    mulmod(w[2602], w[1000], w[1924]);

    // AND 2283 1828 -> 2603
    mulmod(w[2603], w[2283], w[1828]);

    // XOR 810 61 -> 2604
    {
        bn254fr_class t1, t2;
        addmod(t1, w[810], w[61]);
        mulmod(t2, w[810], w[61]);
        mulmod_constant(t2, t2, two);
        submod(w[2604], t1, t2);
    }

    // XOR 1151 368 -> 2605
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1151], w[368]);
        mulmod(t2, w[1151], w[368]);
        mulmod_constant(t2, t2, two);
        submod(w[2605], t1, t2);
    }

    // AND 1455 2380 -> 2606
    mulmod(w[2606], w[1455], w[2380]);

    // AND 2604 2102 -> 2607
    mulmod(w[2607], w[2604], w[2102]);

    // AND 413 1533 -> 2608
    mulmod(w[2608], w[413], w[1533]);

    // AND 2528 2590 -> 2609
    mulmod(w[2609], w[2528], w[2590]);

    // AND 2441 811 -> 2610
    mulmod(w[2610], w[2441], w[811]);

    // XOR 2147 1873 -> 2611
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2147], w[1873]);
        mulmod(t2, w[2147], w[1873]);
        mulmod_constant(t2, t2, two);
        submod(w[2611], t1, t2);
    }

    // XOR 2423 787 -> 2612
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2423], w[787]);
        mulmod(t2, w[2423], w[787]);
        mulmod_constant(t2, t2, two);
        submod(w[2612], t1, t2);
    }

    // INV 664 -> 2613
    submod(w[2613], one, w[664]);

    // AND 1285 983 -> 2614
    mulmod(w[2614], w[1285], w[983]);

    // AND 1305 142 -> 2615
    mulmod(w[2615], w[1305], w[142]);

    // XOR 1324 132 -> 2616
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1324], w[132]);
        mulmod(t2, w[1324], w[132]);
        mulmod_constant(t2, t2, two);
        submod(w[2616], t1, t2);
    }

    // AND 1770 213 -> 2617
    mulmod(w[2617], w[1770], w[213]);

    // XOR 1966 1128 -> 2618
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1966], w[1128]);
        mulmod(t2, w[1966], w[1128]);
        mulmod_constant(t2, t2, two);
        submod(w[2618], t1, t2);
    }

    // XOR 1936 2296 -> 2619
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1936], w[2296]);
        mulmod(t2, w[1936], w[2296]);
        mulmod_constant(t2, t2, two);
        submod(w[2619], t1, t2);
    }

    // AND 2331 183 -> 2620
    mulmod(w[2620], w[2331], w[183]);

    // XOR 34 2070 -> 2621
    {
        bn254fr_class t1, t2;
        addmod(t1, w[34], w[2070]);
        mulmod(t2, w[34], w[2070]);
        mulmod_constant(t2, t2, two);
        submod(w[2621], t1, t2);
    }

    // AND 1239 2129 -> 2622
    mulmod(w[2622], w[1239], w[2129]);

    // XOR 1398 833 -> 2623
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1398], w[833]);
        mulmod(t2, w[1398], w[833]);
        mulmod_constant(t2, t2, two);
        submod(w[2623], t1, t2);
    }

    // XOR 1637 2284 -> 2624
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1637], w[2284]);
        mulmod(t2, w[1637], w[2284]);
        mulmod_constant(t2, t2, two);
        submod(w[2624], t1, t2);
    }

    // AND 2226 918 -> 2625
    mulmod(w[2625], w[2226], w[918]);

    // AND 39 2140 -> 2626
    mulmod(w[2626], w[39], w[2140]);

    // AND 685 2492 -> 2627
    mulmod(w[2627], w[685], w[2492]);

    // AND 208 1119 -> 2628
    mulmod(w[2628], w[208], w[1119]);

    // XOR 1749 1668 -> 2629
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1749], w[1668]);
        mulmod(t2, w[1749], w[1668]);
        mulmod_constant(t2, t2, two);
        submod(w[2629], t1, t2);
    }

    // AND 780 2544 -> 2630
    mulmod(w[2630], w[780], w[2544]);

    // XOR 1140 1435 -> 2631
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1140], w[1435]);
        mulmod(t2, w[1140], w[1435]);
        mulmod_constant(t2, t2, two);
        submod(w[2631], t1, t2);
    }

    // XOR 777 2088 -> 2632
    {
        bn254fr_class t1, t2;
        addmod(t1, w[777], w[2088]);
        mulmod(t2, w[777], w[2088]);
        mulmod_constant(t2, t2, two);
        submod(w[2632], t1, t2);
    }

    // AND 920 1944 -> 2633
    mulmod(w[2633], w[920], w[1944]);

    // XOR 2442 1606 -> 2634
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2442], w[1606]);
        mulmod(t2, w[2442], w[1606]);
        mulmod_constant(t2, t2, two);
        submod(w[2634], t1, t2);
    }

    // AND 663 2322 -> 2635
    mulmod(w[2635], w[663], w[2322]);

    // AND 497 150 -> 2636
    mulmod(w[2636], w[497], w[150]);

    // AND 1801 53 -> 2637
    mulmod(w[2637], w[1801], w[53]);

    // AND 2486 946 -> 2638
    mulmod(w[2638], w[2486], w[946]);

    // INV 1508 -> 2639
    submod(w[2639], one, w[1508]);

    // AND 311 471 -> 2640
    mulmod(w[2640], w[311], w[471]);

    // AND 75 2336 -> 2641
    mulmod(w[2641], w[75], w[2336]);

    // AND 806 393 -> 2642
    mulmod(w[2642], w[806], w[393]);

    // XOR 96 2455 -> 2643
    {
        bn254fr_class t1, t2;
        addmod(t1, w[96], w[2455]);
        mulmod(t2, w[96], w[2455]);
        mulmod_constant(t2, t2, two);
        submod(w[2643], t1, t2);
    }

    // AND 1326 237 -> 2644
    mulmod(w[2644], w[1326], w[237]);

    // XOR 1336 522 -> 2645
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1336], w[522]);
        mulmod(t2, w[1336], w[522]);
        mulmod_constant(t2, t2, two);
        submod(w[2645], t1, t2);
    }

    // INV 112 -> 2646
    submod(w[2646], one, w[112]);

    // AND 181 1891 -> 2647
    mulmod(w[2647], w[181], w[1891]);

    // INV 2218 -> 2648
    submod(w[2648], one, w[2218]);

    // XOR 2573 2235 -> 2649
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2573], w[2235]);
        mulmod(t2, w[2573], w[2235]);
        mulmod_constant(t2, t2, two);
        submod(w[2649], t1, t2);
    }

    // AND 838 755 -> 2650
    mulmod(w[2650], w[838], w[755]);

    // XOR 2554 1314 -> 2651
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2554], w[1314]);
        mulmod(t2, w[2554], w[1314]);
        mulmod_constant(t2, t2, two);
        submod(w[2651], t1, t2);
    }

    // XOR 184 577 -> 2652
    {
        bn254fr_class t1, t2;
        addmod(t1, w[184], w[577]);
        mulmod(t2, w[184], w[577]);
        mulmod_constant(t2, t2, two);
        submod(w[2652], t1, t2);
    }

    // AND 410 1681 -> 2653
    mulmod(w[2653], w[410], w[1681]);

    // AND 674 314 -> 2654
    mulmod(w[2654], w[674], w[314]);

    // AND 712 542 -> 2655
    mulmod(w[2655], w[712], w[542]);

    // AND 1974 408 -> 2656
    mulmod(w[2656], w[1974], w[408]);

    // AND 2142 1734 -> 2657
    mulmod(w[2657], w[2142], w[1734]);

    // XOR 1708 911 -> 2658
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1708], w[911]);
        mulmod(t2, w[1708], w[911]);
        mulmod_constant(t2, t2, two);
        submod(w[2658], t1, t2);
    }

    // XOR 1466 2001 -> 2659
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1466], w[2001]);
        mulmod(t2, w[1466], w[2001]);
        mulmod_constant(t2, t2, two);
        submod(w[2659], t1, t2);
    }

    // AND 717 2031 -> 2660
    mulmod(w[2660], w[717], w[2031]);

    // XOR 147 2222 -> 2661
    {
        bn254fr_class t1, t2;
        addmod(t1, w[147], w[2222]);
        mulmod(t2, w[147], w[2222]);
        mulmod_constant(t2, t2, two);
        submod(w[2661], t1, t2);
    }

    // XOR 883 2088 -> 2662
    {
        bn254fr_class t1, t2;
        addmod(t1, w[883], w[2088]);
        mulmod(t2, w[883], w[2088]);
        mulmod_constant(t2, t2, two);
        submod(w[2662], t1, t2);
    }

    // XOR 1204 1055 -> 2663
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1204], w[1055]);
        mulmod(t2, w[1204], w[1055]);
        mulmod_constant(t2, t2, two);
        submod(w[2663], t1, t2);
    }

    // XOR 2299 2262 -> 2664
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2299], w[2262]);
        mulmod(t2, w[2299], w[2262]);
        mulmod_constant(t2, t2, two);
        submod(w[2664], t1, t2);
    }

    // XOR 2280 1530 -> 2665
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2280], w[1530]);
        mulmod(t2, w[2280], w[1530]);
        mulmod_constant(t2, t2, two);
        submod(w[2665], t1, t2);
    }

    // XOR 1469 787 -> 2666
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1469], w[787]);
        mulmod(t2, w[1469], w[787]);
        mulmod_constant(t2, t2, two);
        submod(w[2666], t1, t2);
    }

    // XOR 1051 656 -> 2667
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1051], w[656]);
        mulmod(t2, w[1051], w[656]);
        mulmod_constant(t2, t2, two);
        submod(w[2667], t1, t2);
    }

    // INV 2 -> 2668
    submod(w[2668], one, w[2]);

    // XOR 327 865 -> 2669
    {
        bn254fr_class t1, t2;
        addmod(t1, w[327], w[865]);
        mulmod(t2, w[327], w[865]);
        mulmod_constant(t2, t2, two);
        submod(w[2669], t1, t2);
    }

    // XOR 1338 1110 -> 2670
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1338], w[1110]);
        mulmod(t2, w[1338], w[1110]);
        mulmod_constant(t2, t2, two);
        submod(w[2670], t1, t2);
    }

    // AND 473 55 -> 2671
    mulmod(w[2671], w[473], w[55]);

    // XOR 1879 1100 -> 2672
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1879], w[1100]);
        mulmod(t2, w[1879], w[1100]);
        mulmod_constant(t2, t2, two);
        submod(w[2672], t1, t2);
    }

    // AND 591 1184 -> 2673
    mulmod(w[2673], w[591], w[1184]);

    // XOR 1855 1150 -> 2674
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1855], w[1150]);
        mulmod(t2, w[1855], w[1150]);
        mulmod_constant(t2, t2, two);
        submod(w[2674], t1, t2);
    }

    // AND 328 1381 -> 2675
    mulmod(w[2675], w[328], w[1381]);

    // XOR 1962 1870 -> 2676
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1962], w[1870]);
        mulmod(t2, w[1962], w[1870]);
        mulmod_constant(t2, t2, two);
        submod(w[2676], t1, t2);
    }

    // AND 1859 1666 -> 2677
    mulmod(w[2677], w[1859], w[1666]);

    // AND 169 1165 -> 2678
    mulmod(w[2678], w[169], w[1165]);

    // AND 2122 1970 -> 2679
    mulmod(w[2679], w[2122], w[1970]);

    // AND 1049 2508 -> 2680
    mulmod(w[2680], w[1049], w[2508]);

    // XOR 1076 2349 -> 2681
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1076], w[2349]);
        mulmod(t2, w[1076], w[2349]);
        mulmod_constant(t2, t2, two);
        submod(w[2681], t1, t2);
    }

    // XOR 945 1887 -> 2682
    {
        bn254fr_class t1, t2;
        addmod(t1, w[945], w[1887]);
        mulmod(t2, w[945], w[1887]);
        mulmod_constant(t2, t2, two);
        submod(w[2682], t1, t2);
    }

    // XOR 2052 47 -> 2683
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2052], w[47]);
        mulmod(t2, w[2052], w[47]);
        mulmod_constant(t2, t2, two);
        submod(w[2683], t1, t2);
    }

    // XOR 2429 1824 -> 2684
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2429], w[1824]);
        mulmod(t2, w[2429], w[1824]);
        mulmod_constant(t2, t2, two);
        submod(w[2684], t1, t2);
    }

    // XOR 20 1883 -> 2685
    {
        bn254fr_class t1, t2;
        addmod(t1, w[20], w[1883]);
        mulmod(t2, w[20], w[1883]);
        mulmod_constant(t2, t2, two);
        submod(w[2685], t1, t2);
    }

    // XOR 1293 1625 -> 2686
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1293], w[1625]);
        mulmod(t2, w[1293], w[1625]);
        mulmod_constant(t2, t2, two);
        submod(w[2686], t1, t2);
    }

    // XOR 338 512 -> 2687
    {
        bn254fr_class t1, t2;
        addmod(t1, w[338], w[512]);
        mulmod(t2, w[338], w[512]);
        mulmod_constant(t2, t2, two);
        submod(w[2687], t1, t2);
    }

    // XOR 1559 2209 -> 2688
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1559], w[2209]);
        mulmod(t2, w[1559], w[2209]);
        mulmod_constant(t2, t2, two);
        submod(w[2688], t1, t2);
    }

    // INV 1020 -> 2689
    submod(w[2689], one, w[1020]);

    // XOR 933 2573 -> 2690
    {
        bn254fr_class t1, t2;
        addmod(t1, w[933], w[2573]);
        mulmod(t2, w[933], w[2573]);
        mulmod_constant(t2, t2, two);
        submod(w[2690], t1, t2);
    }

    // AND 1549 759 -> 2691
    mulmod(w[2691], w[1549], w[759]);

    // AND 2434 1801 -> 2692
    mulmod(w[2692], w[2434], w[1801]);

    // XOR 1922 954 -> 2693
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1922], w[954]);
        mulmod(t2, w[1922], w[954]);
        mulmod_constant(t2, t2, two);
        submod(w[2693], t1, t2);
    }

    // AND 660 2444 -> 2694
    mulmod(w[2694], w[660], w[2444]);

    // XOR 474 1663 -> 2695
    {
        bn254fr_class t1, t2;
        addmod(t1, w[474], w[1663]);
        mulmod(t2, w[474], w[1663]);
        mulmod_constant(t2, t2, two);
        submod(w[2695], t1, t2);
    }

    // XOR 323 159 -> 2696
    {
        bn254fr_class t1, t2;
        addmod(t1, w[323], w[159]);
        mulmod(t2, w[323], w[159]);
        mulmod_constant(t2, t2, two);
        submod(w[2696], t1, t2);
    }

    // AND 2108 1307 -> 2697
    mulmod(w[2697], w[2108], w[1307]);

    // XOR 1729 2348 -> 2698
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1729], w[2348]);
        mulmod(t2, w[1729], w[2348]);
        mulmod_constant(t2, t2, two);
        submod(w[2698], t1, t2);
    }

    // XOR 654 758 -> 2699
    {
        bn254fr_class t1, t2;
        addmod(t1, w[654], w[758]);
        mulmod(t2, w[654], w[758]);
        mulmod_constant(t2, t2, two);
        submod(w[2699], t1, t2);
    }

    // AND 53 1899 -> 2700
    mulmod(w[2700], w[53], w[1899]);

    // XOR 1661 436 -> 2701
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1661], w[436]);
        mulmod(t2, w[1661], w[436]);
        mulmod_constant(t2, t2, two);
        submod(w[2701], t1, t2);
    }

    // AND 2493 43 -> 2702
    mulmod(w[2702], w[2493], w[43]);

    // XOR 1258 718 -> 2703
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1258], w[718]);
        mulmod(t2, w[1258], w[718]);
        mulmod_constant(t2, t2, two);
        submod(w[2703], t1, t2);
    }

    // AND 990 1084 -> 2704
    mulmod(w[2704], w[990], w[1084]);

    // INV 2386 -> 2705
    submod(w[2705], one, w[2386]);

    // AND 559 2496 -> 2706
    mulmod(w[2706], w[559], w[2496]);

    // INV 2667 -> 2707
    submod(w[2707], one, w[2667]);

    // AND 66 877 -> 2708
    mulmod(w[2708], w[66], w[877]);

    // XOR 1727 163 -> 2709
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1727], w[163]);
        mulmod(t2, w[1727], w[163]);
        mulmod_constant(t2, t2, two);
        submod(w[2709], t1, t2);
    }

    // XOR 1324 1639 -> 2710
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1324], w[1639]);
        mulmod(t2, w[1324], w[1639]);
        mulmod_constant(t2, t2, two);
        submod(w[2710], t1, t2);
    }

    // AND 1164 562 -> 2711
    mulmod(w[2711], w[1164], w[562]);

    // AND 511 893 -> 2712
    mulmod(w[2712], w[511], w[893]);

    // XOR 227 1374 -> 2713
    {
        bn254fr_class t1, t2;
        addmod(t1, w[227], w[1374]);
        mulmod(t2, w[227], w[1374]);
        mulmod_constant(t2, t2, two);
        submod(w[2713], t1, t2);
    }

    // AND 34 2074 -> 2714
    mulmod(w[2714], w[34], w[2074]);

    // AND 653 1307 -> 2715
    mulmod(w[2715], w[653], w[1307]);

    // XOR 2472 1831 -> 2716
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2472], w[1831]);
        mulmod(t2, w[2472], w[1831]);
        mulmod_constant(t2, t2, two);
        submod(w[2716], t1, t2);
    }

    // XOR 205 766 -> 2717
    {
        bn254fr_class t1, t2;
        addmod(t1, w[205], w[766]);
        mulmod(t2, w[205], w[766]);
        mulmod_constant(t2, t2, two);
        submod(w[2717], t1, t2);
    }

    // XOR 1396 1692 -> 2718
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1396], w[1692]);
        mulmod(t2, w[1396], w[1692]);
        mulmod_constant(t2, t2, two);
        submod(w[2718], t1, t2);
    }

    // XOR 2358 641 -> 2719
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2358], w[641]);
        mulmod(t2, w[2358], w[641]);
        mulmod_constant(t2, t2, two);
        submod(w[2719], t1, t2);
    }

    // XOR 62 2264 -> 2720
    {
        bn254fr_class t1, t2;
        addmod(t1, w[62], w[2264]);
        mulmod(t2, w[62], w[2264]);
        mulmod_constant(t2, t2, two);
        submod(w[2720], t1, t2);
    }

    // XOR 1278 1978 -> 2721
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1278], w[1978]);
        mulmod(t2, w[1278], w[1978]);
        mulmod_constant(t2, t2, two);
        submod(w[2721], t1, t2);
    }

    // XOR 2020 261 -> 2722
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2020], w[261]);
        mulmod(t2, w[2020], w[261]);
        mulmod_constant(t2, t2, two);
        submod(w[2722], t1, t2);
    }

    // INV 1545 -> 2723
    submod(w[2723], one, w[1545]);

    // AND 993 1625 -> 2724
    mulmod(w[2724], w[993], w[1625]);

    // XOR 2602 1259 -> 2725
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2602], w[1259]);
        mulmod(t2, w[2602], w[1259]);
        mulmod_constant(t2, t2, two);
        submod(w[2725], t1, t2);
    }

    // XOR 519 105 -> 2726
    {
        bn254fr_class t1, t2;
        addmod(t1, w[519], w[105]);
        mulmod(t2, w[519], w[105]);
        mulmod_constant(t2, t2, two);
        submod(w[2726], t1, t2);
    }

    // XOR 1347 897 -> 2727
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1347], w[897]);
        mulmod(t2, w[1347], w[897]);
        mulmod_constant(t2, t2, two);
        submod(w[2727], t1, t2);
    }

    // XOR 476 2190 -> 2728
    {
        bn254fr_class t1, t2;
        addmod(t1, w[476], w[2190]);
        mulmod(t2, w[476], w[2190]);
        mulmod_constant(t2, t2, two);
        submod(w[2728], t1, t2);
    }

    // INV 1821 -> 2729
    submod(w[2729], one, w[1821]);

    // AND 2576 1020 -> 2730
    mulmod(w[2730], w[2576], w[1020]);

    // AND 944 2402 -> 2731
    mulmod(w[2731], w[944], w[2402]);

    // XOR 1575 2611 -> 2732
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1575], w[2611]);
        mulmod(t2, w[1575], w[2611]);
        mulmod_constant(t2, t2, two);
        submod(w[2732], t1, t2);
    }

    // XOR 2307 1875 -> 2733
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2307], w[1875]);
        mulmod(t2, w[2307], w[1875]);
        mulmod_constant(t2, t2, two);
        submod(w[2733], t1, t2);
    }

    // XOR 289 2661 -> 2734
    {
        bn254fr_class t1, t2;
        addmod(t1, w[289], w[2661]);
        mulmod(t2, w[289], w[2661]);
        mulmod_constant(t2, t2, two);
        submod(w[2734], t1, t2);
    }

    // XOR 870 77 -> 2735
    {
        bn254fr_class t1, t2;
        addmod(t1, w[870], w[77]);
        mulmod(t2, w[870], w[77]);
        mulmod_constant(t2, t2, two);
        submod(w[2735], t1, t2);
    }

    // XOR 1198 971 -> 2736
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1198], w[971]);
        mulmod(t2, w[1198], w[971]);
        mulmod_constant(t2, t2, two);
        submod(w[2736], t1, t2);
    }

    // XOR 1570 1853 -> 2737
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1570], w[1853]);
        mulmod(t2, w[1570], w[1853]);
        mulmod_constant(t2, t2, two);
        submod(w[2737], t1, t2);
    }

    // AND 261 1241 -> 2738
    mulmod(w[2738], w[261], w[1241]);

    // XOR 834 2541 -> 2739
    {
        bn254fr_class t1, t2;
        addmod(t1, w[834], w[2541]);
        mulmod(t2, w[834], w[2541]);
        mulmod_constant(t2, t2, two);
        submod(w[2739], t1, t2);
    }

    // XOR 2589 425 -> 2740
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2589], w[425]);
        mulmod(t2, w[2589], w[425]);
        mulmod_constant(t2, t2, two);
        submod(w[2740], t1, t2);
    }

    // AND 595 2548 -> 2741
    mulmod(w[2741], w[595], w[2548]);

    // XOR 399 1874 -> 2742
    {
        bn254fr_class t1, t2;
        addmod(t1, w[399], w[1874]);
        mulmod(t2, w[399], w[1874]);
        mulmod_constant(t2, t2, two);
        submod(w[2742], t1, t2);
    }

    // XOR 429 1327 -> 2743
    {
        bn254fr_class t1, t2;
        addmod(t1, w[429], w[1327]);
        mulmod(t2, w[429], w[1327]);
        mulmod_constant(t2, t2, two);
        submod(w[2743], t1, t2);
    }

    // XOR 1651 1278 -> 2744
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1651], w[1278]);
        mulmod(t2, w[1651], w[1278]);
        mulmod_constant(t2, t2, two);
        submod(w[2744], t1, t2);
    }

    // XOR 1859 1807 -> 2745
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1859], w[1807]);
        mulmod(t2, w[1859], w[1807]);
        mulmod_constant(t2, t2, two);
        submod(w[2745], t1, t2);
    }

    // XOR 1147 789 -> 2746
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1147], w[789]);
        mulmod(t2, w[1147], w[789]);
        mulmod_constant(t2, t2, two);
        submod(w[2746], t1, t2);
    }

    // XOR 2017 1255 -> 2747
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2017], w[1255]);
        mulmod(t2, w[2017], w[1255]);
        mulmod_constant(t2, t2, two);
        submod(w[2747], t1, t2);
    }

    // XOR 1846 1142 -> 2748
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1846], w[1142]);
        mulmod(t2, w[1846], w[1142]);
        mulmod_constant(t2, t2, two);
        submod(w[2748], t1, t2);
    }

    // AND 1785 2178 -> 2749
    mulmod(w[2749], w[1785], w[2178]);

    // XOR 77 682 -> 2750
    {
        bn254fr_class t1, t2;
        addmod(t1, w[77], w[682]);
        mulmod(t2, w[77], w[682]);
        mulmod_constant(t2, t2, two);
        submod(w[2750], t1, t2);
    }

    // INV 1433 -> 2751
    submod(w[2751], one, w[1433]);

    // XOR 1800 671 -> 2752
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1800], w[671]);
        mulmod(t2, w[1800], w[671]);
        mulmod_constant(t2, t2, two);
        submod(w[2752], t1, t2);
    }

    // INV 252 -> 2753
    submod(w[2753], one, w[252]);

    // AND 2127 2524 -> 2754
    mulmod(w[2754], w[2127], w[2524]);

    // XOR 2030 715 -> 2755
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2030], w[715]);
        mulmod(t2, w[2030], w[715]);
        mulmod_constant(t2, t2, two);
        submod(w[2755], t1, t2);
    }

    // XOR 896 158 -> 2756
    {
        bn254fr_class t1, t2;
        addmod(t1, w[896], w[158]);
        mulmod(t2, w[896], w[158]);
        mulmod_constant(t2, t2, two);
        submod(w[2756], t1, t2);
    }

    // AND 2159 2114 -> 2757
    mulmod(w[2757], w[2159], w[2114]);

    // XOR 191 447 -> 2758
    {
        bn254fr_class t1, t2;
        addmod(t1, w[191], w[447]);
        mulmod(t2, w[191], w[447]);
        mulmod_constant(t2, t2, two);
        submod(w[2758], t1, t2);
    }

    // AND 895 2344 -> 2759
    mulmod(w[2759], w[895], w[2344]);

    // AND 468 1610 -> 2760
    mulmod(w[2760], w[468], w[1610]);

    // XOR 1234 2510 -> 2761
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1234], w[2510]);
        mulmod(t2, w[1234], w[2510]);
        mulmod_constant(t2, t2, two);
        submod(w[2761], t1, t2);
    }

    // XOR 46 2237 -> 2762
    {
        bn254fr_class t1, t2;
        addmod(t1, w[46], w[2237]);
        mulmod(t2, w[46], w[2237]);
        mulmod_constant(t2, t2, two);
        submod(w[2762], t1, t2);
    }

    // AND 1630 2231 -> 2763
    mulmod(w[2763], w[1630], w[2231]);

    // XOR 1891 620 -> 2764
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1891], w[620]);
        mulmod(t2, w[1891], w[620]);
        mulmod_constant(t2, t2, two);
        submod(w[2764], t1, t2);
    }

    // AND 2062 918 -> 2765
    mulmod(w[2765], w[2062], w[918]);

    // AND 287 981 -> 2766
    mulmod(w[2766], w[287], w[981]);

    // INV 625 -> 2767
    submod(w[2767], one, w[625]);

    // AND 189 559 -> 2768
    mulmod(w[2768], w[189], w[559]);

    // XOR 611 212 -> 2769
    {
        bn254fr_class t1, t2;
        addmod(t1, w[611], w[212]);
        mulmod(t2, w[611], w[212]);
        mulmod_constant(t2, t2, two);
        submod(w[2769], t1, t2);
    }

    // AND 88 840 -> 2770
    mulmod(w[2770], w[88], w[840]);

    // XOR 1509 1090 -> 2771
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1509], w[1090]);
        mulmod(t2, w[1509], w[1090]);
        mulmod_constant(t2, t2, two);
        submod(w[2771], t1, t2);
    }

    // AND 2691 2404 -> 2772
    mulmod(w[2772], w[2691], w[2404]);

    // AND 1355 2335 -> 2773
    mulmod(w[2773], w[1355], w[2335]);

    // XOR 180 1947 -> 2774
    {
        bn254fr_class t1, t2;
        addmod(t1, w[180], w[1947]);
        mulmod(t2, w[180], w[1947]);
        mulmod_constant(t2, t2, two);
        submod(w[2774], t1, t2);
    }

    // AND 1223 97 -> 2775
    mulmod(w[2775], w[1223], w[97]);

    // XOR 2420 449 -> 2776
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2420], w[449]);
        mulmod(t2, w[2420], w[449]);
        mulmod_constant(t2, t2, two);
        submod(w[2776], t1, t2);
    }

    // AND 203 1319 -> 2777
    mulmod(w[2777], w[203], w[1319]);

    // XOR 282 1881 -> 2778
    {
        bn254fr_class t1, t2;
        addmod(t1, w[282], w[1881]);
        mulmod(t2, w[282], w[1881]);
        mulmod_constant(t2, t2, two);
        submod(w[2778], t1, t2);
    }

    // XOR 1559 2097 -> 2779
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1559], w[2097]);
        mulmod(t2, w[1559], w[2097]);
        mulmod_constant(t2, t2, two);
        submod(w[2779], t1, t2);
    }

    // AND 612 2117 -> 2780
    mulmod(w[2780], w[612], w[2117]);

    // XOR 89 908 -> 2781
    {
        bn254fr_class t1, t2;
        addmod(t1, w[89], w[908]);
        mulmod(t2, w[89], w[908]);
        mulmod_constant(t2, t2, two);
        submod(w[2781], t1, t2);
    }

    // XOR 2134 1338 -> 2782
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2134], w[1338]);
        mulmod(t2, w[2134], w[1338]);
        mulmod_constant(t2, t2, two);
        submod(w[2782], t1, t2);
    }

    // XOR 1003 997 -> 2783
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1003], w[997]);
        mulmod(t2, w[1003], w[997]);
        mulmod_constant(t2, t2, two);
        submod(w[2783], t1, t2);
    }

    // AND 790 1498 -> 2784
    mulmod(w[2784], w[790], w[1498]);

    // XOR 2508 1769 -> 2785
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2508], w[1769]);
        mulmod(t2, w[2508], w[1769]);
        mulmod_constant(t2, t2, two);
        submod(w[2785], t1, t2);
    }

    // XOR 2635 1307 -> 2786
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2635], w[1307]);
        mulmod(t2, w[2635], w[1307]);
        mulmod_constant(t2, t2, two);
        submod(w[2786], t1, t2);
    }

    // XOR 954 2647 -> 2787
    {
        bn254fr_class t1, t2;
        addmod(t1, w[954], w[2647]);
        mulmod(t2, w[954], w[2647]);
        mulmod_constant(t2, t2, two);
        submod(w[2787], t1, t2);
    }

    // XOR 947 753 -> 2788
    {
        bn254fr_class t1, t2;
        addmod(t1, w[947], w[753]);
        mulmod(t2, w[947], w[753]);
        mulmod_constant(t2, t2, two);
        submod(w[2788], t1, t2);
    }

    // XOR 2436 2474 -> 2789
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2436], w[2474]);
        mulmod(t2, w[2436], w[2474]);
        mulmod_constant(t2, t2, two);
        submod(w[2789], t1, t2);
    }

    // XOR 90 1606 -> 2790
    {
        bn254fr_class t1, t2;
        addmod(t1, w[90], w[1606]);
        mulmod(t2, w[90], w[1606]);
        mulmod_constant(t2, t2, two);
        submod(w[2790], t1, t2);
    }

    // AND 1080 2679 -> 2791
    mulmod(w[2791], w[1080], w[2679]);

    // AND 1586 2568 -> 2792
    mulmod(w[2792], w[1586], w[2568]);

    // AND 1391 2633 -> 2793
    mulmod(w[2793], w[1391], w[2633]);

    // INV 1411 -> 2794
    submod(w[2794], one, w[1411]);

    // AND 1218 1701 -> 2795
    mulmod(w[2795], w[1218], w[1701]);

    // XOR 2348 1977 -> 2796
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2348], w[1977]);
        mulmod(t2, w[2348], w[1977]);
        mulmod_constant(t2, t2, two);
        submod(w[2796], t1, t2);
    }

    // XOR 1357 1825 -> 2797
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1357], w[1825]);
        mulmod(t2, w[1357], w[1825]);
        mulmod_constant(t2, t2, two);
        submod(w[2797], t1, t2);
    }

    // XOR 2060 1471 -> 2798
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2060], w[1471]);
        mulmod(t2, w[2060], w[1471]);
        mulmod_constant(t2, t2, two);
        submod(w[2798], t1, t2);
    }

    // XOR 2015 516 -> 2799
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2015], w[516]);
        mulmod(t2, w[2015], w[516]);
        mulmod_constant(t2, t2, two);
        submod(w[2799], t1, t2);
    }

    // XOR 2114 1767 -> 2800
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2114], w[1767]);
        mulmod(t2, w[2114], w[1767]);
        mulmod_constant(t2, t2, two);
        submod(w[2800], t1, t2);
    }

    // AND 1117 1243 -> 2801
    mulmod(w[2801], w[1117], w[1243]);

    // XOR 286 186 -> 2802
    {
        bn254fr_class t1, t2;
        addmod(t1, w[286], w[186]);
        mulmod(t2, w[286], w[186]);
        mulmod_constant(t2, t2, two);
        submod(w[2802], t1, t2);
    }

    // XOR 1572 1988 -> 2803
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1572], w[1988]);
        mulmod(t2, w[1572], w[1988]);
        mulmod_constant(t2, t2, two);
        submod(w[2803], t1, t2);
    }

    // XOR 1911 748 -> 2804
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1911], w[748]);
        mulmod(t2, w[1911], w[748]);
        mulmod_constant(t2, t2, two);
        submod(w[2804], t1, t2);
    }

    // AND 392 120 -> 2805
    mulmod(w[2805], w[392], w[120]);

    // XOR 1989 2052 -> 2806
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1989], w[2052]);
        mulmod(t2, w[1989], w[2052]);
        mulmod_constant(t2, t2, two);
        submod(w[2806], t1, t2);
    }

    // AND 770 495 -> 2807
    mulmod(w[2807], w[770], w[495]);

    // XOR 1887 2409 -> 2808
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1887], w[2409]);
        mulmod(t2, w[1887], w[2409]);
        mulmod_constant(t2, t2, two);
        submod(w[2808], t1, t2);
    }

    // XOR 1492 406 -> 2809
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1492], w[406]);
        mulmod(t2, w[1492], w[406]);
        mulmod_constant(t2, t2, two);
        submod(w[2809], t1, t2);
    }

    // AND 1917 240 -> 2810
    mulmod(w[2810], w[1917], w[240]);

    // XOR 1839 1072 -> 2811
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1839], w[1072]);
        mulmod(t2, w[1839], w[1072]);
        mulmod_constant(t2, t2, two);
        submod(w[2811], t1, t2);
    }

    // XOR 2070 1666 -> 2812
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2070], w[1666]);
        mulmod(t2, w[2070], w[1666]);
        mulmod_constant(t2, t2, two);
        submod(w[2812], t1, t2);
    }

    // XOR 1033 2588 -> 2813
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1033], w[2588]);
        mulmod(t2, w[1033], w[2588]);
        mulmod_constant(t2, t2, two);
        submod(w[2813], t1, t2);
    }

    // XOR 2345 2414 -> 2814
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2345], w[2414]);
        mulmod(t2, w[2345], w[2414]);
        mulmod_constant(t2, t2, two);
        submod(w[2814], t1, t2);
    }

    // AND 638 475 -> 2815
    mulmod(w[2815], w[638], w[475]);

    // XOR 19 1663 -> 2816
    {
        bn254fr_class t1, t2;
        addmod(t1, w[19], w[1663]);
        mulmod(t2, w[19], w[1663]);
        mulmod_constant(t2, t2, two);
        submod(w[2816], t1, t2);
    }

    // AND 1706 1720 -> 2817
    mulmod(w[2817], w[1706], w[1720]);

    // XOR 487 529 -> 2818
    {
        bn254fr_class t1, t2;
        addmod(t1, w[487], w[529]);
        mulmod(t2, w[487], w[529]);
        mulmod_constant(t2, t2, two);
        submod(w[2818], t1, t2);
    }

    // INV 837 -> 2819
    submod(w[2819], one, w[837]);

    // XOR 2543 2351 -> 2820
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2543], w[2351]);
        mulmod(t2, w[2543], w[2351]);
        mulmod_constant(t2, t2, two);
        submod(w[2820], t1, t2);
    }

    // XOR 1979 17 -> 2821
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1979], w[17]);
        mulmod(t2, w[1979], w[17]);
        mulmod_constant(t2, t2, two);
        submod(w[2821], t1, t2);
    }

    // AND 468 982 -> 2822
    mulmod(w[2822], w[468], w[982]);

    // AND 2181 2528 -> 2823
    mulmod(w[2823], w[2181], w[2528]);

    // AND 1151 336 -> 2824
    mulmod(w[2824], w[1151], w[336]);

    // AND 119 1387 -> 2825
    mulmod(w[2825], w[119], w[1387]);

    // INV 709 -> 2826
    submod(w[2826], one, w[709]);

    // XOR 325 1061 -> 2827
    {
        bn254fr_class t1, t2;
        addmod(t1, w[325], w[1061]);
        mulmod(t2, w[325], w[1061]);
        mulmod_constant(t2, t2, two);
        submod(w[2827], t1, t2);
    }

    // XOR 2585 159 -> 2828
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2585], w[159]);
        mulmod(t2, w[2585], w[159]);
        mulmod_constant(t2, t2, two);
        submod(w[2828], t1, t2);
    }

    // AND 666 1587 -> 2829
    mulmod(w[2829], w[666], w[1587]);

    // INV 104 -> 2830
    submod(w[2830], one, w[104]);

    // XOR 147 1108 -> 2831
    {
        bn254fr_class t1, t2;
        addmod(t1, w[147], w[1108]);
        mulmod(t2, w[147], w[1108]);
        mulmod_constant(t2, t2, two);
        submod(w[2831], t1, t2);
    }

    // AND 754 2151 -> 2832
    mulmod(w[2832], w[754], w[2151]);

    // XOR 243 459 -> 2833
    {
        bn254fr_class t1, t2;
        addmod(t1, w[243], w[459]);
        mulmod(t2, w[243], w[459]);
        mulmod_constant(t2, t2, two);
        submod(w[2833], t1, t2);
    }

    // AND 1510 2433 -> 2834
    mulmod(w[2834], w[1510], w[2433]);

    // AND 1311 2009 -> 2835
    mulmod(w[2835], w[1311], w[2009]);

    // AND 1178 1510 -> 2836
    mulmod(w[2836], w[1178], w[1510]);

    // AND 2180 2666 -> 2837
    mulmod(w[2837], w[2180], w[2666]);

    // XOR 1589 2329 -> 2838
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1589], w[2329]);
        mulmod(t2, w[1589], w[2329]);
        mulmod_constant(t2, t2, two);
        submod(w[2838], t1, t2);
    }

    // AND 595 623 -> 2839
    mulmod(w[2839], w[595], w[623]);

    // XOR 2217 195 -> 2840
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2217], w[195]);
        mulmod(t2, w[2217], w[195]);
        mulmod_constant(t2, t2, two);
        submod(w[2840], t1, t2);
    }

    // XOR 1767 2026 -> 2841
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1767], w[2026]);
        mulmod(t2, w[1767], w[2026]);
        mulmod_constant(t2, t2, two);
        submod(w[2841], t1, t2);
    }

    // AND 846 541 -> 2842
    mulmod(w[2842], w[846], w[541]);

    // XOR 1899 1301 -> 2843
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1899], w[1301]);
        mulmod(t2, w[1899], w[1301]);
        mulmod_constant(t2, t2, two);
        submod(w[2843], t1, t2);
    }

    // XOR 340 672 -> 2844
    {
        bn254fr_class t1, t2;
        addmod(t1, w[340], w[672]);
        mulmod(t2, w[340], w[672]);
        mulmod_constant(t2, t2, two);
        submod(w[2844], t1, t2);
    }

    // INV 793 -> 2845
    submod(w[2845], one, w[793]);

    // XOR 2184 2624 -> 2846
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2184], w[2624]);
        mulmod(t2, w[2184], w[2624]);
        mulmod_constant(t2, t2, two);
        submod(w[2846], t1, t2);
    }

    // XOR 2814 1853 -> 2847
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2814], w[1853]);
        mulmod(t2, w[2814], w[1853]);
        mulmod_constant(t2, t2, two);
        submod(w[2847], t1, t2);
    }

    // AND 957 1540 -> 2848
    mulmod(w[2848], w[957], w[1540]);

    // AND 2243 504 -> 2849
    mulmod(w[2849], w[2243], w[504]);

    // XOR 2390 2528 -> 2850
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2390], w[2528]);
        mulmod(t2, w[2390], w[2528]);
        mulmod_constant(t2, t2, two);
        submod(w[2850], t1, t2);
    }

    // XOR 2463 2747 -> 2851
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2463], w[2747]);
        mulmod(t2, w[2463], w[2747]);
        mulmod_constant(t2, t2, two);
        submod(w[2851], t1, t2);
    }

    // XOR 1088 1435 -> 2852
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1088], w[1435]);
        mulmod(t2, w[1088], w[1435]);
        mulmod_constant(t2, t2, two);
        submod(w[2852], t1, t2);
    }

    // XOR 2139 1090 -> 2853
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2139], w[1090]);
        mulmod(t2, w[2139], w[1090]);
        mulmod_constant(t2, t2, two);
        submod(w[2853], t1, t2);
    }

    // XOR 2739 1229 -> 2854
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2739], w[1229]);
        mulmod(t2, w[2739], w[1229]);
        mulmod_constant(t2, t2, two);
        submod(w[2854], t1, t2);
    }

    // XOR 23 282 -> 2855
    {
        bn254fr_class t1, t2;
        addmod(t1, w[23], w[282]);
        mulmod(t2, w[23], w[282]);
        mulmod_constant(t2, t2, two);
        submod(w[2855], t1, t2);
    }

    // AND 1749 1851 -> 2856
    mulmod(w[2856], w[1749], w[1851]);

    // XOR 2194 2744 -> 2857
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2194], w[2744]);
        mulmod(t2, w[2194], w[2744]);
        mulmod_constant(t2, t2, two);
        submod(w[2857], t1, t2);
    }

    // XOR 1662 104 -> 2858
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1662], w[104]);
        mulmod(t2, w[1662], w[104]);
        mulmod_constant(t2, t2, two);
        submod(w[2858], t1, t2);
    }

    // INV 85 -> 2859
    submod(w[2859], one, w[85]);

    // AND 1762 736 -> 2860
    mulmod(w[2860], w[1762], w[736]);

    // XOR 2356 2586 -> 2861
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2356], w[2586]);
        mulmod(t2, w[2356], w[2586]);
        mulmod_constant(t2, t2, two);
        submod(w[2861], t1, t2);
    }

    // AND 1939 431 -> 2862
    mulmod(w[2862], w[1939], w[431]);

    // INV 2688 -> 2863
    submod(w[2863], one, w[2688]);

    // AND 855 1531 -> 2864
    mulmod(w[2864], w[855], w[1531]);

    // INV 2136 -> 2865
    submod(w[2865], one, w[2136]);

    // XOR 2466 1273 -> 2866
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2466], w[1273]);
        mulmod(t2, w[2466], w[1273]);
        mulmod_constant(t2, t2, two);
        submod(w[2866], t1, t2);
    }

    // XOR 209 1029 -> 2867
    {
        bn254fr_class t1, t2;
        addmod(t1, w[209], w[1029]);
        mulmod(t2, w[209], w[1029]);
        mulmod_constant(t2, t2, two);
        submod(w[2867], t1, t2);
    }

    // XOR 1767 2351 -> 2868
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1767], w[2351]);
        mulmod(t2, w[1767], w[2351]);
        mulmod_constant(t2, t2, two);
        submod(w[2868], t1, t2);
    }

    // XOR 953 1052 -> 2869
    {
        bn254fr_class t1, t2;
        addmod(t1, w[953], w[1052]);
        mulmod(t2, w[953], w[1052]);
        mulmod_constant(t2, t2, two);
        submod(w[2869], t1, t2);
    }

    // XOR 1388 1496 -> 2870
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1388], w[1496]);
        mulmod(t2, w[1388], w[1496]);
        mulmod_constant(t2, t2, two);
        submod(w[2870], t1, t2);
    }

    // XOR 358 1321 -> 2871
    {
        bn254fr_class t1, t2;
        addmod(t1, w[358], w[1321]);
        mulmod(t2, w[358], w[1321]);
        mulmod_constant(t2, t2, two);
        submod(w[2871], t1, t2);
    }

    // XOR 1586 931 -> 2872
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1586], w[931]);
        mulmod(t2, w[1586], w[931]);
        mulmod_constant(t2, t2, two);
        submod(w[2872], t1, t2);
    }

    // XOR 696 1384 -> 2873
    {
        bn254fr_class t1, t2;
        addmod(t1, w[696], w[1384]);
        mulmod(t2, w[696], w[1384]);
        mulmod_constant(t2, t2, two);
        submod(w[2873], t1, t2);
    }

    // AND 1221 2624 -> 2874
    mulmod(w[2874], w[1221], w[2624]);

    // AND 254 2719 -> 2875
    mulmod(w[2875], w[254], w[2719]);

    // AND 779 2669 -> 2876
    mulmod(w[2876], w[779], w[2669]);

    // XOR 1915 356 -> 2877
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1915], w[356]);
        mulmod(t2, w[1915], w[356]);
        mulmod_constant(t2, t2, two);
        submod(w[2877], t1, t2);
    }

    // XOR 2177 1950 -> 2878
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2177], w[1950]);
        mulmod(t2, w[2177], w[1950]);
        mulmod_constant(t2, t2, two);
        submod(w[2878], t1, t2);
    }

    // XOR 2022 912 -> 2879
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2022], w[912]);
        mulmod(t2, w[2022], w[912]);
        mulmod_constant(t2, t2, two);
        submod(w[2879], t1, t2);
    }

    // XOR 2125 1077 -> 2880
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2125], w[1077]);
        mulmod(t2, w[2125], w[1077]);
        mulmod_constant(t2, t2, two);
        submod(w[2880], t1, t2);
    }

    // XOR 2775 1030 -> 2881
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2775], w[1030]);
        mulmod(t2, w[2775], w[1030]);
        mulmod_constant(t2, t2, two);
        submod(w[2881], t1, t2);
    }

    // XOR 2507 1665 -> 2882
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2507], w[1665]);
        mulmod(t2, w[2507], w[1665]);
        mulmod_constant(t2, t2, two);
        submod(w[2882], t1, t2);
    }

    // AND 1192 1873 -> 2883
    mulmod(w[2883], w[1192], w[1873]);

    // AND 2597 2001 -> 2884
    mulmod(w[2884], w[2597], w[2001]);

    // XOR 453 1628 -> 2885
    {
        bn254fr_class t1, t2;
        addmod(t1, w[453], w[1628]);
        mulmod(t2, w[453], w[1628]);
        mulmod_constant(t2, t2, two);
        submod(w[2885], t1, t2);
    }

    // AND 1013 2608 -> 2886
    mulmod(w[2886], w[1013], w[2608]);

    // XOR 2689 2120 -> 2887
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2689], w[2120]);
        mulmod(t2, w[2689], w[2120]);
        mulmod_constant(t2, t2, two);
        submod(w[2887], t1, t2);
    }

    // XOR 2773 387 -> 2888
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2773], w[387]);
        mulmod(t2, w[2773], w[387]);
        mulmod_constant(t2, t2, two);
        submod(w[2888], t1, t2);
    }

    // AND 2322 22 -> 2889
    mulmod(w[2889], w[2322], w[22]);

    // XOR 4 2662 -> 2890
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4], w[2662]);
        mulmod(t2, w[4], w[2662]);
        mulmod_constant(t2, t2, two);
        submod(w[2890], t1, t2);
    }

    // AND 2469 982 -> 2891
    mulmod(w[2891], w[2469], w[982]);

    // XOR 2591 704 -> 2892
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2591], w[704]);
        mulmod(t2, w[2591], w[704]);
        mulmod_constant(t2, t2, two);
        submod(w[2892], t1, t2);
    }

    // XOR 2038 1348 -> 2893
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2038], w[1348]);
        mulmod(t2, w[2038], w[1348]);
        mulmod_constant(t2, t2, two);
        submod(w[2893], t1, t2);
    }

    // XOR 433 37 -> 2894
    {
        bn254fr_class t1, t2;
        addmod(t1, w[433], w[37]);
        mulmod(t2, w[433], w[37]);
        mulmod_constant(t2, t2, two);
        submod(w[2894], t1, t2);
    }

    // AND 2245 2425 -> 2895
    mulmod(w[2895], w[2245], w[2425]);

    // AND 2452 1854 -> 2896
    mulmod(w[2896], w[2452], w[1854]);

    // XOR 2772 1285 -> 2897
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2772], w[1285]);
        mulmod(t2, w[2772], w[1285]);
        mulmod_constant(t2, t2, two);
        submod(w[2897], t1, t2);
    }

    // XOR 2438 2006 -> 2898
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2438], w[2006]);
        mulmod(t2, w[2438], w[2006]);
        mulmod_constant(t2, t2, two);
        submod(w[2898], t1, t2);
    }

    // XOR 1284 662 -> 2899
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1284], w[662]);
        mulmod(t2, w[1284], w[662]);
        mulmod_constant(t2, t2, two);
        submod(w[2899], t1, t2);
    }

    // INV 559 -> 2900
    submod(w[2900], one, w[559]);

    // XOR 2301 2164 -> 2901
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2301], w[2164]);
        mulmod(t2, w[2301], w[2164]);
        mulmod_constant(t2, t2, two);
        submod(w[2901], t1, t2);
    }

    // AND 2298 727 -> 2902
    mulmod(w[2902], w[2298], w[727]);

    // XOR 2539 337 -> 2903
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2539], w[337]);
        mulmod(t2, w[2539], w[337]);
        mulmod_constant(t2, t2, two);
        submod(w[2903], t1, t2);
    }

    // XOR 2516 2132 -> 2904
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2516], w[2132]);
        mulmod(t2, w[2516], w[2132]);
        mulmod_constant(t2, t2, two);
        submod(w[2904], t1, t2);
    }

    // XOR 1757 1772 -> 2905
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1757], w[1772]);
        mulmod(t2, w[1757], w[1772]);
        mulmod_constant(t2, t2, two);
        submod(w[2905], t1, t2);
    }

    // XOR 2195 1230 -> 2906
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2195], w[1230]);
        mulmod(t2, w[2195], w[1230]);
        mulmod_constant(t2, t2, two);
        submod(w[2906], t1, t2);
    }

    // XOR 1241 101 -> 2907
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1241], w[101]);
        mulmod(t2, w[1241], w[101]);
        mulmod_constant(t2, t2, two);
        submod(w[2907], t1, t2);
    }

    // AND 983 1315 -> 2908
    mulmod(w[2908], w[983], w[1315]);

    // INV 1310 -> 2909
    submod(w[2909], one, w[1310]);

    // XOR 417 1331 -> 2910
    {
        bn254fr_class t1, t2;
        addmod(t1, w[417], w[1331]);
        mulmod(t2, w[417], w[1331]);
        mulmod_constant(t2, t2, two);
        submod(w[2910], t1, t2);
    }

    // AND 1006 2351 -> 2911
    mulmod(w[2911], w[1006], w[2351]);

    // AND 364 1593 -> 2912
    mulmod(w[2912], w[364], w[1593]);

    // AND 2088 463 -> 2913
    mulmod(w[2913], w[2088], w[463]);

    // INV 1057 -> 2914
    submod(w[2914], one, w[1057]);

    // XOR 355 1414 -> 2915
    {
        bn254fr_class t1, t2;
        addmod(t1, w[355], w[1414]);
        mulmod(t2, w[355], w[1414]);
        mulmod_constant(t2, t2, two);
        submod(w[2915], t1, t2);
    }

    // AND 2472 1229 -> 2916
    mulmod(w[2916], w[2472], w[1229]);

    // AND 1144 916 -> 2917
    mulmod(w[2917], w[1144], w[916]);

    // AND 1799 1207 -> 2918
    mulmod(w[2918], w[1799], w[1207]);

    // INV 2572 -> 2919
    submod(w[2919], one, w[2572]);

    // AND 2544 2810 -> 2920
    mulmod(w[2920], w[2544], w[2810]);

    // XOR 81 2106 -> 2921
    {
        bn254fr_class t1, t2;
        addmod(t1, w[81], w[2106]);
        mulmod(t2, w[81], w[2106]);
        mulmod_constant(t2, t2, two);
        submod(w[2921], t1, t2);
    }

    // AND 2021 1077 -> 2922
    mulmod(w[2922], w[2021], w[1077]);

    // XOR 826 1096 -> 2923
    {
        bn254fr_class t1, t2;
        addmod(t1, w[826], w[1096]);
        mulmod(t2, w[826], w[1096]);
        mulmod_constant(t2, t2, two);
        submod(w[2923], t1, t2);
    }

    // AND 298 2531 -> 2924
    mulmod(w[2924], w[298], w[2531]);

    // AND 2403 2464 -> 2925
    mulmod(w[2925], w[2403], w[2464]);

    // XOR 1351 2173 -> 2926
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1351], w[2173]);
        mulmod(t2, w[1351], w[2173]);
        mulmod_constant(t2, t2, two);
        submod(w[2926], t1, t2);
    }

    // AND 2446 2425 -> 2927
    mulmod(w[2927], w[2446], w[2425]);

    // XOR 392 1094 -> 2928
    {
        bn254fr_class t1, t2;
        addmod(t1, w[392], w[1094]);
        mulmod(t2, w[392], w[1094]);
        mulmod_constant(t2, t2, two);
        submod(w[2928], t1, t2);
    }

    // XOR 1042 1786 -> 2929
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1042], w[1786]);
        mulmod(t2, w[1042], w[1786]);
        mulmod_constant(t2, t2, two);
        submod(w[2929], t1, t2);
    }

    // XOR 1900 896 -> 2930
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1900], w[896]);
        mulmod(t2, w[1900], w[896]);
        mulmod_constant(t2, t2, two);
        submod(w[2930], t1, t2);
    }

    // INV 2231 -> 2931
    submod(w[2931], one, w[2231]);

    // XOR 2261 1567 -> 2932
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2261], w[1567]);
        mulmod(t2, w[2261], w[1567]);
        mulmod_constant(t2, t2, two);
        submod(w[2932], t1, t2);
    }

    // AND 550 1907 -> 2933
    mulmod(w[2933], w[550], w[1907]);

    // XOR 1151 516 -> 2934
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1151], w[516]);
        mulmod(t2, w[1151], w[516]);
        mulmod_constant(t2, t2, two);
        submod(w[2934], t1, t2);
    }

    // AND 2467 1309 -> 2935
    mulmod(w[2935], w[2467], w[1309]);

    // XOR 200 585 -> 2936
    {
        bn254fr_class t1, t2;
        addmod(t1, w[200], w[585]);
        mulmod(t2, w[200], w[585]);
        mulmod_constant(t2, t2, two);
        submod(w[2936], t1, t2);
    }

    // INV 2746 -> 2937
    submod(w[2937], one, w[2746]);

    // XOR 787 870 -> 2938
    {
        bn254fr_class t1, t2;
        addmod(t1, w[787], w[870]);
        mulmod(t2, w[787], w[870]);
        mulmod_constant(t2, t2, two);
        submod(w[2938], t1, t2);
    }

    // XOR 2523 2032 -> 2939
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2523], w[2032]);
        mulmod(t2, w[2523], w[2032]);
        mulmod_constant(t2, t2, two);
        submod(w[2939], t1, t2);
    }

    // XOR 1072 2167 -> 2940
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1072], w[2167]);
        mulmod(t2, w[1072], w[2167]);
        mulmod_constant(t2, t2, two);
        submod(w[2940], t1, t2);
    }

    // AND 78 2021 -> 2941
    mulmod(w[2941], w[78], w[2021]);

    // XOR 752 499 -> 2942
    {
        bn254fr_class t1, t2;
        addmod(t1, w[752], w[499]);
        mulmod(t2, w[752], w[499]);
        mulmod_constant(t2, t2, two);
        submod(w[2942], t1, t2);
    }

    // AND 1163 627 -> 2943
    mulmod(w[2943], w[1163], w[627]);

    // AND 2439 827 -> 2944
    mulmod(w[2944], w[2439], w[827]);

    // XOR 2631 2135 -> 2945
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2631], w[2135]);
        mulmod(t2, w[2631], w[2135]);
        mulmod_constant(t2, t2, two);
        submod(w[2945], t1, t2);
    }

    // AND 1292 297 -> 2946
    mulmod(w[2946], w[1292], w[297]);

    // AND 2204 244 -> 2947
    mulmod(w[2947], w[2204], w[244]);

    // XOR 1429 888 -> 2948
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1429], w[888]);
        mulmod(t2, w[1429], w[888]);
        mulmod_constant(t2, t2, two);
        submod(w[2948], t1, t2);
    }

    // XOR 450 154 -> 2949
    {
        bn254fr_class t1, t2;
        addmod(t1, w[450], w[154]);
        mulmod(t2, w[450], w[154]);
        mulmod_constant(t2, t2, two);
        submod(w[2949], t1, t2);
    }

    // AND 2681 632 -> 2950
    mulmod(w[2950], w[2681], w[632]);

    // AND 575 2798 -> 2951
    mulmod(w[2951], w[575], w[2798]);

    // AND 1921 2809 -> 2952
    mulmod(w[2952], w[1921], w[2809]);

    // AND 755 877 -> 2953
    mulmod(w[2953], w[755], w[877]);

    // AND 56 1017 -> 2954
    mulmod(w[2954], w[56], w[1017]);

    // AND 2327 144 -> 2955
    mulmod(w[2955], w[2327], w[144]);

    // XOR 796 2835 -> 2956
    {
        bn254fr_class t1, t2;
        addmod(t1, w[796], w[2835]);
        mulmod(t2, w[796], w[2835]);
        mulmod_constant(t2, t2, two);
        submod(w[2956], t1, t2);
    }

    // XOR 902 267 -> 2957
    {
        bn254fr_class t1, t2;
        addmod(t1, w[902], w[267]);
        mulmod(t2, w[902], w[267]);
        mulmod_constant(t2, t2, two);
        submod(w[2957], t1, t2);
    }

    // AND 419 893 -> 2958
    mulmod(w[2958], w[419], w[893]);

    // AND 369 399 -> 2959
    mulmod(w[2959], w[369], w[399]);

    // XOR 2726 1565 -> 2960
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2726], w[1565]);
        mulmod(t2, w[2726], w[1565]);
        mulmod_constant(t2, t2, two);
        submod(w[2960], t1, t2);
    }

    // XOR 659 1446 -> 2961
    {
        bn254fr_class t1, t2;
        addmod(t1, w[659], w[1446]);
        mulmod(t2, w[659], w[1446]);
        mulmod_constant(t2, t2, two);
        submod(w[2961], t1, t2);
    }

    // AND 2595 671 -> 2962
    mulmod(w[2962], w[2595], w[671]);

    // XOR 1941 926 -> 2963
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1941], w[926]);
        mulmod(t2, w[1941], w[926]);
        mulmod_constant(t2, t2, two);
        submod(w[2963], t1, t2);
    }

    // XOR 464 732 -> 2964
    {
        bn254fr_class t1, t2;
        addmod(t1, w[464], w[732]);
        mulmod(t2, w[464], w[732]);
        mulmod_constant(t2, t2, two);
        submod(w[2964], t1, t2);
    }

    // XOR 2221 1221 -> 2965
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2221], w[1221]);
        mulmod(t2, w[2221], w[1221]);
        mulmod_constant(t2, t2, two);
        submod(w[2965], t1, t2);
    }

    // XOR 2726 1124 -> 2966
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2726], w[1124]);
        mulmod(t2, w[2726], w[1124]);
        mulmod_constant(t2, t2, two);
        submod(w[2966], t1, t2);
    }

    // XOR 2622 610 -> 2967
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2622], w[610]);
        mulmod(t2, w[2622], w[610]);
        mulmod_constant(t2, t2, two);
        submod(w[2967], t1, t2);
    }

    // AND 868 1995 -> 2968
    mulmod(w[2968], w[868], w[1995]);

    // XOR 1304 492 -> 2969
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1304], w[492]);
        mulmod(t2, w[1304], w[492]);
        mulmod_constant(t2, t2, two);
        submod(w[2969], t1, t2);
    }

    // INV 1118 -> 2970
    submod(w[2970], one, w[1118]);

    // XOR 1169 446 -> 2971
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1169], w[446]);
        mulmod(t2, w[1169], w[446]);
        mulmod_constant(t2, t2, two);
        submod(w[2971], t1, t2);
    }

    // AND 2078 1410 -> 2972
    mulmod(w[2972], w[2078], w[1410]);

    // AND 848 411 -> 2973
    mulmod(w[2973], w[848], w[411]);

    // XOR 1301 124 -> 2974
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1301], w[124]);
        mulmod(t2, w[1301], w[124]);
        mulmod_constant(t2, t2, two);
        submod(w[2974], t1, t2);
    }

    // AND 1199 626 -> 2975
    mulmod(w[2975], w[1199], w[626]);

    // XOR 1469 724 -> 2976
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1469], w[724]);
        mulmod(t2, w[1469], w[724]);
        mulmod_constant(t2, t2, two);
        submod(w[2976], t1, t2);
    }

    // XOR 1943 92 -> 2977
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1943], w[92]);
        mulmod(t2, w[1943], w[92]);
        mulmod_constant(t2, t2, two);
        submod(w[2977], t1, t2);
    }

    // AND 2544 701 -> 2978
    mulmod(w[2978], w[2544], w[701]);

    // XOR 1624 1768 -> 2979
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1624], w[1768]);
        mulmod(t2, w[1624], w[1768]);
        mulmod_constant(t2, t2, two);
        submod(w[2979], t1, t2);
    }

    // INV 2156 -> 2980
    submod(w[2980], one, w[2156]);

    // XOR 1913 838 -> 2981
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1913], w[838]);
        mulmod(t2, w[1913], w[838]);
        mulmod_constant(t2, t2, two);
        submod(w[2981], t1, t2);
    }

    // XOR 999 287 -> 2982
    {
        bn254fr_class t1, t2;
        addmod(t1, w[999], w[287]);
        mulmod(t2, w[999], w[287]);
        mulmod_constant(t2, t2, two);
        submod(w[2982], t1, t2);
    }

    // XOR 1062 2161 -> 2983
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1062], w[2161]);
        mulmod(t2, w[1062], w[2161]);
        mulmod_constant(t2, t2, two);
        submod(w[2983], t1, t2);
    }

    // INV 550 -> 2984
    submod(w[2984], one, w[550]);

    // AND 577 901 -> 2985
    mulmod(w[2985], w[577], w[901]);

    // AND 2116 392 -> 2986
    mulmod(w[2986], w[2116], w[392]);

    // AND 666 1352 -> 2987
    mulmod(w[2987], w[666], w[1352]);

    // AND 2073 777 -> 2988
    mulmod(w[2988], w[2073], w[777]);

    // XOR 1927 174 -> 2989
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1927], w[174]);
        mulmod(t2, w[1927], w[174]);
        mulmod_constant(t2, t2, two);
        submod(w[2989], t1, t2);
    }

    // AND 2426 2690 -> 2990
    mulmod(w[2990], w[2426], w[2690]);

    // XOR 454 2054 -> 2991
    {
        bn254fr_class t1, t2;
        addmod(t1, w[454], w[2054]);
        mulmod(t2, w[454], w[2054]);
        mulmod_constant(t2, t2, two);
        submod(w[2991], t1, t2);
    }

    // XOR 1213 2355 -> 2992
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1213], w[2355]);
        mulmod(t2, w[1213], w[2355]);
        mulmod_constant(t2, t2, two);
        submod(w[2992], t1, t2);
    }

    // XOR 2780 1107 -> 2993
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2780], w[1107]);
        mulmod(t2, w[2780], w[1107]);
        mulmod_constant(t2, t2, two);
        submod(w[2993], t1, t2);
    }

    // INV 2541 -> 2994
    submod(w[2994], one, w[2541]);

    // AND 1193 706 -> 2995
    mulmod(w[2995], w[1193], w[706]);

    // AND 2292 975 -> 2996
    mulmod(w[2996], w[2292], w[975]);

    // AND 443 670 -> 2997
    mulmod(w[2997], w[443], w[670]);

    // AND 1418 1906 -> 2998
    mulmod(w[2998], w[1418], w[1906]);

    // AND 499 1835 -> 2999
    mulmod(w[2999], w[499], w[1835]);

    // XOR 1615 2021 -> 3000
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1615], w[2021]);
        mulmod(t2, w[1615], w[2021]);
        mulmod_constant(t2, t2, two);
        submod(w[3000], t1, t2);
    }

    // XOR 2178 1444 -> 3001
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2178], w[1444]);
        mulmod(t2, w[2178], w[1444]);
        mulmod_constant(t2, t2, two);
        submod(w[3001], t1, t2);
    }

    // XOR 411 2919 -> 3002
    {
        bn254fr_class t1, t2;
        addmod(t1, w[411], w[2919]);
        mulmod(t2, w[411], w[2919]);
        mulmod_constant(t2, t2, two);
        submod(w[3002], t1, t2);
    }

    // INV 596 -> 3003
    submod(w[3003], one, w[596]);

    // INV 2458 -> 3004
    submod(w[3004], one, w[2458]);

    // XOR 627 448 -> 3005
    {
        bn254fr_class t1, t2;
        addmod(t1, w[627], w[448]);
        mulmod(t2, w[627], w[448]);
        mulmod_constant(t2, t2, two);
        submod(w[3005], t1, t2);
    }

    // XOR 2377 1722 -> 3006
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2377], w[1722]);
        mulmod(t2, w[2377], w[1722]);
        mulmod_constant(t2, t2, two);
        submod(w[3006], t1, t2);
    }

    // XOR 2066 2115 -> 3007
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2066], w[2115]);
        mulmod(t2, w[2066], w[2115]);
        mulmod_constant(t2, t2, two);
        submod(w[3007], t1, t2);
    }

    // XOR 1420 640 -> 3008
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1420], w[640]);
        mulmod(t2, w[1420], w[640]);
        mulmod_constant(t2, t2, two);
        submod(w[3008], t1, t2);
    }

    // AND 2289 2244 -> 3009
    mulmod(w[3009], w[2289], w[2244]);

    // AND 2797 686 -> 3010
    mulmod(w[3010], w[2797], w[686]);

    // AND 1061 1954 -> 3011
    mulmod(w[3011], w[1061], w[1954]);

    // XOR 1375 2733 -> 3012
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1375], w[2733]);
        mulmod(t2, w[1375], w[2733]);
        mulmod_constant(t2, t2, two);
        submod(w[3012], t1, t2);
    }

    // XOR 817 251 -> 3013
    {
        bn254fr_class t1, t2;
        addmod(t1, w[817], w[251]);
        mulmod(t2, w[817], w[251]);
        mulmod_constant(t2, t2, two);
        submod(w[3013], t1, t2);
    }

    // AND 571 2131 -> 3014
    mulmod(w[3014], w[571], w[2131]);

    // AND 232 1754 -> 3015
    mulmod(w[3015], w[232], w[1754]);

    // AND 1029 589 -> 3016
    mulmod(w[3016], w[1029], w[589]);

    // INV 1054 -> 3017
    submod(w[3017], one, w[1054]);

    // XOR 2379 1186 -> 3018
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2379], w[1186]);
        mulmod(t2, w[2379], w[1186]);
        mulmod_constant(t2, t2, two);
        submod(w[3018], t1, t2);
    }

    // XOR 1672 581 -> 3019
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1672], w[581]);
        mulmod(t2, w[1672], w[581]);
        mulmod_constant(t2, t2, two);
        submod(w[3019], t1, t2);
    }

    // XOR 1483 425 -> 3020
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1483], w[425]);
        mulmod(t2, w[1483], w[425]);
        mulmod_constant(t2, t2, two);
        submod(w[3020], t1, t2);
    }

    // XOR 850 2438 -> 3021
    {
        bn254fr_class t1, t2;
        addmod(t1, w[850], w[2438]);
        mulmod(t2, w[850], w[2438]);
        mulmod_constant(t2, t2, two);
        submod(w[3021], t1, t2);
    }

    // XOR 2034 1464 -> 3022
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2034], w[1464]);
        mulmod(t2, w[2034], w[1464]);
        mulmod_constant(t2, t2, two);
        submod(w[3022], t1, t2);
    }

    // AND 11 2412 -> 3023
    mulmod(w[3023], w[11], w[2412]);

    // AND 1806 446 -> 3024
    mulmod(w[3024], w[1806], w[446]);

    // AND 604 460 -> 3025
    mulmod(w[3025], w[604], w[460]);

    // XOR 1830 1408 -> 3026
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1830], w[1408]);
        mulmod(t2, w[1830], w[1408]);
        mulmod_constant(t2, t2, two);
        submod(w[3026], t1, t2);
    }

    // XOR 2304 79 -> 3027
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2304], w[79]);
        mulmod(t2, w[2304], w[79]);
        mulmod_constant(t2, t2, two);
        submod(w[3027], t1, t2);
    }

    // XOR 1913 2839 -> 3028
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1913], w[2839]);
        mulmod(t2, w[1913], w[2839]);
        mulmod_constant(t2, t2, two);
        submod(w[3028], t1, t2);
    }

    // XOR 1286 65 -> 3029
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1286], w[65]);
        mulmod(t2, w[1286], w[65]);
        mulmod_constant(t2, t2, two);
        submod(w[3029], t1, t2);
    }

    // XOR 343 3013 -> 3030
    {
        bn254fr_class t1, t2;
        addmod(t1, w[343], w[3013]);
        mulmod(t2, w[343], w[3013]);
        mulmod_constant(t2, t2, two);
        submod(w[3030], t1, t2);
    }

    // AND 1874 97 -> 3031
    mulmod(w[3031], w[1874], w[97]);

    // XOR 1518 382 -> 3032
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1518], w[382]);
        mulmod(t2, w[1518], w[382]);
        mulmod_constant(t2, t2, two);
        submod(w[3032], t1, t2);
    }

    // XOR 2170 2418 -> 3033
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2170], w[2418]);
        mulmod(t2, w[2170], w[2418]);
        mulmod_constant(t2, t2, two);
        submod(w[3033], t1, t2);
    }

    // XOR 886 702 -> 3034
    {
        bn254fr_class t1, t2;
        addmod(t1, w[886], w[702]);
        mulmod(t2, w[886], w[702]);
        mulmod_constant(t2, t2, two);
        submod(w[3034], t1, t2);
    }

    // XOR 327 2232 -> 3035
    {
        bn254fr_class t1, t2;
        addmod(t1, w[327], w[2232]);
        mulmod(t2, w[327], w[2232]);
        mulmod_constant(t2, t2, two);
        submod(w[3035], t1, t2);
    }

    // XOR 103 1902 -> 3036
    {
        bn254fr_class t1, t2;
        addmod(t1, w[103], w[1902]);
        mulmod(t2, w[103], w[1902]);
        mulmod_constant(t2, t2, two);
        submod(w[3036], t1, t2);
    }

    // XOR 1111 1243 -> 3037
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1111], w[1243]);
        mulmod(t2, w[1111], w[1243]);
        mulmod_constant(t2, t2, two);
        submod(w[3037], t1, t2);
    }

    // AND 474 2392 -> 3038
    mulmod(w[3038], w[474], w[2392]);

    // INV 2391 -> 3039
    submod(w[3039], one, w[2391]);

    // INV 1797 -> 3040
    submod(w[3040], one, w[1797]);

    // XOR 1984 1263 -> 3041
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1984], w[1263]);
        mulmod(t2, w[1984], w[1263]);
        mulmod_constant(t2, t2, two);
        submod(w[3041], t1, t2);
    }

    // XOR 723 346 -> 3042
    {
        bn254fr_class t1, t2;
        addmod(t1, w[723], w[346]);
        mulmod(t2, w[723], w[346]);
        mulmod_constant(t2, t2, two);
        submod(w[3042], t1, t2);
    }

    // AND 2240 1458 -> 3043
    mulmod(w[3043], w[2240], w[1458]);

    // XOR 2201 102 -> 3044
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2201], w[102]);
        mulmod(t2, w[2201], w[102]);
        mulmod_constant(t2, t2, two);
        submod(w[3044], t1, t2);
    }

    // AND 2912 2817 -> 3045
    mulmod(w[3045], w[2912], w[2817]);

    // AND 1776 399 -> 3046
    mulmod(w[3046], w[1776], w[399]);

    // XOR 2345 1780 -> 3047
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2345], w[1780]);
        mulmod(t2, w[2345], w[1780]);
        mulmod_constant(t2, t2, two);
        submod(w[3047], t1, t2);
    }

    // INV 715 -> 3048
    submod(w[3048], one, w[715]);

    // XOR 2935 2258 -> 3049
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2935], w[2258]);
        mulmod(t2, w[2935], w[2258]);
        mulmod_constant(t2, t2, two);
        submod(w[3049], t1, t2);
    }

    // AND 1373 282 -> 3050
    mulmod(w[3050], w[1373], w[282]);

    // INV 1206 -> 3051
    submod(w[3051], one, w[1206]);

    // AND 185 1449 -> 3052
    mulmod(w[3052], w[185], w[1449]);

    // AND 1226 1004 -> 3053
    mulmod(w[3053], w[1226], w[1004]);

    // AND 1607 2413 -> 3054
    mulmod(w[3054], w[1607], w[2413]);

    // XOR 1267 1189 -> 3055
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1267], w[1189]);
        mulmod(t2, w[1267], w[1189]);
        mulmod_constant(t2, t2, two);
        submod(w[3055], t1, t2);
    }

    // XOR 768 1989 -> 3056
    {
        bn254fr_class t1, t2;
        addmod(t1, w[768], w[1989]);
        mulmod(t2, w[768], w[1989]);
        mulmod_constant(t2, t2, two);
        submod(w[3056], t1, t2);
    }

    // AND 258 620 -> 3057
    mulmod(w[3057], w[258], w[620]);

    // INV 1391 -> 3058
    submod(w[3058], one, w[1391]);

    // AND 2881 1851 -> 3059
    mulmod(w[3059], w[2881], w[1851]);

    // AND 2200 1082 -> 3060
    mulmod(w[3060], w[2200], w[1082]);

    // AND 2081 2394 -> 3061
    mulmod(w[3061], w[2081], w[2394]);

    // XOR 2949 1655 -> 3062
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2949], w[1655]);
        mulmod(t2, w[2949], w[1655]);
        mulmod_constant(t2, t2, two);
        submod(w[3062], t1, t2);
    }

    // AND 1225 2779 -> 3063
    mulmod(w[3063], w[1225], w[2779]);

    // XOR 1762 1394 -> 3064
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1762], w[1394]);
        mulmod(t2, w[1762], w[1394]);
        mulmod_constant(t2, t2, two);
        submod(w[3064], t1, t2);
    }

    // AND 1781 621 -> 3065
    mulmod(w[3065], w[1781], w[621]);

    // XOR 399 738 -> 3066
    {
        bn254fr_class t1, t2;
        addmod(t1, w[399], w[738]);
        mulmod(t2, w[399], w[738]);
        mulmod_constant(t2, t2, two);
        submod(w[3066], t1, t2);
    }

    // XOR 1846 181 -> 3067
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1846], w[181]);
        mulmod(t2, w[1846], w[181]);
        mulmod_constant(t2, t2, two);
        submod(w[3067], t1, t2);
    }

    // AND 959 2788 -> 3068
    mulmod(w[3068], w[959], w[2788]);

    // XOR 2833 610 -> 3069
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2833], w[610]);
        mulmod(t2, w[2833], w[610]);
        mulmod_constant(t2, t2, two);
        submod(w[3069], t1, t2);
    }

    // AND 665 1296 -> 3070
    mulmod(w[3070], w[665], w[1296]);

    // XOR 2675 831 -> 3071
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2675], w[831]);
        mulmod(t2, w[2675], w[831]);
        mulmod_constant(t2, t2, two);
        submod(w[3071], t1, t2);
    }

    // AND 1230 1966 -> 3072
    mulmod(w[3072], w[1230], w[1966]);

    // INV 189 -> 3073
    submod(w[3073], one, w[189]);

    // AND 2509 315 -> 3074
    mulmod(w[3074], w[2509], w[315]);

    // AND 1942 2235 -> 3075
    mulmod(w[3075], w[1942], w[2235]);

    // XOR 1691 2821 -> 3076
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1691], w[2821]);
        mulmod(t2, w[1691], w[2821]);
        mulmod_constant(t2, t2, two);
        submod(w[3076], t1, t2);
    }

    // XOR 2833 2662 -> 3077
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2833], w[2662]);
        mulmod(t2, w[2833], w[2662]);
        mulmod_constant(t2, t2, two);
        submod(w[3077], t1, t2);
    }

    // XOR 1509 3014 -> 3078
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1509], w[3014]);
        mulmod(t2, w[1509], w[3014]);
        mulmod_constant(t2, t2, two);
        submod(w[3078], t1, t2);
    }

    // XOR 2916 1571 -> 3079
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2916], w[1571]);
        mulmod(t2, w[2916], w[1571]);
        mulmod_constant(t2, t2, two);
        submod(w[3079], t1, t2);
    }

    // XOR 850 339 -> 3080
    {
        bn254fr_class t1, t2;
        addmod(t1, w[850], w[339]);
        mulmod(t2, w[850], w[339]);
        mulmod_constant(t2, t2, two);
        submod(w[3080], t1, t2);
    }

    // XOR 948 938 -> 3081
    {
        bn254fr_class t1, t2;
        addmod(t1, w[948], w[938]);
        mulmod(t2, w[948], w[938]);
        mulmod_constant(t2, t2, two);
        submod(w[3081], t1, t2);
    }

    // XOR 3005 828 -> 3082
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3005], w[828]);
        mulmod(t2, w[3005], w[828]);
        mulmod_constant(t2, t2, two);
        submod(w[3082], t1, t2);
    }

    // XOR 1664 89 -> 3083
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1664], w[89]);
        mulmod(t2, w[1664], w[89]);
        mulmod_constant(t2, t2, two);
        submod(w[3083], t1, t2);
    }

    // INV 2596 -> 3084
    submod(w[3084], one, w[2596]);

    // XOR 1787 2156 -> 3085
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1787], w[2156]);
        mulmod(t2, w[1787], w[2156]);
        mulmod_constant(t2, t2, two);
        submod(w[3085], t1, t2);
    }

    // XOR 2530 1813 -> 3086
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2530], w[1813]);
        mulmod(t2, w[2530], w[1813]);
        mulmod_constant(t2, t2, two);
        submod(w[3086], t1, t2);
    }

    // XOR 1761 2391 -> 3087
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1761], w[2391]);
        mulmod(t2, w[1761], w[2391]);
        mulmod_constant(t2, t2, two);
        submod(w[3087], t1, t2);
    }

    // AND 2086 1248 -> 3088
    mulmod(w[3088], w[2086], w[1248]);

    // AND 2945 2627 -> 3089
    mulmod(w[3089], w[2945], w[2627]);

    // AND 1373 1800 -> 3090
    mulmod(w[3090], w[1373], w[1800]);

    // XOR 674 2568 -> 3091
    {
        bn254fr_class t1, t2;
        addmod(t1, w[674], w[2568]);
        mulmod(t2, w[674], w[2568]);
        mulmod_constant(t2, t2, two);
        submod(w[3091], t1, t2);
    }

    // XOR 1582 1532 -> 3092
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1582], w[1532]);
        mulmod(t2, w[1582], w[1532]);
        mulmod_constant(t2, t2, two);
        submod(w[3092], t1, t2);
    }

    // XOR 2888 1544 -> 3093
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2888], w[1544]);
        mulmod(t2, w[2888], w[1544]);
        mulmod_constant(t2, t2, two);
        submod(w[3093], t1, t2);
    }

    // INV 95 -> 3094
    submod(w[3094], one, w[95]);

    // AND 776 1999 -> 3095
    mulmod(w[3095], w[776], w[1999]);

    // XOR 2310 1541 -> 3096
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2310], w[1541]);
        mulmod(t2, w[2310], w[1541]);
        mulmod_constant(t2, t2, two);
        submod(w[3096], t1, t2);
    }

    // XOR 1308 2781 -> 3097
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1308], w[2781]);
        mulmod(t2, w[1308], w[2781]);
        mulmod_constant(t2, t2, two);
        submod(w[3097], t1, t2);
    }

    // XOR 211 2943 -> 3098
    {
        bn254fr_class t1, t2;
        addmod(t1, w[211], w[2943]);
        mulmod(t2, w[211], w[2943]);
        mulmod_constant(t2, t2, two);
        submod(w[3098], t1, t2);
    }

    // AND 1361 733 -> 3099
    mulmod(w[3099], w[1361], w[733]);

    // AND 2049 158 -> 3100
    mulmod(w[3100], w[2049], w[158]);

    // AND 2400 2313 -> 3101
    mulmod(w[3101], w[2400], w[2313]);

    // AND 1256 1226 -> 3102
    mulmod(w[3102], w[1256], w[1226]);

    // AND 497 433 -> 3103
    mulmod(w[3103], w[497], w[433]);

    // XOR 819 372 -> 3104
    {
        bn254fr_class t1, t2;
        addmod(t1, w[819], w[372]);
        mulmod(t2, w[819], w[372]);
        mulmod_constant(t2, t2, two);
        submod(w[3104], t1, t2);
    }

    // AND 497 1514 -> 3105
    mulmod(w[3105], w[497], w[1514]);

    // XOR 569 1352 -> 3106
    {
        bn254fr_class t1, t2;
        addmod(t1, w[569], w[1352]);
        mulmod(t2, w[569], w[1352]);
        mulmod_constant(t2, t2, two);
        submod(w[3106], t1, t2);
    }

    // XOR 2338 1905 -> 3107
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2338], w[1905]);
        mulmod(t2, w[2338], w[1905]);
        mulmod_constant(t2, t2, two);
        submod(w[3107], t1, t2);
    }

    // XOR 2332 997 -> 3108
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2332], w[997]);
        mulmod(t2, w[2332], w[997]);
        mulmod_constant(t2, t2, two);
        submod(w[3108], t1, t2);
    }

    // INV 2501 -> 3109
    submod(w[3109], one, w[2501]);

    // XOR 2199 3012 -> 3110
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2199], w[3012]);
        mulmod(t2, w[2199], w[3012]);
        mulmod_constant(t2, t2, two);
        submod(w[3110], t1, t2);
    }

    // XOR 2654 2356 -> 3111
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2654], w[2356]);
        mulmod(t2, w[2654], w[2356]);
        mulmod_constant(t2, t2, two);
        submod(w[3111], t1, t2);
    }

    // XOR 678 994 -> 3112
    {
        bn254fr_class t1, t2;
        addmod(t1, w[678], w[994]);
        mulmod(t2, w[678], w[994]);
        mulmod_constant(t2, t2, two);
        submod(w[3112], t1, t2);
    }

    // XOR 577 1937 -> 3113
    {
        bn254fr_class t1, t2;
        addmod(t1, w[577], w[1937]);
        mulmod(t2, w[577], w[1937]);
        mulmod_constant(t2, t2, two);
        submod(w[3113], t1, t2);
    }

    // INV 1475 -> 3114
    submod(w[3114], one, w[1475]);

    // AND 3066 752 -> 3115
    mulmod(w[3115], w[3066], w[752]);

    // AND 682 1376 -> 3116
    mulmod(w[3116], w[682], w[1376]);

    // INV 2330 -> 3117
    submod(w[3117], one, w[2330]);

    // XOR 3065 1618 -> 3118
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3065], w[1618]);
        mulmod(t2, w[3065], w[1618]);
        mulmod_constant(t2, t2, two);
        submod(w[3118], t1, t2);
    }

    // XOR 1962 1972 -> 3119
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1962], w[1972]);
        mulmod(t2, w[1962], w[1972]);
        mulmod_constant(t2, t2, two);
        submod(w[3119], t1, t2);
    }

    // AND 1063 1979 -> 3120
    mulmod(w[3120], w[1063], w[1979]);

    // XOR 2038 155 -> 3121
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2038], w[155]);
        mulmod(t2, w[2038], w[155]);
        mulmod_constant(t2, t2, two);
        submod(w[3121], t1, t2);
    }

    // XOR 1467 2078 -> 3122
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1467], w[2078]);
        mulmod(t2, w[1467], w[2078]);
        mulmod_constant(t2, t2, two);
        submod(w[3122], t1, t2);
    }

    // XOR 2825 113 -> 3123
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2825], w[113]);
        mulmod(t2, w[2825], w[113]);
        mulmod_constant(t2, t2, two);
        submod(w[3123], t1, t2);
    }

    // AND 370 52 -> 3124
    mulmod(w[3124], w[370], w[52]);

    // AND 2099 1983 -> 3125
    mulmod(w[3125], w[2099], w[1983]);

    // XOR 3075 2713 -> 3126
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3075], w[2713]);
        mulmod(t2, w[3075], w[2713]);
        mulmod_constant(t2, t2, two);
        submod(w[3126], t1, t2);
    }

    // XOR 2167 784 -> 3127
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2167], w[784]);
        mulmod(t2, w[2167], w[784]);
        mulmod_constant(t2, t2, two);
        submod(w[3127], t1, t2);
    }

    // AND 2195 505 -> 3128
    mulmod(w[3128], w[2195], w[505]);

    // AND 1096 2177 -> 3129
    mulmod(w[3129], w[1096], w[2177]);

    // INV 2731 -> 3130
    submod(w[3130], one, w[2731]);

    // AND 1936 1490 -> 3131
    mulmod(w[3131], w[1936], w[1490]);

    // XOR 900 2502 -> 3132
    {
        bn254fr_class t1, t2;
        addmod(t1, w[900], w[2502]);
        mulmod(t2, w[900], w[2502]);
        mulmod_constant(t2, t2, two);
        submod(w[3132], t1, t2);
    }

    // AND 1574 1929 -> 3133
    mulmod(w[3133], w[1574], w[1929]);

    // AND 20 51 -> 3134
    mulmod(w[3134], w[20], w[51]);

    // XOR 2340 2482 -> 3135
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2340], w[2482]);
        mulmod(t2, w[2340], w[2482]);
        mulmod_constant(t2, t2, two);
        submod(w[3135], t1, t2);
    }

    // AND 1356 769 -> 3136
    mulmod(w[3136], w[1356], w[769]);

    // XOR 2384 3027 -> 3137
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2384], w[3027]);
        mulmod(t2, w[2384], w[3027]);
        mulmod_constant(t2, t2, two);
        submod(w[3137], t1, t2);
    }

    // AND 1513 2155 -> 3138
    mulmod(w[3138], w[1513], w[2155]);

    // XOR 2129 1717 -> 3139
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2129], w[1717]);
        mulmod(t2, w[2129], w[1717]);
        mulmod_constant(t2, t2, two);
        submod(w[3139], t1, t2);
    }

    // AND 895 2440 -> 3140
    mulmod(w[3140], w[895], w[2440]);

    // AND 966 2974 -> 3141
    mulmod(w[3141], w[966], w[2974]);

    // AND 988 864 -> 3142
    mulmod(w[3142], w[988], w[864]);

    // INV 1812 -> 3143
    submod(w[3143], one, w[1812]);

    // XOR 89 2838 -> 3144
    {
        bn254fr_class t1, t2;
        addmod(t1, w[89], w[2838]);
        mulmod(t2, w[89], w[2838]);
        mulmod_constant(t2, t2, two);
        submod(w[3144], t1, t2);
    }

    // AND 24 2955 -> 3145
    mulmod(w[3145], w[24], w[2955]);

    // INV 821 -> 3146
    submod(w[3146], one, w[821]);

    // INV 627 -> 3147
    submod(w[3147], one, w[627]);

    // XOR 2022 850 -> 3148
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2022], w[850]);
        mulmod(t2, w[2022], w[850]);
        mulmod_constant(t2, t2, two);
        submod(w[3148], t1, t2);
    }

    // XOR 2216 2837 -> 3149
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2216], w[2837]);
        mulmod(t2, w[2216], w[2837]);
        mulmod_constant(t2, t2, two);
        submod(w[3149], t1, t2);
    }

    // XOR 707 1411 -> 3150
    {
        bn254fr_class t1, t2;
        addmod(t1, w[707], w[1411]);
        mulmod(t2, w[707], w[1411]);
        mulmod_constant(t2, t2, two);
        submod(w[3150], t1, t2);
    }

    // XOR 2687 3018 -> 3151
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2687], w[3018]);
        mulmod(t2, w[2687], w[3018]);
        mulmod_constant(t2, t2, two);
        submod(w[3151], t1, t2);
    }

    // INV 1748 -> 3152
    submod(w[3152], one, w[1748]);

    // AND 2432 700 -> 3153
    mulmod(w[3153], w[2432], w[700]);

    // AND 2584 1399 -> 3154
    mulmod(w[3154], w[2584], w[1399]);

    // AND 2873 1328 -> 3155
    mulmod(w[3155], w[2873], w[1328]);

    // XOR 341 204 -> 3156
    {
        bn254fr_class t1, t2;
        addmod(t1, w[341], w[204]);
        mulmod(t2, w[341], w[204]);
        mulmod_constant(t2, t2, two);
        submod(w[3156], t1, t2);
    }

    // XOR 2115 1987 -> 3157
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2115], w[1987]);
        mulmod(t2, w[2115], w[1987]);
        mulmod_constant(t2, t2, two);
        submod(w[3157], t1, t2);
    }

    // XOR 1926 1186 -> 3158
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1926], w[1186]);
        mulmod(t2, w[1926], w[1186]);
        mulmod_constant(t2, t2, two);
        submod(w[3158], t1, t2);
    }

    // XOR 2990 220 -> 3159
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2990], w[220]);
        mulmod(t2, w[2990], w[220]);
        mulmod_constant(t2, t2, two);
        submod(w[3159], t1, t2);
    }

    // AND 2560 1344 -> 3160
    mulmod(w[3160], w[2560], w[1344]);

    // XOR 513 1490 -> 3161
    {
        bn254fr_class t1, t2;
        addmod(t1, w[513], w[1490]);
        mulmod(t2, w[513], w[1490]);
        mulmod_constant(t2, t2, two);
        submod(w[3161], t1, t2);
    }

    // INV 2938 -> 3162
    submod(w[3162], one, w[2938]);

    // XOR 162 206 -> 3163
    {
        bn254fr_class t1, t2;
        addmod(t1, w[162], w[206]);
        mulmod(t2, w[162], w[206]);
        mulmod_constant(t2, t2, two);
        submod(w[3163], t1, t2);
    }

    // AND 1490 1868 -> 3164
    mulmod(w[3164], w[1490], w[1868]);

    // INV 18 -> 3165
    submod(w[3165], one, w[18]);

    // XOR 2360 2564 -> 3166
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2360], w[2564]);
        mulmod(t2, w[2360], w[2564]);
        mulmod_constant(t2, t2, two);
        submod(w[3166], t1, t2);
    }

    // AND 1707 1980 -> 3167
    mulmod(w[3167], w[1707], w[1980]);

    // XOR 472 1010 -> 3168
    {
        bn254fr_class t1, t2;
        addmod(t1, w[472], w[1010]);
        mulmod(t2, w[472], w[1010]);
        mulmod_constant(t2, t2, two);
        submod(w[3168], t1, t2);
    }

    // XOR 2327 634 -> 3169
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2327], w[634]);
        mulmod(t2, w[2327], w[634]);
        mulmod_constant(t2, t2, two);
        submod(w[3169], t1, t2);
    }

    // XOR 2969 2606 -> 3170
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2969], w[2606]);
        mulmod(t2, w[2969], w[2606]);
        mulmod_constant(t2, t2, two);
        submod(w[3170], t1, t2);
    }

    // XOR 1892 2990 -> 3171
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1892], w[2990]);
        mulmod(t2, w[1892], w[2990]);
        mulmod_constant(t2, t2, two);
        submod(w[3171], t1, t2);
    }

    // AND 2941 1463 -> 3172
    mulmod(w[3172], w[2941], w[1463]);

    // AND 912 1177 -> 3173
    mulmod(w[3173], w[912], w[1177]);

    // AND 2601 2495 -> 3174
    mulmod(w[3174], w[2601], w[2495]);

    // XOR 32 103 -> 3175
    {
        bn254fr_class t1, t2;
        addmod(t1, w[32], w[103]);
        mulmod(t2, w[32], w[103]);
        mulmod_constant(t2, t2, two);
        submod(w[3175], t1, t2);
    }

    // XOR 3031 3109 -> 3176
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3031], w[3109]);
        mulmod(t2, w[3031], w[3109]);
        mulmod_constant(t2, t2, two);
        submod(w[3176], t1, t2);
    }

    // XOR 2397 1461 -> 3177
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2397], w[1461]);
        mulmod(t2, w[2397], w[1461]);
        mulmod_constant(t2, t2, two);
        submod(w[3177], t1, t2);
    }

    // XOR 774 1537 -> 3178
    {
        bn254fr_class t1, t2;
        addmod(t1, w[774], w[1537]);
        mulmod(t2, w[774], w[1537]);
        mulmod_constant(t2, t2, two);
        submod(w[3178], t1, t2);
    }

    // INV 1214 -> 3179
    submod(w[3179], one, w[1214]);

    // AND 1749 1181 -> 3180
    mulmod(w[3180], w[1749], w[1181]);

    // AND 430 2304 -> 3181
    mulmod(w[3181], w[430], w[2304]);

    // XOR 2539 579 -> 3182
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2539], w[579]);
        mulmod(t2, w[2539], w[579]);
        mulmod_constant(t2, t2, two);
        submod(w[3182], t1, t2);
    }

    // XOR 1561 1426 -> 3183
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1561], w[1426]);
        mulmod(t2, w[1561], w[1426]);
        mulmod_constant(t2, t2, two);
        submod(w[3183], t1, t2);
    }

    // XOR 2724 641 -> 3184
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2724], w[641]);
        mulmod(t2, w[2724], w[641]);
        mulmod_constant(t2, t2, two);
        submod(w[3184], t1, t2);
    }

    // XOR 3080 1450 -> 3185
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3080], w[1450]);
        mulmod(t2, w[3080], w[1450]);
        mulmod_constant(t2, t2, two);
        submod(w[3185], t1, t2);
    }

    // AND 1458 2300 -> 3186
    mulmod(w[3186], w[1458], w[2300]);

    // XOR 3083 2487 -> 3187
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3083], w[2487]);
        mulmod(t2, w[3083], w[2487]);
        mulmod_constant(t2, t2, two);
        submod(w[3187], t1, t2);
    }

    // XOR 2482 2952 -> 3188
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2482], w[2952]);
        mulmod(t2, w[2482], w[2952]);
        mulmod_constant(t2, t2, two);
        submod(w[3188], t1, t2);
    }

    // AND 1263 27 -> 3189
    mulmod(w[3189], w[1263], w[27]);

    // AND 2253 2250 -> 3190
    mulmod(w[3190], w[2253], w[2250]);

    // AND 2894 8 -> 3191
    mulmod(w[3191], w[2894], w[8]);

    // XOR 1653 1293 -> 3192
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1653], w[1293]);
        mulmod(t2, w[1653], w[1293]);
        mulmod_constant(t2, t2, two);
        submod(w[3192], t1, t2);
    }

    // AND 2327 1758 -> 3193
    mulmod(w[3193], w[2327], w[1758]);

    // XOR 784 1870 -> 3194
    {
        bn254fr_class t1, t2;
        addmod(t1, w[784], w[1870]);
        mulmod(t2, w[784], w[1870]);
        mulmod_constant(t2, t2, two);
        submod(w[3194], t1, t2);
    }

    // XOR 88 688 -> 3195
    {
        bn254fr_class t1, t2;
        addmod(t1, w[88], w[688]);
        mulmod(t2, w[88], w[688]);
        mulmod_constant(t2, t2, two);
        submod(w[3195], t1, t2);
    }

    // AND 2985 367 -> 3196
    mulmod(w[3196], w[2985], w[367]);

    // XOR 3107 1120 -> 3197
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3107], w[1120]);
        mulmod(t2, w[3107], w[1120]);
        mulmod_constant(t2, t2, two);
        submod(w[3197], t1, t2);
    }

    // XOR 619 2291 -> 3198
    {
        bn254fr_class t1, t2;
        addmod(t1, w[619], w[2291]);
        mulmod(t2, w[619], w[2291]);
        mulmod_constant(t2, t2, two);
        submod(w[3198], t1, t2);
    }

    // XOR 768 2983 -> 3199
    {
        bn254fr_class t1, t2;
        addmod(t1, w[768], w[2983]);
        mulmod(t2, w[768], w[2983]);
        mulmod_constant(t2, t2, two);
        submod(w[3199], t1, t2);
    }

    // AND 372 1131 -> 3200
    mulmod(w[3200], w[372], w[1131]);

    // AND 2259 2552 -> 3201
    mulmod(w[3201], w[2259], w[2552]);

    // XOR 865 1115 -> 3202
    {
        bn254fr_class t1, t2;
        addmod(t1, w[865], w[1115]);
        mulmod(t2, w[865], w[1115]);
        mulmod_constant(t2, t2, two);
        submod(w[3202], t1, t2);
    }

    // INV 2106 -> 3203
    submod(w[3203], one, w[2106]);

    // XOR 1533 1498 -> 3204
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1533], w[1498]);
        mulmod(t2, w[1533], w[1498]);
        mulmod_constant(t2, t2, two);
        submod(w[3204], t1, t2);
    }

    // XOR 922 393 -> 3205
    {
        bn254fr_class t1, t2;
        addmod(t1, w[922], w[393]);
        mulmod(t2, w[922], w[393]);
        mulmod_constant(t2, t2, two);
        submod(w[3205], t1, t2);
    }

    // AND 1761 1115 -> 3206
    mulmod(w[3206], w[1761], w[1115]);

    // AND 774 1099 -> 3207
    mulmod(w[3207], w[774], w[1099]);

    // XOR 461 2798 -> 3208
    {
        bn254fr_class t1, t2;
        addmod(t1, w[461], w[2798]);
        mulmod(t2, w[461], w[2798]);
        mulmod_constant(t2, t2, two);
        submod(w[3208], t1, t2);
    }

    // XOR 1233 1627 -> 3209
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1233], w[1627]);
        mulmod(t2, w[1233], w[1627]);
        mulmod_constant(t2, t2, two);
        submod(w[3209], t1, t2);
    }

    // INV 2256 -> 3210
    submod(w[3210], one, w[2256]);

    // XOR 862 2322 -> 3211
    {
        bn254fr_class t1, t2;
        addmod(t1, w[862], w[2322]);
        mulmod(t2, w[862], w[2322]);
        mulmod_constant(t2, t2, two);
        submod(w[3211], t1, t2);
    }

    // XOR 192 1474 -> 3212
    {
        bn254fr_class t1, t2;
        addmod(t1, w[192], w[1474]);
        mulmod(t2, w[192], w[1474]);
        mulmod_constant(t2, t2, two);
        submod(w[3212], t1, t2);
    }

    // XOR 316 2503 -> 3213
    {
        bn254fr_class t1, t2;
        addmod(t1, w[316], w[2503]);
        mulmod(t2, w[316], w[2503]);
        mulmod_constant(t2, t2, two);
        submod(w[3213], t1, t2);
    }

    // AND 1849 2694 -> 3214
    mulmod(w[3214], w[1849], w[2694]);

    // XOR 1618 838 -> 3215
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1618], w[838]);
        mulmod(t2, w[1618], w[838]);
        mulmod_constant(t2, t2, two);
        submod(w[3215], t1, t2);
    }

    // XOR 713 2915 -> 3216
    {
        bn254fr_class t1, t2;
        addmod(t1, w[713], w[2915]);
        mulmod(t2, w[713], w[2915]);
        mulmod_constant(t2, t2, two);
        submod(w[3216], t1, t2);
    }

    // AND 2523 1828 -> 3217
    mulmod(w[3217], w[2523], w[1828]);

    // XOR 1589 3067 -> 3218
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1589], w[3067]);
        mulmod(t2, w[1589], w[3067]);
        mulmod_constant(t2, t2, two);
        submod(w[3218], t1, t2);
    }

    // XOR 2679 793 -> 3219
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2679], w[793]);
        mulmod(t2, w[2679], w[793]);
        mulmod_constant(t2, t2, two);
        submod(w[3219], t1, t2);
    }

    // AND 1685 1200 -> 3220
    mulmod(w[3220], w[1685], w[1200]);

    // XOR 2084 1583 -> 3221
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2084], w[1583]);
        mulmod(t2, w[2084], w[1583]);
        mulmod_constant(t2, t2, two);
        submod(w[3221], t1, t2);
    }

    // AND 443 2463 -> 3222
    mulmod(w[3222], w[443], w[2463]);

    // XOR 1598 1001 -> 3223
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1598], w[1001]);
        mulmod(t2, w[1598], w[1001]);
        mulmod_constant(t2, t2, two);
        submod(w[3223], t1, t2);
    }

    // AND 1197 2809 -> 3224
    mulmod(w[3224], w[1197], w[2809]);

    // XOR 2768 520 -> 3225
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2768], w[520]);
        mulmod(t2, w[2768], w[520]);
        mulmod_constant(t2, t2, two);
        submod(w[3225], t1, t2);
    }

    // AND 2053 2106 -> 3226
    mulmod(w[3226], w[2053], w[2106]);

    // XOR 2318 2053 -> 3227
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2318], w[2053]);
        mulmod(t2, w[2318], w[2053]);
        mulmod_constant(t2, t2, two);
        submod(w[3227], t1, t2);
    }

    // INV 2261 -> 3228
    submod(w[3228], one, w[2261]);

    // XOR 664 397 -> 3229
    {
        bn254fr_class t1, t2;
        addmod(t1, w[664], w[397]);
        mulmod(t2, w[664], w[397]);
        mulmod_constant(t2, t2, two);
        submod(w[3229], t1, t2);
    }

    // AND 1063 2671 -> 3230
    mulmod(w[3230], w[1063], w[2671]);

    // AND 1821 326 -> 3231
    mulmod(w[3231], w[1821], w[326]);

    // AND 1415 3181 -> 3232
    mulmod(w[3232], w[1415], w[3181]);

    // XOR 2352 1879 -> 3233
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2352], w[1879]);
        mulmod(t2, w[2352], w[1879]);
        mulmod_constant(t2, t2, two);
        submod(w[3233], t1, t2);
    }

    // AND 787 995 -> 3234
    mulmod(w[3234], w[787], w[995]);

    // XOR 973 2481 -> 3235
    {
        bn254fr_class t1, t2;
        addmod(t1, w[973], w[2481]);
        mulmod(t2, w[973], w[2481]);
        mulmod_constant(t2, t2, two);
        submod(w[3235], t1, t2);
    }

    // AND 208 39 -> 3236
    mulmod(w[3236], w[208], w[39]);

    // XOR 1037 1948 -> 3237
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1037], w[1948]);
        mulmod(t2, w[1037], w[1948]);
        mulmod_constant(t2, t2, two);
        submod(w[3237], t1, t2);
    }

    // XOR 2902 586 -> 3238
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2902], w[586]);
        mulmod(t2, w[2902], w[586]);
        mulmod_constant(t2, t2, two);
        submod(w[3238], t1, t2);
    }

    // AND 2946 952 -> 3239
    mulmod(w[3239], w[2946], w[952]);

    // INV 575 -> 3240
    submod(w[3240], one, w[575]);

    // INV 596 -> 3241
    submod(w[3241], one, w[596]);

    // AND 2913 725 -> 3242
    mulmod(w[3242], w[2913], w[725]);

    // AND 1328 2446 -> 3243
    mulmod(w[3243], w[1328], w[2446]);

    // AND 940 3186 -> 3244
    mulmod(w[3244], w[940], w[3186]);

    // XOR 1281 1809 -> 3245
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1281], w[1809]);
        mulmod(t2, w[1281], w[1809]);
        mulmod_constant(t2, t2, two);
        submod(w[3245], t1, t2);
    }

    // XOR 2034 2252 -> 3246
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2034], w[2252]);
        mulmod(t2, w[2034], w[2252]);
        mulmod_constant(t2, t2, two);
        submod(w[3246], t1, t2);
    }

    // INV 337 -> 3247
    submod(w[3247], one, w[337]);

    // XOR 1026 414 -> 3248
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1026], w[414]);
        mulmod(t2, w[1026], w[414]);
        mulmod_constant(t2, t2, two);
        submod(w[3248], t1, t2);
    }

    // INV 930 -> 3249
    submod(w[3249], one, w[930]);

    // XOR 641 2440 -> 3250
    {
        bn254fr_class t1, t2;
        addmod(t1, w[641], w[2440]);
        mulmod(t2, w[641], w[2440]);
        mulmod_constant(t2, t2, two);
        submod(w[3250], t1, t2);
    }

    // AND 802 526 -> 3251
    mulmod(w[3251], w[802], w[526]);

    // AND 523 2478 -> 3252
    mulmod(w[3252], w[523], w[2478]);

    // XOR 89 2175 -> 3253
    {
        bn254fr_class t1, t2;
        addmod(t1, w[89], w[2175]);
        mulmod(t2, w[89], w[2175]);
        mulmod_constant(t2, t2, two);
        submod(w[3253], t1, t2);
    }

    // AND 605 1907 -> 3254
    mulmod(w[3254], w[605], w[1907]);

    // XOR 1500 2509 -> 3255
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1500], w[2509]);
        mulmod(t2, w[1500], w[2509]);
        mulmod_constant(t2, t2, two);
        submod(w[3255], t1, t2);
    }

    // AND 1930 2637 -> 3256
    mulmod(w[3256], w[1930], w[2637]);

    // XOR 2240 1020 -> 3257
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2240], w[1020]);
        mulmod(t2, w[2240], w[1020]);
        mulmod_constant(t2, t2, two);
        submod(w[3257], t1, t2);
    }

    // AND 1420 572 -> 3258
    mulmod(w[3258], w[1420], w[572]);

    // AND 1508 3109 -> 3259
    mulmod(w[3259], w[1508], w[3109]);

    // XOR 1388 1549 -> 3260
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1388], w[1549]);
        mulmod(t2, w[1388], w[1549]);
        mulmod_constant(t2, t2, two);
        submod(w[3260], t1, t2);
    }

    // XOR 885 810 -> 3261
    {
        bn254fr_class t1, t2;
        addmod(t1, w[885], w[810]);
        mulmod(t2, w[885], w[810]);
        mulmod_constant(t2, t2, two);
        submod(w[3261], t1, t2);
    }

    // AND 1919 1714 -> 3262
    mulmod(w[3262], w[1919], w[1714]);

    // AND 2022 2638 -> 3263
    mulmod(w[3263], w[2022], w[2638]);

    // AND 2882 966 -> 3264
    mulmod(w[3264], w[2882], w[966]);

    // XOR 2416 1662 -> 3265
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2416], w[1662]);
        mulmod(t2, w[2416], w[1662]);
        mulmod_constant(t2, t2, two);
        submod(w[3265], t1, t2);
    }

    // XOR 1922 3107 -> 3266
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1922], w[3107]);
        mulmod(t2, w[1922], w[3107]);
        mulmod_constant(t2, t2, two);
        submod(w[3266], t1, t2);
    }

    // XOR 650 1775 -> 3267
    {
        bn254fr_class t1, t2;
        addmod(t1, w[650], w[1775]);
        mulmod(t2, w[650], w[1775]);
        mulmod_constant(t2, t2, two);
        submod(w[3267], t1, t2);
    }

    // XOR 2179 1208 -> 3268
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2179], w[1208]);
        mulmod(t2, w[2179], w[1208]);
        mulmod_constant(t2, t2, two);
        submod(w[3268], t1, t2);
    }

    // XOR 1554 1307 -> 3269
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1554], w[1307]);
        mulmod(t2, w[1554], w[1307]);
        mulmod_constant(t2, t2, two);
        submod(w[3269], t1, t2);
    }

    // XOR 2668 2922 -> 3270
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2668], w[2922]);
        mulmod(t2, w[2668], w[2922]);
        mulmod_constant(t2, t2, two);
        submod(w[3270], t1, t2);
    }

    // XOR 2511 444 -> 3271
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2511], w[444]);
        mulmod(t2, w[2511], w[444]);
        mulmod_constant(t2, t2, two);
        submod(w[3271], t1, t2);
    }

    // INV 2054 -> 3272
    submod(w[3272], one, w[2054]);

    // XOR 2413 1396 -> 3273
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2413], w[1396]);
        mulmod(t2, w[2413], w[1396]);
        mulmod_constant(t2, t2, two);
        submod(w[3273], t1, t2);
    }

    // AND 712 1536 -> 3274
    mulmod(w[3274], w[712], w[1536]);

    // XOR 670 1549 -> 3275
    {
        bn254fr_class t1, t2;
        addmod(t1, w[670], w[1549]);
        mulmod(t2, w[670], w[1549]);
        mulmod_constant(t2, t2, two);
        submod(w[3275], t1, t2);
    }

    // AND 1574 2843 -> 3276
    mulmod(w[3276], w[1574], w[2843]);

    // INV 1420 -> 3277
    submod(w[3277], one, w[1420]);

    // INV 2905 -> 3278
    submod(w[3278], one, w[2905]);

    // XOR 606 2187 -> 3279
    {
        bn254fr_class t1, t2;
        addmod(t1, w[606], w[2187]);
        mulmod(t2, w[606], w[2187]);
        mulmod_constant(t2, t2, two);
        submod(w[3279], t1, t2);
    }

    // XOR 251 2786 -> 3280
    {
        bn254fr_class t1, t2;
        addmod(t1, w[251], w[2786]);
        mulmod(t2, w[251], w[2786]);
        mulmod_constant(t2, t2, two);
        submod(w[3280], t1, t2);
    }

    // INV 2384 -> 3281
    submod(w[3281], one, w[2384]);

    // AND 2223 531 -> 3282
    mulmod(w[3282], w[2223], w[531]);

    // AND 412 283 -> 3283
    mulmod(w[3283], w[412], w[283]);

    // INV 2792 -> 3284
    submod(w[3284], one, w[2792]);

    // XOR 786 1363 -> 3285
    {
        bn254fr_class t1, t2;
        addmod(t1, w[786], w[1363]);
        mulmod(t2, w[786], w[1363]);
        mulmod_constant(t2, t2, two);
        submod(w[3285], t1, t2);
    }

    // XOR 2344 573 -> 3286
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2344], w[573]);
        mulmod(t2, w[2344], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[3286], t1, t2);
    }

    // AND 3183 3170 -> 3287
    mulmod(w[3287], w[3183], w[3170]);

    // AND 1037 1566 -> 3288
    mulmod(w[3288], w[1037], w[1566]);

    // AND 2703 1528 -> 3289
    mulmod(w[3289], w[2703], w[1528]);

    // XOR 2557 1310 -> 3290
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2557], w[1310]);
        mulmod(t2, w[2557], w[1310]);
        mulmod_constant(t2, t2, two);
        submod(w[3290], t1, t2);
    }

    // XOR 1344 2602 -> 3291
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1344], w[2602]);
        mulmod(t2, w[1344], w[2602]);
        mulmod_constant(t2, t2, two);
        submod(w[3291], t1, t2);
    }

    // XOR 2461 1397 -> 3292
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2461], w[1397]);
        mulmod(t2, w[2461], w[1397]);
        mulmod_constant(t2, t2, two);
        submod(w[3292], t1, t2);
    }

    // XOR 2846 1087 -> 3293
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2846], w[1087]);
        mulmod(t2, w[2846], w[1087]);
        mulmod_constant(t2, t2, two);
        submod(w[3293], t1, t2);
    }

    // XOR 543 63 -> 3294
    {
        bn254fr_class t1, t2;
        addmod(t1, w[543], w[63]);
        mulmod(t2, w[543], w[63]);
        mulmod_constant(t2, t2, two);
        submod(w[3294], t1, t2);
    }

    // AND 662 1327 -> 3295
    mulmod(w[3295], w[662], w[1327]);

    // AND 1592 77 -> 3296
    mulmod(w[3296], w[1592], w[77]);

    // XOR 2541 3173 -> 3297
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2541], w[3173]);
        mulmod(t2, w[2541], w[3173]);
        mulmod_constant(t2, t2, two);
        submod(w[3297], t1, t2);
    }

    // XOR 1953 3094 -> 3298
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1953], w[3094]);
        mulmod(t2, w[1953], w[3094]);
        mulmod_constant(t2, t2, two);
        submod(w[3298], t1, t2);
    }

    // XOR 196 2568 -> 3299
    {
        bn254fr_class t1, t2;
        addmod(t1, w[196], w[2568]);
        mulmod(t2, w[196], w[2568]);
        mulmod_constant(t2, t2, two);
        submod(w[3299], t1, t2);
    }

    // XOR 2717 485 -> 3300
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2717], w[485]);
        mulmod(t2, w[2717], w[485]);
        mulmod_constant(t2, t2, two);
        submod(w[3300], t1, t2);
    }

    // XOR 487 2172 -> 3301
    {
        bn254fr_class t1, t2;
        addmod(t1, w[487], w[2172]);
        mulmod(t2, w[487], w[2172]);
        mulmod_constant(t2, t2, two);
        submod(w[3301], t1, t2);
    }

    // AND 1842 538 -> 3302
    mulmod(w[3302], w[1842], w[538]);

    // INV 1797 -> 3303
    submod(w[3303], one, w[1797]);

    // AND 1419 657 -> 3304
    mulmod(w[3304], w[1419], w[657]);

    // XOR 368 1694 -> 3305
    {
        bn254fr_class t1, t2;
        addmod(t1, w[368], w[1694]);
        mulmod(t2, w[368], w[1694]);
        mulmod_constant(t2, t2, two);
        submod(w[3305], t1, t2);
    }

    // AND 1482 2109 -> 3306
    mulmod(w[3306], w[1482], w[2109]);

    // AND 876 1251 -> 3307
    mulmod(w[3307], w[876], w[1251]);

    // XOR 553 286 -> 3308
    {
        bn254fr_class t1, t2;
        addmod(t1, w[553], w[286]);
        mulmod(t2, w[553], w[286]);
        mulmod_constant(t2, t2, two);
        submod(w[3308], t1, t2);
    }

    // AND 2408 402 -> 3309
    mulmod(w[3309], w[2408], w[402]);

    // XOR 1308 343 -> 3310
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1308], w[343]);
        mulmod(t2, w[1308], w[343]);
        mulmod_constant(t2, t2, two);
        submod(w[3310], t1, t2);
    }

    // AND 1917 176 -> 3311
    mulmod(w[3311], w[1917], w[176]);

    // AND 2388 164 -> 3312
    mulmod(w[3312], w[2388], w[164]);

    // AND 2353 2565 -> 3313
    mulmod(w[3313], w[2353], w[2565]);

    // XOR 897 504 -> 3314
    {
        bn254fr_class t1, t2;
        addmod(t1, w[897], w[504]);
        mulmod(t2, w[897], w[504]);
        mulmod_constant(t2, t2, two);
        submod(w[3314], t1, t2);
    }

    // XOR 3015 1645 -> 3315
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3015], w[1645]);
        mulmod(t2, w[3015], w[1645]);
        mulmod_constant(t2, t2, two);
        submod(w[3315], t1, t2);
    }

    // XOR 194 573 -> 3316
    {
        bn254fr_class t1, t2;
        addmod(t1, w[194], w[573]);
        mulmod(t2, w[194], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[3316], t1, t2);
    }

    // INV 2381 -> 3317
    submod(w[3317], one, w[2381]);

    // INV 347 -> 3318
    submod(w[3318], one, w[347]);

    // AND 3072 3014 -> 3319
    mulmod(w[3319], w[3072], w[3014]);

    // XOR 2357 1212 -> 3320
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2357], w[1212]);
        mulmod(t2, w[2357], w[1212]);
        mulmod_constant(t2, t2, two);
        submod(w[3320], t1, t2);
    }

    // AND 274 1022 -> 3321
    mulmod(w[3321], w[274], w[1022]);

    // XOR 807 1901 -> 3322
    {
        bn254fr_class t1, t2;
        addmod(t1, w[807], w[1901]);
        mulmod(t2, w[807], w[1901]);
        mulmod_constant(t2, t2, two);
        submod(w[3322], t1, t2);
    }

    // AND 2090 640 -> 3323
    mulmod(w[3323], w[2090], w[640]);

    // XOR 1456 1580 -> 3324
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1456], w[1580]);
        mulmod(t2, w[1456], w[1580]);
        mulmod_constant(t2, t2, two);
        submod(w[3324], t1, t2);
    }

    // AND 185 1304 -> 3325
    mulmod(w[3325], w[185], w[1304]);

    // XOR 1331 1050 -> 3326
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1331], w[1050]);
        mulmod(t2, w[1331], w[1050]);
        mulmod_constant(t2, t2, two);
        submod(w[3326], t1, t2);
    }

    // XOR 201 2975 -> 3327
    {
        bn254fr_class t1, t2;
        addmod(t1, w[201], w[2975]);
        mulmod(t2, w[201], w[2975]);
        mulmod_constant(t2, t2, two);
        submod(w[3327], t1, t2);
    }

    // XOR 2162 27 -> 3328
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2162], w[27]);
        mulmod(t2, w[2162], w[27]);
        mulmod_constant(t2, t2, two);
        submod(w[3328], t1, t2);
    }

    // AND 323 1322 -> 3329
    mulmod(w[3329], w[323], w[1322]);

    // AND 1069 2503 -> 3330
    mulmod(w[3330], w[1069], w[2503]);

    // XOR 2157 691 -> 3331
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2157], w[691]);
        mulmod(t2, w[2157], w[691]);
        mulmod_constant(t2, t2, two);
        submod(w[3331], t1, t2);
    }

    // AND 2748 2294 -> 3332
    mulmod(w[3332], w[2748], w[2294]);

    // XOR 2942 653 -> 3333
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2942], w[653]);
        mulmod(t2, w[2942], w[653]);
        mulmod_constant(t2, t2, two);
        submod(w[3333], t1, t2);
    }

    // XOR 817 2301 -> 3334
    {
        bn254fr_class t1, t2;
        addmod(t1, w[817], w[2301]);
        mulmod(t2, w[817], w[2301]);
        mulmod_constant(t2, t2, two);
        submod(w[3334], t1, t2);
    }

    // AND 2922 489 -> 3335
    mulmod(w[3335], w[2922], w[489]);

    // XOR 40 2776 -> 3336
    {
        bn254fr_class t1, t2;
        addmod(t1, w[40], w[2776]);
        mulmod(t2, w[40], w[2776]);
        mulmod_constant(t2, t2, two);
        submod(w[3336], t1, t2);
    }

    // INV 3160 -> 3337
    submod(w[3337], one, w[3160]);

    // INV 2305 -> 3338
    submod(w[3338], one, w[2305]);

    // AND 2266 1755 -> 3339
    mulmod(w[3339], w[2266], w[1755]);

    // XOR 2976 2958 -> 3340
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2976], w[2958]);
        mulmod(t2, w[2976], w[2958]);
        mulmod_constant(t2, t2, two);
        submod(w[3340], t1, t2);
    }

    // XOR 1335 309 -> 3341
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1335], w[309]);
        mulmod(t2, w[1335], w[309]);
        mulmod_constant(t2, t2, two);
        submod(w[3341], t1, t2);
    }

    // XOR 292 2957 -> 3342
    {
        bn254fr_class t1, t2;
        addmod(t1, w[292], w[2957]);
        mulmod(t2, w[292], w[2957]);
        mulmod_constant(t2, t2, two);
        submod(w[3342], t1, t2);
    }

    // XOR 2890 2889 -> 3343
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2890], w[2889]);
        mulmod(t2, w[2890], w[2889]);
        mulmod_constant(t2, t2, two);
        submod(w[3343], t1, t2);
    }

    // XOR 705 529 -> 3344
    {
        bn254fr_class t1, t2;
        addmod(t1, w[705], w[529]);
        mulmod(t2, w[705], w[529]);
        mulmod_constant(t2, t2, two);
        submod(w[3344], t1, t2);
    }

    // XOR 2198 2604 -> 3345
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2198], w[2604]);
        mulmod(t2, w[2198], w[2604]);
        mulmod_constant(t2, t2, two);
        submod(w[3345], t1, t2);
    }

    // AND 1010 542 -> 3346
    mulmod(w[3346], w[1010], w[542]);

    // XOR 1933 512 -> 3347
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1933], w[512]);
        mulmod(t2, w[1933], w[512]);
        mulmod_constant(t2, t2, two);
        submod(w[3347], t1, t2);
    }

    // AND 1950 1427 -> 3348
    mulmod(w[3348], w[1950], w[1427]);

    // XOR 2756 2884 -> 3349
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2756], w[2884]);
        mulmod(t2, w[2756], w[2884]);
        mulmod_constant(t2, t2, two);
        submod(w[3349], t1, t2);
    }

    // XOR 3241 3043 -> 3350
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3241], w[3043]);
        mulmod(t2, w[3241], w[3043]);
        mulmod_constant(t2, t2, two);
        submod(w[3350], t1, t2);
    }

    // XOR 2083 2123 -> 3351
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2083], w[2123]);
        mulmod(t2, w[2083], w[2123]);
        mulmod_constant(t2, t2, two);
        submod(w[3351], t1, t2);
    }

    // INV 1723 -> 3352
    submod(w[3352], one, w[1723]);

    // XOR 1831 1938 -> 3353
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1831], w[1938]);
        mulmod(t2, w[1831], w[1938]);
        mulmod_constant(t2, t2, two);
        submod(w[3353], t1, t2);
    }

    // INV 2587 -> 3354
    submod(w[3354], one, w[2587]);

    // XOR 2695 3012 -> 3355
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2695], w[3012]);
        mulmod(t2, w[2695], w[3012]);
        mulmod_constant(t2, t2, two);
        submod(w[3355], t1, t2);
    }

    // XOR 2408 1776 -> 3356
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2408], w[1776]);
        mulmod(t2, w[2408], w[1776]);
        mulmod_constant(t2, t2, two);
        submod(w[3356], t1, t2);
    }

    // AND 886 2515 -> 3357
    mulmod(w[3357], w[886], w[2515]);

    // XOR 2592 344 -> 3358
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2592], w[344]);
        mulmod(t2, w[2592], w[344]);
        mulmod_constant(t2, t2, two);
        submod(w[3358], t1, t2);
    }

    // AND 377 1994 -> 3359
    mulmod(w[3359], w[377], w[1994]);

    // AND 153 1595 -> 3360
    mulmod(w[3360], w[153], w[1595]);

    // XOR 2827 1190 -> 3361
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2827], w[1190]);
        mulmod(t2, w[2827], w[1190]);
        mulmod_constant(t2, t2, two);
        submod(w[3361], t1, t2);
    }

    // XOR 1353 493 -> 3362
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1353], w[493]);
        mulmod(t2, w[1353], w[493]);
        mulmod_constant(t2, t2, two);
        submod(w[3362], t1, t2);
    }

    // XOR 1465 210 -> 3363
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1465], w[210]);
        mulmod(t2, w[1465], w[210]);
        mulmod_constant(t2, t2, two);
        submod(w[3363], t1, t2);
    }

    // XOR 2558 2961 -> 3364
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2558], w[2961]);
        mulmod(t2, w[2558], w[2961]);
        mulmod_constant(t2, t2, two);
        submod(w[3364], t1, t2);
    }

    // XOR 2933 580 -> 3365
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2933], w[580]);
        mulmod(t2, w[2933], w[580]);
        mulmod_constant(t2, t2, two);
        submod(w[3365], t1, t2);
    }

    // AND 2162 2968 -> 3366
    mulmod(w[3366], w[2162], w[2968]);

    // XOR 3157 2720 -> 3367
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3157], w[2720]);
        mulmod(t2, w[3157], w[2720]);
        mulmod_constant(t2, t2, two);
        submod(w[3367], t1, t2);
    }

    // XOR 469 3244 -> 3368
    {
        bn254fr_class t1, t2;
        addmod(t1, w[469], w[3244]);
        mulmod(t2, w[469], w[3244]);
        mulmod_constant(t2, t2, two);
        submod(w[3368], t1, t2);
    }

    // AND 1456 1422 -> 3369
    mulmod(w[3369], w[1456], w[1422]);

    // AND 1352 727 -> 3370
    mulmod(w[3370], w[1352], w[727]);

    // XOR 2645 1437 -> 3371
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2645], w[1437]);
        mulmod(t2, w[2645], w[1437]);
        mulmod_constant(t2, t2, two);
        submod(w[3371], t1, t2);
    }

    // XOR 2708 2619 -> 3372
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2708], w[2619]);
        mulmod(t2, w[2708], w[2619]);
        mulmod_constant(t2, t2, two);
        submod(w[3372], t1, t2);
    }

    // XOR 2214 487 -> 3373
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2214], w[487]);
        mulmod(t2, w[2214], w[487]);
        mulmod_constant(t2, t2, two);
        submod(w[3373], t1, t2);
    }

    // AND 3289 791 -> 3374
    mulmod(w[3374], w[3289], w[791]);

    // XOR 460 2137 -> 3375
    {
        bn254fr_class t1, t2;
        addmod(t1, w[460], w[2137]);
        mulmod(t2, w[460], w[2137]);
        mulmod_constant(t2, t2, two);
        submod(w[3375], t1, t2);
    }

    // AND 2549 2006 -> 3376
    mulmod(w[3376], w[2549], w[2006]);

    // XOR 1342 3326 -> 3377
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1342], w[3326]);
        mulmod(t2, w[1342], w[3326]);
        mulmod_constant(t2, t2, two);
        submod(w[3377], t1, t2);
    }

    // XOR 658 870 -> 3378
    {
        bn254fr_class t1, t2;
        addmod(t1, w[658], w[870]);
        mulmod(t2, w[658], w[870]);
        mulmod_constant(t2, t2, two);
        submod(w[3378], t1, t2);
    }

    // XOR 2574 2323 -> 3379
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2574], w[2323]);
        mulmod(t2, w[2574], w[2323]);
        mulmod_constant(t2, t2, two);
        submod(w[3379], t1, t2);
    }

    // XOR 2639 1632 -> 3380
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2639], w[1632]);
        mulmod(t2, w[2639], w[1632]);
        mulmod_constant(t2, t2, two);
        submod(w[3380], t1, t2);
    }

    // AND 447 3150 -> 3381
    mulmod(w[3381], w[447], w[3150]);

    // INV 968 -> 3382
    submod(w[3382], one, w[968]);

    // XOR 3327 1477 -> 3383
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3327], w[1477]);
        mulmod(t2, w[3327], w[1477]);
        mulmod_constant(t2, t2, two);
        submod(w[3383], t1, t2);
    }

    // XOR 2434 123 -> 3384
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2434], w[123]);
        mulmod(t2, w[2434], w[123]);
        mulmod_constant(t2, t2, two);
        submod(w[3384], t1, t2);
    }

    // INV 3326 -> 3385
    submod(w[3385], one, w[3326]);

    // XOR 526 2062 -> 3386
    {
        bn254fr_class t1, t2;
        addmod(t1, w[526], w[2062]);
        mulmod(t2, w[526], w[2062]);
        mulmod_constant(t2, t2, two);
        submod(w[3386], t1, t2);
    }

    // XOR 3125 1136 -> 3387
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3125], w[1136]);
        mulmod(t2, w[3125], w[1136]);
        mulmod_constant(t2, t2, two);
        submod(w[3387], t1, t2);
    }

    // XOR 381 1504 -> 3388
    {
        bn254fr_class t1, t2;
        addmod(t1, w[381], w[1504]);
        mulmod(t2, w[381], w[1504]);
        mulmod_constant(t2, t2, two);
        submod(w[3388], t1, t2);
    }

    // INV 383 -> 3389
    submod(w[3389], one, w[383]);

    // XOR 2670 169 -> 3390
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2670], w[169]);
        mulmod(t2, w[2670], w[169]);
        mulmod_constant(t2, t2, two);
        submod(w[3390], t1, t2);
    }

    // XOR 2780 1202 -> 3391
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2780], w[1202]);
        mulmod(t2, w[2780], w[1202]);
        mulmod_constant(t2, t2, two);
        submod(w[3391], t1, t2);
    }

    // XOR 3083 825 -> 3392
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3083], w[825]);
        mulmod(t2, w[3083], w[825]);
        mulmod_constant(t2, t2, two);
        submod(w[3392], t1, t2);
    }

    // XOR 2983 713 -> 3393
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2983], w[713]);
        mulmod(t2, w[2983], w[713]);
        mulmod_constant(t2, t2, two);
        submod(w[3393], t1, t2);
    }

    // AND 3319 1384 -> 3394
    mulmod(w[3394], w[3319], w[1384]);

    // AND 329 760 -> 3395
    mulmod(w[3395], w[329], w[760]);

    // XOR 564 597 -> 3396
    {
        bn254fr_class t1, t2;
        addmod(t1, w[564], w[597]);
        mulmod(t2, w[564], w[597]);
        mulmod_constant(t2, t2, two);
        submod(w[3396], t1, t2);
    }

    // XOR 1851 2521 -> 3397
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1851], w[2521]);
        mulmod(t2, w[1851], w[2521]);
        mulmod_constant(t2, t2, two);
        submod(w[3397], t1, t2);
    }

    // XOR 2840 610 -> 3398
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2840], w[610]);
        mulmod(t2, w[2840], w[610]);
        mulmod_constant(t2, t2, two);
        submod(w[3398], t1, t2);
    }

    // XOR 3094 3013 -> 3399
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3094], w[3013]);
        mulmod(t2, w[3094], w[3013]);
        mulmod_constant(t2, t2, two);
        submod(w[3399], t1, t2);
    }

    // XOR 1137 566 -> 3400
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1137], w[566]);
        mulmod(t2, w[1137], w[566]);
        mulmod_constant(t2, t2, two);
        submod(w[3400], t1, t2);
    }

    // AND 2931 17 -> 3401
    mulmod(w[3401], w[2931], w[17]);

    // XOR 3068 1151 -> 3402
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3068], w[1151]);
        mulmod(t2, w[3068], w[1151]);
        mulmod_constant(t2, t2, two);
        submod(w[3402], t1, t2);
    }

    // AND 39 768 -> 3403
    mulmod(w[3403], w[39], w[768]);

    // XOR 1630 927 -> 3404
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1630], w[927]);
        mulmod(t2, w[1630], w[927]);
        mulmod_constant(t2, t2, two);
        submod(w[3404], t1, t2);
    }

    // INV 1041 -> 3405
    submod(w[3405], one, w[1041]);

    // AND 1064 1401 -> 3406
    mulmod(w[3406], w[1064], w[1401]);

    // XOR 1526 2543 -> 3407
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1526], w[2543]);
        mulmod(t2, w[1526], w[2543]);
        mulmod_constant(t2, t2, two);
        submod(w[3407], t1, t2);
    }

    // AND 296 545 -> 3408
    mulmod(w[3408], w[296], w[545]);

    // AND 1431 1050 -> 3409
    mulmod(w[3409], w[1431], w[1050]);

    // AND 17 2126 -> 3410
    mulmod(w[3410], w[17], w[2126]);

    // AND 1157 3239 -> 3411
    mulmod(w[3411], w[1157], w[3239]);

    // AND 1085 1334 -> 3412
    mulmod(w[3412], w[1085], w[1334]);

    // AND 368 3177 -> 3413
    mulmod(w[3413], w[368], w[3177]);

    // XOR 547 1987 -> 3414
    {
        bn254fr_class t1, t2;
        addmod(t1, w[547], w[1987]);
        mulmod(t2, w[547], w[1987]);
        mulmod_constant(t2, t2, two);
        submod(w[3414], t1, t2);
    }

    // AND 3288 1583 -> 3415
    mulmod(w[3415], w[3288], w[1583]);

    // INV 1251 -> 3416
    submod(w[3416], one, w[1251]);

    // INV 1635 -> 3417
    submod(w[3417], one, w[1635]);

    // XOR 2305 1314 -> 3418
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2305], w[1314]);
        mulmod(t2, w[2305], w[1314]);
        mulmod_constant(t2, t2, two);
        submod(w[3418], t1, t2);
    }

    // XOR 1092 236 -> 3419
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1092], w[236]);
        mulmod(t2, w[1092], w[236]);
        mulmod_constant(t2, t2, two);
        submod(w[3419], t1, t2);
    }

    // AND 844 597 -> 3420
    mulmod(w[3420], w[844], w[597]);

    // AND 2059 1450 -> 3421
    mulmod(w[3421], w[2059], w[1450]);

    // XOR 2474 647 -> 3422
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2474], w[647]);
        mulmod(t2, w[2474], w[647]);
        mulmod_constant(t2, t2, two);
        submod(w[3422], t1, t2);
    }

    // XOR 2283 1135 -> 3423
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2283], w[1135]);
        mulmod(t2, w[2283], w[1135]);
        mulmod_constant(t2, t2, two);
        submod(w[3423], t1, t2);
    }

    // XOR 3220 244 -> 3424
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3220], w[244]);
        mulmod(t2, w[3220], w[244]);
        mulmod_constant(t2, t2, two);
        submod(w[3424], t1, t2);
    }

    // INV 2758 -> 3425
    submod(w[3425], one, w[2758]);

    // AND 3049 661 -> 3426
    mulmod(w[3426], w[3049], w[661]);

    // XOR 635 56 -> 3427
    {
        bn254fr_class t1, t2;
        addmod(t1, w[635], w[56]);
        mulmod(t2, w[635], w[56]);
        mulmod_constant(t2, t2, two);
        submod(w[3427], t1, t2);
    }

    // XOR 1332 596 -> 3428
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1332], w[596]);
        mulmod(t2, w[1332], w[596]);
        mulmod_constant(t2, t2, two);
        submod(w[3428], t1, t2);
    }

    // AND 221 1683 -> 3429
    mulmod(w[3429], w[221], w[1683]);

    // XOR 366 142 -> 3430
    {
        bn254fr_class t1, t2;
        addmod(t1, w[366], w[142]);
        mulmod(t2, w[366], w[142]);
        mulmod_constant(t2, t2, two);
        submod(w[3430], t1, t2);
    }

    // XOR 1762 3124 -> 3431
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1762], w[3124]);
        mulmod(t2, w[1762], w[3124]);
        mulmod_constant(t2, t2, two);
        submod(w[3431], t1, t2);
    }

    // XOR 944 1922 -> 3432
    {
        bn254fr_class t1, t2;
        addmod(t1, w[944], w[1922]);
        mulmod(t2, w[944], w[1922]);
        mulmod_constant(t2, t2, two);
        submod(w[3432], t1, t2);
    }

    // AND 2316 265 -> 3433
    mulmod(w[3433], w[2316], w[265]);

    // AND 1122 274 -> 3434
    mulmod(w[3434], w[1122], w[274]);

    // XOR 1472 117 -> 3435
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1472], w[117]);
        mulmod(t2, w[1472], w[117]);
        mulmod_constant(t2, t2, two);
        submod(w[3435], t1, t2);
    }

    // XOR 1351 1671 -> 3436
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1351], w[1671]);
        mulmod(t2, w[1351], w[1671]);
        mulmod_constant(t2, t2, two);
        submod(w[3436], t1, t2);
    }

    // INV 3147 -> 3437
    submod(w[3437], one, w[3147]);

    // INV 2291 -> 3438
    submod(w[3438], one, w[2291]);

    // AND 20 1615 -> 3439
    mulmod(w[3439], w[20], w[1615]);

    // XOR 2431 799 -> 3440
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2431], w[799]);
        mulmod(t2, w[2431], w[799]);
        mulmod_constant(t2, t2, two);
        submod(w[3440], t1, t2);
    }

    // AND 77 1231 -> 3441
    mulmod(w[3441], w[77], w[1231]);

    // XOR 1969 1859 -> 3442
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1969], w[1859]);
        mulmod(t2, w[1969], w[1859]);
        mulmod_constant(t2, t2, two);
        submod(w[3442], t1, t2);
    }

    // AND 3151 2563 -> 3443
    mulmod(w[3443], w[3151], w[2563]);

    // AND 1716 536 -> 3444
    mulmod(w[3444], w[1716], w[536]);

    // XOR 140 674 -> 3445
    {
        bn254fr_class t1, t2;
        addmod(t1, w[140], w[674]);
        mulmod(t2, w[140], w[674]);
        mulmod_constant(t2, t2, two);
        submod(w[3445], t1, t2);
    }

    // AND 1886 2951 -> 3446
    mulmod(w[3446], w[1886], w[2951]);

    // XOR 2820 1115 -> 3447
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2820], w[1115]);
        mulmod(t2, w[2820], w[1115]);
        mulmod_constant(t2, t2, two);
        submod(w[3447], t1, t2);
    }

    // XOR 2322 73 -> 3448
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2322], w[73]);
        mulmod(t2, w[2322], w[73]);
        mulmod_constant(t2, t2, two);
        submod(w[3448], t1, t2);
    }

    // XOR 3322 688 -> 3449
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3322], w[688]);
        mulmod(t2, w[3322], w[688]);
        mulmod_constant(t2, t2, two);
        submod(w[3449], t1, t2);
    }

    // AND 1586 349 -> 3450
    mulmod(w[3450], w[1586], w[349]);

    // XOR 1711 1178 -> 3451
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1711], w[1178]);
        mulmod(t2, w[1711], w[1178]);
        mulmod_constant(t2, t2, two);
        submod(w[3451], t1, t2);
    }

    // XOR 328 13 -> 3452
    {
        bn254fr_class t1, t2;
        addmod(t1, w[328], w[13]);
        mulmod(t2, w[328], w[13]);
        mulmod_constant(t2, t2, two);
        submod(w[3452], t1, t2);
    }

    // XOR 1178 2963 -> 3453
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1178], w[2963]);
        mulmod(t2, w[1178], w[2963]);
        mulmod_constant(t2, t2, two);
        submod(w[3453], t1, t2);
    }

    // XOR 2799 2149 -> 3454
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2799], w[2149]);
        mulmod(t2, w[2799], w[2149]);
        mulmod_constant(t2, t2, two);
        submod(w[3454], t1, t2);
    }

    // XOR 579 3415 -> 3455
    {
        bn254fr_class t1, t2;
        addmod(t1, w[579], w[3415]);
        mulmod(t2, w[579], w[3415]);
        mulmod_constant(t2, t2, two);
        submod(w[3455], t1, t2);
    }

    // XOR 3223 1454 -> 3456
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3223], w[1454]);
        mulmod(t2, w[3223], w[1454]);
        mulmod_constant(t2, t2, two);
        submod(w[3456], t1, t2);
    }

    // XOR 2948 910 -> 3457
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2948], w[910]);
        mulmod(t2, w[2948], w[910]);
        mulmod_constant(t2, t2, two);
        submod(w[3457], t1, t2);
    }

    // AND 2897 2839 -> 3458
    mulmod(w[3458], w[2897], w[2839]);

    // XOR 2510 2208 -> 3459
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2510], w[2208]);
        mulmod(t2, w[2510], w[2208]);
        mulmod_constant(t2, t2, two);
        submod(w[3459], t1, t2);
    }

    // XOR 2800 661 -> 3460
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2800], w[661]);
        mulmod(t2, w[2800], w[661]);
        mulmod_constant(t2, t2, two);
        submod(w[3460], t1, t2);
    }

    // AND 458 3383 -> 3461
    mulmod(w[3461], w[458], w[3383]);

    // XOR 1491 18 -> 3462
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1491], w[18]);
        mulmod(t2, w[1491], w[18]);
        mulmod_constant(t2, t2, two);
        submod(w[3462], t1, t2);
    }

    // XOR 309 466 -> 3463
    {
        bn254fr_class t1, t2;
        addmod(t1, w[309], w[466]);
        mulmod(t2, w[309], w[466]);
        mulmod_constant(t2, t2, two);
        submod(w[3463], t1, t2);
    }

    // INV 1322 -> 3464
    submod(w[3464], one, w[1322]);

    // XOR 3298 3384 -> 3465
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3298], w[3384]);
        mulmod(t2, w[3298], w[3384]);
        mulmod_constant(t2, t2, two);
        submod(w[3465], t1, t2);
    }

    // AND 2780 1561 -> 3466
    mulmod(w[3466], w[2780], w[1561]);

    // AND 3054 3326 -> 3467
    mulmod(w[3467], w[3054], w[3326]);

    // INV 56 -> 3468
    submod(w[3468], one, w[56]);

    // XOR 455 1446 -> 3469
    {
        bn254fr_class t1, t2;
        addmod(t1, w[455], w[1446]);
        mulmod(t2, w[455], w[1446]);
        mulmod_constant(t2, t2, two);
        submod(w[3469], t1, t2);
    }

    // AND 1049 1058 -> 3470
    mulmod(w[3470], w[1049], w[1058]);

    // XOR 3053 560 -> 3471
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3053], w[560]);
        mulmod(t2, w[3053], w[560]);
        mulmod_constant(t2, t2, two);
        submod(w[3471], t1, t2);
    }

    // AND 18 2424 -> 3472
    mulmod(w[3472], w[18], w[2424]);

    // XOR 1170 3244 -> 3473
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1170], w[3244]);
        mulmod(t2, w[1170], w[3244]);
        mulmod_constant(t2, t2, two);
        submod(w[3473], t1, t2);
    }

    // XOR 36 2339 -> 3474
    {
        bn254fr_class t1, t2;
        addmod(t1, w[36], w[2339]);
        mulmod(t2, w[36], w[2339]);
        mulmod_constant(t2, t2, two);
        submod(w[3474], t1, t2);
    }

    // XOR 2931 933 -> 3475
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2931], w[933]);
        mulmod(t2, w[2931], w[933]);
        mulmod_constant(t2, t2, two);
        submod(w[3475], t1, t2);
    }

    // INV 1197 -> 3476
    submod(w[3476], one, w[1197]);

    // XOR 2295 3308 -> 3477
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2295], w[3308]);
        mulmod(t2, w[2295], w[3308]);
        mulmod_constant(t2, t2, two);
        submod(w[3477], t1, t2);
    }

    // AND 436 2718 -> 3478
    mulmod(w[3478], w[436], w[2718]);

    // XOR 2993 3003 -> 3479
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2993], w[3003]);
        mulmod(t2, w[2993], w[3003]);
        mulmod_constant(t2, t2, two);
        submod(w[3479], t1, t2);
    }

    // AND 1190 444 -> 3480
    mulmod(w[3480], w[1190], w[444]);

    // XOR 663 395 -> 3481
    {
        bn254fr_class t1, t2;
        addmod(t1, w[663], w[395]);
        mulmod(t2, w[663], w[395]);
        mulmod_constant(t2, t2, two);
        submod(w[3481], t1, t2);
    }

    // XOR 189 3385 -> 3482
    {
        bn254fr_class t1, t2;
        addmod(t1, w[189], w[3385]);
        mulmod(t2, w[189], w[3385]);
        mulmod_constant(t2, t2, two);
        submod(w[3482], t1, t2);
    }

    // XOR 2113 2237 -> 3483
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2113], w[2237]);
        mulmod(t2, w[2113], w[2237]);
        mulmod_constant(t2, t2, two);
        submod(w[3483], t1, t2);
    }

    // XOR 1925 1722 -> 3484
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1925], w[1722]);
        mulmod(t2, w[1925], w[1722]);
        mulmod_constant(t2, t2, two);
        submod(w[3484], t1, t2);
    }

    // XOR 1169 2002 -> 3485
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1169], w[2002]);
        mulmod(t2, w[1169], w[2002]);
        mulmod_constant(t2, t2, two);
        submod(w[3485], t1, t2);
    }

    // XOR 1568 26 -> 3486
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1568], w[26]);
        mulmod(t2, w[1568], w[26]);
        mulmod_constant(t2, t2, two);
        submod(w[3486], t1, t2);
    }

    // XOR 3344 2213 -> 3487
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3344], w[2213]);
        mulmod(t2, w[3344], w[2213]);
        mulmod_constant(t2, t2, two);
        submod(w[3487], t1, t2);
    }

    // AND 1928 3281 -> 3488
    mulmod(w[3488], w[1928], w[3281]);

    // AND 3258 3303 -> 3489
    mulmod(w[3489], w[3258], w[3303]);

    // XOR 1569 1785 -> 3490
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1569], w[1785]);
        mulmod(t2, w[1569], w[1785]);
        mulmod_constant(t2, t2, two);
        submod(w[3490], t1, t2);
    }

    // XOR 3060 2282 -> 3491
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3060], w[2282]);
        mulmod(t2, w[3060], w[2282]);
        mulmod_constant(t2, t2, two);
        submod(w[3491], t1, t2);
    }

    // XOR 3390 2937 -> 3492
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3390], w[2937]);
        mulmod(t2, w[3390], w[2937]);
        mulmod_constant(t2, t2, two);
        submod(w[3492], t1, t2);
    }

    // XOR 2832 2757 -> 3493
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2832], w[2757]);
        mulmod(t2, w[2832], w[2757]);
        mulmod_constant(t2, t2, two);
        submod(w[3493], t1, t2);
    }

    // AND 794 3126 -> 3494
    mulmod(w[3494], w[794], w[3126]);

    // XOR 2105 3225 -> 3495
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2105], w[3225]);
        mulmod(t2, w[2105], w[3225]);
        mulmod_constant(t2, t2, two);
        submod(w[3495], t1, t2);
    }

    // AND 1234 2667 -> 3496
    mulmod(w[3496], w[1234], w[2667]);

    // AND 421 1390 -> 3497
    mulmod(w[3497], w[421], w[1390]);

    // AND 593 1985 -> 3498
    mulmod(w[3498], w[593], w[1985]);

    // AND 2278 617 -> 3499
    mulmod(w[3499], w[2278], w[617]);

    // AND 2878 2019 -> 3500
    mulmod(w[3500], w[2878], w[2019]);

    // XOR 2357 2914 -> 3501
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2357], w[2914]);
        mulmod(t2, w[2357], w[2914]);
        mulmod_constant(t2, t2, two);
        submod(w[3501], t1, t2);
    }

    // XOR 1967 265 -> 3502
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1967], w[265]);
        mulmod(t2, w[1967], w[265]);
        mulmod_constant(t2, t2, two);
        submod(w[3502], t1, t2);
    }

    // XOR 864 1664 -> 3503
    {
        bn254fr_class t1, t2;
        addmod(t1, w[864], w[1664]);
        mulmod(t2, w[864], w[1664]);
        mulmod_constant(t2, t2, two);
        submod(w[3503], t1, t2);
    }

    // XOR 1498 1185 -> 3504
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1498], w[1185]);
        mulmod(t2, w[1498], w[1185]);
        mulmod_constant(t2, t2, two);
        submod(w[3504], t1, t2);
    }

    // AND 614 200 -> 3505
    mulmod(w[3505], w[614], w[200]);

    // XOR 832 678 -> 3506
    {
        bn254fr_class t1, t2;
        addmod(t1, w[832], w[678]);
        mulmod(t2, w[832], w[678]);
        mulmod_constant(t2, t2, two);
        submod(w[3506], t1, t2);
    }

    // XOR 2197 2450 -> 3507
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2197], w[2450]);
        mulmod(t2, w[2197], w[2450]);
        mulmod_constant(t2, t2, two);
        submod(w[3507], t1, t2);
    }

    // AND 280 2011 -> 3508
    mulmod(w[3508], w[280], w[2011]);

    // XOR 1339 1425 -> 3509
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1339], w[1425]);
        mulmod(t2, w[1339], w[1425]);
        mulmod_constant(t2, t2, two);
        submod(w[3509], t1, t2);
    }

    // AND 3149 2181 -> 3510
    mulmod(w[3510], w[3149], w[2181]);

    // XOR 3454 2980 -> 3511
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3454], w[2980]);
        mulmod(t2, w[3454], w[2980]);
        mulmod_constant(t2, t2, two);
        submod(w[3511], t1, t2);
    }

    // INV 3426 -> 3512
    submod(w[3512], one, w[3426]);

    // XOR 1746 2020 -> 3513
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1746], w[2020]);
        mulmod(t2, w[1746], w[2020]);
        mulmod_constant(t2, t2, two);
        submod(w[3513], t1, t2);
    }

    // XOR 1682 2224 -> 3514
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1682], w[2224]);
        mulmod(t2, w[1682], w[2224]);
        mulmod_constant(t2, t2, two);
        submod(w[3514], t1, t2);
    }

    // XOR 3287 2231 -> 3515
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3287], w[2231]);
        mulmod(t2, w[3287], w[2231]);
        mulmod_constant(t2, t2, two);
        submod(w[3515], t1, t2);
    }

    // XOR 11 329 -> 3516
    {
        bn254fr_class t1, t2;
        addmod(t1, w[11], w[329]);
        mulmod(t2, w[11], w[329]);
        mulmod_constant(t2, t2, two);
        submod(w[3516], t1, t2);
    }

    // XOR 1487 1072 -> 3517
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1487], w[1072]);
        mulmod(t2, w[1487], w[1072]);
        mulmod_constant(t2, t2, two);
        submod(w[3517], t1, t2);
    }

    // AND 2143 3425 -> 3518
    mulmod(w[3518], w[2143], w[3425]);

    // AND 2730 2867 -> 3519
    mulmod(w[3519], w[2730], w[2867]);

    // XOR 2997 2296 -> 3520
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2997], w[2296]);
        mulmod(t2, w[2997], w[2296]);
        mulmod_constant(t2, t2, two);
        submod(w[3520], t1, t2);
    }

    // AND 1235 470 -> 3521
    mulmod(w[3521], w[1235], w[470]);

    // AND 1615 2049 -> 3522
    mulmod(w[3522], w[1615], w[2049]);

    // XOR 944 2095 -> 3523
    {
        bn254fr_class t1, t2;
        addmod(t1, w[944], w[2095]);
        mulmod(t2, w[944], w[2095]);
        mulmod_constant(t2, t2, two);
        submod(w[3523], t1, t2);
    }

    // XOR 959 182 -> 3524
    {
        bn254fr_class t1, t2;
        addmod(t1, w[959], w[182]);
        mulmod(t2, w[959], w[182]);
        mulmod_constant(t2, t2, two);
        submod(w[3524], t1, t2);
    }

    // AND 1195 2698 -> 3525
    mulmod(w[3525], w[1195], w[2698]);

    // AND 302 1962 -> 3526
    mulmod(w[3526], w[302], w[1962]);

    // XOR 889 2888 -> 3527
    {
        bn254fr_class t1, t2;
        addmod(t1, w[889], w[2888]);
        mulmod(t2, w[889], w[2888]);
        mulmod_constant(t2, t2, two);
        submod(w[3527], t1, t2);
    }

    // XOR 318 583 -> 3528
    {
        bn254fr_class t1, t2;
        addmod(t1, w[318], w[583]);
        mulmod(t2, w[318], w[583]);
        mulmod_constant(t2, t2, two);
        submod(w[3528], t1, t2);
    }

    // XOR 556 2924 -> 3529
    {
        bn254fr_class t1, t2;
        addmod(t1, w[556], w[2924]);
        mulmod(t2, w[556], w[2924]);
        mulmod_constant(t2, t2, two);
        submod(w[3529], t1, t2);
    }

    // XOR 2407 3424 -> 3530
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2407], w[3424]);
        mulmod(t2, w[2407], w[3424]);
        mulmod_constant(t2, t2, two);
        submod(w[3530], t1, t2);
    }

    // AND 1225 2100 -> 3531
    mulmod(w[3531], w[1225], w[2100]);

    // AND 1104 3452 -> 3532
    mulmod(w[3532], w[1104], w[3452]);

    // AND 1480 2518 -> 3533
    mulmod(w[3533], w[1480], w[2518]);

    // XOR 1412 3285 -> 3534
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1412], w[3285]);
        mulmod(t2, w[1412], w[3285]);
        mulmod_constant(t2, t2, two);
        submod(w[3534], t1, t2);
    }

    // AND 1542 1796 -> 3535
    mulmod(w[3535], w[1542], w[1796]);

    // INV 2469 -> 3536
    submod(w[3536], one, w[2469]);

    // XOR 1144 285 -> 3537
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1144], w[285]);
        mulmod(t2, w[1144], w[285]);
        mulmod_constant(t2, t2, two);
        submod(w[3537], t1, t2);
    }

    // XOR 1699 2571 -> 3538
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1699], w[2571]);
        mulmod(t2, w[1699], w[2571]);
        mulmod_constant(t2, t2, two);
        submod(w[3538], t1, t2);
    }

    // AND 824 477 -> 3539
    mulmod(w[3539], w[824], w[477]);

    // XOR 2300 2743 -> 3540
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2300], w[2743]);
        mulmod(t2, w[2300], w[2743]);
        mulmod_constant(t2, t2, two);
        submod(w[3540], t1, t2);
    }

    // XOR 457 2775 -> 3541
    {
        bn254fr_class t1, t2;
        addmod(t1, w[457], w[2775]);
        mulmod(t2, w[457], w[2775]);
        mulmod_constant(t2, t2, two);
        submod(w[3541], t1, t2);
    }

    // AND 3176 3341 -> 3542
    mulmod(w[3542], w[3176], w[3341]);

    // XOR 1247 1791 -> 3543
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1247], w[1791]);
        mulmod(t2, w[1247], w[1791]);
        mulmod_constant(t2, t2, two);
        submod(w[3543], t1, t2);
    }

    // XOR 360 2163 -> 3544
    {
        bn254fr_class t1, t2;
        addmod(t1, w[360], w[2163]);
        mulmod(t2, w[360], w[2163]);
        mulmod_constant(t2, t2, two);
        submod(w[3544], t1, t2);
    }

    // XOR 2796 938 -> 3545
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2796], w[938]);
        mulmod(t2, w[2796], w[938]);
        mulmod_constant(t2, t2, two);
        submod(w[3545], t1, t2);
    }

    // XOR 437 2728 -> 3546
    {
        bn254fr_class t1, t2;
        addmod(t1, w[437], w[2728]);
        mulmod(t2, w[437], w[2728]);
        mulmod_constant(t2, t2, two);
        submod(w[3546], t1, t2);
    }

    // XOR 2155 1834 -> 3547
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2155], w[1834]);
        mulmod(t2, w[2155], w[1834]);
        mulmod_constant(t2, t2, two);
        submod(w[3547], t1, t2);
    }

    // XOR 3031 3441 -> 3548
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3031], w[3441]);
        mulmod(t2, w[3031], w[3441]);
        mulmod_constant(t2, t2, two);
        submod(w[3548], t1, t2);
    }

    // XOR 3352 3142 -> 3549
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3352], w[3142]);
        mulmod(t2, w[3352], w[3142]);
        mulmod_constant(t2, t2, two);
        submod(w[3549], t1, t2);
    }

    // INV 1066 -> 3550
    submod(w[3550], one, w[1066]);

    // XOR 180 192 -> 3551
    {
        bn254fr_class t1, t2;
        addmod(t1, w[180], w[192]);
        mulmod(t2, w[180], w[192]);
        mulmod_constant(t2, t2, two);
        submod(w[3551], t1, t2);
    }

    // XOR 2939 878 -> 3552
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2939], w[878]);
        mulmod(t2, w[2939], w[878]);
        mulmod_constant(t2, t2, two);
        submod(w[3552], t1, t2);
    }

    // AND 2007 130 -> 3553
    mulmod(w[3553], w[2007], w[130]);

    // AND 1307 171 -> 3554
    mulmod(w[3554], w[1307], w[171]);

    // XOR 3380 218 -> 3555
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3380], w[218]);
        mulmod(t2, w[3380], w[218]);
        mulmod_constant(t2, t2, two);
        submod(w[3555], t1, t2);
    }

    // XOR 1000 2229 -> 3556
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1000], w[2229]);
        mulmod(t2, w[1000], w[2229]);
        mulmod_constant(t2, t2, two);
        submod(w[3556], t1, t2);
    }

    // XOR 2084 2401 -> 3557
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2084], w[2401]);
        mulmod(t2, w[2084], w[2401]);
        mulmod_constant(t2, t2, two);
        submod(w[3557], t1, t2);
    }

    // AND 322 797 -> 3558
    mulmod(w[3558], w[322], w[797]);

    // XOR 445 2458 -> 3559
    {
        bn254fr_class t1, t2;
        addmod(t1, w[445], w[2458]);
        mulmod(t2, w[445], w[2458]);
        mulmod_constant(t2, t2, two);
        submod(w[3559], t1, t2);
    }

    // AND 3408 3408 -> 3560
    mulmod(w[3560], w[3408], w[3408]);

    // XOR 2126 3024 -> 3561
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2126], w[3024]);
        mulmod(t2, w[2126], w[3024]);
        mulmod_constant(t2, t2, two);
        submod(w[3561], t1, t2);
    }

    // XOR 205 644 -> 3562
    {
        bn254fr_class t1, t2;
        addmod(t1, w[205], w[644]);
        mulmod(t2, w[205], w[644]);
        mulmod_constant(t2, t2, two);
        submod(w[3562], t1, t2);
    }

    // AND 1586 2907 -> 3563
    mulmod(w[3563], w[1586], w[2907]);

    // INV 803 -> 3564
    submod(w[3564], one, w[803]);

    // XOR 2888 2208 -> 3565
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2888], w[2208]);
        mulmod(t2, w[2888], w[2208]);
        mulmod_constant(t2, t2, two);
        submod(w[3565], t1, t2);
    }

    // XOR 2633 1523 -> 3566
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2633], w[1523]);
        mulmod(t2, w[2633], w[1523]);
        mulmod_constant(t2, t2, two);
        submod(w[3566], t1, t2);
    }

    // XOR 1148 2078 -> 3567
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1148], w[2078]);
        mulmod(t2, w[1148], w[2078]);
        mulmod_constant(t2, t2, two);
        submod(w[3567], t1, t2);
    }

    // AND 2724 594 -> 3568
    mulmod(w[3568], w[2724], w[594]);

    // AND 826 3067 -> 3569
    mulmod(w[3569], w[826], w[3067]);

    // XOR 1828 2356 -> 3570
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1828], w[2356]);
        mulmod(t2, w[1828], w[2356]);
        mulmod_constant(t2, t2, two);
        submod(w[3570], t1, t2);
    }

    // AND 2728 1316 -> 3571
    mulmod(w[3571], w[2728], w[1316]);

    // XOR 2672 311 -> 3572
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2672], w[311]);
        mulmod(t2, w[2672], w[311]);
        mulmod_constant(t2, t2, two);
        submod(w[3572], t1, t2);
    }

    // AND 2866 2224 -> 3573
    mulmod(w[3573], w[2866], w[2224]);

    // AND 2201 2424 -> 3574
    mulmod(w[3574], w[2201], w[2424]);

    // XOR 2990 2721 -> 3575
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2990], w[2721]);
        mulmod(t2, w[2990], w[2721]);
        mulmod_constant(t2, t2, two);
        submod(w[3575], t1, t2);
    }

    // AND 569 3070 -> 3576
    mulmod(w[3576], w[569], w[3070]);

    // XOR 525 2092 -> 3577
    {
        bn254fr_class t1, t2;
        addmod(t1, w[525], w[2092]);
        mulmod(t2, w[525], w[2092]);
        mulmod_constant(t2, t2, two);
        submod(w[3577], t1, t2);
    }

    // XOR 2090 1983 -> 3578
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2090], w[1983]);
        mulmod(t2, w[2090], w[1983]);
        mulmod_constant(t2, t2, two);
        submod(w[3578], t1, t2);
    }

    // XOR 112 2198 -> 3579
    {
        bn254fr_class t1, t2;
        addmod(t1, w[112], w[2198]);
        mulmod(t2, w[112], w[2198]);
        mulmod_constant(t2, t2, two);
        submod(w[3579], t1, t2);
    }

    // XOR 285 2110 -> 3580
    {
        bn254fr_class t1, t2;
        addmod(t1, w[285], w[2110]);
        mulmod(t2, w[285], w[2110]);
        mulmod_constant(t2, t2, two);
        submod(w[3580], t1, t2);
    }

    // AND 519 2830 -> 3581
    mulmod(w[3581], w[519], w[2830]);

    // XOR 2247 1618 -> 3582
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2247], w[1618]);
        mulmod(t2, w[2247], w[1618]);
        mulmod_constant(t2, t2, two);
        submod(w[3582], t1, t2);
    }

    // XOR 1688 1922 -> 3583
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1688], w[1922]);
        mulmod(t2, w[1688], w[1922]);
        mulmod_constant(t2, t2, two);
        submod(w[3583], t1, t2);
    }

    // AND 1363 2406 -> 3584
    mulmod(w[3584], w[1363], w[2406]);

    // XOR 3533 2255 -> 3585
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3533], w[2255]);
        mulmod(t2, w[3533], w[2255]);
        mulmod_constant(t2, t2, two);
        submod(w[3585], t1, t2);
    }

    // AND 289 1990 -> 3586
    mulmod(w[3586], w[289], w[1990]);

    // XOR 771 387 -> 3587
    {
        bn254fr_class t1, t2;
        addmod(t1, w[771], w[387]);
        mulmod(t2, w[771], w[387]);
        mulmod_constant(t2, t2, two);
        submod(w[3587], t1, t2);
    }

    // XOR 2353 1740 -> 3588
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2353], w[1740]);
        mulmod(t2, w[2353], w[1740]);
        mulmod_constant(t2, t2, two);
        submod(w[3588], t1, t2);
    }

    // XOR 2042 1431 -> 3589
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2042], w[1431]);
        mulmod(t2, w[2042], w[1431]);
        mulmod_constant(t2, t2, two);
        submod(w[3589], t1, t2);
    }

    // XOR 1673 27 -> 3590
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1673], w[27]);
        mulmod(t2, w[1673], w[27]);
        mulmod_constant(t2, t2, two);
        submod(w[3590], t1, t2);
    }

    // XOR 987 3114 -> 3591
    {
        bn254fr_class t1, t2;
        addmod(t1, w[987], w[3114]);
        mulmod(t2, w[987], w[3114]);
        mulmod_constant(t2, t2, two);
        submod(w[3591], t1, t2);
    }

    // INV 2862 -> 3592
    submod(w[3592], one, w[2862]);

    // XOR 233 2477 -> 3593
    {
        bn254fr_class t1, t2;
        addmod(t1, w[233], w[2477]);
        mulmod(t2, w[233], w[2477]);
        mulmod_constant(t2, t2, two);
        submod(w[3593], t1, t2);
    }

    // INV 2649 -> 3594
    submod(w[3594], one, w[2649]);

    // AND 470 447 -> 3595
    mulmod(w[3595], w[470], w[447]);

    // XOR 1913 3079 -> 3596
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1913], w[3079]);
        mulmod(t2, w[1913], w[3079]);
        mulmod_constant(t2, t2, two);
        submod(w[3596], t1, t2);
    }

    // XOR 2758 3119 -> 3597
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2758], w[3119]);
        mulmod(t2, w[2758], w[3119]);
        mulmod_constant(t2, t2, two);
        submod(w[3597], t1, t2);
    }

    // XOR 2595 1037 -> 3598
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2595], w[1037]);
        mulmod(t2, w[2595], w[1037]);
        mulmod_constant(t2, t2, two);
        submod(w[3598], t1, t2);
    }

    // AND 2514 449 -> 3599
    mulmod(w[3599], w[2514], w[449]);

    // XOR 957 493 -> 3600
    {
        bn254fr_class t1, t2;
        addmod(t1, w[957], w[493]);
        mulmod(t2, w[957], w[493]);
        mulmod_constant(t2, t2, two);
        submod(w[3600], t1, t2);
    }

    // XOR 1478 1314 -> 3601
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1478], w[1314]);
        mulmod(t2, w[1478], w[1314]);
        mulmod_constant(t2, t2, two);
        submod(w[3601], t1, t2);
    }

    // XOR 396 785 -> 3602
    {
        bn254fr_class t1, t2;
        addmod(t1, w[396], w[785]);
        mulmod(t2, w[396], w[785]);
        mulmod_constant(t2, t2, two);
        submod(w[3602], t1, t2);
    }

    // AND 188 3284 -> 3603
    mulmod(w[3603], w[188], w[3284]);

    // AND 724 272 -> 3604
    mulmod(w[3604], w[724], w[272]);

    // AND 1651 2974 -> 3605
    mulmod(w[3605], w[1651], w[2974]);

    // AND 245 2494 -> 3606
    mulmod(w[3606], w[245], w[2494]);

    // AND 631 214 -> 3607
    mulmod(w[3607], w[631], w[214]);

    // XOR 2934 2514 -> 3608
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2934], w[2514]);
        mulmod(t2, w[2934], w[2514]);
        mulmod_constant(t2, t2, two);
        submod(w[3608], t1, t2);
    }

    // INV 934 -> 3609
    submod(w[3609], one, w[934]);

    // XOR 1220 2101 -> 3610
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1220], w[2101]);
        mulmod(t2, w[1220], w[2101]);
        mulmod_constant(t2, t2, two);
        submod(w[3610], t1, t2);
    }

    // XOR 782 3514 -> 3611
    {
        bn254fr_class t1, t2;
        addmod(t1, w[782], w[3514]);
        mulmod(t2, w[782], w[3514]);
        mulmod_constant(t2, t2, two);
        submod(w[3611], t1, t2);
    }

    // XOR 1038 1446 -> 3612
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1038], w[1446]);
        mulmod(t2, w[1038], w[1446]);
        mulmod_constant(t2, t2, two);
        submod(w[3612], t1, t2);
    }

    // AND 3172 445 -> 3613
    mulmod(w[3613], w[3172], w[445]);

    // AND 2518 2258 -> 3614
    mulmod(w[3614], w[2518], w[2258]);

    // XOR 2595 2053 -> 3615
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2595], w[2053]);
        mulmod(t2, w[2595], w[2053]);
        mulmod_constant(t2, t2, two);
        submod(w[3615], t1, t2);
    }

    // INV 1163 -> 3616
    submod(w[3616], one, w[1163]);

    // XOR 1835 1088 -> 3617
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1835], w[1088]);
        mulmod(t2, w[1835], w[1088]);
        mulmod_constant(t2, t2, two);
        submod(w[3617], t1, t2);
    }

    // XOR 2134 2871 -> 3618
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2134], w[2871]);
        mulmod(t2, w[2134], w[2871]);
        mulmod_constant(t2, t2, two);
        submod(w[3618], t1, t2);
    }

    // AND 3145 663 -> 3619
    mulmod(w[3619], w[3145], w[663]);

    // INV 1802 -> 3620
    submod(w[3620], one, w[1802]);

    // INV 3128 -> 3621
    submod(w[3621], one, w[3128]);

    // XOR 1378 316 -> 3622
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1378], w[316]);
        mulmod(t2, w[1378], w[316]);
        mulmod_constant(t2, t2, two);
        submod(w[3622], t1, t2);
    }

    // XOR 710 3130 -> 3623
    {
        bn254fr_class t1, t2;
        addmod(t1, w[710], w[3130]);
        mulmod(t2, w[710], w[3130]);
        mulmod_constant(t2, t2, two);
        submod(w[3623], t1, t2);
    }

    // XOR 93 719 -> 3624
    {
        bn254fr_class t1, t2;
        addmod(t1, w[93], w[719]);
        mulmod(t2, w[93], w[719]);
        mulmod_constant(t2, t2, two);
        submod(w[3624], t1, t2);
    }

    // XOR 1626 901 -> 3625
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1626], w[901]);
        mulmod(t2, w[1626], w[901]);
        mulmod_constant(t2, t2, two);
        submod(w[3625], t1, t2);
    }

    // AND 926 506 -> 3626
    mulmod(w[3626], w[926], w[506]);

    // AND 3104 1551 -> 3627
    mulmod(w[3627], w[3104], w[1551]);

    // XOR 2019 1548 -> 3628
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2019], w[1548]);
        mulmod(t2, w[2019], w[1548]);
        mulmod_constant(t2, t2, two);
        submod(w[3628], t1, t2);
    }

    // AND 2125 2416 -> 3629
    mulmod(w[3629], w[2125], w[2416]);

    // XOR 1690 2143 -> 3630
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1690], w[2143]);
        mulmod(t2, w[1690], w[2143]);
        mulmod_constant(t2, t2, two);
        submod(w[3630], t1, t2);
    }

    // AND 1326 2024 -> 3631
    mulmod(w[3631], w[1326], w[2024]);

    // AND 2569 2764 -> 3632
    mulmod(w[3632], w[2569], w[2764]);

    // XOR 2654 1742 -> 3633
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2654], w[1742]);
        mulmod(t2, w[2654], w[1742]);
        mulmod_constant(t2, t2, two);
        submod(w[3633], t1, t2);
    }

    // XOR 3150 1148 -> 3634
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3150], w[1148]);
        mulmod(t2, w[3150], w[1148]);
        mulmod_constant(t2, t2, two);
        submod(w[3634], t1, t2);
    }

    // XOR 1441 2849 -> 3635
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1441], w[2849]);
        mulmod(t2, w[1441], w[2849]);
        mulmod_constant(t2, t2, two);
        submod(w[3635], t1, t2);
    }

    // AND 1103 1595 -> 3636
    mulmod(w[3636], w[1103], w[1595]);

    // AND 263 856 -> 3637
    mulmod(w[3637], w[263], w[856]);

    // XOR 2586 104 -> 3638
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2586], w[104]);
        mulmod(t2, w[2586], w[104]);
        mulmod_constant(t2, t2, two);
        submod(w[3638], t1, t2);
    }

    // XOR 1982 2300 -> 3639
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1982], w[2300]);
        mulmod(t2, w[1982], w[2300]);
        mulmod_constant(t2, t2, two);
        submod(w[3639], t1, t2);
    }

    // AND 2467 2332 -> 3640
    mulmod(w[3640], w[2467], w[2332]);

    // AND 145 501 -> 3641
    mulmod(w[3641], w[145], w[501]);

    // AND 2812 3070 -> 3642
    mulmod(w[3642], w[2812], w[3070]);

    // AND 1405 264 -> 3643
    mulmod(w[3643], w[1405], w[264]);

    // XOR 1400 1814 -> 3644
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1400], w[1814]);
        mulmod(t2, w[1400], w[1814]);
        mulmod_constant(t2, t2, two);
        submod(w[3644], t1, t2);
    }

    // XOR 2560 1522 -> 3645
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2560], w[1522]);
        mulmod(t2, w[2560], w[1522]);
        mulmod_constant(t2, t2, two);
        submod(w[3645], t1, t2);
    }

    // AND 2140 706 -> 3646
    mulmod(w[3646], w[2140], w[706]);

    // INV 3472 -> 3647
    submod(w[3647], one, w[3472]);

    // AND 2076 257 -> 3648
    mulmod(w[3648], w[2076], w[257]);

    // AND 3430 1394 -> 3649
    mulmod(w[3649], w[3430], w[1394]);

    // XOR 2908 2170 -> 3650
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2908], w[2170]);
        mulmod(t2, w[2908], w[2170]);
        mulmod_constant(t2, t2, two);
        submod(w[3650], t1, t2);
    }

    // AND 1322 2420 -> 3651
    mulmod(w[3651], w[1322], w[2420]);

    // AND 1982 2814 -> 3652
    mulmod(w[3652], w[1982], w[2814]);

    // AND 3297 2962 -> 3653
    mulmod(w[3653], w[3297], w[2962]);

    // AND 2574 1761 -> 3654
    mulmod(w[3654], w[2574], w[1761]);

    // XOR 2885 3536 -> 3655
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2885], w[3536]);
        mulmod(t2, w[2885], w[3536]);
        mulmod_constant(t2, t2, two);
        submod(w[3655], t1, t2);
    }

    // XOR 530 1232 -> 3656
    {
        bn254fr_class t1, t2;
        addmod(t1, w[530], w[1232]);
        mulmod(t2, w[530], w[1232]);
        mulmod_constant(t2, t2, two);
        submod(w[3656], t1, t2);
    }

    // XOR 320 1579 -> 3657
    {
        bn254fr_class t1, t2;
        addmod(t1, w[320], w[1579]);
        mulmod(t2, w[320], w[1579]);
        mulmod_constant(t2, t2, two);
        submod(w[3657], t1, t2);
    }

    // XOR 3514 1622 -> 3658
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3514], w[1622]);
        mulmod(t2, w[3514], w[1622]);
        mulmod_constant(t2, t2, two);
        submod(w[3658], t1, t2);
    }

    // XOR 1478 363 -> 3659
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1478], w[363]);
        mulmod(t2, w[1478], w[363]);
        mulmod_constant(t2, t2, two);
        submod(w[3659], t1, t2);
    }

    // AND 3201 2948 -> 3660
    mulmod(w[3660], w[3201], w[2948]);

    // XOR 462 2544 -> 3661
    {
        bn254fr_class t1, t2;
        addmod(t1, w[462], w[2544]);
        mulmod(t2, w[462], w[2544]);
        mulmod_constant(t2, t2, two);
        submod(w[3661], t1, t2);
    }

    // XOR 1412 106 -> 3662
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1412], w[106]);
        mulmod(t2, w[1412], w[106]);
        mulmod_constant(t2, t2, two);
        submod(w[3662], t1, t2);
    }

    // XOR 3030 699 -> 3663
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3030], w[699]);
        mulmod(t2, w[3030], w[699]);
        mulmod_constant(t2, t2, two);
        submod(w[3663], t1, t2);
    }

    // XOR 2529 567 -> 3664
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2529], w[567]);
        mulmod(t2, w[2529], w[567]);
        mulmod_constant(t2, t2, two);
        submod(w[3664], t1, t2);
    }

    // AND 2665 2406 -> 3665
    mulmod(w[3665], w[2665], w[2406]);

    // AND 2159 2753 -> 3666
    mulmod(w[3666], w[2159], w[2753]);

    // INV 2362 -> 3667
    submod(w[3667], one, w[2362]);

    // XOR 3421 2967 -> 3668
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3421], w[2967]);
        mulmod(t2, w[3421], w[2967]);
        mulmod_constant(t2, t2, two);
        submod(w[3668], t1, t2);
    }

    // XOR 3575 536 -> 3669
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3575], w[536]);
        mulmod(t2, w[3575], w[536]);
        mulmod_constant(t2, t2, two);
        submod(w[3669], t1, t2);
    }

    // XOR 3281 2246 -> 3670
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3281], w[2246]);
        mulmod(t2, w[3281], w[2246]);
        mulmod_constant(t2, t2, two);
        submod(w[3670], t1, t2);
    }

    // XOR 2328 1982 -> 3671
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2328], w[1982]);
        mulmod(t2, w[2328], w[1982]);
        mulmod_constant(t2, t2, two);
        submod(w[3671], t1, t2);
    }

    // INV 2540 -> 3672
    submod(w[3672], one, w[2540]);

    // XOR 53 2038 -> 3673
    {
        bn254fr_class t1, t2;
        addmod(t1, w[53], w[2038]);
        mulmod(t2, w[53], w[2038]);
        mulmod_constant(t2, t2, two);
        submod(w[3673], t1, t2);
    }

    // XOR 1714 2773 -> 3674
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1714], w[2773]);
        mulmod(t2, w[1714], w[2773]);
        mulmod_constant(t2, t2, two);
        submod(w[3674], t1, t2);
    }

    // AND 1190 1898 -> 3675
    mulmod(w[3675], w[1190], w[1898]);

    // AND 995 3610 -> 3676
    mulmod(w[3676], w[995], w[3610]);

    // XOR 461 780 -> 3677
    {
        bn254fr_class t1, t2;
        addmod(t1, w[461], w[780]);
        mulmod(t2, w[461], w[780]);
        mulmod_constant(t2, t2, two);
        submod(w[3677], t1, t2);
    }

    // XOR 2742 2955 -> 3678
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2742], w[2955]);
        mulmod(t2, w[2742], w[2955]);
        mulmod_constant(t2, t2, two);
        submod(w[3678], t1, t2);
    }

    // AND 1848 1430 -> 3679
    mulmod(w[3679], w[1848], w[1430]);

    // AND 2161 1201 -> 3680
    mulmod(w[3680], w[2161], w[1201]);

    // XOR 1216 3398 -> 3681
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1216], w[3398]);
        mulmod(t2, w[1216], w[3398]);
        mulmod_constant(t2, t2, two);
        submod(w[3681], t1, t2);
    }

    // XOR 3633 2080 -> 3682
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3633], w[2080]);
        mulmod(t2, w[3633], w[2080]);
        mulmod_constant(t2, t2, two);
        submod(w[3682], t1, t2);
    }

    // XOR 705 3144 -> 3683
    {
        bn254fr_class t1, t2;
        addmod(t1, w[705], w[3144]);
        mulmod(t2, w[705], w[3144]);
        mulmod_constant(t2, t2, two);
        submod(w[3683], t1, t2);
    }

    // XOR 394 584 -> 3684
    {
        bn254fr_class t1, t2;
        addmod(t1, w[394], w[584]);
        mulmod(t2, w[394], w[584]);
        mulmod_constant(t2, t2, two);
        submod(w[3684], t1, t2);
    }

    // XOR 526 919 -> 3685
    {
        bn254fr_class t1, t2;
        addmod(t1, w[526], w[919]);
        mulmod(t2, w[526], w[919]);
        mulmod_constant(t2, t2, two);
        submod(w[3685], t1, t2);
    }

    // XOR 1885 3302 -> 3686
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1885], w[3302]);
        mulmod(t2, w[1885], w[3302]);
        mulmod_constant(t2, t2, two);
        submod(w[3686], t1, t2);
    }

    // XOR 1116 1696 -> 3687
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1116], w[1696]);
        mulmod(t2, w[1116], w[1696]);
        mulmod_constant(t2, t2, two);
        submod(w[3687], t1, t2);
    }

    // AND 119 1370 -> 3688
    mulmod(w[3688], w[119], w[1370]);

    // XOR 3401 755 -> 3689
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3401], w[755]);
        mulmod(t2, w[3401], w[755]);
        mulmod_constant(t2, t2, two);
        submod(w[3689], t1, t2);
    }

    // AND 3266 2325 -> 3690
    mulmod(w[3690], w[3266], w[2325]);

    // AND 2139 2941 -> 3691
    mulmod(w[3691], w[2139], w[2941]);

    // XOR 1941 1962 -> 3692
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1941], w[1962]);
        mulmod(t2, w[1941], w[1962]);
        mulmod_constant(t2, t2, two);
        submod(w[3692], t1, t2);
    }

    // AND 1599 3129 -> 3693
    mulmod(w[3693], w[1599], w[3129]);

    // AND 856 1416 -> 3694
    mulmod(w[3694], w[856], w[1416]);

    // XOR 67 2703 -> 3695
    {
        bn254fr_class t1, t2;
        addmod(t1, w[67], w[2703]);
        mulmod(t2, w[67], w[2703]);
        mulmod_constant(t2, t2, two);
        submod(w[3695], t1, t2);
    }

    // XOR 3386 400 -> 3696
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3386], w[400]);
        mulmod(t2, w[3386], w[400]);
        mulmod_constant(t2, t2, two);
        submod(w[3696], t1, t2);
    }

    // AND 1134 636 -> 3697
    mulmod(w[3697], w[1134], w[636]);

    // XOR 744 508 -> 3698
    {
        bn254fr_class t1, t2;
        addmod(t1, w[744], w[508]);
        mulmod(t2, w[744], w[508]);
        mulmod_constant(t2, t2, two);
        submod(w[3698], t1, t2);
    }

    // XOR 2776 1851 -> 3699
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2776], w[1851]);
        mulmod(t2, w[2776], w[1851]);
        mulmod_constant(t2, t2, two);
        submod(w[3699], t1, t2);
    }

    // INV 2052 -> 3700
    submod(w[3700], one, w[2052]);

    // XOR 1752 349 -> 3701
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1752], w[349]);
        mulmod(t2, w[1752], w[349]);
        mulmod_constant(t2, t2, two);
        submod(w[3701], t1, t2);
    }

    // XOR 1674 2484 -> 3702
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1674], w[2484]);
        mulmod(t2, w[1674], w[2484]);
        mulmod_constant(t2, t2, two);
        submod(w[3702], t1, t2);
    }

    // INV 2322 -> 3703
    submod(w[3703], one, w[2322]);

    // AND 180 34 -> 3704
    mulmod(w[3704], w[180], w[34]);

    // XOR 2179 566 -> 3705
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2179], w[566]);
        mulmod(t2, w[2179], w[566]);
        mulmod_constant(t2, t2, two);
        submod(w[3705], t1, t2);
    }

    // XOR 2640 376 -> 3706
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2640], w[376]);
        mulmod(t2, w[2640], w[376]);
        mulmod_constant(t2, t2, two);
        submod(w[3706], t1, t2);
    }

    // XOR 252 12 -> 3707
    {
        bn254fr_class t1, t2;
        addmod(t1, w[252], w[12]);
        mulmod(t2, w[252], w[12]);
        mulmod_constant(t2, t2, two);
        submod(w[3707], t1, t2);
    }

    // AND 2031 1559 -> 3708
    mulmod(w[3708], w[2031], w[1559]);

    // XOR 3596 501 -> 3709
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3596], w[501]);
        mulmod(t2, w[3596], w[501]);
        mulmod_constant(t2, t2, two);
        submod(w[3709], t1, t2);
    }

    // AND 2678 3301 -> 3710
    mulmod(w[3710], w[2678], w[3301]);

    // XOR 2854 157 -> 3711
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2854], w[157]);
        mulmod(t2, w[2854], w[157]);
        mulmod_constant(t2, t2, two);
        submod(w[3711], t1, t2);
    }

    // AND 154 1592 -> 3712
    mulmod(w[3712], w[154], w[1592]);

    // AND 2674 2332 -> 3713
    mulmod(w[3713], w[2674], w[2332]);

    // AND 1654 1667 -> 3714
    mulmod(w[3714], w[1654], w[1667]);

    // XOR 201 52 -> 3715
    {
        bn254fr_class t1, t2;
        addmod(t1, w[201], w[52]);
        mulmod(t2, w[201], w[52]);
        mulmod_constant(t2, t2, two);
        submod(w[3715], t1, t2);
    }

    // XOR 104 1592 -> 3716
    {
        bn254fr_class t1, t2;
        addmod(t1, w[104], w[1592]);
        mulmod(t2, w[104], w[1592]);
        mulmod_constant(t2, t2, two);
        submod(w[3716], t1, t2);
    }

    // XOR 1379 968 -> 3717
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1379], w[968]);
        mulmod(t2, w[1379], w[968]);
        mulmod_constant(t2, t2, two);
        submod(w[3717], t1, t2);
    }

    // XOR 991 3562 -> 3718
    {
        bn254fr_class t1, t2;
        addmod(t1, w[991], w[3562]);
        mulmod(t2, w[991], w[3562]);
        mulmod_constant(t2, t2, two);
        submod(w[3718], t1, t2);
    }

    // XOR 2973 2584 -> 3719
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2973], w[2584]);
        mulmod(t2, w[2973], w[2584]);
        mulmod_constant(t2, t2, two);
        submod(w[3719], t1, t2);
    }

    // XOR 1657 135 -> 3720
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1657], w[135]);
        mulmod(t2, w[1657], w[135]);
        mulmod_constant(t2, t2, two);
        submod(w[3720], t1, t2);
    }

    // AND 1213 905 -> 3721
    mulmod(w[3721], w[1213], w[905]);

    // INV 3501 -> 3722
    submod(w[3722], one, w[3501]);

    // XOR 3170 1317 -> 3723
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3170], w[1317]);
        mulmod(t2, w[3170], w[1317]);
        mulmod_constant(t2, t2, two);
        submod(w[3723], t1, t2);
    }

    // XOR 2180 3177 -> 3724
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2180], w[3177]);
        mulmod(t2, w[2180], w[3177]);
        mulmod_constant(t2, t2, two);
        submod(w[3724], t1, t2);
    }

    // INV 3060 -> 3725
    submod(w[3725], one, w[3060]);

    // INV 1464 -> 3726
    submod(w[3726], one, w[1464]);

    // XOR 1994 3521 -> 3727
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1994], w[3521]);
        mulmod(t2, w[1994], w[3521]);
        mulmod_constant(t2, t2, two);
        submod(w[3727], t1, t2);
    }

    // AND 3549 574 -> 3728
    mulmod(w[3728], w[3549], w[574]);

    // XOR 2096 1177 -> 3729
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2096], w[1177]);
        mulmod(t2, w[2096], w[1177]);
        mulmod_constant(t2, t2, two);
        submod(w[3729], t1, t2);
    }

    // AND 2202 429 -> 3730
    mulmod(w[3730], w[2202], w[429]);

    // AND 3325 190 -> 3731
    mulmod(w[3731], w[3325], w[190]);

    // XOR 2598 873 -> 3732
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2598], w[873]);
        mulmod(t2, w[2598], w[873]);
        mulmod_constant(t2, t2, two);
        submod(w[3732], t1, t2);
    }

    // AND 1223 2166 -> 3733
    mulmod(w[3733], w[1223], w[2166]);

    // AND 1875 2217 -> 3734
    mulmod(w[3734], w[1875], w[2217]);

    // AND 352 1183 -> 3735
    mulmod(w[3735], w[352], w[1183]);

    // XOR 521 1248 -> 3736
    {
        bn254fr_class t1, t2;
        addmod(t1, w[521], w[1248]);
        mulmod(t2, w[521], w[1248]);
        mulmod_constant(t2, t2, two);
        submod(w[3736], t1, t2);
    }

    // XOR 2164 3278 -> 3737
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2164], w[3278]);
        mulmod(t2, w[2164], w[3278]);
        mulmod_constant(t2, t2, two);
        submod(w[3737], t1, t2);
    }

    // INV 3577 -> 3738
    submod(w[3738], one, w[3577]);

    // AND 1044 2387 -> 3739
    mulmod(w[3739], w[1044], w[2387]);

    // INV 1280 -> 3740
    submod(w[3740], one, w[1280]);

    // AND 3184 3360 -> 3741
    mulmod(w[3741], w[3184], w[3360]);

    // AND 702 1100 -> 3742
    mulmod(w[3742], w[702], w[1100]);

    // XOR 933 1233 -> 3743
    {
        bn254fr_class t1, t2;
        addmod(t1, w[933], w[1233]);
        mulmod(t2, w[933], w[1233]);
        mulmod_constant(t2, t2, two);
        submod(w[3743], t1, t2);
    }

    // XOR 2538 424 -> 3744
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2538], w[424]);
        mulmod(t2, w[2538], w[424]);
        mulmod_constant(t2, t2, two);
        submod(w[3744], t1, t2);
    }

    // AND 3236 1092 -> 3745
    mulmod(w[3745], w[3236], w[1092]);

    // INV 1478 -> 3746
    submod(w[3746], one, w[1478]);

    // XOR 1811 3524 -> 3747
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1811], w[3524]);
        mulmod(t2, w[1811], w[3524]);
        mulmod_constant(t2, t2, two);
        submod(w[3747], t1, t2);
    }

    // AND 950 2327 -> 3748
    mulmod(w[3748], w[950], w[2327]);

    // XOR 312 2652 -> 3749
    {
        bn254fr_class t1, t2;
        addmod(t1, w[312], w[2652]);
        mulmod(t2, w[312], w[2652]);
        mulmod_constant(t2, t2, two);
        submod(w[3749], t1, t2);
    }

    // XOR 3637 2938 -> 3750
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3637], w[2938]);
        mulmod(t2, w[3637], w[2938]);
        mulmod_constant(t2, t2, two);
        submod(w[3750], t1, t2);
    }

    // AND 136 3044 -> 3751
    mulmod(w[3751], w[136], w[3044]);

    // AND 1602 3373 -> 3752
    mulmod(w[3752], w[1602], w[3373]);

    // XOR 2930 797 -> 3753
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2930], w[797]);
        mulmod(t2, w[2930], w[797]);
        mulmod_constant(t2, t2, two);
        submod(w[3753], t1, t2);
    }

    // XOR 2084 3660 -> 3754
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2084], w[3660]);
        mulmod(t2, w[2084], w[3660]);
        mulmod_constant(t2, t2, two);
        submod(w[3754], t1, t2);
    }

    // XOR 2062 2265 -> 3755
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2062], w[2265]);
        mulmod(t2, w[2062], w[2265]);
        mulmod_constant(t2, t2, two);
        submod(w[3755], t1, t2);
    }

    // AND 638 507 -> 3756
    mulmod(w[3756], w[638], w[507]);

    // XOR 2656 2468 -> 3757
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2656], w[2468]);
        mulmod(t2, w[2656], w[2468]);
        mulmod_constant(t2, t2, two);
        submod(w[3757], t1, t2);
    }

    // AND 1593 1251 -> 3758
    mulmod(w[3758], w[1593], w[1251]);

    // XOR 619 2327 -> 3759
    {
        bn254fr_class t1, t2;
        addmod(t1, w[619], w[2327]);
        mulmod(t2, w[619], w[2327]);
        mulmod_constant(t2, t2, two);
        submod(w[3759], t1, t2);
    }

    // XOR 2654 1613 -> 3760
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2654], w[1613]);
        mulmod(t2, w[2654], w[1613]);
        mulmod_constant(t2, t2, two);
        submod(w[3760], t1, t2);
    }

    // XOR 1169 3653 -> 3761
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1169], w[3653]);
        mulmod(t2, w[1169], w[3653]);
        mulmod_constant(t2, t2, two);
        submod(w[3761], t1, t2);
    }

    // XOR 1949 1555 -> 3762
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1949], w[1555]);
        mulmod(t2, w[1949], w[1555]);
        mulmod_constant(t2, t2, two);
        submod(w[3762], t1, t2);
    }

    // XOR 3123 1714 -> 3763
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3123], w[1714]);
        mulmod(t2, w[3123], w[1714]);
        mulmod_constant(t2, t2, two);
        submod(w[3763], t1, t2);
    }

    // AND 205 2390 -> 3764
    mulmod(w[3764], w[205], w[2390]);

    // AND 1530 3447 -> 3765
    mulmod(w[3765], w[1530], w[3447]);

    // AND 381 3030 -> 3766
    mulmod(w[3766], w[381], w[3030]);

    // AND 2609 2763 -> 3767
    mulmod(w[3767], w[2609], w[2763]);

    // XOR 321 3473 -> 3768
    {
        bn254fr_class t1, t2;
        addmod(t1, w[321], w[3473]);
        mulmod(t2, w[321], w[3473]);
        mulmod_constant(t2, t2, two);
        submod(w[3768], t1, t2);
    }

    // INV 1087 -> 3769
    submod(w[3769], one, w[1087]);

    // XOR 1328 3041 -> 3770
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1328], w[3041]);
        mulmod(t2, w[1328], w[3041]);
        mulmod_constant(t2, t2, two);
        submod(w[3770], t1, t2);
    }

    // INV 1563 -> 3771
    submod(w[3771], one, w[1563]);

    // XOR 745 3592 -> 3772
    {
        bn254fr_class t1, t2;
        addmod(t1, w[745], w[3592]);
        mulmod(t2, w[745], w[3592]);
        mulmod_constant(t2, t2, two);
        submod(w[3772], t1, t2);
    }

    // AND 477 1787 -> 3773
    mulmod(w[3773], w[477], w[1787]);

    // AND 924 2850 -> 3774
    mulmod(w[3774], w[924], w[2850]);

    // AND 2085 1382 -> 3775
    mulmod(w[3775], w[2085], w[1382]);

    // XOR 2018 820 -> 3776
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2018], w[820]);
        mulmod(t2, w[2018], w[820]);
        mulmod_constant(t2, t2, two);
        submod(w[3776], t1, t2);
    }

    // AND 3149 3113 -> 3777
    mulmod(w[3777], w[3149], w[3113]);

    // XOR 1815 547 -> 3778
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1815], w[547]);
        mulmod(t2, w[1815], w[547]);
        mulmod_constant(t2, t2, two);
        submod(w[3778], t1, t2);
    }

    // XOR 1381 3578 -> 3779
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1381], w[3578]);
        mulmod(t2, w[1381], w[3578]);
        mulmod_constant(t2, t2, two);
        submod(w[3779], t1, t2);
    }

    // XOR 714 69 -> 3780
    {
        bn254fr_class t1, t2;
        addmod(t1, w[714], w[69]);
        mulmod(t2, w[714], w[69]);
        mulmod_constant(t2, t2, two);
        submod(w[3780], t1, t2);
    }

    // XOR 3659 2086 -> 3781
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3659], w[2086]);
        mulmod(t2, w[3659], w[2086]);
        mulmod_constant(t2, t2, two);
        submod(w[3781], t1, t2);
    }

    // XOR 336 330 -> 3782
    {
        bn254fr_class t1, t2;
        addmod(t1, w[336], w[330]);
        mulmod(t2, w[336], w[330]);
        mulmod_constant(t2, t2, two);
        submod(w[3782], t1, t2);
    }

    // AND 176 778 -> 3783
    mulmod(w[3783], w[176], w[778]);

    // XOR 3033 2791 -> 3784
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3033], w[2791]);
        mulmod(t2, w[3033], w[2791]);
        mulmod_constant(t2, t2, two);
        submod(w[3784], t1, t2);
    }

    // XOR 214 1812 -> 3785
    {
        bn254fr_class t1, t2;
        addmod(t1, w[214], w[1812]);
        mulmod(t2, w[214], w[1812]);
        mulmod_constant(t2, t2, two);
        submod(w[3785], t1, t2);
    }

    // XOR 1514 770 -> 3786
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1514], w[770]);
        mulmod(t2, w[1514], w[770]);
        mulmod_constant(t2, t2, two);
        submod(w[3786], t1, t2);
    }

    // AND 384 26 -> 3787
    mulmod(w[3787], w[384], w[26]);

    // AND 2051 1754 -> 3788
    mulmod(w[3788], w[2051], w[1754]);

    // AND 1522 1550 -> 3789
    mulmod(w[3789], w[1522], w[1550]);

    // XOR 61 3566 -> 3790
    {
        bn254fr_class t1, t2;
        addmod(t1, w[61], w[3566]);
        mulmod(t2, w[61], w[3566]);
        mulmod_constant(t2, t2, two);
        submod(w[3790], t1, t2);
    }

    // AND 1707 2423 -> 3791
    mulmod(w[3791], w[1707], w[2423]);

    // AND 2483 3737 -> 3792
    mulmod(w[3792], w[2483], w[3737]);

    // AND 3564 1698 -> 3793
    mulmod(w[3793], w[3564], w[1698]);

    // XOR 2007 176 -> 3794
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2007], w[176]);
        mulmod(t2, w[2007], w[176]);
        mulmod_constant(t2, t2, two);
        submod(w[3794], t1, t2);
    }

    // XOR 1995 1267 -> 3795
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1995], w[1267]);
        mulmod(t2, w[1995], w[1267]);
        mulmod_constant(t2, t2, two);
        submod(w[3795], t1, t2);
    }

    // XOR 1824 1925 -> 3796
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1824], w[1925]);
        mulmod(t2, w[1824], w[1925]);
        mulmod_constant(t2, t2, two);
        submod(w[3796], t1, t2);
    }

    // XOR 1286 2194 -> 3797
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1286], w[2194]);
        mulmod(t2, w[1286], w[2194]);
        mulmod_constant(t2, t2, two);
        submod(w[3797], t1, t2);
    }

    // XOR 3576 1111 -> 3798
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3576], w[1111]);
        mulmod(t2, w[3576], w[1111]);
        mulmod_constant(t2, t2, two);
        submod(w[3798], t1, t2);
    }

    // AND 3077 3180 -> 3799
    mulmod(w[3799], w[3077], w[3180]);

    // AND 2136 1331 -> 3800
    mulmod(w[3800], w[2136], w[1331]);

    // AND 2569 3091 -> 3801
    mulmod(w[3801], w[2569], w[3091]);

    // XOR 992 229 -> 3802
    {
        bn254fr_class t1, t2;
        addmod(t1, w[992], w[229]);
        mulmod(t2, w[992], w[229]);
        mulmod_constant(t2, t2, two);
        submod(w[3802], t1, t2);
    }

    // INV 2278 -> 3803
    submod(w[3803], one, w[2278]);

    // XOR 159 122 -> 3804
    {
        bn254fr_class t1, t2;
        addmod(t1, w[159], w[122]);
        mulmod(t2, w[159], w[122]);
        mulmod_constant(t2, t2, two);
        submod(w[3804], t1, t2);
    }

    // AND 1100 3551 -> 3805
    mulmod(w[3805], w[1100], w[3551]);

    // AND 614 1561 -> 3806
    mulmod(w[3806], w[614], w[1561]);

    // AND 3053 1564 -> 3807
    mulmod(w[3807], w[3053], w[1564]);

    // AND 3216 1368 -> 3808
    mulmod(w[3808], w[3216], w[1368]);

    // XOR 1035 622 -> 3809
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1035], w[622]);
        mulmod(t2, w[1035], w[622]);
        mulmod_constant(t2, t2, two);
        submod(w[3809], t1, t2);
    }

    // XOR 861 3299 -> 3810
    {
        bn254fr_class t1, t2;
        addmod(t1, w[861], w[3299]);
        mulmod(t2, w[861], w[3299]);
        mulmod_constant(t2, t2, two);
        submod(w[3810], t1, t2);
    }

    // AND 68 1981 -> 3811
    mulmod(w[3811], w[68], w[1981]);

    // XOR 2011 1472 -> 3812
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2011], w[1472]);
        mulmod(t2, w[2011], w[1472]);
        mulmod_constant(t2, t2, two);
        submod(w[3812], t1, t2);
    }

    // XOR 2931 2485 -> 3813
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2931], w[2485]);
        mulmod(t2, w[2931], w[2485]);
        mulmod_constant(t2, t2, two);
        submod(w[3813], t1, t2);
    }

    // XOR 2726 2229 -> 3814
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2726], w[2229]);
        mulmod(t2, w[2726], w[2229]);
        mulmod_constant(t2, t2, two);
        submod(w[3814], t1, t2);
    }

    // AND 2007 642 -> 3815
    mulmod(w[3815], w[2007], w[642]);

    // AND 3003 79 -> 3816
    mulmod(w[3816], w[3003], w[79]);

    // INV 1967 -> 3817
    submod(w[3817], one, w[1967]);

    // INV 3759 -> 3818
    submod(w[3818], one, w[3759]);

    // XOR 712 2791 -> 3819
    {
        bn254fr_class t1, t2;
        addmod(t1, w[712], w[2791]);
        mulmod(t2, w[712], w[2791]);
        mulmod_constant(t2, t2, two);
        submod(w[3819], t1, t2);
    }

    // XOR 2493 1825 -> 3820
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2493], w[1825]);
        mulmod(t2, w[2493], w[1825]);
        mulmod_constant(t2, t2, two);
        submod(w[3820], t1, t2);
    }

    // XOR 3370 3424 -> 3821
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3370], w[3424]);
        mulmod(t2, w[3370], w[3424]);
        mulmod_constant(t2, t2, two);
        submod(w[3821], t1, t2);
    }

    // XOR 463 911 -> 3822
    {
        bn254fr_class t1, t2;
        addmod(t1, w[463], w[911]);
        mulmod(t2, w[463], w[911]);
        mulmod_constant(t2, t2, two);
        submod(w[3822], t1, t2);
    }

    // XOR 345 1464 -> 3823
    {
        bn254fr_class t1, t2;
        addmod(t1, w[345], w[1464]);
        mulmod(t2, w[345], w[1464]);
        mulmod_constant(t2, t2, two);
        submod(w[3823], t1, t2);
    }

    // INV 163 -> 3824
    submod(w[3824], one, w[163]);

    // AND 770 2013 -> 3825
    mulmod(w[3825], w[770], w[2013]);

    // INV 3749 -> 3826
    submod(w[3826], one, w[3749]);

    // XOR 382 1358 -> 3827
    {
        bn254fr_class t1, t2;
        addmod(t1, w[382], w[1358]);
        mulmod(t2, w[382], w[1358]);
        mulmod_constant(t2, t2, two);
        submod(w[3827], t1, t2);
    }

    // AND 3552 1816 -> 3828
    mulmod(w[3828], w[3552], w[1816]);

    // INV 1944 -> 3829
    submod(w[3829], one, w[1944]);

    // XOR 2623 3302 -> 3830
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2623], w[3302]);
        mulmod(t2, w[2623], w[3302]);
        mulmod_constant(t2, t2, two);
        submod(w[3830], t1, t2);
    }

    // XOR 684 2616 -> 3831
    {
        bn254fr_class t1, t2;
        addmod(t1, w[684], w[2616]);
        mulmod(t2, w[684], w[2616]);
        mulmod_constant(t2, t2, two);
        submod(w[3831], t1, t2);
    }

    // AND 1856 3284 -> 3832
    mulmod(w[3832], w[1856], w[3284]);

    // AND 873 1458 -> 3833
    mulmod(w[3833], w[873], w[1458]);

    // AND 2679 1135 -> 3834
    mulmod(w[3834], w[2679], w[1135]);

    // XOR 727 450 -> 3835
    {
        bn254fr_class t1, t2;
        addmod(t1, w[727], w[450]);
        mulmod(t2, w[727], w[450]);
        mulmod_constant(t2, t2, two);
        submod(w[3835], t1, t2);
    }

    // XOR 759 2665 -> 3836
    {
        bn254fr_class t1, t2;
        addmod(t1, w[759], w[2665]);
        mulmod(t2, w[759], w[2665]);
        mulmod_constant(t2, t2, two);
        submod(w[3836], t1, t2);
    }

    // AND 42 1888 -> 3837
    mulmod(w[3837], w[42], w[1888]);

    // XOR 392 2321 -> 3838
    {
        bn254fr_class t1, t2;
        addmod(t1, w[392], w[2321]);
        mulmod(t2, w[392], w[2321]);
        mulmod_constant(t2, t2, two);
        submod(w[3838], t1, t2);
    }

    // AND 1478 3037 -> 3839
    mulmod(w[3839], w[1478], w[3037]);

    // AND 271 509 -> 3840
    mulmod(w[3840], w[271], w[509]);

    // XOR 1379 2936 -> 3841
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1379], w[2936]);
        mulmod(t2, w[1379], w[2936]);
        mulmod_constant(t2, t2, two);
        submod(w[3841], t1, t2);
    }

    // AND 1202 1207 -> 3842
    mulmod(w[3842], w[1202], w[1207]);

    // AND 186 36 -> 3843
    mulmod(w[3843], w[186], w[36]);

    // AND 1622 3678 -> 3844
    mulmod(w[3844], w[1622], w[3678]);

    // INV 1341 -> 3845
    submod(w[3845], one, w[1341]);

    // XOR 3595 1274 -> 3846
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3595], w[1274]);
        mulmod(t2, w[3595], w[1274]);
        mulmod_constant(t2, t2, two);
        submod(w[3846], t1, t2);
    }

    // AND 3145 1716 -> 3847
    mulmod(w[3847], w[3145], w[1716]);

    // XOR 3760 1189 -> 3848
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3760], w[1189]);
        mulmod(t2, w[3760], w[1189]);
        mulmod_constant(t2, t2, two);
        submod(w[3848], t1, t2);
    }

    // AND 893 3250 -> 3849
    mulmod(w[3849], w[893], w[3250]);

    // XOR 2089 1986 -> 3850
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2089], w[1986]);
        mulmod(t2, w[2089], w[1986]);
        mulmod_constant(t2, t2, two);
        submod(w[3850], t1, t2);
    }

    // XOR 636 2049 -> 3851
    {
        bn254fr_class t1, t2;
        addmod(t1, w[636], w[2049]);
        mulmod(t2, w[636], w[2049]);
        mulmod_constant(t2, t2, two);
        submod(w[3851], t1, t2);
    }

    // XOR 2686 3092 -> 3852
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2686], w[3092]);
        mulmod(t2, w[2686], w[3092]);
        mulmod_constant(t2, t2, two);
        submod(w[3852], t1, t2);
    }

    // XOR 128 2347 -> 3853
    {
        bn254fr_class t1, t2;
        addmod(t1, w[128], w[2347]);
        mulmod(t2, w[128], w[2347]);
        mulmod_constant(t2, t2, two);
        submod(w[3853], t1, t2);
    }

    // XOR 937 3495 -> 3854
    {
        bn254fr_class t1, t2;
        addmod(t1, w[937], w[3495]);
        mulmod(t2, w[937], w[3495]);
        mulmod_constant(t2, t2, two);
        submod(w[3854], t1, t2);
    }

    // AND 2554 1361 -> 3855
    mulmod(w[3855], w[2554], w[1361]);

    // AND 315 1040 -> 3856
    mulmod(w[3856], w[315], w[1040]);

    // XOR 1731 2696 -> 3857
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1731], w[2696]);
        mulmod(t2, w[1731], w[2696]);
        mulmod_constant(t2, t2, two);
        submod(w[3857], t1, t2);
    }

    // XOR 2258 3178 -> 3858
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2258], w[3178]);
        mulmod(t2, w[2258], w[3178]);
        mulmod_constant(t2, t2, two);
        submod(w[3858], t1, t2);
    }

    // XOR 1035 1192 -> 3859
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1035], w[1192]);
        mulmod(t2, w[1035], w[1192]);
        mulmod_constant(t2, t2, two);
        submod(w[3859], t1, t2);
    }

    // INV 2990 -> 3860
    submod(w[3860], one, w[2990]);

    // XOR 3561 1293 -> 3861
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3561], w[1293]);
        mulmod(t2, w[3561], w[1293]);
        mulmod_constant(t2, t2, two);
        submod(w[3861], t1, t2);
    }

    // AND 1865 1728 -> 3862
    mulmod(w[3862], w[1865], w[1728]);

    // AND 1756 2421 -> 3863
    mulmod(w[3863], w[1756], w[2421]);

    // XOR 2340 11 -> 3864
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2340], w[11]);
        mulmod(t2, w[2340], w[11]);
        mulmod_constant(t2, t2, two);
        submod(w[3864], t1, t2);
    }

    // XOR 434 156 -> 3865
    {
        bn254fr_class t1, t2;
        addmod(t1, w[434], w[156]);
        mulmod(t2, w[434], w[156]);
        mulmod_constant(t2, t2, two);
        submod(w[3865], t1, t2);
    }

    // AND 1388 3314 -> 3866
    mulmod(w[3866], w[1388], w[3314]);

    // XOR 1879 173 -> 3867
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1879], w[173]);
        mulmod(t2, w[1879], w[173]);
        mulmod_constant(t2, t2, two);
        submod(w[3867], t1, t2);
    }

    // XOR 1380 1975 -> 3868
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1380], w[1975]);
        mulmod(t2, w[1380], w[1975]);
        mulmod_constant(t2, t2, two);
        submod(w[3868], t1, t2);
    }

    // XOR 2115 1511 -> 3869
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2115], w[1511]);
        mulmod(t2, w[2115], w[1511]);
        mulmod_constant(t2, t2, two);
        submod(w[3869], t1, t2);
    }

    // INV 2023 -> 3870
    submod(w[3870], one, w[2023]);

    // AND 2370 3045 -> 3871
    mulmod(w[3871], w[2370], w[3045]);

    // XOR 2046 1954 -> 3872
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2046], w[1954]);
        mulmod(t2, w[2046], w[1954]);
        mulmod_constant(t2, t2, two);
        submod(w[3872], t1, t2);
    }

    // XOR 3558 2151 -> 3873
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3558], w[2151]);
        mulmod(t2, w[3558], w[2151]);
        mulmod_constant(t2, t2, two);
        submod(w[3873], t1, t2);
    }

    // AND 1885 891 -> 3874
    mulmod(w[3874], w[1885], w[891]);

    // AND 3486 3177 -> 3875
    mulmod(w[3875], w[3486], w[3177]);

    // AND 3371 1403 -> 3876
    mulmod(w[3876], w[3371], w[1403]);

    // AND 348 144 -> 3877
    mulmod(w[3877], w[348], w[144]);

    // XOR 605 1292 -> 3878
    {
        bn254fr_class t1, t2;
        addmod(t1, w[605], w[1292]);
        mulmod(t2, w[605], w[1292]);
        mulmod_constant(t2, t2, two);
        submod(w[3878], t1, t2);
    }

    // AND 2736 2027 -> 3879
    mulmod(w[3879], w[2736], w[2027]);

    // AND 2392 3272 -> 3880
    mulmod(w[3880], w[2392], w[3272]);

    // XOR 3343 1064 -> 3881
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3343], w[1064]);
        mulmod(t2, w[3343], w[1064]);
        mulmod_constant(t2, t2, two);
        submod(w[3881], t1, t2);
    }

    // AND 93 2256 -> 3882
    mulmod(w[3882], w[93], w[2256]);

    // XOR 1259 2609 -> 3883
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1259], w[2609]);
        mulmod(t2, w[1259], w[2609]);
        mulmod_constant(t2, t2, two);
        submod(w[3883], t1, t2);
    }

    // AND 1301 2320 -> 3884
    mulmod(w[3884], w[1301], w[2320]);

    // AND 798 1002 -> 3885
    mulmod(w[3885], w[798], w[1002]);

    // INV 2042 -> 3886
    submod(w[3886], one, w[2042]);

    // AND 141 2757 -> 3887
    mulmod(w[3887], w[141], w[2757]);

    // AND 3356 2289 -> 3888
    mulmod(w[3888], w[3356], w[2289]);

    // XOR 674 2159 -> 3889
    {
        bn254fr_class t1, t2;
        addmod(t1, w[674], w[2159]);
        mulmod(t2, w[674], w[2159]);
        mulmod_constant(t2, t2, two);
        submod(w[3889], t1, t2);
    }

    // AND 957 164 -> 3890
    mulmod(w[3890], w[957], w[164]);

    // XOR 1478 208 -> 3891
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1478], w[208]);
        mulmod(t2, w[1478], w[208]);
        mulmod_constant(t2, t2, two);
        submod(w[3891], t1, t2);
    }

    // AND 2774 2111 -> 3892
    mulmod(w[3892], w[2774], w[2111]);

    // XOR 1310 1001 -> 3893
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1310], w[1001]);
        mulmod(t2, w[1310], w[1001]);
        mulmod_constant(t2, t2, two);
        submod(w[3893], t1, t2);
    }

    // XOR 1931 1615 -> 3894
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1931], w[1615]);
        mulmod(t2, w[1931], w[1615]);
        mulmod_constant(t2, t2, two);
        submod(w[3894], t1, t2);
    }

    // AND 1638 525 -> 3895
    mulmod(w[3895], w[1638], w[525]);

    // AND 3527 1020 -> 3896
    mulmod(w[3896], w[3527], w[1020]);

    // XOR 1053 2267 -> 3897
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1053], w[2267]);
        mulmod(t2, w[1053], w[2267]);
        mulmod_constant(t2, t2, two);
        submod(w[3897], t1, t2);
    }

    // XOR 2341 1630 -> 3898
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2341], w[1630]);
        mulmod(t2, w[2341], w[1630]);
        mulmod_constant(t2, t2, two);
        submod(w[3898], t1, t2);
    }

    // AND 859 3246 -> 3899
    mulmod(w[3899], w[859], w[3246]);

    // XOR 3469 1800 -> 3900
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3469], w[1800]);
        mulmod(t2, w[3469], w[1800]);
        mulmod_constant(t2, t2, two);
        submod(w[3900], t1, t2);
    }

    // XOR 3548 2413 -> 3901
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3548], w[2413]);
        mulmod(t2, w[3548], w[2413]);
        mulmod_constant(t2, t2, two);
        submod(w[3901], t1, t2);
    }

    // AND 1359 3861 -> 3902
    mulmod(w[3902], w[1359], w[3861]);

    // XOR 3618 859 -> 3903
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3618], w[859]);
        mulmod(t2, w[3618], w[859]);
        mulmod_constant(t2, t2, two);
        submod(w[3903], t1, t2);
    }

    // AND 2100 2389 -> 3904
    mulmod(w[3904], w[2100], w[2389]);

    // XOR 1226 2604 -> 3905
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1226], w[2604]);
        mulmod(t2, w[1226], w[2604]);
        mulmod_constant(t2, t2, two);
        submod(w[3905], t1, t2);
    }

    // AND 3691 2508 -> 3906
    mulmod(w[3906], w[3691], w[2508]);

    // XOR 3549 1609 -> 3907
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3549], w[1609]);
        mulmod(t2, w[3549], w[1609]);
        mulmod_constant(t2, t2, two);
        submod(w[3907], t1, t2);
    }

    // AND 1730 1295 -> 3908
    mulmod(w[3908], w[1730], w[1295]);

    // XOR 518 2926 -> 3909
    {
        bn254fr_class t1, t2;
        addmod(t1, w[518], w[2926]);
        mulmod(t2, w[518], w[2926]);
        mulmod_constant(t2, t2, two);
        submod(w[3909], t1, t2);
    }

    // XOR 2182 3525 -> 3910
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2182], w[3525]);
        mulmod(t2, w[2182], w[3525]);
        mulmod_constant(t2, t2, two);
        submod(w[3910], t1, t2);
    }

    // XOR 2908 154 -> 3911
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2908], w[154]);
        mulmod(t2, w[2908], w[154]);
        mulmod_constant(t2, t2, two);
        submod(w[3911], t1, t2);
    }

    // XOR 3656 242 -> 3912
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3656], w[242]);
        mulmod(t2, w[3656], w[242]);
        mulmod_constant(t2, t2, two);
        submod(w[3912], t1, t2);
    }

    // XOR 2629 2998 -> 3913
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2629], w[2998]);
        mulmod(t2, w[2629], w[2998]);
        mulmod_constant(t2, t2, two);
        submod(w[3913], t1, t2);
    }

    // XOR 2814 1417 -> 3914
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2814], w[1417]);
        mulmod(t2, w[2814], w[1417]);
        mulmod_constant(t2, t2, two);
        submod(w[3914], t1, t2);
    }

    // XOR 962 3667 -> 3915
    {
        bn254fr_class t1, t2;
        addmod(t1, w[962], w[3667]);
        mulmod(t2, w[962], w[3667]);
        mulmod_constant(t2, t2, two);
        submod(w[3915], t1, t2);
    }

    // AND 3756 1558 -> 3916
    mulmod(w[3916], w[3756], w[1558]);

    // XOR 3642 2475 -> 3917
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3642], w[2475]);
        mulmod(t2, w[3642], w[2475]);
        mulmod_constant(t2, t2, two);
        submod(w[3917], t1, t2);
    }

    // XOR 2831 181 -> 3918
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2831], w[181]);
        mulmod(t2, w[2831], w[181]);
        mulmod_constant(t2, t2, two);
        submod(w[3918], t1, t2);
    }

    // AND 2707 1874 -> 3919
    mulmod(w[3919], w[2707], w[1874]);

    // XOR 498 602 -> 3920
    {
        bn254fr_class t1, t2;
        addmod(t1, w[498], w[602]);
        mulmod(t2, w[498], w[602]);
        mulmod_constant(t2, t2, two);
        submod(w[3920], t1, t2);
    }

    // AND 845 3686 -> 3921
    mulmod(w[3921], w[845], w[3686]);

    // AND 2769 1103 -> 3922
    mulmod(w[3922], w[2769], w[1103]);

    // AND 247 98 -> 3923
    mulmod(w[3923], w[247], w[98]);

    // XOR 1569 2005 -> 3924
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1569], w[2005]);
        mulmod(t2, w[1569], w[2005]);
        mulmod_constant(t2, t2, two);
        submod(w[3924], t1, t2);
    }

    // AND 1789 2696 -> 3925
    mulmod(w[3925], w[1789], w[2696]);

    // XOR 1745 2252 -> 3926
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1745], w[2252]);
        mulmod(t2, w[1745], w[2252]);
        mulmod_constant(t2, t2, two);
        submod(w[3926], t1, t2);
    }

    // INV 2503 -> 3927
    submod(w[3927], one, w[2503]);

    // XOR 1849 1702 -> 3928
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1849], w[1702]);
        mulmod(t2, w[1849], w[1702]);
        mulmod_constant(t2, t2, two);
        submod(w[3928], t1, t2);
    }

    // XOR 102 279 -> 3929
    {
        bn254fr_class t1, t2;
        addmod(t1, w[102], w[279]);
        mulmod(t2, w[102], w[279]);
        mulmod_constant(t2, t2, two);
        submod(w[3929], t1, t2);
    }

    // INV 2016 -> 3930
    submod(w[3930], one, w[2016]);

    // AND 2650 1380 -> 3931
    mulmod(w[3931], w[2650], w[1380]);

    // XOR 2169 3834 -> 3932
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2169], w[3834]);
        mulmod(t2, w[2169], w[3834]);
        mulmod_constant(t2, t2, two);
        submod(w[3932], t1, t2);
    }

    // XOR 1836 3715 -> 3933
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1836], w[3715]);
        mulmod(t2, w[1836], w[3715]);
        mulmod_constant(t2, t2, two);
        submod(w[3933], t1, t2);
    }

    // AND 708 2522 -> 3934
    mulmod(w[3934], w[708], w[2522]);

    // AND 814 3485 -> 3935
    mulmod(w[3935], w[814], w[3485]);

    // XOR 2236 3504 -> 3936
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2236], w[3504]);
        mulmod(t2, w[2236], w[3504]);
        mulmod_constant(t2, t2, two);
        submod(w[3936], t1, t2);
    }

    // XOR 3606 2824 -> 3937
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3606], w[2824]);
        mulmod(t2, w[3606], w[2824]);
        mulmod_constant(t2, t2, two);
        submod(w[3937], t1, t2);
    }

    // AND 1524 890 -> 3938
    mulmod(w[3938], w[1524], w[890]);

    // AND 734 2501 -> 3939
    mulmod(w[3939], w[734], w[2501]);

    // XOR 1169 2649 -> 3940
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1169], w[2649]);
        mulmod(t2, w[1169], w[2649]);
        mulmod_constant(t2, t2, two);
        submod(w[3940], t1, t2);
    }

    // AND 2246 2902 -> 3941
    mulmod(w[3941], w[2246], w[2902]);

    // XOR 3088 3070 -> 3942
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3088], w[3070]);
        mulmod(t2, w[3088], w[3070]);
        mulmod_constant(t2, t2, two);
        submod(w[3942], t1, t2);
    }

    // XOR 1952 2583 -> 3943
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1952], w[2583]);
        mulmod(t2, w[1952], w[2583]);
        mulmod_constant(t2, t2, two);
        submod(w[3943], t1, t2);
    }

    // INV 3003 -> 3944
    submod(w[3944], one, w[3003]);

    // XOR 511 2637 -> 3945
    {
        bn254fr_class t1, t2;
        addmod(t1, w[511], w[2637]);
        mulmod(t2, w[511], w[2637]);
        mulmod_constant(t2, t2, two);
        submod(w[3945], t1, t2);
    }

    // XOR 2138 2994 -> 3946
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2138], w[2994]);
        mulmod(t2, w[2138], w[2994]);
        mulmod_constant(t2, t2, two);
        submod(w[3946], t1, t2);
    }

    // INV 1186 -> 3947
    submod(w[3947], one, w[1186]);

    // XOR 3593 1629 -> 3948
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3593], w[1629]);
        mulmod(t2, w[3593], w[1629]);
        mulmod_constant(t2, t2, two);
        submod(w[3948], t1, t2);
    }

    // AND 2443 851 -> 3949
    mulmod(w[3949], w[2443], w[851]);

    // XOR 3426 1759 -> 3950
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3426], w[1759]);
        mulmod(t2, w[3426], w[1759]);
        mulmod_constant(t2, t2, two);
        submod(w[3950], t1, t2);
    }

    // XOR 3622 1521 -> 3951
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3622], w[1521]);
        mulmod(t2, w[3622], w[1521]);
        mulmod_constant(t2, t2, two);
        submod(w[3951], t1, t2);
    }

    // AND 3403 2137 -> 3952
    mulmod(w[3952], w[3403], w[2137]);

    // AND 356 533 -> 3953
    mulmod(w[3953], w[356], w[533]);

    // XOR 3846 3855 -> 3954
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3846], w[3855]);
        mulmod(t2, w[3846], w[3855]);
        mulmod_constant(t2, t2, two);
        submod(w[3954], t1, t2);
    }

    // XOR 467 1955 -> 3955
    {
        bn254fr_class t1, t2;
        addmod(t1, w[467], w[1955]);
        mulmod(t2, w[467], w[1955]);
        mulmod_constant(t2, t2, two);
        submod(w[3955], t1, t2);
    }

    // XOR 1447 1587 -> 3956
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1447], w[1587]);
        mulmod(t2, w[1447], w[1587]);
        mulmod_constant(t2, t2, two);
        submod(w[3956], t1, t2);
    }

    // XOR 2209 836 -> 3957
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2209], w[836]);
        mulmod(t2, w[2209], w[836]);
        mulmod_constant(t2, t2, two);
        submod(w[3957], t1, t2);
    }

    // XOR 1344 390 -> 3958
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1344], w[390]);
        mulmod(t2, w[1344], w[390]);
        mulmod_constant(t2, t2, two);
        submod(w[3958], t1, t2);
    }

    // XOR 719 880 -> 3959
    {
        bn254fr_class t1, t2;
        addmod(t1, w[719], w[880]);
        mulmod(t2, w[719], w[880]);
        mulmod_constant(t2, t2, two);
        submod(w[3959], t1, t2);
    }

    // XOR 3045 2816 -> 3960
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3045], w[2816]);
        mulmod(t2, w[3045], w[2816]);
        mulmod_constant(t2, t2, two);
        submod(w[3960], t1, t2);
    }

    // XOR 3357 643 -> 3961
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3357], w[643]);
        mulmod(t2, w[3357], w[643]);
        mulmod_constant(t2, t2, two);
        submod(w[3961], t1, t2);
    }

    // XOR 367 345 -> 3962
    {
        bn254fr_class t1, t2;
        addmod(t1, w[367], w[345]);
        mulmod(t2, w[367], w[345]);
        mulmod_constant(t2, t2, two);
        submod(w[3962], t1, t2);
    }

    // AND 619 3791 -> 3963
    mulmod(w[3963], w[619], w[3791]);

    // XOR 3437 1290 -> 3964
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3437], w[1290]);
        mulmod(t2, w[3437], w[1290]);
        mulmod_constant(t2, t2, two);
        submod(w[3964], t1, t2);
    }

    // XOR 3728 1105 -> 3965
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3728], w[1105]);
        mulmod(t2, w[3728], w[1105]);
        mulmod_constant(t2, t2, two);
        submod(w[3965], t1, t2);
    }

    // INV 2002 -> 3966
    submod(w[3966], one, w[2002]);

    // AND 3262 3258 -> 3967
    mulmod(w[3967], w[3262], w[3258]);

    // XOR 3395 875 -> 3968
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3395], w[875]);
        mulmod(t2, w[3395], w[875]);
        mulmod_constant(t2, t2, two);
        submod(w[3968], t1, t2);
    }

    // INV 3722 -> 3969
    submod(w[3969], one, w[3722]);

    // XOR 581 1166 -> 3970
    {
        bn254fr_class t1, t2;
        addmod(t1, w[581], w[1166]);
        mulmod(t2, w[581], w[1166]);
        mulmod_constant(t2, t2, two);
        submod(w[3970], t1, t2);
    }

    // XOR 1799 2390 -> 3971
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1799], w[2390]);
        mulmod(t2, w[1799], w[2390]);
        mulmod_constant(t2, t2, two);
        submod(w[3971], t1, t2);
    }

    // INV 122 -> 3972
    submod(w[3972], one, w[122]);

    // INV 3540 -> 3973
    submod(w[3973], one, w[3540]);

    // AND 2719 2333 -> 3974
    mulmod(w[3974], w[2719], w[2333]);

    // XOR 3323 1536 -> 3975
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3323], w[1536]);
        mulmod(t2, w[3323], w[1536]);
        mulmod_constant(t2, t2, two);
        submod(w[3975], t1, t2);
    }

    // XOR 897 575 -> 3976
    {
        bn254fr_class t1, t2;
        addmod(t1, w[897], w[575]);
        mulmod(t2, w[897], w[575]);
        mulmod_constant(t2, t2, two);
        submod(w[3976], t1, t2);
    }

    // AND 797 2412 -> 3977
    mulmod(w[3977], w[797], w[2412]);

    // XOR 3574 2977 -> 3978
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3574], w[2977]);
        mulmod(t2, w[3574], w[2977]);
        mulmod_constant(t2, t2, two);
        submod(w[3978], t1, t2);
    }

    // XOR 42 2482 -> 3979
    {
        bn254fr_class t1, t2;
        addmod(t1, w[42], w[2482]);
        mulmod(t2, w[42], w[2482]);
        mulmod_constant(t2, t2, two);
        submod(w[3979], t1, t2);
    }

    // INV 3257 -> 3980
    submod(w[3980], one, w[3257]);

    // XOR 1106 2477 -> 3981
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1106], w[2477]);
        mulmod(t2, w[1106], w[2477]);
        mulmod_constant(t2, t2, two);
        submod(w[3981], t1, t2);
    }

    // XOR 3225 2736 -> 3982
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3225], w[2736]);
        mulmod(t2, w[3225], w[2736]);
        mulmod_constant(t2, t2, two);
        submod(w[3982], t1, t2);
    }

    // XOR 591 43 -> 3983
    {
        bn254fr_class t1, t2;
        addmod(t1, w[591], w[43]);
        mulmod(t2, w[591], w[43]);
        mulmod_constant(t2, t2, two);
        submod(w[3983], t1, t2);
    }

    // AND 1070 3312 -> 3984
    mulmod(w[3984], w[1070], w[3312]);

    // XOR 2337 3523 -> 3985
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2337], w[3523]);
        mulmod(t2, w[2337], w[3523]);
        mulmod_constant(t2, t2, two);
        submod(w[3985], t1, t2);
    }

    // XOR 750 3209 -> 3986
    {
        bn254fr_class t1, t2;
        addmod(t1, w[750], w[3209]);
        mulmod(t2, w[750], w[3209]);
        mulmod_constant(t2, t2, two);
        submod(w[3986], t1, t2);
    }

    // XOR 1001 3179 -> 3987
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1001], w[3179]);
        mulmod(t2, w[1001], w[3179]);
        mulmod_constant(t2, t2, two);
        submod(w[3987], t1, t2);
    }

    // INV 2696 -> 3988
    submod(w[3988], one, w[2696]);

    // XOR 2780 2193 -> 3989
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2780], w[2193]);
        mulmod(t2, w[2780], w[2193]);
        mulmod_constant(t2, t2, two);
        submod(w[3989], t1, t2);
    }

    // XOR 1397 1669 -> 3990
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1397], w[1669]);
        mulmod(t2, w[1397], w[1669]);
        mulmod_constant(t2, t2, two);
        submod(w[3990], t1, t2);
    }

    // XOR 731 2528 -> 3991
    {
        bn254fr_class t1, t2;
        addmod(t1, w[731], w[2528]);
        mulmod(t2, w[731], w[2528]);
        mulmod_constant(t2, t2, two);
        submod(w[3991], t1, t2);
    }

    // INV 882 -> 3992
    submod(w[3992], one, w[882]);

    // XOR 1254 645 -> 3993
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1254], w[645]);
        mulmod(t2, w[1254], w[645]);
        mulmod_constant(t2, t2, two);
        submod(w[3993], t1, t2);
    }

    // AND 2208 836 -> 3994
    mulmod(w[3994], w[2208], w[836]);

    // XOR 2500 2955 -> 3995
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2500], w[2955]);
        mulmod(t2, w[2500], w[2955]);
        mulmod_constant(t2, t2, two);
        submod(w[3995], t1, t2);
    }

    // AND 2001 1731 -> 3996
    mulmod(w[3996], w[2001], w[1731]);

    // AND 2998 2090 -> 3997
    mulmod(w[3997], w[2998], w[2090]);

    // XOR 3171 212 -> 3998
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3171], w[212]);
        mulmod(t2, w[3171], w[212]);
        mulmod_constant(t2, t2, two);
        submod(w[3998], t1, t2);
    }

    // AND 2791 1418 -> 3999
    mulmod(w[3999], w[2791], w[1418]);

    // XOR 2182 3102 -> 4000
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2182], w[3102]);
        mulmod(t2, w[2182], w[3102]);
        mulmod_constant(t2, t2, two);
        submod(w[4000], t1, t2);
    }

    // XOR 2150 1524 -> 4001
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2150], w[1524]);
        mulmod(t2, w[2150], w[1524]);
        mulmod_constant(t2, t2, two);
        submod(w[4001], t1, t2);
    }

    // AND 1651 1477 -> 4002
    mulmod(w[4002], w[1651], w[1477]);

    // XOR 1950 3031 -> 4003
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1950], w[3031]);
        mulmod(t2, w[1950], w[3031]);
        mulmod_constant(t2, t2, two);
        submod(w[4003], t1, t2);
    }

    // XOR 2245 2799 -> 4004
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2245], w[2799]);
        mulmod(t2, w[2245], w[2799]);
        mulmod_constant(t2, t2, two);
        submod(w[4004], t1, t2);
    }

    // AND 2581 3750 -> 4005
    mulmod(w[4005], w[2581], w[3750]);

    // AND 2940 2518 -> 4006
    mulmod(w[4006], w[2940], w[2518]);

    // AND 3664 3699 -> 4007
    mulmod(w[4007], w[3664], w[3699]);

    // AND 2925 3104 -> 4008
    mulmod(w[4008], w[2925], w[3104]);

    // XOR 460 3402 -> 4009
    {
        bn254fr_class t1, t2;
        addmod(t1, w[460], w[3402]);
        mulmod(t2, w[460], w[3402]);
        mulmod_constant(t2, t2, two);
        submod(w[4009], t1, t2);
    }

    // INV 1660 -> 4010
    submod(w[4010], one, w[1660]);

    // XOR 2409 2861 -> 4011
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2409], w[2861]);
        mulmod(t2, w[2409], w[2861]);
        mulmod_constant(t2, t2, two);
        submod(w[4011], t1, t2);
    }

    // INV 2502 -> 4012
    submod(w[4012], one, w[2502]);

    // AND 3318 2269 -> 4013
    mulmod(w[4013], w[3318], w[2269]);

    // XOR 765 1115 -> 4014
    {
        bn254fr_class t1, t2;
        addmod(t1, w[765], w[1115]);
        mulmod(t2, w[765], w[1115]);
        mulmod_constant(t2, t2, two);
        submod(w[4014], t1, t2);
    }

    // XOR 964 2322 -> 4015
    {
        bn254fr_class t1, t2;
        addmod(t1, w[964], w[2322]);
        mulmod(t2, w[964], w[2322]);
        mulmod_constant(t2, t2, two);
        submod(w[4015], t1, t2);
    }

    // XOR 1057 1271 -> 4016
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1057], w[1271]);
        mulmod(t2, w[1057], w[1271]);
        mulmod_constant(t2, t2, two);
        submod(w[4016], t1, t2);
    }

    // AND 1288 3075 -> 4017
    mulmod(w[4017], w[1288], w[3075]);

    // XOR 2891 2337 -> 4018
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2891], w[2337]);
        mulmod(t2, w[2891], w[2337]);
        mulmod_constant(t2, t2, two);
        submod(w[4018], t1, t2);
    }

    // AND 354 1924 -> 4019
    mulmod(w[4019], w[354], w[1924]);

    // AND 689 863 -> 4020
    mulmod(w[4020], w[689], w[863]);

    // XOR 2917 3052 -> 4021
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2917], w[3052]);
        mulmod(t2, w[2917], w[3052]);
        mulmod_constant(t2, t2, two);
        submod(w[4021], t1, t2);
    }

    // XOR 330 675 -> 4022
    {
        bn254fr_class t1, t2;
        addmod(t1, w[330], w[675]);
        mulmod(t2, w[330], w[675]);
        mulmod_constant(t2, t2, two);
        submod(w[4022], t1, t2);
    }

    // AND 3185 2573 -> 4023
    mulmod(w[4023], w[3185], w[2573]);

    // AND 141 2104 -> 4024
    mulmod(w[4024], w[141], w[2104]);

    // AND 993 617 -> 4025
    mulmod(w[4025], w[993], w[617]);

    // AND 3774 611 -> 4026
    mulmod(w[4026], w[3774], w[611]);

    // XOR 3881 3545 -> 4027
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3881], w[3545]);
        mulmod(t2, w[3881], w[3545]);
        mulmod_constant(t2, t2, two);
        submod(w[4027], t1, t2);
    }

    // XOR 727 1583 -> 4028
    {
        bn254fr_class t1, t2;
        addmod(t1, w[727], w[1583]);
        mulmod(t2, w[727], w[1583]);
        mulmod_constant(t2, t2, two);
        submod(w[4028], t1, t2);
    }

    // XOR 3396 1215 -> 4029
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3396], w[1215]);
        mulmod(t2, w[3396], w[1215]);
        mulmod_constant(t2, t2, two);
        submod(w[4029], t1, t2);
    }

    // INV 1365 -> 4030
    submod(w[4030], one, w[1365]);

    // AND 3019 874 -> 4031
    mulmod(w[4031], w[3019], w[874]);

    // AND 1323 3566 -> 4032
    mulmod(w[4032], w[1323], w[3566]);

    // XOR 1454 3372 -> 4033
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1454], w[3372]);
        mulmod(t2, w[1454], w[3372]);
        mulmod_constant(t2, t2, two);
        submod(w[4033], t1, t2);
    }

    // AND 1150 637 -> 4034
    mulmod(w[4034], w[1150], w[637]);

    // AND 2099 478 -> 4035
    mulmod(w[4035], w[2099], w[478]);

    // XOR 1849 2395 -> 4036
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1849], w[2395]);
        mulmod(t2, w[1849], w[2395]);
        mulmod_constant(t2, t2, two);
        submod(w[4036], t1, t2);
    }

    // AND 2196 1999 -> 4037
    mulmod(w[4037], w[2196], w[1999]);

    // AND 3692 3833 -> 4038
    mulmod(w[4038], w[3692], w[3833]);

    // INV 150 -> 4039
    submod(w[4039], one, w[150]);

    // AND 3990 1971 -> 4040
    mulmod(w[4040], w[3990], w[1971]);

    // XOR 729 283 -> 4041
    {
        bn254fr_class t1, t2;
        addmod(t1, w[729], w[283]);
        mulmod(t2, w[729], w[283]);
        mulmod_constant(t2, t2, two);
        submod(w[4041], t1, t2);
    }

    // AND 2207 1789 -> 4042
    mulmod(w[4042], w[2207], w[1789]);

    // AND 364 269 -> 4043
    mulmod(w[4043], w[364], w[269]);

    // AND 353 2139 -> 4044
    mulmod(w[4044], w[353], w[2139]);

    // AND 3355 1252 -> 4045
    mulmod(w[4045], w[3355], w[1252]);

    // AND 2297 392 -> 4046
    mulmod(w[4046], w[2297], w[392]);

    // INV 1722 -> 4047
    submod(w[4047], one, w[1722]);

    // AND 249 2729 -> 4048
    mulmod(w[4048], w[249], w[2729]);

    // XOR 3363 2735 -> 4049
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3363], w[2735]);
        mulmod(t2, w[3363], w[2735]);
        mulmod_constant(t2, t2, two);
        submod(w[4049], t1, t2);
    }

    // XOR 796 2495 -> 4050
    {
        bn254fr_class t1, t2;
        addmod(t1, w[796], w[2495]);
        mulmod(t2, w[796], w[2495]);
        mulmod_constant(t2, t2, two);
        submod(w[4050], t1, t2);
    }

    // XOR 1689 2872 -> 4051
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1689], w[2872]);
        mulmod(t2, w[1689], w[2872]);
        mulmod_constant(t2, t2, two);
        submod(w[4051], t1, t2);
    }

    // AND 3944 1451 -> 4052
    mulmod(w[4052], w[3944], w[1451]);

    // AND 218 3264 -> 4053
    mulmod(w[4053], w[218], w[3264]);

    // AND 1421 3754 -> 4054
    mulmod(w[4054], w[1421], w[3754]);

    // AND 3516 3319 -> 4055
    mulmod(w[4055], w[3516], w[3319]);

    // AND 1288 2786 -> 4056
    mulmod(w[4056], w[1288], w[2786]);

    // AND 1646 1715 -> 4057
    mulmod(w[4057], w[1646], w[1715]);

    // AND 3478 2760 -> 4058
    mulmod(w[4058], w[3478], w[2760]);

    // XOR 497 1416 -> 4059
    {
        bn254fr_class t1, t2;
        addmod(t1, w[497], w[1416]);
        mulmod(t2, w[497], w[1416]);
        mulmod_constant(t2, t2, two);
        submod(w[4059], t1, t2);
    }

    // AND 242 1611 -> 4060
    mulmod(w[4060], w[242], w[1611]);

    // XOR 3328 2412 -> 4061
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3328], w[2412]);
        mulmod(t2, w[3328], w[2412]);
        mulmod_constant(t2, t2, two);
        submod(w[4061], t1, t2);
    }

    // AND 1 3501 -> 4062
    mulmod(w[4062], w[1], w[3501]);

    // AND 1318 701 -> 4063
    mulmod(w[4063], w[1318], w[701]);

    // AND 599 3535 -> 4064
    mulmod(w[4064], w[599], w[3535]);

    // XOR 2992 2343 -> 4065
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2992], w[2343]);
        mulmod(t2, w[2992], w[2343]);
        mulmod_constant(t2, t2, two);
        submod(w[4065], t1, t2);
    }

    // AND 1494 2261 -> 4066
    mulmod(w[4066], w[1494], w[2261]);

    // XOR 475 2777 -> 4067
    {
        bn254fr_class t1, t2;
        addmod(t1, w[475], w[2777]);
        mulmod(t2, w[475], w[2777]);
        mulmod_constant(t2, t2, two);
        submod(w[4067], t1, t2);
    }

    // AND 2203 2329 -> 4068
    mulmod(w[4068], w[2203], w[2329]);

    // XOR 2997 3570 -> 4069
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2997], w[3570]);
        mulmod(t2, w[2997], w[3570]);
        mulmod_constant(t2, t2, two);
        submod(w[4069], t1, t2);
    }

    // XOR 2663 2871 -> 4070
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2663], w[2871]);
        mulmod(t2, w[2663], w[2871]);
        mulmod_constant(t2, t2, two);
        submod(w[4070], t1, t2);
    }

    // XOR 1454 902 -> 4071
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1454], w[902]);
        mulmod(t2, w[1454], w[902]);
        mulmod_constant(t2, t2, two);
        submod(w[4071], t1, t2);
    }

    // AND 2423 3827 -> 4072
    mulmod(w[4072], w[2423], w[3827]);

    // AND 2536 654 -> 4073
    mulmod(w[4073], w[2536], w[654]);

    // XOR 3928 764 -> 4074
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3928], w[764]);
        mulmod(t2, w[3928], w[764]);
        mulmod_constant(t2, t2, two);
        submod(w[4074], t1, t2);
    }

    // XOR 572 479 -> 4075
    {
        bn254fr_class t1, t2;
        addmod(t1, w[572], w[479]);
        mulmod(t2, w[572], w[479]);
        mulmod_constant(t2, t2, two);
        submod(w[4075], t1, t2);
    }

    // XOR 1709 2460 -> 4076
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1709], w[2460]);
        mulmod(t2, w[1709], w[2460]);
        mulmod_constant(t2, t2, two);
        submod(w[4076], t1, t2);
    }

    // XOR 2958 3490 -> 4077
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2958], w[3490]);
        mulmod(t2, w[2958], w[3490]);
        mulmod_constant(t2, t2, two);
        submod(w[4077], t1, t2);
    }

    // AND 1433 2818 -> 4078
    mulmod(w[4078], w[1433], w[2818]);

    // AND 97 3962 -> 4079
    mulmod(w[4079], w[97], w[3962]);

    // AND 2755 1374 -> 4080
    mulmod(w[4080], w[2755], w[1374]);

    // AND 949 2887 -> 4081
    mulmod(w[4081], w[949], w[2887]);

    // XOR 325 3735 -> 4082
    {
        bn254fr_class t1, t2;
        addmod(t1, w[325], w[3735]);
        mulmod(t2, w[325], w[3735]);
        mulmod_constant(t2, t2, two);
        submod(w[4082], t1, t2);
    }

    // AND 637 1486 -> 4083
    mulmod(w[4083], w[637], w[1486]);

    // AND 2548 3886 -> 4084
    mulmod(w[4084], w[2548], w[3886]);

    // XOR 2977 1582 -> 4085
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2977], w[1582]);
        mulmod(t2, w[2977], w[1582]);
        mulmod_constant(t2, t2, two);
        submod(w[4085], t1, t2);
    }

    // INV 921 -> 4086
    submod(w[4086], one, w[921]);

    // XOR 1550 2514 -> 4087
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1550], w[2514]);
        mulmod(t2, w[1550], w[2514]);
        mulmod_constant(t2, t2, two);
        submod(w[4087], t1, t2);
    }

    // XOR 1892 2215 -> 4088
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1892], w[2215]);
        mulmod(t2, w[1892], w[2215]);
        mulmod_constant(t2, t2, two);
        submod(w[4088], t1, t2);
    }

    // AND 745 3759 -> 4089
    mulmod(w[4089], w[745], w[3759]);

    // AND 1272 403 -> 4090
    mulmod(w[4090], w[1272], w[403]);

    // AND 2434 1288 -> 4091
    mulmod(w[4091], w[2434], w[1288]);

    // AND 28 880 -> 4092
    mulmod(w[4092], w[28], w[880]);

    // AND 1788 1945 -> 4093
    mulmod(w[4093], w[1788], w[1945]);

    // XOR 3099 3684 -> 4094
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3099], w[3684]);
        mulmod(t2, w[3099], w[3684]);
        mulmod_constant(t2, t2, two);
        submod(w[4094], t1, t2);
    }

    // AND 2024 2182 -> 4095
    mulmod(w[4095], w[2024], w[2182]);

    // XOR 696 3916 -> 4096
    {
        bn254fr_class t1, t2;
        addmod(t1, w[696], w[3916]);
        mulmod(t2, w[696], w[3916]);
        mulmod_constant(t2, t2, two);
        submod(w[4096], t1, t2);
    }

    // AND 1176 1173 -> 4097
    mulmod(w[4097], w[1176], w[1173]);

    // XOR 3116 2806 -> 4098
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3116], w[2806]);
        mulmod(t2, w[3116], w[2806]);
        mulmod_constant(t2, t2, two);
        submod(w[4098], t1, t2);
    }

    // AND 2930 1931 -> 4099
    mulmod(w[4099], w[2930], w[1931]);

    // XOR 85 20 -> 4100
    {
        bn254fr_class t1, t2;
        addmod(t1, w[85], w[20]);
        mulmod(t2, w[85], w[20]);
        mulmod_constant(t2, t2, two);
        submod(w[4100], t1, t2);
    }

    // AND 530 3190 -> 4101
    mulmod(w[4101], w[530], w[3190]);

    // AND 3042 1167 -> 4102
    mulmod(w[4102], w[3042], w[1167]);

    // XOR 3186 522 -> 4103
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3186], w[522]);
        mulmod(t2, w[3186], w[522]);
        mulmod_constant(t2, t2, two);
        submod(w[4103], t1, t2);
    }

    // XOR 2789 3227 -> 4104
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2789], w[3227]);
        mulmod(t2, w[2789], w[3227]);
        mulmod_constant(t2, t2, two);
        submod(w[4104], t1, t2);
    }

    // AND 2996 455 -> 4105
    mulmod(w[4105], w[2996], w[455]);

    // INV 3296 -> 4106
    submod(w[4106], one, w[3296]);

    // AND 1960 556 -> 4107
    mulmod(w[4107], w[1960], w[556]);

    // XOR 1260 2893 -> 4108
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1260], w[2893]);
        mulmod(t2, w[1260], w[2893]);
        mulmod_constant(t2, t2, two);
        submod(w[4108], t1, t2);
    }

    // AND 2968 1249 -> 4109
    mulmod(w[4109], w[2968], w[1249]);

    // AND 1948 197 -> 4110
    mulmod(w[4110], w[1948], w[197]);

    // AND 3390 2355 -> 4111
    mulmod(w[4111], w[3390], w[2355]);

    // XOR 2228 1333 -> 4112
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2228], w[1333]);
        mulmod(t2, w[2228], w[1333]);
        mulmod_constant(t2, t2, two);
        submod(w[4112], t1, t2);
    }

    // INV 2249 -> 4113
    submod(w[4113], one, w[2249]);

    // AND 1254 3459 -> 4114
    mulmod(w[4114], w[1254], w[3459]);

    // XOR 810 3396 -> 4115
    {
        bn254fr_class t1, t2;
        addmod(t1, w[810], w[3396]);
        mulmod(t2, w[810], w[3396]);
        mulmod_constant(t2, t2, two);
        submod(w[4115], t1, t2);
    }

    // AND 2874 2155 -> 4116
    mulmod(w[4116], w[2874], w[2155]);

    // AND 3387 1743 -> 4117
    mulmod(w[4117], w[3387], w[1743]);

    // AND 3494 2999 -> 4118
    mulmod(w[4118], w[3494], w[2999]);

    // AND 3918 2245 -> 4119
    mulmod(w[4119], w[3918], w[2245]);

    // AND 3374 1225 -> 4120
    mulmod(w[4120], w[3374], w[1225]);

    // AND 3806 2299 -> 4121
    mulmod(w[4121], w[3806], w[2299]);

    // XOR 1626 3433 -> 4122
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1626], w[3433]);
        mulmod(t2, w[1626], w[3433]);
        mulmod_constant(t2, t2, two);
        submod(w[4122], t1, t2);
    }

    // XOR 3861 738 -> 4123
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3861], w[738]);
        mulmod(t2, w[3861], w[738]);
        mulmod_constant(t2, t2, two);
        submod(w[4123], t1, t2);
    }

    // INV 1285 -> 4124
    submod(w[4124], one, w[1285]);

    // AND 3790 1520 -> 4125
    mulmod(w[4125], w[3790], w[1520]);

    // XOR 3409 1260 -> 4126
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3409], w[1260]);
        mulmod(t2, w[3409], w[1260]);
        mulmod_constant(t2, t2, two);
        submod(w[4126], t1, t2);
    }

    // XOR 2444 160 -> 4127
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2444], w[160]);
        mulmod(t2, w[2444], w[160]);
        mulmod_constant(t2, t2, two);
        submod(w[4127], t1, t2);
    }

    // AND 1306 1386 -> 4128
    mulmod(w[4128], w[1306], w[1386]);

    // XOR 1911 248 -> 4129
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1911], w[248]);
        mulmod(t2, w[1911], w[248]);
        mulmod_constant(t2, t2, two);
        submod(w[4129], t1, t2);
    }

    // XOR 3420 161 -> 4130
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3420], w[161]);
        mulmod(t2, w[3420], w[161]);
        mulmod_constant(t2, t2, two);
        submod(w[4130], t1, t2);
    }

    // AND 2506 207 -> 4131
    mulmod(w[4131], w[2506], w[207]);

    // AND 2921 3872 -> 4132
    mulmod(w[4132], w[2921], w[3872]);

    // XOR 431 3783 -> 4133
    {
        bn254fr_class t1, t2;
        addmod(t1, w[431], w[3783]);
        mulmod(t2, w[431], w[3783]);
        mulmod_constant(t2, t2, two);
        submod(w[4133], t1, t2);
    }

    // XOR 49 2329 -> 4134
    {
        bn254fr_class t1, t2;
        addmod(t1, w[49], w[2329]);
        mulmod(t2, w[49], w[2329]);
        mulmod_constant(t2, t2, two);
        submod(w[4134], t1, t2);
    }

    // XOR 1998 1744 -> 4135
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1998], w[1744]);
        mulmod(t2, w[1998], w[1744]);
        mulmod_constant(t2, t2, two);
        submod(w[4135], t1, t2);
    }

    // XOR 1269 4021 -> 4136
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1269], w[4021]);
        mulmod(t2, w[1269], w[4021]);
        mulmod_constant(t2, t2, two);
        submod(w[4136], t1, t2);
    }

    // AND 1914 2948 -> 4137
    mulmod(w[4137], w[1914], w[2948]);

    // AND 2200 621 -> 4138
    mulmod(w[4138], w[2200], w[621]);

    // AND 3815 423 -> 4139
    mulmod(w[4139], w[3815], w[423]);

    // AND 158 3353 -> 4140
    mulmod(w[4140], w[158], w[3353]);

    // INV 3984 -> 4141
    submod(w[4141], one, w[3984]);

    // XOR 2372 3171 -> 4142
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2372], w[3171]);
        mulmod(t2, w[2372], w[3171]);
        mulmod_constant(t2, t2, two);
        submod(w[4142], t1, t2);
    }

    // XOR 3664 2648 -> 4143
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3664], w[2648]);
        mulmod(t2, w[3664], w[2648]);
        mulmod_constant(t2, t2, two);
        submod(w[4143], t1, t2);
    }

    // AND 2699 2781 -> 4144
    mulmod(w[4144], w[2699], w[2781]);

    // XOR 3092 586 -> 4145
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3092], w[586]);
        mulmod(t2, w[3092], w[586]);
        mulmod_constant(t2, t2, two);
        submod(w[4145], t1, t2);
    }

    // AND 1200 2993 -> 4146
    mulmod(w[4146], w[1200], w[2993]);

    // XOR 2894 541 -> 4147
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2894], w[541]);
        mulmod(t2, w[2894], w[541]);
        mulmod_constant(t2, t2, two);
        submod(w[4147], t1, t2);
    }

    // AND 2231 1376 -> 4148
    mulmod(w[4148], w[2231], w[1376]);

    // AND 2246 565 -> 4149
    mulmod(w[4149], w[2246], w[565]);

    // INV 1850 -> 4150
    submod(w[4150], one, w[1850]);

    // XOR 3446 2707 -> 4151
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3446], w[2707]);
        mulmod(t2, w[3446], w[2707]);
        mulmod_constant(t2, t2, two);
        submod(w[4151], t1, t2);
    }

    // XOR 2492 1342 -> 4152
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2492], w[1342]);
        mulmod(t2, w[2492], w[1342]);
        mulmod_constant(t2, t2, two);
        submod(w[4152], t1, t2);
    }

    // XOR 471 1095 -> 4153
    {
        bn254fr_class t1, t2;
        addmod(t1, w[471], w[1095]);
        mulmod(t2, w[471], w[1095]);
        mulmod_constant(t2, t2, two);
        submod(w[4153], t1, t2);
    }

    // XOR 3982 3602 -> 4154
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3982], w[3602]);
        mulmod(t2, w[3982], w[3602]);
        mulmod_constant(t2, t2, two);
        submod(w[4154], t1, t2);
    }

    // XOR 447 3928 -> 4155
    {
        bn254fr_class t1, t2;
        addmod(t1, w[447], w[3928]);
        mulmod(t2, w[447], w[3928]);
        mulmod_constant(t2, t2, two);
        submod(w[4155], t1, t2);
    }

    // INV 21 -> 4156
    submod(w[4156], one, w[21]);

    // XOR 402 573 -> 4157
    {
        bn254fr_class t1, t2;
        addmod(t1, w[402], w[573]);
        mulmod(t2, w[402], w[573]);
        mulmod_constant(t2, t2, two);
        submod(w[4157], t1, t2);
    }

    // INV 2955 -> 4158
    submod(w[4158], one, w[2955]);

    // XOR 666 3272 -> 4159
    {
        bn254fr_class t1, t2;
        addmod(t1, w[666], w[3272]);
        mulmod(t2, w[666], w[3272]);
        mulmod_constant(t2, t2, two);
        submod(w[4159], t1, t2);
    }

    // AND 4045 3183 -> 4160
    mulmod(w[4160], w[4045], w[3183]);

    // XOR 2946 531 -> 4161
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2946], w[531]);
        mulmod(t2, w[2946], w[531]);
        mulmod_constant(t2, t2, two);
        submod(w[4161], t1, t2);
    }

    // INV 22 -> 4162
    submod(w[4162], one, w[22]);

    // AND 328 2833 -> 4163
    mulmod(w[4163], w[328], w[2833]);

    // XOR 1953 2577 -> 4164
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1953], w[2577]);
        mulmod(t2, w[1953], w[2577]);
        mulmod_constant(t2, t2, two);
        submod(w[4164], t1, t2);
    }

    // XOR 2217 2470 -> 4165
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2217], w[2470]);
        mulmod(t2, w[2217], w[2470]);
        mulmod_constant(t2, t2, two);
        submod(w[4165], t1, t2);
    }

    // AND 701 3327 -> 4166
    mulmod(w[4166], w[701], w[3327]);

    // XOR 753 471 -> 4167
    {
        bn254fr_class t1, t2;
        addmod(t1, w[753], w[471]);
        mulmod(t2, w[753], w[471]);
        mulmod_constant(t2, t2, two);
        submod(w[4167], t1, t2);
    }

    // AND 2053 3546 -> 4168
    mulmod(w[4168], w[2053], w[3546]);

    // AND 3981 2841 -> 4169
    mulmod(w[4169], w[3981], w[2841]);

    // XOR 3192 1389 -> 4170
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3192], w[1389]);
        mulmod(t2, w[3192], w[1389]);
        mulmod_constant(t2, t2, two);
        submod(w[4170], t1, t2);
    }

    // INV 806 -> 4171
    submod(w[4171], one, w[806]);

    // XOR 3878 2618 -> 4172
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3878], w[2618]);
        mulmod(t2, w[3878], w[2618]);
        mulmod_constant(t2, t2, two);
        submod(w[4172], t1, t2);
    }

    // XOR 484 2335 -> 4173
    {
        bn254fr_class t1, t2;
        addmod(t1, w[484], w[2335]);
        mulmod(t2, w[484], w[2335]);
        mulmod_constant(t2, t2, two);
        submod(w[4173], t1, t2);
    }

    // XOR 2684 2402 -> 4174
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2684], w[2402]);
        mulmod(t2, w[2684], w[2402]);
        mulmod_constant(t2, t2, two);
        submod(w[4174], t1, t2);
    }

    // AND 3290 3613 -> 4175
    mulmod(w[4175], w[3290], w[3613]);

    // AND 1120 1061 -> 4176
    mulmod(w[4176], w[1120], w[1061]);

    // AND 2393 3078 -> 4177
    mulmod(w[4177], w[2393], w[3078]);

    // AND 2554 99 -> 4178
    mulmod(w[4178], w[2554], w[99]);

    // AND 2409 1871 -> 4179
    mulmod(w[4179], w[2409], w[1871]);

    // XOR 2966 3816 -> 4180
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2966], w[3816]);
        mulmod(t2, w[2966], w[3816]);
        mulmod_constant(t2, t2, two);
        submod(w[4180], t1, t2);
    }

    // AND 2201 1101 -> 4181
    mulmod(w[4181], w[2201], w[1101]);

    // XOR 3613 1379 -> 4182
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3613], w[1379]);
        mulmod(t2, w[3613], w[1379]);
        mulmod_constant(t2, t2, two);
        submod(w[4182], t1, t2);
    }

    // XOR 434 2532 -> 4183
    {
        bn254fr_class t1, t2;
        addmod(t1, w[434], w[2532]);
        mulmod(t2, w[434], w[2532]);
        mulmod_constant(t2, t2, two);
        submod(w[4183], t1, t2);
    }

    // XOR 3594 969 -> 4184
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3594], w[969]);
        mulmod(t2, w[3594], w[969]);
        mulmod_constant(t2, t2, two);
        submod(w[4184], t1, t2);
    }

    // XOR 1600 1953 -> 4185
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1600], w[1953]);
        mulmod(t2, w[1600], w[1953]);
        mulmod_constant(t2, t2, two);
        submod(w[4185], t1, t2);
    }

    // XOR 2033 4051 -> 4186
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2033], w[4051]);
        mulmod(t2, w[2033], w[4051]);
        mulmod_constant(t2, t2, two);
        submod(w[4186], t1, t2);
    }

    // XOR 491 2816 -> 4187
    {
        bn254fr_class t1, t2;
        addmod(t1, w[491], w[2816]);
        mulmod(t2, w[491], w[2816]);
        mulmod_constant(t2, t2, two);
        submod(w[4187], t1, t2);
    }

    // XOR 1910 2135 -> 4188
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1910], w[2135]);
        mulmod(t2, w[1910], w[2135]);
        mulmod_constant(t2, t2, two);
        submod(w[4188], t1, t2);
    }

    // XOR 1911 491 -> 4189
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1911], w[491]);
        mulmod(t2, w[1911], w[491]);
        mulmod_constant(t2, t2, two);
        submod(w[4189], t1, t2);
    }

    // AND 1548 2914 -> 4190
    mulmod(w[4190], w[1548], w[2914]);

    // AND 2319 3861 -> 4191
    mulmod(w[4191], w[2319], w[3861]);

    // AND 1538 1635 -> 4192
    mulmod(w[4192], w[1538], w[1635]);

    // XOR 2716 1934 -> 4193
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2716], w[1934]);
        mulmod(t2, w[2716], w[1934]);
        mulmod_constant(t2, t2, two);
        submod(w[4193], t1, t2);
    }

    // AND 3066 2698 -> 4194
    mulmod(w[4194], w[3066], w[2698]);

    // XOR 3331 2525 -> 4195
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3331], w[2525]);
        mulmod(t2, w[3331], w[2525]);
        mulmod_constant(t2, t2, two);
        submod(w[4195], t1, t2);
    }

    // XOR 899 3753 -> 4196
    {
        bn254fr_class t1, t2;
        addmod(t1, w[899], w[3753]);
        mulmod(t2, w[899], w[3753]);
        mulmod_constant(t2, t2, two);
        submod(w[4196], t1, t2);
    }

    // XOR 1484 3461 -> 4197
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1484], w[3461]);
        mulmod(t2, w[1484], w[3461]);
        mulmod_constant(t2, t2, two);
        submod(w[4197], t1, t2);
    }

    // XOR 1422 1640 -> 4198
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1422], w[1640]);
        mulmod(t2, w[1422], w[1640]);
        mulmod_constant(t2, t2, two);
        submod(w[4198], t1, t2);
    }

    // INV 2796 -> 4199
    submod(w[4199], one, w[2796]);

    // AND 450 2404 -> 4200
    mulmod(w[4200], w[450], w[2404]);

    // INV 767 -> 4201
    submod(w[4201], one, w[767]);

    // AND 3751 1806 -> 4202
    mulmod(w[4202], w[3751], w[1806]);

    // AND 2263 3958 -> 4203
    mulmod(w[4203], w[2263], w[3958]);

    // AND 1587 2380 -> 4204
    mulmod(w[4204], w[1587], w[2380]);

    // INV 2230 -> 4205
    submod(w[4205], one, w[2230]);

    // INV 522 -> 4206
    submod(w[4206], one, w[522]);

    // AND 1604 370 -> 4207
    mulmod(w[4207], w[1604], w[370]);

    // XOR 2895 3414 -> 4208
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2895], w[3414]);
        mulmod(t2, w[2895], w[3414]);
        mulmod_constant(t2, t2, two);
        submod(w[4208], t1, t2);
    }

    // AND 2654 4074 -> 4209
    mulmod(w[4209], w[2654], w[4074]);

    // AND 2998 3208 -> 4210
    mulmod(w[4210], w[2998], w[3208]);

    // AND 705 2213 -> 4211
    mulmod(w[4211], w[705], w[2213]);

    // AND 3056 702 -> 4212
    mulmod(w[4212], w[3056], w[702]);

    // XOR 1762 536 -> 4213
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1762], w[536]);
        mulmod(t2, w[1762], w[536]);
        mulmod_constant(t2, t2, two);
        submod(w[4213], t1, t2);
    }

    // XOR 2206 1099 -> 4214
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2206], w[1099]);
        mulmod(t2, w[2206], w[1099]);
        mulmod_constant(t2, t2, two);
        submod(w[4214], t1, t2);
    }

    // AND 4060 2745 -> 4215
    mulmod(w[4215], w[4060], w[2745]);

    // XOR 202 3447 -> 4216
    {
        bn254fr_class t1, t2;
        addmod(t1, w[202], w[3447]);
        mulmod(t2, w[202], w[3447]);
        mulmod_constant(t2, t2, two);
        submod(w[4216], t1, t2);
    }

    // INV 3729 -> 4217
    submod(w[4217], one, w[3729]);

    // AND 1906 2956 -> 4218
    mulmod(w[4218], w[1906], w[2956]);

    // AND 2516 3343 -> 4219
    mulmod(w[4219], w[2516], w[3343]);

    // XOR 3080 64 -> 4220
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3080], w[64]);
        mulmod(t2, w[3080], w[64]);
        mulmod_constant(t2, t2, two);
        submod(w[4220], t1, t2);
    }

    // XOR 2320 383 -> 4221
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2320], w[383]);
        mulmod(t2, w[2320], w[383]);
        mulmod_constant(t2, t2, two);
        submod(w[4221], t1, t2);
    }

    // AND 934 3416 -> 4222
    mulmod(w[4222], w[934], w[3416]);

    // AND 2150 3142 -> 4223
    mulmod(w[4223], w[2150], w[3142]);

    // AND 2522 2308 -> 4224
    mulmod(w[4224], w[2522], w[2308]);

    // XOR 2238 244 -> 4225
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2238], w[244]);
        mulmod(t2, w[2238], w[244]);
        mulmod_constant(t2, t2, two);
        submod(w[4225], t1, t2);
    }

    // AND 1314 3561 -> 4226
    mulmod(w[4226], w[1314], w[3561]);

    // AND 726 34 -> 4227
    mulmod(w[4227], w[726], w[34]);

    // AND 3982 3622 -> 4228
    mulmod(w[4228], w[3982], w[3622]);

    // AND 3613 1151 -> 4229
    mulmod(w[4229], w[3613], w[1151]);

    // XOR 835 3883 -> 4230
    {
        bn254fr_class t1, t2;
        addmod(t1, w[835], w[3883]);
        mulmod(t2, w[835], w[3883]);
        mulmod_constant(t2, t2, two);
        submod(w[4230], t1, t2);
    }

    // XOR 1723 2385 -> 4231
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1723], w[2385]);
        mulmod(t2, w[1723], w[2385]);
        mulmod_constant(t2, t2, two);
        submod(w[4231], t1, t2);
    }

    // AND 89 3878 -> 4232
    mulmod(w[4232], w[89], w[3878]);

    // XOR 3342 2160 -> 4233
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3342], w[2160]);
        mulmod(t2, w[3342], w[2160]);
        mulmod_constant(t2, t2, two);
        submod(w[4233], t1, t2);
    }

    // XOR 1861 2796 -> 4234
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1861], w[2796]);
        mulmod(t2, w[1861], w[2796]);
        mulmod_constant(t2, t2, two);
        submod(w[4234], t1, t2);
    }

    // AND 2567 2774 -> 4235
    mulmod(w[4235], w[2567], w[2774]);

    // AND 1192 1912 -> 4236
    mulmod(w[4236], w[1192], w[1912]);

    // XOR 2607 3452 -> 4237
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2607], w[3452]);
        mulmod(t2, w[2607], w[3452]);
        mulmod_constant(t2, t2, two);
        submod(w[4237], t1, t2);
    }

    // XOR 3798 3746 -> 4238
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3798], w[3746]);
        mulmod(t2, w[3798], w[3746]);
        mulmod_constant(t2, t2, two);
        submod(w[4238], t1, t2);
    }

    // AND 1558 3076 -> 4239
    mulmod(w[4239], w[1558], w[3076]);

    // AND 2821 478 -> 4240
    mulmod(w[4240], w[2821], w[478]);

    // AND 4077 1594 -> 4241
    mulmod(w[4241], w[4077], w[1594]);

    // AND 2447 430 -> 4242
    mulmod(w[4242], w[2447], w[430]);

    // AND 896 763 -> 4243
    mulmod(w[4243], w[896], w[763]);

    // AND 3127 3812 -> 4244
    mulmod(w[4244], w[3127], w[3812]);

    // AND 2813 3724 -> 4245
    mulmod(w[4245], w[2813], w[3724]);

    // XOR 1391 3694 -> 4246
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1391], w[3694]);
        mulmod(t2, w[1391], w[3694]);
        mulmod_constant(t2, t2, two);
        submod(w[4246], t1, t2);
    }

    // XOR 1102 858 -> 4247
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1102], w[858]);
        mulmod(t2, w[1102], w[858]);
        mulmod_constant(t2, t2, two);
        submod(w[4247], t1, t2);
    }

    // XOR 2451 444 -> 4248
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2451], w[444]);
        mulmod(t2, w[2451], w[444]);
        mulmod_constant(t2, t2, two);
        submod(w[4248], t1, t2);
    }

    // XOR 357 1713 -> 4249
    {
        bn254fr_class t1, t2;
        addmod(t1, w[357], w[1713]);
        mulmod(t2, w[357], w[1713]);
        mulmod_constant(t2, t2, two);
        submod(w[4249], t1, t2);
    }

    // XOR 1067 2482 -> 4250
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1067], w[2482]);
        mulmod(t2, w[1067], w[2482]);
        mulmod_constant(t2, t2, two);
        submod(w[4250], t1, t2);
    }

    // XOR 448 346 -> 4251
    {
        bn254fr_class t1, t2;
        addmod(t1, w[448], w[346]);
        mulmod(t2, w[448], w[346]);
        mulmod_constant(t2, t2, two);
        submod(w[4251], t1, t2);
    }

    // XOR 729 3182 -> 4252
    {
        bn254fr_class t1, t2;
        addmod(t1, w[729], w[3182]);
        mulmod(t2, w[729], w[3182]);
        mulmod_constant(t2, t2, two);
        submod(w[4252], t1, t2);
    }

    // AND 1416 746 -> 4253
    mulmod(w[4253], w[1416], w[746]);

    // XOR 2813 2931 -> 4254
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2813], w[2931]);
        mulmod(t2, w[2813], w[2931]);
        mulmod_constant(t2, t2, two);
        submod(w[4254], t1, t2);
    }

    // XOR 1567 2748 -> 4255
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1567], w[2748]);
        mulmod(t2, w[1567], w[2748]);
        mulmod_constant(t2, t2, two);
        submod(w[4255], t1, t2);
    }

    // XOR 2998 4012 -> 4256
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2998], w[4012]);
        mulmod(t2, w[2998], w[4012]);
        mulmod_constant(t2, t2, two);
        submod(w[4256], t1, t2);
    }

    // XOR 1414 2844 -> 4257
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1414], w[2844]);
        mulmod(t2, w[1414], w[2844]);
        mulmod_constant(t2, t2, two);
        submod(w[4257], t1, t2);
    }

    // AND 1777 3000 -> 4258
    mulmod(w[4258], w[1777], w[3000]);

    // XOR 2052 82 -> 4259
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2052], w[82]);
        mulmod(t2, w[2052], w[82]);
        mulmod_constant(t2, t2, two);
        submod(w[4259], t1, t2);
    }

    // XOR 3462 1964 -> 4260
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3462], w[1964]);
        mulmod(t2, w[3462], w[1964]);
        mulmod_constant(t2, t2, two);
        submod(w[4260], t1, t2);
    }

    // AND 173 2716 -> 4261
    mulmod(w[4261], w[173], w[2716]);

    // XOR 3982 1837 -> 4262
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3982], w[1837]);
        mulmod(t2, w[3982], w[1837]);
        mulmod_constant(t2, t2, two);
        submod(w[4262], t1, t2);
    }

    // INV 604 -> 4263
    submod(w[4263], one, w[604]);

    // XOR 1297 780 -> 4264
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1297], w[780]);
        mulmod(t2, w[1297], w[780]);
        mulmod_constant(t2, t2, two);
        submod(w[4264], t1, t2);
    }

    // XOR 3982 2712 -> 4265
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3982], w[2712]);
        mulmod(t2, w[3982], w[2712]);
        mulmod_constant(t2, t2, two);
        submod(w[4265], t1, t2);
    }

    // XOR 1751 1472 -> 4266
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1751], w[1472]);
        mulmod(t2, w[1751], w[1472]);
        mulmod_constant(t2, t2, two);
        submod(w[4266], t1, t2);
    }

    // XOR 2377 2622 -> 4267
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2377], w[2622]);
        mulmod(t2, w[2377], w[2622]);
        mulmod_constant(t2, t2, two);
        submod(w[4267], t1, t2);
    }

    // XOR 778 1890 -> 4268
    {
        bn254fr_class t1, t2;
        addmod(t1, w[778], w[1890]);
        mulmod(t2, w[778], w[1890]);
        mulmod_constant(t2, t2, two);
        submod(w[4268], t1, t2);
    }

    // XOR 3546 1022 -> 4269
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3546], w[1022]);
        mulmod(t2, w[3546], w[1022]);
        mulmod_constant(t2, t2, two);
        submod(w[4269], t1, t2);
    }

    // XOR 635 1410 -> 4270
    {
        bn254fr_class t1, t2;
        addmod(t1, w[635], w[1410]);
        mulmod(t2, w[635], w[1410]);
        mulmod_constant(t2, t2, two);
        submod(w[4270], t1, t2);
    }

    // AND 3693 1807 -> 4271
    mulmod(w[4271], w[3693], w[1807]);

    // AND 2587 2376 -> 4272
    mulmod(w[4272], w[2587], w[2376]);

    // AND 91 2252 -> 4273
    mulmod(w[4273], w[91], w[2252]);

    // XOR 1350 2945 -> 4274
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1350], w[2945]);
        mulmod(t2, w[1350], w[2945]);
        mulmod_constant(t2, t2, two);
        submod(w[4274], t1, t2);
    }

    // XOR 3614 1650 -> 4275
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3614], w[1650]);
        mulmod(t2, w[3614], w[1650]);
        mulmod_constant(t2, t2, two);
        submod(w[4275], t1, t2);
    }

    // AND 2718 3547 -> 4276
    mulmod(w[4276], w[2718], w[3547]);

    // XOR 930 1699 -> 4277
    {
        bn254fr_class t1, t2;
        addmod(t1, w[930], w[1699]);
        mulmod(t2, w[930], w[1699]);
        mulmod_constant(t2, t2, two);
        submod(w[4277], t1, t2);
    }

    // AND 3211 238 -> 4278
    mulmod(w[4278], w[3211], w[238]);

    // INV 3928 -> 4279
    submod(w[4279], one, w[3928]);

    // AND 2783 3772 -> 4280
    mulmod(w[4280], w[2783], w[3772]);

    // INV 2177 -> 4281
    submod(w[4281], one, w[2177]);

    // XOR 2247 2065 -> 4282
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2247], w[2065]);
        mulmod(t2, w[2247], w[2065]);
        mulmod_constant(t2, t2, two);
        submod(w[4282], t1, t2);
    }

    // XOR 3534 3397 -> 4283
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3534], w[3397]);
        mulmod(t2, w[3534], w[3397]);
        mulmod_constant(t2, t2, two);
        submod(w[4283], t1, t2);
    }

    // XOR 3457 1232 -> 4284
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3457], w[1232]);
        mulmod(t2, w[3457], w[1232]);
        mulmod_constant(t2, t2, two);
        submod(w[4284], t1, t2);
    }

    // AND 3181 3199 -> 4285
    mulmod(w[4285], w[3181], w[3199]);

    // AND 3174 1326 -> 4286
    mulmod(w[4286], w[3174], w[1326]);

    // AND 563 2816 -> 4287
    mulmod(w[4287], w[563], w[2816]);

    // XOR 2741 2517 -> 4288
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2741], w[2517]);
        mulmod(t2, w[2741], w[2517]);
        mulmod_constant(t2, t2, two);
        submod(w[4288], t1, t2);
    }

    // XOR 1755 2618 -> 4289
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1755], w[2618]);
        mulmod(t2, w[1755], w[2618]);
        mulmod_constant(t2, t2, two);
        submod(w[4289], t1, t2);
    }

    // XOR 1280 2537 -> 4290
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1280], w[2537]);
        mulmod(t2, w[1280], w[2537]);
        mulmod_constant(t2, t2, two);
        submod(w[4290], t1, t2);
    }

    // XOR 3896 3609 -> 4291
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3896], w[3609]);
        mulmod(t2, w[3896], w[3609]);
        mulmod_constant(t2, t2, two);
        submod(w[4291], t1, t2);
    }

    // INV 3347 -> 4292
    submod(w[4292], one, w[3347]);

    // XOR 3052 1363 -> 4293
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3052], w[1363]);
        mulmod(t2, w[3052], w[1363]);
        mulmod_constant(t2, t2, two);
        submod(w[4293], t1, t2);
    }

    // AND 976 2826 -> 4294
    mulmod(w[4294], w[976], w[2826]);

    // AND 3361 2676 -> 4295
    mulmod(w[4295], w[3361], w[2676]);

    // XOR 333 118 -> 4296
    {
        bn254fr_class t1, t2;
        addmod(t1, w[333], w[118]);
        mulmod(t2, w[333], w[118]);
        mulmod_constant(t2, t2, two);
        submod(w[4296], t1, t2);
    }

    // AND 593 3531 -> 4297
    mulmod(w[4297], w[593], w[3531]);

    // INV 1140 -> 4298
    submod(w[4298], one, w[1140]);

    // AND 3597 1668 -> 4299
    mulmod(w[4299], w[3597], w[1668]);

    // INV 2375 -> 4300
    submod(w[4300], one, w[2375]);

    // XOR 3153 2433 -> 4301
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3153], w[2433]);
        mulmod(t2, w[3153], w[2433]);
        mulmod_constant(t2, t2, two);
        submod(w[4301], t1, t2);
    }

    // XOR 1017 1144 -> 4302
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1017], w[1144]);
        mulmod(t2, w[1017], w[1144]);
        mulmod_constant(t2, t2, two);
        submod(w[4302], t1, t2);
    }

    // XOR 3561 681 -> 4303
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3561], w[681]);
        mulmod(t2, w[3561], w[681]);
        mulmod_constant(t2, t2, two);
        submod(w[4303], t1, t2);
    }

    // AND 3522 1829 -> 4304
    mulmod(w[4304], w[3522], w[1829]);

    // XOR 446 1619 -> 4305
    {
        bn254fr_class t1, t2;
        addmod(t1, w[446], w[1619]);
        mulmod(t2, w[446], w[1619]);
        mulmod_constant(t2, t2, two);
        submod(w[4305], t1, t2);
    }

    // AND 770 2771 -> 4306
    mulmod(w[4306], w[770], w[2771]);

    // INV 3825 -> 4307
    submod(w[4307], one, w[3825]);

    // XOR 2356 2254 -> 4308
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2356], w[2254]);
        mulmod(t2, w[2356], w[2254]);
        mulmod_constant(t2, t2, two);
        submod(w[4308], t1, t2);
    }

    // XOR 101 2732 -> 4309
    {
        bn254fr_class t1, t2;
        addmod(t1, w[101], w[2732]);
        mulmod(t2, w[101], w[2732]);
        mulmod_constant(t2, t2, two);
        submod(w[4309], t1, t2);
    }

    // AND 3186 313 -> 4310
    mulmod(w[4310], w[3186], w[313]);

    // XOR 322 2025 -> 4311
    {
        bn254fr_class t1, t2;
        addmod(t1, w[322], w[2025]);
        mulmod(t2, w[322], w[2025]);
        mulmod_constant(t2, t2, two);
        submod(w[4311], t1, t2);
    }

    // INV 1913 -> 4312
    submod(w[4312], one, w[1913]);

    // AND 2554 83 -> 4313
    mulmod(w[4313], w[2554], w[83]);

    // INV 2444 -> 4314
    submod(w[4314], one, w[2444]);

    // AND 1472 4203 -> 4315
    mulmod(w[4315], w[1472], w[4203]);

    // AND 2745 2075 -> 4316
    mulmod(w[4316], w[2745], w[2075]);

    // XOR 2007 477 -> 4317
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2007], w[477]);
        mulmod(t2, w[2007], w[477]);
        mulmod_constant(t2, t2, two);
        submod(w[4317], t1, t2);
    }

    // AND 3273 1599 -> 4318
    mulmod(w[4318], w[3273], w[1599]);

    // AND 2596 2019 -> 4319
    mulmod(w[4319], w[2596], w[2019]);

    // XOR 807 264 -> 4320
    {
        bn254fr_class t1, t2;
        addmod(t1, w[807], w[264]);
        mulmod(t2, w[807], w[264]);
        mulmod_constant(t2, t2, two);
        submod(w[4320], t1, t2);
    }

    // AND 2521 1800 -> 4321
    mulmod(w[4321], w[2521], w[1800]);

    // XOR 4234 2926 -> 4322
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4234], w[2926]);
        mulmod(t2, w[4234], w[2926]);
        mulmod_constant(t2, t2, two);
        submod(w[4322], t1, t2);
    }

    // AND 3938 767 -> 4323
    mulmod(w[4323], w[3938], w[767]);

    // AND 3789 58 -> 4324
    mulmod(w[4324], w[3789], w[58]);

    // AND 2145 76 -> 4325
    mulmod(w[4325], w[2145], w[76]);

    // AND 3869 3115 -> 4326
    mulmod(w[4326], w[3869], w[3115]);

    // XOR 3452 3386 -> 4327
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3452], w[3386]);
        mulmod(t2, w[3452], w[3386]);
        mulmod_constant(t2, t2, two);
        submod(w[4327], t1, t2);
    }

    // XOR 1857 780 -> 4328
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1857], w[780]);
        mulmod(t2, w[1857], w[780]);
        mulmod_constant(t2, t2, two);
        submod(w[4328], t1, t2);
    }

    // XOR 2879 847 -> 4329
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2879], w[847]);
        mulmod(t2, w[2879], w[847]);
        mulmod_constant(t2, t2, two);
        submod(w[4329], t1, t2);
    }

    // AND 1143 1809 -> 4330
    mulmod(w[4330], w[1143], w[1809]);

    // XOR 3181 2512 -> 4331
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3181], w[2512]);
        mulmod(t2, w[3181], w[2512]);
        mulmod_constant(t2, t2, two);
        submod(w[4331], t1, t2);
    }

    // XOR 315 712 -> 4332
    {
        bn254fr_class t1, t2;
        addmod(t1, w[315], w[712]);
        mulmod(t2, w[315], w[712]);
        mulmod_constant(t2, t2, two);
        submod(w[4332], t1, t2);
    }

    // AND 290 1835 -> 4333
    mulmod(w[4333], w[290], w[1835]);

    // XOR 1673 510 -> 4334
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1673], w[510]);
        mulmod(t2, w[1673], w[510]);
        mulmod_constant(t2, t2, two);
        submod(w[4334], t1, t2);
    }

    // AND 3803 2192 -> 4335
    mulmod(w[4335], w[3803], w[2192]);

    // XOR 1995 2532 -> 4336
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1995], w[2532]);
        mulmod(t2, w[1995], w[2532]);
        mulmod_constant(t2, t2, two);
        submod(w[4336], t1, t2);
    }

    // AND 1517 2839 -> 4337
    mulmod(w[4337], w[1517], w[2839]);

    // XOR 1345 1656 -> 4338
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1345], w[1656]);
        mulmod(t2, w[1345], w[1656]);
        mulmod_constant(t2, t2, two);
        submod(w[4338], t1, t2);
    }

    // XOR 1550 442 -> 4339
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1550], w[442]);
        mulmod(t2, w[1550], w[442]);
        mulmod_constant(t2, t2, two);
        submod(w[4339], t1, t2);
    }

    // XOR 2693 2746 -> 4340
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2693], w[2746]);
        mulmod(t2, w[2693], w[2746]);
        mulmod_constant(t2, t2, two);
        submod(w[4340], t1, t2);
    }

    // XOR 3313 204 -> 4341
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3313], w[204]);
        mulmod(t2, w[3313], w[204]);
        mulmod_constant(t2, t2, two);
        submod(w[4341], t1, t2);
    }

    // XOR 2358 2458 -> 4342
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2358], w[2458]);
        mulmod(t2, w[2358], w[2458]);
        mulmod_constant(t2, t2, two);
        submod(w[4342], t1, t2);
    }

    // XOR 3853 1606 -> 4343
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3853], w[1606]);
        mulmod(t2, w[3853], w[1606]);
        mulmod_constant(t2, t2, two);
        submod(w[4343], t1, t2);
    }

    // XOR 818 908 -> 4344
    {
        bn254fr_class t1, t2;
        addmod(t1, w[818], w[908]);
        mulmod(t2, w[818], w[908]);
        mulmod_constant(t2, t2, two);
        submod(w[4344], t1, t2);
    }

    // AND 3128 3278 -> 4345
    mulmod(w[4345], w[3128], w[3278]);

    // XOR 2212 224 -> 4346
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2212], w[224]);
        mulmod(t2, w[2212], w[224]);
        mulmod_constant(t2, t2, two);
        submod(w[4346], t1, t2);
    }

    // XOR 1212 1657 -> 4347
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1212], w[1657]);
        mulmod(t2, w[1212], w[1657]);
        mulmod_constant(t2, t2, two);
        submod(w[4347], t1, t2);
    }

    // AND 2107 804 -> 4348
    mulmod(w[4348], w[2107], w[804]);

    // AND 1364 2727 -> 4349
    mulmod(w[4349], w[1364], w[2727]);

    // XOR 128 364 -> 4350
    {
        bn254fr_class t1, t2;
        addmod(t1, w[128], w[364]);
        mulmod(t2, w[128], w[364]);
        mulmod_constant(t2, t2, two);
        submod(w[4350], t1, t2);
    }

    // XOR 2158 497 -> 4351
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2158], w[497]);
        mulmod(t2, w[2158], w[497]);
        mulmod_constant(t2, t2, two);
        submod(w[4351], t1, t2);
    }

    // XOR 2654 1825 -> 4352
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2654], w[1825]);
        mulmod(t2, w[2654], w[1825]);
        mulmod_constant(t2, t2, two);
        submod(w[4352], t1, t2);
    }

    // AND 104 2747 -> 4353
    mulmod(w[4353], w[104], w[2747]);

    // XOR 2501 2649 -> 4354
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2501], w[2649]);
        mulmod(t2, w[2501], w[2649]);
        mulmod_constant(t2, t2, two);
        submod(w[4354], t1, t2);
    }

    // XOR 3641 1239 -> 4355
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3641], w[1239]);
        mulmod(t2, w[3641], w[1239]);
        mulmod_constant(t2, t2, two);
        submod(w[4355], t1, t2);
    }

    // XOR 1145 2323 -> 4356
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1145], w[2323]);
        mulmod(t2, w[1145], w[2323]);
        mulmod_constant(t2, t2, two);
        submod(w[4356], t1, t2);
    }

    // AND 3041 603 -> 4357
    mulmod(w[4357], w[3041], w[603]);

    // AND 3457 1466 -> 4358
    mulmod(w[4358], w[3457], w[1466]);

    // AND 3020 998 -> 4359
    mulmod(w[4359], w[3020], w[998]);

    // AND 2039 3280 -> 4360
    mulmod(w[4360], w[2039], w[3280]);

    // XOR 3726 2343 -> 4361
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3726], w[2343]);
        mulmod(t2, w[3726], w[2343]);
        mulmod_constant(t2, t2, two);
        submod(w[4361], t1, t2);
    }

    // AND 3151 2185 -> 4362
    mulmod(w[4362], w[3151], w[2185]);

    // XOR 3471 1446 -> 4363
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3471], w[1446]);
        mulmod(t2, w[3471], w[1446]);
        mulmod_constant(t2, t2, two);
        submod(w[4363], t1, t2);
    }

    // AND 1472 2579 -> 4364
    mulmod(w[4364], w[1472], w[2579]);

    // XOR 1000 2076 -> 4365
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1000], w[2076]);
        mulmod(t2, w[1000], w[2076]);
        mulmod_constant(t2, t2, two);
        submod(w[4365], t1, t2);
    }

    // XOR 3038 1088 -> 4366
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3038], w[1088]);
        mulmod(t2, w[3038], w[1088]);
        mulmod_constant(t2, t2, two);
        submod(w[4366], t1, t2);
    }

    // XOR 2292 2325 -> 4367
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2292], w[2325]);
        mulmod(t2, w[2292], w[2325]);
        mulmod_constant(t2, t2, two);
        submod(w[4367], t1, t2);
    }

    // XOR 1747 1141 -> 4368
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1747], w[1141]);
        mulmod(t2, w[1747], w[1141]);
        mulmod_constant(t2, t2, two);
        submod(w[4368], t1, t2);
    }

    // XOR 4297 4344 -> 4369
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4297], w[4344]);
        mulmod(t2, w[4297], w[4344]);
        mulmod_constant(t2, t2, two);
        submod(w[4369], t1, t2);
    }

    // AND 4036 3432 -> 4370
    mulmod(w[4370], w[4036], w[3432]);

    // XOR 1107 2989 -> 4371
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1107], w[2989]);
        mulmod(t2, w[1107], w[2989]);
        mulmod_constant(t2, t2, two);
        submod(w[4371], t1, t2);
    }

    // AND 3130 2660 -> 4372
    mulmod(w[4372], w[3130], w[2660]);

    // INV 4010 -> 4373
    submod(w[4373], one, w[4010]);

    // XOR 2263 3732 -> 4374
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2263], w[3732]);
        mulmod(t2, w[2263], w[3732]);
        mulmod_constant(t2, t2, two);
        submod(w[4374], t1, t2);
    }

    // AND 894 4117 -> 4375
    mulmod(w[4375], w[894], w[4117]);

    // XOR 3584 3144 -> 4376
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3584], w[3144]);
        mulmod(t2, w[3584], w[3144]);
        mulmod_constant(t2, t2, two);
        submod(w[4376], t1, t2);
    }

    // XOR 3808 1627 -> 4377
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3808], w[1627]);
        mulmod(t2, w[3808], w[1627]);
        mulmod_constant(t2, t2, two);
        submod(w[4377], t1, t2);
    }

    // AND 714 1614 -> 4378
    mulmod(w[4378], w[714], w[1614]);

    // AND 505 3846 -> 4379
    mulmod(w[4379], w[505], w[3846]);

    // XOR 4187 193 -> 4380
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4187], w[193]);
        mulmod(t2, w[4187], w[193]);
        mulmod_constant(t2, t2, two);
        submod(w[4380], t1, t2);
    }

    // AND 1034 3265 -> 4381
    mulmod(w[4381], w[1034], w[3265]);

    // XOR 2333 1644 -> 4382
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2333], w[1644]);
        mulmod(t2, w[2333], w[1644]);
        mulmod_constant(t2, t2, two);
        submod(w[4382], t1, t2);
    }

    // XOR 54 2156 -> 4383
    {
        bn254fr_class t1, t2;
        addmod(t1, w[54], w[2156]);
        mulmod(t2, w[54], w[2156]);
        mulmod_constant(t2, t2, two);
        submod(w[4383], t1, t2);
    }

    // XOR 830 3274 -> 4384
    {
        bn254fr_class t1, t2;
        addmod(t1, w[830], w[3274]);
        mulmod(t2, w[830], w[3274]);
        mulmod_constant(t2, t2, two);
        submod(w[4384], t1, t2);
    }

    // XOR 1167 2541 -> 4385
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1167], w[2541]);
        mulmod(t2, w[1167], w[2541]);
        mulmod_constant(t2, t2, two);
        submod(w[4385], t1, t2);
    }

    // XOR 283 4155 -> 4386
    {
        bn254fr_class t1, t2;
        addmod(t1, w[283], w[4155]);
        mulmod(t2, w[283], w[4155]);
        mulmod_constant(t2, t2, two);
        submod(w[4386], t1, t2);
    }

    // AND 4082 3456 -> 4387
    mulmod(w[4387], w[4082], w[3456]);

    // AND 2814 3168 -> 4388
    mulmod(w[4388], w[2814], w[3168]);

    // INV 2649 -> 4389
    submod(w[4389], one, w[2649]);

    // XOR 3685 2302 -> 4390
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3685], w[2302]);
        mulmod(t2, w[3685], w[2302]);
        mulmod_constant(t2, t2, two);
        submod(w[4390], t1, t2);
    }

    // INV 892 -> 4391
    submod(w[4391], one, w[892]);

    // INV 762 -> 4392
    submod(w[4392], one, w[762]);

    // INV 512 -> 4393
    submod(w[4393], one, w[512]);

    // AND 722 1548 -> 4394
    mulmod(w[4394], w[722], w[1548]);

    // XOR 2250 1358 -> 4395
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2250], w[1358]);
        mulmod(t2, w[2250], w[1358]);
        mulmod_constant(t2, t2, two);
        submod(w[4395], t1, t2);
    }

    // INV 0 -> 4396
    submod(w[4396], one, w[0]);

    // INV 1502 -> 4397
    submod(w[4397], one, w[1502]);

    // XOR 4336 4273 -> 4398
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4336], w[4273]);
        mulmod(t2, w[4336], w[4273]);
        mulmod_constant(t2, t2, two);
        submod(w[4398], t1, t2);
    }

    // AND 165 1695 -> 4399
    mulmod(w[4399], w[165], w[1695]);

    // XOR 3263 692 -> 4400
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3263], w[692]);
        mulmod(t2, w[3263], w[692]);
        mulmod_constant(t2, t2, two);
        submod(w[4400], t1, t2);
    }

    // XOR 81 4001 -> 4401
    {
        bn254fr_class t1, t2;
        addmod(t1, w[81], w[4001]);
        mulmod(t2, w[81], w[4001]);
        mulmod_constant(t2, t2, two);
        submod(w[4401], t1, t2);
    }

    // AND 3298 414 -> 4402
    mulmod(w[4402], w[3298], w[414]);

    // AND 3680 2572 -> 4403
    mulmod(w[4403], w[3680], w[2572]);

    // AND 2549 3891 -> 4404
    mulmod(w[4404], w[2549], w[3891]);

    // INV 3230 -> 4405
    submod(w[4405], one, w[3230]);

    // AND 3863 2628 -> 4406
    mulmod(w[4406], w[3863], w[2628]);

    // XOR 1832 3522 -> 4407
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1832], w[3522]);
        mulmod(t2, w[1832], w[3522]);
        mulmod_constant(t2, t2, two);
        submod(w[4407], t1, t2);
    }

    // AND 1998 324 -> 4408
    mulmod(w[4408], w[1998], w[324]);

    // INV 4228 -> 4409
    submod(w[4409], one, w[4228]);

    // AND 682 61 -> 4410
    mulmod(w[4410], w[682], w[61]);

    // XOR 3892 3562 -> 4411
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3892], w[3562]);
        mulmod(t2, w[3892], w[3562]);
        mulmod_constant(t2, t2, two);
        submod(w[4411], t1, t2);
    }

    // AND 144 2921 -> 4412
    mulmod(w[4412], w[144], w[2921]);

    // XOR 3304 1482 -> 4413
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3304], w[1482]);
        mulmod(t2, w[3304], w[1482]);
        mulmod_constant(t2, t2, two);
        submod(w[4413], t1, t2);
    }

    // AND 232 4250 -> 4414
    mulmod(w[4414], w[232], w[4250]);

    // AND 2861 3353 -> 4415
    mulmod(w[4415], w[2861], w[3353]);

    // XOR 47 2797 -> 4416
    {
        bn254fr_class t1, t2;
        addmod(t1, w[47], w[2797]);
        mulmod(t2, w[47], w[2797]);
        mulmod_constant(t2, t2, two);
        submod(w[4416], t1, t2);
    }

    // AND 4248 3859 -> 4417
    mulmod(w[4417], w[4248], w[3859]);

    // AND 3413 248 -> 4418
    mulmod(w[4418], w[3413], w[248]);

    // AND 2139 1701 -> 4419
    mulmod(w[4419], w[2139], w[1701]);

    // XOR 1813 4119 -> 4420
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1813], w[4119]);
        mulmod(t2, w[1813], w[4119]);
        mulmod_constant(t2, t2, two);
        submod(w[4420], t1, t2);
    }

    // AND 2047 351 -> 4421
    mulmod(w[4421], w[2047], w[351]);

    // INV 3939 -> 4422
    submod(w[4422], one, w[3939]);

    // XOR 4061 2718 -> 4423
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4061], w[2718]);
        mulmod(t2, w[4061], w[2718]);
        mulmod_constant(t2, t2, two);
        submod(w[4423], t1, t2);
    }

    // XOR 1339 2705 -> 4424
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1339], w[2705]);
        mulmod(t2, w[1339], w[2705]);
        mulmod_constant(t2, t2, two);
        submod(w[4424], t1, t2);
    }

    // XOR 4305 4284 -> 4425
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4305], w[4284]);
        mulmod(t2, w[4305], w[4284]);
        mulmod_constant(t2, t2, two);
        submod(w[4425], t1, t2);
    }

    // AND 3915 4060 -> 4426
    mulmod(w[4426], w[3915], w[4060]);

    // AND 3965 1236 -> 4427
    mulmod(w[4427], w[3965], w[1236]);

    // XOR 2323 2707 -> 4428
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2323], w[2707]);
        mulmod(t2, w[2323], w[2707]);
        mulmod_constant(t2, t2, two);
        submod(w[4428], t1, t2);
    }

    // XOR 2184 3950 -> 4429
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2184], w[3950]);
        mulmod(t2, w[2184], w[3950]);
        mulmod_constant(t2, t2, two);
        submod(w[4429], t1, t2);
    }

    // AND 339 81 -> 4430
    mulmod(w[4430], w[339], w[81]);

    // XOR 3024 2149 -> 4431
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3024], w[2149]);
        mulmod(t2, w[3024], w[2149]);
        mulmod_constant(t2, t2, two);
        submod(w[4431], t1, t2);
    }

    // XOR 3124 1141 -> 4432
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3124], w[1141]);
        mulmod(t2, w[3124], w[1141]);
        mulmod_constant(t2, t2, two);
        submod(w[4432], t1, t2);
    }

    // AND 3750 1633 -> 4433
    mulmod(w[4433], w[3750], w[1633]);

    // XOR 4261 1259 -> 4434
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4261], w[1259]);
        mulmod(t2, w[4261], w[1259]);
        mulmod_constant(t2, t2, two);
        submod(w[4434], t1, t2);
    }

    // XOR 3805 614 -> 4435
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3805], w[614]);
        mulmod(t2, w[3805], w[614]);
        mulmod_constant(t2, t2, two);
        submod(w[4435], t1, t2);
    }

    // XOR 3604 2353 -> 4436
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3604], w[2353]);
        mulmod(t2, w[3604], w[2353]);
        mulmod_constant(t2, t2, two);
        submod(w[4436], t1, t2);
    }

    // XOR 16 4008 -> 4437
    {
        bn254fr_class t1, t2;
        addmod(t1, w[16], w[4008]);
        mulmod(t2, w[16], w[4008]);
        mulmod_constant(t2, t2, two);
        submod(w[4437], t1, t2);
    }

    // XOR 1594 1718 -> 4438
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1594], w[1718]);
        mulmod(t2, w[1594], w[1718]);
        mulmod_constant(t2, t2, two);
        submod(w[4438], t1, t2);
    }

    // AND 811 2016 -> 4439
    mulmod(w[4439], w[811], w[2016]);

    // XOR 3746 730 -> 4440
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3746], w[730]);
        mulmod(t2, w[3746], w[730]);
        mulmod_constant(t2, t2, two);
        submod(w[4440], t1, t2);
    }

    // AND 502 1465 -> 4441
    mulmod(w[4441], w[502], w[1465]);

    // XOR 1988 2277 -> 4442
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1988], w[2277]);
        mulmod(t2, w[1988], w[2277]);
        mulmod_constant(t2, t2, two);
        submod(w[4442], t1, t2);
    }

    // XOR 3693 3824 -> 4443
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3693], w[3824]);
        mulmod(t2, w[3693], w[3824]);
        mulmod_constant(t2, t2, two);
        submod(w[4443], t1, t2);
    }

    // XOR 3726 1777 -> 4444
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3726], w[1777]);
        mulmod(t2, w[3726], w[1777]);
        mulmod_constant(t2, t2, two);
        submod(w[4444], t1, t2);
    }

    // XOR 475 23 -> 4445
    {
        bn254fr_class t1, t2;
        addmod(t1, w[475], w[23]);
        mulmod(t2, w[475], w[23]);
        mulmod_constant(t2, t2, two);
        submod(w[4445], t1, t2);
    }

    // INV 2842 -> 4446
    submod(w[4446], one, w[2842]);

    // XOR 2654 3144 -> 4447
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2654], w[3144]);
        mulmod(t2, w[2654], w[3144]);
        mulmod_constant(t2, t2, two);
        submod(w[4447], t1, t2);
    }

    // XOR 3177 2395 -> 4448
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3177], w[2395]);
        mulmod(t2, w[3177], w[2395]);
        mulmod_constant(t2, t2, two);
        submod(w[4448], t1, t2);
    }

    // AND 2546 3623 -> 4449
    mulmod(w[4449], w[2546], w[3623]);

    // XOR 1216 2947 -> 4450
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1216], w[2947]);
        mulmod(t2, w[1216], w[2947]);
        mulmod_constant(t2, t2, two);
        submod(w[4450], t1, t2);
    }

    // XOR 4091 1312 -> 4451
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4091], w[1312]);
        mulmod(t2, w[4091], w[1312]);
        mulmod_constant(t2, t2, two);
        submod(w[4451], t1, t2);
    }

    // XOR 1873 469 -> 4452
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1873], w[469]);
        mulmod(t2, w[1873], w[469]);
        mulmod_constant(t2, t2, two);
        submod(w[4452], t1, t2);
    }

    // XOR 3016 1943 -> 4453
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3016], w[1943]);
        mulmod(t2, w[3016], w[1943]);
        mulmod_constant(t2, t2, two);
        submod(w[4453], t1, t2);
    }

    // INV 1706 -> 4454
    submod(w[4454], one, w[1706]);

    // XOR 1423 4298 -> 4455
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1423], w[4298]);
        mulmod(t2, w[1423], w[4298]);
        mulmod_constant(t2, t2, two);
        submod(w[4455], t1, t2);
    }

    // XOR 3409 2836 -> 4456
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3409], w[2836]);
        mulmod(t2, w[3409], w[2836]);
        mulmod_constant(t2, t2, two);
        submod(w[4456], t1, t2);
    }

    // XOR 2550 839 -> 4457
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2550], w[839]);
        mulmod(t2, w[2550], w[839]);
        mulmod_constant(t2, t2, two);
        submod(w[4457], t1, t2);
    }

    // XOR 459 3526 -> 4458
    {
        bn254fr_class t1, t2;
        addmod(t1, w[459], w[3526]);
        mulmod(t2, w[459], w[3526]);
        mulmod_constant(t2, t2, two);
        submod(w[4458], t1, t2);
    }

    // INV 3390 -> 4459
    submod(w[4459], one, w[3390]);

    // XOR 405 2597 -> 4460
    {
        bn254fr_class t1, t2;
        addmod(t1, w[405], w[2597]);
        mulmod(t2, w[405], w[2597]);
        mulmod_constant(t2, t2, two);
        submod(w[4460], t1, t2);
    }

    // AND 4038 1145 -> 4461
    mulmod(w[4461], w[4038], w[1145]);

    // XOR 281 669 -> 4462
    {
        bn254fr_class t1, t2;
        addmod(t1, w[281], w[669]);
        mulmod(t2, w[281], w[669]);
        mulmod_constant(t2, t2, two);
        submod(w[4462], t1, t2);
    }

    // XOR 2294 172 -> 4463
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2294], w[172]);
        mulmod(t2, w[2294], w[172]);
        mulmod_constant(t2, t2, two);
        submod(w[4463], t1, t2);
    }

    // AND 1712 1004 -> 4464
    mulmod(w[4464], w[1712], w[1004]);

    // XOR 4016 2322 -> 4465
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4016], w[2322]);
        mulmod(t2, w[4016], w[2322]);
        mulmod_constant(t2, t2, two);
        submod(w[4465], t1, t2);
    }

    // XOR 3480 4281 -> 4466
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3480], w[4281]);
        mulmod(t2, w[3480], w[4281]);
        mulmod_constant(t2, t2, two);
        submod(w[4466], t1, t2);
    }

    // XOR 1700 2196 -> 4467
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1700], w[2196]);
        mulmod(t2, w[1700], w[2196]);
        mulmod_constant(t2, t2, two);
        submod(w[4467], t1, t2);
    }

    // INV 1149 -> 4468
    submod(w[4468], one, w[1149]);

    // AND 1132 3729 -> 4469
    mulmod(w[4469], w[1132], w[3729]);

    // AND 2213 885 -> 4470
    mulmod(w[4470], w[2213], w[885]);

    // AND 2289 2848 -> 4471
    mulmod(w[4471], w[2289], w[2848]);

    // XOR 3396 2527 -> 4472
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3396], w[2527]);
        mulmod(t2, w[3396], w[2527]);
        mulmod_constant(t2, t2, two);
        submod(w[4472], t1, t2);
    }

    // INV 3844 -> 4473
    submod(w[4473], one, w[3844]);

    // AND 746 610 -> 4474
    mulmod(w[4474], w[746], w[610]);

    // XOR 1846 1933 -> 4475
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1846], w[1933]);
        mulmod(t2, w[1846], w[1933]);
        mulmod_constant(t2, t2, two);
        submod(w[4475], t1, t2);
    }

    // XOR 3853 2210 -> 4476
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3853], w[2210]);
        mulmod(t2, w[3853], w[2210]);
        mulmod_constant(t2, t2, two);
        submod(w[4476], t1, t2);
    }

    // AND 3103 2125 -> 4477
    mulmod(w[4477], w[3103], w[2125]);

    // INV 412 -> 4478
    submod(w[4478], one, w[412]);

    // XOR 2698 2124 -> 4479
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2698], w[2124]);
        mulmod(t2, w[2698], w[2124]);
        mulmod_constant(t2, t2, two);
        submod(w[4479], t1, t2);
    }

    // AND 2419 2135 -> 4480
    mulmod(w[4480], w[2419], w[2135]);

    // XOR 637 3937 -> 4481
    {
        bn254fr_class t1, t2;
        addmod(t1, w[637], w[3937]);
        mulmod(t2, w[637], w[3937]);
        mulmod_constant(t2, t2, two);
        submod(w[4481], t1, t2);
    }

    // XOR 2348 4369 -> 4482
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2348], w[4369]);
        mulmod(t2, w[2348], w[4369]);
        mulmod_constant(t2, t2, two);
        submod(w[4482], t1, t2);
    }

    // AND 105 2188 -> 4483
    mulmod(w[4483], w[105], w[2188]);

    // AND 2442 2505 -> 4484
    mulmod(w[4484], w[2442], w[2505]);

    // XOR 290 4169 -> 4485
    {
        bn254fr_class t1, t2;
        addmod(t1, w[290], w[4169]);
        mulmod(t2, w[290], w[4169]);
        mulmod_constant(t2, t2, two);
        submod(w[4485], t1, t2);
    }

    // XOR 3977 4461 -> 4486
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3977], w[4461]);
        mulmod(t2, w[3977], w[4461]);
        mulmod_constant(t2, t2, two);
        submod(w[4486], t1, t2);
    }

    // XOR 4251 3741 -> 4487
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4251], w[3741]);
        mulmod(t2, w[4251], w[3741]);
        mulmod_constant(t2, t2, two);
        submod(w[4487], t1, t2);
    }

    // XOR 250 3748 -> 4488
    {
        bn254fr_class t1, t2;
        addmod(t1, w[250], w[3748]);
        mulmod(t2, w[250], w[3748]);
        mulmod_constant(t2, t2, two);
        submod(w[4488], t1, t2);
    }

    // INV 4108 -> 4489
    submod(w[4489], one, w[4108]);

    // AND 2554 4046 -> 4490
    mulmod(w[4490], w[2554], w[4046]);

    // XOR 4188 2384 -> 4491
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4188], w[2384]);
        mulmod(t2, w[4188], w[2384]);
        mulmod_constant(t2, t2, two);
        submod(w[4491], t1, t2);
    }

    // XOR 1577 3929 -> 4492
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1577], w[3929]);
        mulmod(t2, w[1577], w[3929]);
        mulmod_constant(t2, t2, two);
        submod(w[4492], t1, t2);
    }

    // INV 2156 -> 4493
    submod(w[4493], one, w[2156]);

    // XOR 1526 1087 -> 4494
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1526], w[1087]);
        mulmod(t2, w[1526], w[1087]);
        mulmod_constant(t2, t2, two);
        submod(w[4494], t1, t2);
    }

    // INV 3673 -> 4495
    submod(w[4495], one, w[3673]);

    // XOR 4130 1584 -> 4496
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4130], w[1584]);
        mulmod(t2, w[4130], w[1584]);
        mulmod_constant(t2, t2, two);
        submod(w[4496], t1, t2);
    }

    // XOR 684 3100 -> 4497
    {
        bn254fr_class t1, t2;
        addmod(t1, w[684], w[3100]);
        mulmod(t2, w[684], w[3100]);
        mulmod_constant(t2, t2, two);
        submod(w[4497], t1, t2);
    }

    // XOR 2911 178 -> 4498
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2911], w[178]);
        mulmod(t2, w[2911], w[178]);
        mulmod_constant(t2, t2, two);
        submod(w[4498], t1, t2);
    }

    // XOR 4037 1802 -> 4499
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4037], w[1802]);
        mulmod(t2, w[4037], w[1802]);
        mulmod_constant(t2, t2, two);
        submod(w[4499], t1, t2);
    }

    // XOR 1604 507 -> 4500
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1604], w[507]);
        mulmod(t2, w[1604], w[507]);
        mulmod_constant(t2, t2, two);
        submod(w[4500], t1, t2);
    }

    // XOR 677 1088 -> 4501
    {
        bn254fr_class t1, t2;
        addmod(t1, w[677], w[1088]);
        mulmod(t2, w[677], w[1088]);
        mulmod_constant(t2, t2, two);
        submod(w[4501], t1, t2);
    }

    // XOR 2612 4176 -> 4502
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2612], w[4176]);
        mulmod(t2, w[2612], w[4176]);
        mulmod_constant(t2, t2, two);
        submod(w[4502], t1, t2);
    }

    // AND 1350 1359 -> 4503
    mulmod(w[4503], w[1350], w[1359]);

    // AND 4125 69 -> 4504
    mulmod(w[4504], w[4125], w[69]);

    // XOR 1630 938 -> 4505
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1630], w[938]);
        mulmod(t2, w[1630], w[938]);
        mulmod_constant(t2, t2, two);
        submod(w[4505], t1, t2);
    }

    // XOR 474 1404 -> 4506
    {
        bn254fr_class t1, t2;
        addmod(t1, w[474], w[1404]);
        mulmod(t2, w[474], w[1404]);
        mulmod_constant(t2, t2, two);
        submod(w[4506], t1, t2);
    }

    // XOR 2430 1389 -> 4507
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2430], w[1389]);
        mulmod(t2, w[2430], w[1389]);
        mulmod_constant(t2, t2, two);
        submod(w[4507], t1, t2);
    }

    // XOR 2357 110 -> 4508
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2357], w[110]);
        mulmod(t2, w[2357], w[110]);
        mulmod_constant(t2, t2, two);
        submod(w[4508], t1, t2);
    }

    // XOR 421 402 -> 4509
    {
        bn254fr_class t1, t2;
        addmod(t1, w[421], w[402]);
        mulmod(t2, w[421], w[402]);
        mulmod_constant(t2, t2, two);
        submod(w[4509], t1, t2);
    }

    // AND 2429 1681 -> 4510
    mulmod(w[4510], w[2429], w[1681]);

    // XOR 576 640 -> 4511
    {
        bn254fr_class t1, t2;
        addmod(t1, w[576], w[640]);
        mulmod(t2, w[576], w[640]);
        mulmod_constant(t2, t2, two);
        submod(w[4511], t1, t2);
    }

    // INV 1146 -> 4512
    submod(w[4512], one, w[1146]);

    // AND 1147 3023 -> 4513
    mulmod(w[4513], w[1147], w[3023]);

    // XOR 402 2674 -> 4514
    {
        bn254fr_class t1, t2;
        addmod(t1, w[402], w[2674]);
        mulmod(t2, w[402], w[2674]);
        mulmod_constant(t2, t2, two);
        submod(w[4514], t1, t2);
    }

    // AND 4206 3071 -> 4515
    mulmod(w[4515], w[4206], w[3071]);

    // AND 3257 2480 -> 4516
    mulmod(w[4516], w[3257], w[2480]);

    // XOR 2018 4216 -> 4517
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2018], w[4216]);
        mulmod(t2, w[2018], w[4216]);
        mulmod_constant(t2, t2, two);
        submod(w[4517], t1, t2);
    }

    // AND 2138 1535 -> 4518
    mulmod(w[4518], w[2138], w[1535]);

    // AND 3829 1044 -> 4519
    mulmod(w[4519], w[3829], w[1044]);

    // AND 3092 626 -> 4520
    mulmod(w[4520], w[3092], w[626]);

    // XOR 3028 2718 -> 4521
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3028], w[2718]);
        mulmod(t2, w[3028], w[2718]);
        mulmod_constant(t2, t2, two);
        submod(w[4521], t1, t2);
    }

    // XOR 2938 2934 -> 4522
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2938], w[2934]);
        mulmod(t2, w[2938], w[2934]);
        mulmod_constant(t2, t2, two);
        submod(w[4522], t1, t2);
    }

    // INV 2105 -> 4523
    submod(w[4523], one, w[2105]);

    // XOR 2626 3973 -> 4524
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2626], w[3973]);
        mulmod(t2, w[2626], w[3973]);
        mulmod_constant(t2, t2, two);
        submod(w[4524], t1, t2);
    }

    // AND 3578 142 -> 4525
    mulmod(w[4525], w[3578], w[142]);

    // XOR 4093 1108 -> 4526
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4093], w[1108]);
        mulmod(t2, w[4093], w[1108]);
        mulmod_constant(t2, t2, two);
        submod(w[4526], t1, t2);
    }

    // XOR 1274 4220 -> 4527
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1274], w[4220]);
        mulmod(t2, w[1274], w[4220]);
        mulmod_constant(t2, t2, two);
        submod(w[4527], t1, t2);
    }

    // INV 2662 -> 4528
    submod(w[4528], one, w[2662]);

    // AND 3207 1764 -> 4529
    mulmod(w[4529], w[3207], w[1764]);

    // XOR 2978 623 -> 4530
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2978], w[623]);
        mulmod(t2, w[2978], w[623]);
        mulmod_constant(t2, t2, two);
        submod(w[4530], t1, t2);
    }

    // AND 3162 3773 -> 4531
    mulmod(w[4531], w[3162], w[3773]);

    // XOR 3450 3339 -> 4532
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3450], w[3339]);
        mulmod(t2, w[3450], w[3339]);
        mulmod_constant(t2, t2, two);
        submod(w[4532], t1, t2);
    }

    // AND 1088 4282 -> 4533
    mulmod(w[4533], w[1088], w[4282]);

    // XOR 2415 1731 -> 4534
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2415], w[1731]);
        mulmod(t2, w[2415], w[1731]);
        mulmod_constant(t2, t2, two);
        submod(w[4534], t1, t2);
    }

    // AND 435 3939 -> 4535
    mulmod(w[4535], w[435], w[3939]);

    // XOR 1667 3991 -> 4536
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1667], w[3991]);
        mulmod(t2, w[1667], w[3991]);
        mulmod_constant(t2, t2, two);
        submod(w[4536], t1, t2);
    }

    // XOR 4361 691 -> 4537
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4361], w[691]);
        mulmod(t2, w[4361], w[691]);
        mulmod_constant(t2, t2, two);
        submod(w[4537], t1, t2);
    }

    // INV 4051 -> 4538
    submod(w[4538], one, w[4051]);

    // AND 149 2409 -> 4539
    mulmod(w[4539], w[149], w[2409]);

    // XOR 1963 971 -> 4540
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1963], w[971]);
        mulmod(t2, w[1963], w[971]);
        mulmod_constant(t2, t2, two);
        submod(w[4540], t1, t2);
    }

    // XOR 1952 4052 -> 4541
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1952], w[4052]);
        mulmod(t2, w[1952], w[4052]);
        mulmod_constant(t2, t2, two);
        submod(w[4541], t1, t2);
    }

    // XOR 3028 2584 -> 4542
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3028], w[2584]);
        mulmod(t2, w[3028], w[2584]);
        mulmod_constant(t2, t2, two);
        submod(w[4542], t1, t2);
    }

    // AND 658 3721 -> 4543
    mulmod(w[4543], w[658], w[3721]);

    // AND 2335 1859 -> 4544
    mulmod(w[4544], w[2335], w[1859]);

    // XOR 2362 4143 -> 4545
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2362], w[4143]);
        mulmod(t2, w[2362], w[4143]);
        mulmod_constant(t2, t2, two);
        submod(w[4545], t1, t2);
    }

    // XOR 932 3386 -> 4546
    {
        bn254fr_class t1, t2;
        addmod(t1, w[932], w[3386]);
        mulmod(t2, w[932], w[3386]);
        mulmod_constant(t2, t2, two);
        submod(w[4546], t1, t2);
    }

    // AND 2883 4301 -> 4547
    mulmod(w[4547], w[2883], w[4301]);

    // XOR 2409 4004 -> 4548
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2409], w[4004]);
        mulmod(t2, w[2409], w[4004]);
        mulmod_constant(t2, t2, two);
        submod(w[4548], t1, t2);
    }

    // AND 2059 3955 -> 4549
    mulmod(w[4549], w[2059], w[3955]);

    // XOR 4396 213 -> 4550
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4396], w[213]);
        mulmod(t2, w[4396], w[213]);
        mulmod_constant(t2, t2, two);
        submod(w[4550], t1, t2);
    }

    // XOR 1138 438 -> 4551
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1138], w[438]);
        mulmod(t2, w[1138], w[438]);
        mulmod_constant(t2, t2, two);
        submod(w[4551], t1, t2);
    }

    // AND 3196 1480 -> 4552
    mulmod(w[4552], w[3196], w[1480]);

    // XOR 2908 560 -> 4553
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2908], w[560]);
        mulmod(t2, w[2908], w[560]);
        mulmod_constant(t2, t2, two);
        submod(w[4553], t1, t2);
    }

    // INV 2743 -> 4554
    submod(w[4554], one, w[2743]);

    // XOR 3794 3275 -> 4555
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3794], w[3275]);
        mulmod(t2, w[3794], w[3275]);
        mulmod_constant(t2, t2, two);
        submod(w[4555], t1, t2);
    }

    // AND 2645 147 -> 4556
    mulmod(w[4556], w[2645], w[147]);

    // AND 2606 217 -> 4557
    mulmod(w[4557], w[2606], w[217]);

    // XOR 2353 816 -> 4558
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2353], w[816]);
        mulmod(t2, w[2353], w[816]);
        mulmod_constant(t2, t2, two);
        submod(w[4558], t1, t2);
    }

    // AND 2099 1122 -> 4559
    mulmod(w[4559], w[2099], w[1122]);

    // INV 1748 -> 4560
    submod(w[4560], one, w[1748]);

    // AND 135 4024 -> 4561
    mulmod(w[4561], w[135], w[4024]);

    // XOR 428 1212 -> 4562
    {
        bn254fr_class t1, t2;
        addmod(t1, w[428], w[1212]);
        mulmod(t2, w[428], w[1212]);
        mulmod_constant(t2, t2, two);
        submod(w[4562], t1, t2);
    }

    // AND 4120 2931 -> 4563
    mulmod(w[4563], w[4120], w[2931]);

    // XOR 1424 1146 -> 4564
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1424], w[1146]);
        mulmod(t2, w[1424], w[1146]);
        mulmod_constant(t2, t2, two);
        submod(w[4564], t1, t2);
    }

    // XOR 67 4236 -> 4565
    {
        bn254fr_class t1, t2;
        addmod(t1, w[67], w[4236]);
        mulmod(t2, w[67], w[4236]);
        mulmod_constant(t2, t2, two);
        submod(w[4565], t1, t2);
    }

    // AND 2245 1437 -> 4566
    mulmod(w[4566], w[2245], w[1437]);

    // AND 1489 845 -> 4567
    mulmod(w[4567], w[1489], w[845]);

    // XOR 690 2683 -> 4568
    {
        bn254fr_class t1, t2;
        addmod(t1, w[690], w[2683]);
        mulmod(t2, w[690], w[2683]);
        mulmod_constant(t2, t2, two);
        submod(w[4568], t1, t2);
    }

    // XOR 1617 3546 -> 4569
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1617], w[3546]);
        mulmod(t2, w[1617], w[3546]);
        mulmod_constant(t2, t2, two);
        submod(w[4569], t1, t2);
    }

    // XOR 186 3527 -> 4570
    {
        bn254fr_class t1, t2;
        addmod(t1, w[186], w[3527]);
        mulmod(t2, w[186], w[3527]);
        mulmod_constant(t2, t2, two);
        submod(w[4570], t1, t2);
    }

    // XOR 2393 1583 -> 4571
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2393], w[1583]);
        mulmod(t2, w[2393], w[1583]);
        mulmod_constant(t2, t2, two);
        submod(w[4571], t1, t2);
    }

    // XOR 3531 2074 -> 4572
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3531], w[2074]);
        mulmod(t2, w[3531], w[2074]);
        mulmod_constant(t2, t2, two);
        submod(w[4572], t1, t2);
    }

    // XOR 2146 1159 -> 4573
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2146], w[1159]);
        mulmod(t2, w[2146], w[1159]);
        mulmod_constant(t2, t2, two);
        submod(w[4573], t1, t2);
    }

    // XOR 3116 1225 -> 4574
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3116], w[1225]);
        mulmod(t2, w[3116], w[1225]);
        mulmod_constant(t2, t2, two);
        submod(w[4574], t1, t2);
    }

    // XOR 2088 4283 -> 4575
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2088], w[4283]);
        mulmod(t2, w[2088], w[4283]);
        mulmod_constant(t2, t2, two);
        submod(w[4575], t1, t2);
    }

    // AND 823 3329 -> 4576
    mulmod(w[4576], w[823], w[3329]);

    // XOR 1272 4298 -> 4577
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1272], w[4298]);
        mulmod(t2, w[1272], w[4298]);
        mulmod_constant(t2, t2, two);
        submod(w[4577], t1, t2);
    }

    // INV 4358 -> 4578
    submod(w[4578], one, w[4358]);

    // XOR 3400 3883 -> 4579
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3400], w[3883]);
        mulmod(t2, w[3400], w[3883]);
        mulmod_constant(t2, t2, two);
        submod(w[4579], t1, t2);
    }

    // AND 1457 2146 -> 4580
    mulmod(w[4580], w[1457], w[2146]);

    // XOR 2907 568 -> 4581
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2907], w[568]);
        mulmod(t2, w[2907], w[568]);
        mulmod_constant(t2, t2, two);
        submod(w[4581], t1, t2);
    }

    // XOR 3624 2072 -> 4582
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3624], w[2072]);
        mulmod(t2, w[3624], w[2072]);
        mulmod_constant(t2, t2, two);
        submod(w[4582], t1, t2);
    }

    // AND 1112 4416 -> 4583
    mulmod(w[4583], w[1112], w[4416]);

    // AND 741 964 -> 4584
    mulmod(w[4584], w[741], w[964]);

    // XOR 667 3219 -> 4585
    {
        bn254fr_class t1, t2;
        addmod(t1, w[667], w[3219]);
        mulmod(t2, w[667], w[3219]);
        mulmod_constant(t2, t2, two);
        submod(w[4585], t1, t2);
    }

    // XOR 1924 2274 -> 4586
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1924], w[2274]);
        mulmod(t2, w[1924], w[2274]);
        mulmod_constant(t2, t2, two);
        submod(w[4586], t1, t2);
    }

    // INV 390 -> 4587
    submod(w[4587], one, w[390]);

    // INV 1768 -> 4588
    submod(w[4588], one, w[1768]);

    // INV 3843 -> 4589
    submod(w[4589], one, w[3843]);

    // XOR 3984 2564 -> 4590
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3984], w[2564]);
        mulmod(t2, w[3984], w[2564]);
        mulmod_constant(t2, t2, two);
        submod(w[4590], t1, t2);
    }

    // INV 467 -> 4591
    submod(w[4591], one, w[467]);

    // XOR 1214 3595 -> 4592
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1214], w[3595]);
        mulmod(t2, w[1214], w[3595]);
        mulmod_constant(t2, t2, two);
        submod(w[4592], t1, t2);
    }

    // XOR 940 3842 -> 4593
    {
        bn254fr_class t1, t2;
        addmod(t1, w[940], w[3842]);
        mulmod(t2, w[940], w[3842]);
        mulmod_constant(t2, t2, two);
        submod(w[4593], t1, t2);
    }

    // XOR 1486 2290 -> 4594
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1486], w[2290]);
        mulmod(t2, w[1486], w[2290]);
        mulmod_constant(t2, t2, two);
        submod(w[4594], t1, t2);
    }

    // XOR 1622 1884 -> 4595
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1622], w[1884]);
        mulmod(t2, w[1622], w[1884]);
        mulmod_constant(t2, t2, two);
        submod(w[4595], t1, t2);
    }

    // XOR 2637 3290 -> 4596
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2637], w[3290]);
        mulmod(t2, w[2637], w[3290]);
        mulmod_constant(t2, t2, two);
        submod(w[4596], t1, t2);
    }

    // XOR 4147 2072 -> 4597
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4147], w[2072]);
        mulmod(t2, w[4147], w[2072]);
        mulmod_constant(t2, t2, two);
        submod(w[4597], t1, t2);
    }

    // AND 1580 1888 -> 4598
    mulmod(w[4598], w[1580], w[1888]);

    // XOR 4474 2238 -> 4599
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4474], w[2238]);
        mulmod(t2, w[4474], w[2238]);
        mulmod_constant(t2, t2, two);
        submod(w[4599], t1, t2);
    }

    // XOR 1944 1765 -> 4600
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1944], w[1765]);
        mulmod(t2, w[1944], w[1765]);
        mulmod_constant(t2, t2, two);
        submod(w[4600], t1, t2);
    }

    // XOR 2988 4278 -> 4601
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2988], w[4278]);
        mulmod(t2, w[2988], w[4278]);
        mulmod_constant(t2, t2, two);
        submod(w[4601], t1, t2);
    }

    // AND 888 1405 -> 4602
    mulmod(w[4602], w[888], w[1405]);

    // XOR 3195 2918 -> 4603
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3195], w[2918]);
        mulmod(t2, w[3195], w[2918]);
        mulmod_constant(t2, t2, two);
        submod(w[4603], t1, t2);
    }

    // XOR 3615 2585 -> 4604
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3615], w[2585]);
        mulmod(t2, w[3615], w[2585]);
        mulmod_constant(t2, t2, two);
        submod(w[4604], t1, t2);
    }

    // XOR 2994 136 -> 4605
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2994], w[136]);
        mulmod(t2, w[2994], w[136]);
        mulmod_constant(t2, t2, two);
        submod(w[4605], t1, t2);
    }

    // INV 4004 -> 4606
    submod(w[4606], one, w[4004]);

    // XOR 1409 2452 -> 4607
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1409], w[2452]);
        mulmod(t2, w[1409], w[2452]);
        mulmod_constant(t2, t2, two);
        submod(w[4607], t1, t2);
    }

    // AND 1131 2255 -> 4608
    mulmod(w[4608], w[1131], w[2255]);

    // XOR 184 2001 -> 4609
    {
        bn254fr_class t1, t2;
        addmod(t1, w[184], w[2001]);
        mulmod(t2, w[184], w[2001]);
        mulmod_constant(t2, t2, two);
        submod(w[4609], t1, t2);
    }

    // XOR 2688 3548 -> 4610
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2688], w[3548]);
        mulmod(t2, w[2688], w[3548]);
        mulmod_constant(t2, t2, two);
        submod(w[4610], t1, t2);
    }

    // XOR 2401 840 -> 4611
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2401], w[840]);
        mulmod(t2, w[2401], w[840]);
        mulmod_constant(t2, t2, two);
        submod(w[4611], t1, t2);
    }

    // XOR 1224 2748 -> 4612
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1224], w[2748]);
        mulmod(t2, w[1224], w[2748]);
        mulmod_constant(t2, t2, two);
        submod(w[4612], t1, t2);
    }

    // XOR 1563 2376 -> 4613
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1563], w[2376]);
        mulmod(t2, w[1563], w[2376]);
        mulmod_constant(t2, t2, two);
        submod(w[4613], t1, t2);
    }

    // AND 4080 2718 -> 4614
    mulmod(w[4614], w[4080], w[2718]);

    // XOR 3362 1960 -> 4615
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3362], w[1960]);
        mulmod(t2, w[3362], w[1960]);
        mulmod_constant(t2, t2, two);
        submod(w[4615], t1, t2);
    }

    // XOR 3017 3337 -> 4616
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3017], w[3337]);
        mulmod(t2, w[3017], w[3337]);
        mulmod_constant(t2, t2, two);
        submod(w[4616], t1, t2);
    }

    // XOR 2647 1511 -> 4617
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2647], w[1511]);
        mulmod(t2, w[2647], w[1511]);
        mulmod_constant(t2, t2, two);
        submod(w[4617], t1, t2);
    }

    // INV 3775 -> 4618
    submod(w[4618], one, w[3775]);

    // XOR 505 2186 -> 4619
    {
        bn254fr_class t1, t2;
        addmod(t1, w[505], w[2186]);
        mulmod(t2, w[505], w[2186]);
        mulmod_constant(t2, t2, two);
        submod(w[4619], t1, t2);
    }

    // AND 3091 3892 -> 4620
    mulmod(w[4620], w[3091], w[3892]);

    // XOR 4485 3432 -> 4621
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4485], w[3432]);
        mulmod(t2, w[4485], w[3432]);
        mulmod_constant(t2, t2, two);
        submod(w[4621], t1, t2);
    }

    // XOR 2181 2022 -> 4622
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2181], w[2022]);
        mulmod(t2, w[2181], w[2022]);
        mulmod_constant(t2, t2, two);
        submod(w[4622], t1, t2);
    }

    // XOR 42 1615 -> 4623
    {
        bn254fr_class t1, t2;
        addmod(t1, w[42], w[1615]);
        mulmod(t2, w[42], w[1615]);
        mulmod_constant(t2, t2, two);
        submod(w[4623], t1, t2);
    }

    // INV 491 -> 4624
    submod(w[4624], one, w[491]);

    // AND 3735 3417 -> 4625
    mulmod(w[4625], w[3735], w[3417]);

    // INV 3918 -> 4626
    submod(w[4626], one, w[3918]);

    // XOR 198 3398 -> 4627
    {
        bn254fr_class t1, t2;
        addmod(t1, w[198], w[3398]);
        mulmod(t2, w[198], w[3398]);
        mulmod_constant(t2, t2, two);
        submod(w[4627], t1, t2);
    }

    // INV 3322 -> 4628
    submod(w[4628], one, w[3322]);

    // XOR 3437 991 -> 4629
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3437], w[991]);
        mulmod(t2, w[3437], w[991]);
        mulmod_constant(t2, t2, two);
        submod(w[4629], t1, t2);
    }

    // XOR 597 512 -> 4630
    {
        bn254fr_class t1, t2;
        addmod(t1, w[597], w[512]);
        mulmod(t2, w[597], w[512]);
        mulmod_constant(t2, t2, two);
        submod(w[4630], t1, t2);
    }

    // AND 1299 1100 -> 4631
    mulmod(w[4631], w[1299], w[1100]);

    // AND 197 1328 -> 4632
    mulmod(w[4632], w[197], w[1328]);

    // XOR 1046 2761 -> 4633
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1046], w[2761]);
        mulmod(t2, w[1046], w[2761]);
        mulmod_constant(t2, t2, two);
        submod(w[4633], t1, t2);
    }

    // XOR 183 4564 -> 4634
    {
        bn254fr_class t1, t2;
        addmod(t1, w[183], w[4564]);
        mulmod(t2, w[183], w[4564]);
        mulmod_constant(t2, t2, two);
        submod(w[4634], t1, t2);
    }

    // AND 4047 792 -> 4635
    mulmod(w[4635], w[4047], w[792]);

    // AND 3970 2970 -> 4636
    mulmod(w[4636], w[3970], w[2970]);

    // INV 1649 -> 4637
    submod(w[4637], one, w[1649]);

    // XOR 163 34 -> 4638
    {
        bn254fr_class t1, t2;
        addmod(t1, w[163], w[34]);
        mulmod(t2, w[163], w[34]);
        mulmod_constant(t2, t2, two);
        submod(w[4638], t1, t2);
    }

    // INV 4361 -> 4639
    submod(w[4639], one, w[4361]);

    // XOR 2424 2150 -> 4640
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2424], w[2150]);
        mulmod(t2, w[2424], w[2150]);
        mulmod_constant(t2, t2, two);
        submod(w[4640], t1, t2);
    }

    // XOR 1279 162 -> 4641
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1279], w[162]);
        mulmod(t2, w[1279], w[162]);
        mulmod_constant(t2, t2, two);
        submod(w[4641], t1, t2);
    }

    // XOR 473 4332 -> 4642
    {
        bn254fr_class t1, t2;
        addmod(t1, w[473], w[4332]);
        mulmod(t2, w[473], w[4332]);
        mulmod_constant(t2, t2, two);
        submod(w[4642], t1, t2);
    }

    // AND 644 2690 -> 4643
    mulmod(w[4643], w[644], w[2690]);

    // AND 530 3197 -> 4644
    mulmod(w[4644], w[530], w[3197]);

    // XOR 1864 1944 -> 4645
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1864], w[1944]);
        mulmod(t2, w[1864], w[1944]);
        mulmod_constant(t2, t2, two);
        submod(w[4645], t1, t2);
    }

    // XOR 1526 2354 -> 4646
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1526], w[2354]);
        mulmod(t2, w[1526], w[2354]);
        mulmod_constant(t2, t2, two);
        submod(w[4646], t1, t2);
    }

    // AND 347 4441 -> 4647
    mulmod(w[4647], w[347], w[4441]);

    // AND 1411 1967 -> 4648
    mulmod(w[4648], w[1411], w[1967]);

    // AND 2436 997 -> 4649
    mulmod(w[4649], w[2436], w[997]);

    // XOR 1220 2637 -> 4650
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1220], w[2637]);
        mulmod(t2, w[1220], w[2637]);
        mulmod_constant(t2, t2, two);
        submod(w[4650], t1, t2);
    }

    // AND 3804 220 -> 4651
    mulmod(w[4651], w[3804], w[220]);

    // INV 748 -> 4652
    submod(w[4652], one, w[748]);

    // AND 3235 586 -> 4653
    mulmod(w[4653], w[3235], w[586]);

    // XOR 2804 4553 -> 4654
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2804], w[4553]);
        mulmod(t2, w[2804], w[4553]);
        mulmod_constant(t2, t2, two);
        submod(w[4654], t1, t2);
    }

    // XOR 2229 1572 -> 4655
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2229], w[1572]);
        mulmod(t2, w[2229], w[1572]);
        mulmod_constant(t2, t2, two);
        submod(w[4655], t1, t2);
    }

    // XOR 4323 4191 -> 4656
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4323], w[4191]);
        mulmod(t2, w[4323], w[4191]);
        mulmod_constant(t2, t2, two);
        submod(w[4656], t1, t2);
    }

    // XOR 3698 1551 -> 4657
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3698], w[1551]);
        mulmod(t2, w[3698], w[1551]);
        mulmod_constant(t2, t2, two);
        submod(w[4657], t1, t2);
    }

    // XOR 792 4262 -> 4658
    {
        bn254fr_class t1, t2;
        addmod(t1, w[792], w[4262]);
        mulmod(t2, w[792], w[4262]);
        mulmod_constant(t2, t2, two);
        submod(w[4658], t1, t2);
    }

    // XOR 2346 3496 -> 4659
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2346], w[3496]);
        mulmod(t2, w[2346], w[3496]);
        mulmod_constant(t2, t2, two);
        submod(w[4659], t1, t2);
    }

    // AND 84 3751 -> 4660
    mulmod(w[4660], w[84], w[3751]);

    // AND 4503 1320 -> 4661
    mulmod(w[4661], w[4503], w[1320]);

    // AND 3552 4066 -> 4662
    mulmod(w[4662], w[3552], w[4066]);

    // XOR 1771 4178 -> 4663
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1771], w[4178]);
        mulmod(t2, w[1771], w[4178]);
        mulmod_constant(t2, t2, two);
        submod(w[4663], t1, t2);
    }

    // XOR 3007 3919 -> 4664
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3007], w[3919]);
        mulmod(t2, w[3007], w[3919]);
        mulmod_constant(t2, t2, two);
        submod(w[4664], t1, t2);
    }

    // XOR 2905 1572 -> 4665
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2905], w[1572]);
        mulmod(t2, w[2905], w[1572]);
        mulmod_constant(t2, t2, two);
        submod(w[4665], t1, t2);
    }

    // XOR 1691 526 -> 4666
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1691], w[526]);
        mulmod(t2, w[1691], w[526]);
        mulmod_constant(t2, t2, two);
        submod(w[4666], t1, t2);
    }

    // XOR 823 4380 -> 4667
    {
        bn254fr_class t1, t2;
        addmod(t1, w[823], w[4380]);
        mulmod(t2, w[823], w[4380]);
        mulmod_constant(t2, t2, two);
        submod(w[4667], t1, t2);
    }

    // XOR 382 473 -> 4668
    {
        bn254fr_class t1, t2;
        addmod(t1, w[382], w[473]);
        mulmod(t2, w[382], w[473]);
        mulmod_constant(t2, t2, two);
        submod(w[4668], t1, t2);
    }

    // XOR 177 3161 -> 4669
    {
        bn254fr_class t1, t2;
        addmod(t1, w[177], w[3161]);
        mulmod(t2, w[177], w[3161]);
        mulmod_constant(t2, t2, two);
        submod(w[4669], t1, t2);
    }

    // INV 570 -> 4670
    submod(w[4670], one, w[570]);

    // AND 1190 3129 -> 4671
    mulmod(w[4671], w[1190], w[3129]);

    // INV 2252 -> 4672
    submod(w[4672], one, w[2252]);

    // AND 116 4080 -> 4673
    mulmod(w[4673], w[116], w[4080]);

    // XOR 1679 4594 -> 4674
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1679], w[4594]);
        mulmod(t2, w[1679], w[4594]);
        mulmod_constant(t2, t2, two);
        submod(w[4674], t1, t2);
    }

    // AND 2103 299 -> 4675
    mulmod(w[4675], w[2103], w[299]);

    // XOR 3772 735 -> 4676
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3772], w[735]);
        mulmod(t2, w[3772], w[735]);
        mulmod_constant(t2, t2, two);
        submod(w[4676], t1, t2);
    }

    // XOR 2821 830 -> 4677
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2821], w[830]);
        mulmod(t2, w[2821], w[830]);
        mulmod_constant(t2, t2, two);
        submod(w[4677], t1, t2);
    }

    // AND 921 891 -> 4678
    mulmod(w[4678], w[921], w[891]);

    // INV 4492 -> 4679
    submod(w[4679], one, w[4492]);

    // AND 251 2319 -> 4680
    mulmod(w[4680], w[251], w[2319]);

    // XOR 2406 725 -> 4681
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2406], w[725]);
        mulmod(t2, w[2406], w[725]);
        mulmod_constant(t2, t2, two);
        submod(w[4681], t1, t2);
    }

    // AND 2415 1511 -> 4682
    mulmod(w[4682], w[2415], w[1511]);

    // XOR 214 645 -> 4683
    {
        bn254fr_class t1, t2;
        addmod(t1, w[214], w[645]);
        mulmod(t2, w[214], w[645]);
        mulmod_constant(t2, t2, two);
        submod(w[4683], t1, t2);
    }

    // INV 633 -> 4684
    submod(w[4684], one, w[633]);

    // XOR 1111 2979 -> 4685
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1111], w[2979]);
        mulmod(t2, w[1111], w[2979]);
        mulmod_constant(t2, t2, two);
        submod(w[4685], t1, t2);
    }

    // XOR 2445 1541 -> 4686
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2445], w[1541]);
        mulmod(t2, w[2445], w[1541]);
        mulmod_constant(t2, t2, two);
        submod(w[4686], t1, t2);
    }

    // XOR 2060 3457 -> 4687
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2060], w[3457]);
        mulmod(t2, w[2060], w[3457]);
        mulmod_constant(t2, t2, two);
        submod(w[4687], t1, t2);
    }

    // AND 2402 3251 -> 4688
    mulmod(w[4688], w[2402], w[3251]);

    // AND 1319 1547 -> 4689
    mulmod(w[4689], w[1319], w[1547]);

    // XOR 3838 38 -> 4690
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3838], w[38]);
        mulmod(t2, w[3838], w[38]);
        mulmod_constant(t2, t2, two);
        submod(w[4690], t1, t2);
    }

    // XOR 675 83 -> 4691
    {
        bn254fr_class t1, t2;
        addmod(t1, w[675], w[83]);
        mulmod(t2, w[675], w[83]);
        mulmod_constant(t2, t2, two);
        submod(w[4691], t1, t2);
    }

    // XOR 1585 1206 -> 4692
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1585], w[1206]);
        mulmod(t2, w[1585], w[1206]);
        mulmod_constant(t2, t2, two);
        submod(w[4692], t1, t2);
    }

    // AND 837 3069 -> 4693
    mulmod(w[4693], w[837], w[3069]);

    // XOR 3688 3168 -> 4694
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3688], w[3168]);
        mulmod(t2, w[3688], w[3168]);
        mulmod_constant(t2, t2, two);
        submod(w[4694], t1, t2);
    }

    // XOR 4361 3808 -> 4695
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4361], w[3808]);
        mulmod(t2, w[4361], w[3808]);
        mulmod_constant(t2, t2, two);
        submod(w[4695], t1, t2);
    }

    // XOR 3246 655 -> 4696
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3246], w[655]);
        mulmod(t2, w[3246], w[655]);
        mulmod_constant(t2, t2, two);
        submod(w[4696], t1, t2);
    }

    // XOR 3976 3148 -> 4697
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3976], w[3148]);
        mulmod(t2, w[3976], w[3148]);
        mulmod_constant(t2, t2, two);
        submod(w[4697], t1, t2);
    }

    // AND 3464 3403 -> 4698
    mulmod(w[4698], w[3464], w[3403]);

    // XOR 2158 1934 -> 4699
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2158], w[1934]);
        mulmod(t2, w[2158], w[1934]);
        mulmod_constant(t2, t2, two);
        submod(w[4699], t1, t2);
    }

    // XOR 2216 1239 -> 4700
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2216], w[1239]);
        mulmod(t2, w[2216], w[1239]);
        mulmod_constant(t2, t2, two);
        submod(w[4700], t1, t2);
    }

    // XOR 89 2589 -> 4701
    {
        bn254fr_class t1, t2;
        addmod(t1, w[89], w[2589]);
        mulmod(t2, w[89], w[2589]);
        mulmod_constant(t2, t2, two);
        submod(w[4701], t1, t2);
    }

    // INV 1211 -> 4702
    submod(w[4702], one, w[1211]);

    // XOR 3316 4099 -> 4703
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3316], w[4099]);
        mulmod(t2, w[3316], w[4099]);
        mulmod_constant(t2, t2, two);
        submod(w[4703], t1, t2);
    }

    // XOR 672 1075 -> 4704
    {
        bn254fr_class t1, t2;
        addmod(t1, w[672], w[1075]);
        mulmod(t2, w[672], w[1075]);
        mulmod_constant(t2, t2, two);
        submod(w[4704], t1, t2);
    }

    // XOR 3457 734 -> 4705
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3457], w[734]);
        mulmod(t2, w[3457], w[734]);
        mulmod_constant(t2, t2, two);
        submod(w[4705], t1, t2);
    }

    // XOR 2212 272 -> 4706
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2212], w[272]);
        mulmod(t2, w[2212], w[272]);
        mulmod_constant(t2, t2, two);
        submod(w[4706], t1, t2);
    }

    // XOR 2885 1631 -> 4707
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2885], w[1631]);
        mulmod(t2, w[2885], w[1631]);
        mulmod_constant(t2, t2, two);
        submod(w[4707], t1, t2);
    }

    // XOR 1987 3203 -> 4708
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1987], w[3203]);
        mulmod(t2, w[1987], w[3203]);
        mulmod_constant(t2, t2, two);
        submod(w[4708], t1, t2);
    }

    // XOR 3873 629 -> 4709
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3873], w[629]);
        mulmod(t2, w[3873], w[629]);
        mulmod_constant(t2, t2, two);
        submod(w[4709], t1, t2);
    }

    // XOR 4240 2382 -> 4710
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4240], w[2382]);
        mulmod(t2, w[4240], w[2382]);
        mulmod_constant(t2, t2, two);
        submod(w[4710], t1, t2);
    }

    // XOR 1259 1667 -> 4711
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1259], w[1667]);
        mulmod(t2, w[1259], w[1667]);
        mulmod_constant(t2, t2, two);
        submod(w[4711], t1, t2);
    }

    // XOR 1830 3436 -> 4712
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1830], w[3436]);
        mulmod(t2, w[1830], w[3436]);
        mulmod_constant(t2, t2, two);
        submod(w[4712], t1, t2);
    }

    // AND 2742 1634 -> 4713
    mulmod(w[4713], w[2742], w[1634]);

    // INV 2050 -> 4714
    submod(w[4714], one, w[2050]);

    // XOR 2125 4367 -> 4715
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2125], w[4367]);
        mulmod(t2, w[2125], w[4367]);
        mulmod_constant(t2, t2, two);
        submod(w[4715], t1, t2);
    }

    // AND 909 5 -> 4716
    mulmod(w[4716], w[909], w[5]);

    // XOR 1738 409 -> 4717
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1738], w[409]);
        mulmod(t2, w[1738], w[409]);
        mulmod_constant(t2, t2, two);
        submod(w[4717], t1, t2);
    }

    // XOR 1380 2879 -> 4718
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1380], w[2879]);
        mulmod(t2, w[1380], w[2879]);
        mulmod_constant(t2, t2, two);
        submod(w[4718], t1, t2);
    }

    // AND 2034 875 -> 4719
    mulmod(w[4719], w[2034], w[875]);

    // XOR 269 3881 -> 4720
    {
        bn254fr_class t1, t2;
        addmod(t1, w[269], w[3881]);
        mulmod(t2, w[269], w[3881]);
        mulmod_constant(t2, t2, two);
        submod(w[4720], t1, t2);
    }

    // XOR 2182 3172 -> 4721
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2182], w[3172]);
        mulmod(t2, w[2182], w[3172]);
        mulmod_constant(t2, t2, two);
        submod(w[4721], t1, t2);
    }

    // XOR 3684 2982 -> 4722
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3684], w[2982]);
        mulmod(t2, w[3684], w[2982]);
        mulmod_constant(t2, t2, two);
        submod(w[4722], t1, t2);
    }

    // XOR 3150 2129 -> 4723
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3150], w[2129]);
        mulmod(t2, w[3150], w[2129]);
        mulmod_constant(t2, t2, two);
        submod(w[4723], t1, t2);
    }

    // XOR 2411 879 -> 4724
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2411], w[879]);
        mulmod(t2, w[2411], w[879]);
        mulmod_constant(t2, t2, two);
        submod(w[4724], t1, t2);
    }

    // XOR 1256 773 -> 4725
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1256], w[773]);
        mulmod(t2, w[1256], w[773]);
        mulmod_constant(t2, t2, two);
        submod(w[4725], t1, t2);
    }

    // INV 754 -> 4726
    submod(w[4726], one, w[754]);

    // AND 34 2392 -> 4727
    mulmod(w[4727], w[34], w[2392]);

    // INV 3535 -> 4728
    submod(w[4728], one, w[3535]);

    // AND 2574 1502 -> 4729
    mulmod(w[4729], w[2574], w[1502]);

    // XOR 4396 3226 -> 4730
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4396], w[3226]);
        mulmod(t2, w[4396], w[3226]);
        mulmod_constant(t2, t2, two);
        submod(w[4730], t1, t2);
    }

    // INV 3183 -> 4731
    submod(w[4731], one, w[3183]);

    // XOR 407 4488 -> 4732
    {
        bn254fr_class t1, t2;
        addmod(t1, w[407], w[4488]);
        mulmod(t2, w[407], w[4488]);
        mulmod_constant(t2, t2, two);
        submod(w[4732], t1, t2);
    }

    // XOR 2402 4224 -> 4733
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2402], w[4224]);
        mulmod(t2, w[2402], w[4224]);
        mulmod_constant(t2, t2, two);
        submod(w[4733], t1, t2);
    }

    // INV 2115 -> 4734
    submod(w[4734], one, w[2115]);

    // INV 173 -> 4735
    submod(w[4735], one, w[173]);

    // XOR 2085 917 -> 4736
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2085], w[917]);
        mulmod(t2, w[2085], w[917]);
        mulmod_constant(t2, t2, two);
        submod(w[4736], t1, t2);
    }

    // XOR 1244 3478 -> 4737
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1244], w[3478]);
        mulmod(t2, w[1244], w[3478]);
        mulmod_constant(t2, t2, two);
        submod(w[4737], t1, t2);
    }

    // XOR 890 4632 -> 4738
    {
        bn254fr_class t1, t2;
        addmod(t1, w[890], w[4632]);
        mulmod(t2, w[890], w[4632]);
        mulmod_constant(t2, t2, two);
        submod(w[4738], t1, t2);
    }

    // XOR 3086 2106 -> 4739
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3086], w[2106]);
        mulmod(t2, w[3086], w[2106]);
        mulmod_constant(t2, t2, two);
        submod(w[4739], t1, t2);
    }

    // XOR 2961 4683 -> 4740
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2961], w[4683]);
        mulmod(t2, w[2961], w[4683]);
        mulmod_constant(t2, t2, two);
        submod(w[4740], t1, t2);
    }

    // XOR 4087 1166 -> 4741
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4087], w[1166]);
        mulmod(t2, w[4087], w[1166]);
        mulmod_constant(t2, t2, two);
        submod(w[4741], t1, t2);
    }

    // INV 3402 -> 4742
    submod(w[4742], one, w[3402]);

    // XOR 260 1751 -> 4743
    {
        bn254fr_class t1, t2;
        addmod(t1, w[260], w[1751]);
        mulmod(t2, w[260], w[1751]);
        mulmod_constant(t2, t2, two);
        submod(w[4743], t1, t2);
    }

    // XOR 4067 11 -> 4744
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4067], w[11]);
        mulmod(t2, w[4067], w[11]);
        mulmod_constant(t2, t2, two);
        submod(w[4744], t1, t2);
    }

    // XOR 1045 1002 -> 4745
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1045], w[1002]);
        mulmod(t2, w[1045], w[1002]);
        mulmod_constant(t2, t2, two);
        submod(w[4745], t1, t2);
    }

    // XOR 1340 953 -> 4746
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1340], w[953]);
        mulmod(t2, w[1340], w[953]);
        mulmod_constant(t2, t2, two);
        submod(w[4746], t1, t2);
    }

    // AND 4491 322 -> 4747
    mulmod(w[4747], w[4491], w[322]);

    // AND 756 917 -> 4748
    mulmod(w[4748], w[756], w[917]);

    // XOR 2843 2035 -> 4749
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2843], w[2035]);
        mulmod(t2, w[2843], w[2035]);
        mulmod_constant(t2, t2, two);
        submod(w[4749], t1, t2);
    }

    // XOR 2735 989 -> 4750
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2735], w[989]);
        mulmod(t2, w[2735], w[989]);
        mulmod_constant(t2, t2, two);
        submod(w[4750], t1, t2);
    }

    // XOR 2201 1550 -> 4751
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2201], w[1550]);
        mulmod(t2, w[2201], w[1550]);
        mulmod_constant(t2, t2, two);
        submod(w[4751], t1, t2);
    }

    // AND 511 3260 -> 4752
    mulmod(w[4752], w[511], w[3260]);

    // XOR 1666 2786 -> 4753
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1666], w[2786]);
        mulmod(t2, w[1666], w[2786]);
        mulmod_constant(t2, t2, two);
        submod(w[4753], t1, t2);
    }

    // AND 4280 2308 -> 4754
    mulmod(w[4754], w[4280], w[2308]);

    // XOR 3117 1402 -> 4755
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3117], w[1402]);
        mulmod(t2, w[3117], w[1402]);
        mulmod_constant(t2, t2, two);
        submod(w[4755], t1, t2);
    }

    // AND 3968 89 -> 4756
    mulmod(w[4756], w[3968], w[89]);

    // AND 478 1150 -> 4757
    mulmod(w[4757], w[478], w[1150]);

    // AND 3718 663 -> 4758
    mulmod(w[4758], w[3718], w[663]);

    // AND 3257 896 -> 4759
    mulmod(w[4759], w[3257], w[896]);

    // XOR 1658 4462 -> 4760
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1658], w[4462]);
        mulmod(t2, w[1658], w[4462]);
        mulmod_constant(t2, t2, two);
        submod(w[4760], t1, t2);
    }

    // XOR 2405 1248 -> 4761
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2405], w[1248]);
        mulmod(t2, w[2405], w[1248]);
        mulmod_constant(t2, t2, two);
        submod(w[4761], t1, t2);
    }

    // XOR 2566 3676 -> 4762
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2566], w[3676]);
        mulmod(t2, w[2566], w[3676]);
        mulmod_constant(t2, t2, two);
        submod(w[4762], t1, t2);
    }

    // XOR 3401 3008 -> 4763
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3401], w[3008]);
        mulmod(t2, w[3401], w[3008]);
        mulmod_constant(t2, t2, two);
        submod(w[4763], t1, t2);
    }

    // AND 1520 269 -> 4764
    mulmod(w[4764], w[1520], w[269]);

    // INV 4058 -> 4765
    submod(w[4765], one, w[4058]);

    // XOR 2374 336 -> 4766
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2374], w[336]);
        mulmod(t2, w[2374], w[336]);
        mulmod_constant(t2, t2, two);
        submod(w[4766], t1, t2);
    }

    // AND 4009 2409 -> 4767
    mulmod(w[4767], w[4009], w[2409]);

    // XOR 1542 3998 -> 4768
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1542], w[3998]);
        mulmod(t2, w[1542], w[3998]);
        mulmod_constant(t2, t2, two);
        submod(w[4768], t1, t2);
    }

    // AND 4396 3884 -> 4769
    mulmod(w[4769], w[4396], w[3884]);

    // AND 1045 3615 -> 4770
    mulmod(w[4770], w[1045], w[3615]);

    // AND 159 2867 -> 4771
    mulmod(w[4771], w[159], w[2867]);

    // AND 2469 3999 -> 4772
    mulmod(w[4772], w[2469], w[3999]);

    // XOR 227 4226 -> 4773
    {
        bn254fr_class t1, t2;
        addmod(t1, w[227], w[4226]);
        mulmod(t2, w[227], w[4226]);
        mulmod_constant(t2, t2, two);
        submod(w[4773], t1, t2);
    }

    // XOR 294 1678 -> 4774
    {
        bn254fr_class t1, t2;
        addmod(t1, w[294], w[1678]);
        mulmod(t2, w[294], w[1678]);
        mulmod_constant(t2, t2, two);
        submod(w[4774], t1, t2);
    }

    // AND 4238 2159 -> 4775
    mulmod(w[4775], w[4238], w[2159]);

    // XOR 460 1231 -> 4776
    {
        bn254fr_class t1, t2;
        addmod(t1, w[460], w[1231]);
        mulmod(t2, w[460], w[1231]);
        mulmod_constant(t2, t2, two);
        submod(w[4776], t1, t2);
    }

    // INV 3163 -> 4777
    submod(w[4777], one, w[3163]);

    // XOR 3346 2008 -> 4778
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3346], w[2008]);
        mulmod(t2, w[3346], w[2008]);
        mulmod_constant(t2, t2, two);
        submod(w[4778], t1, t2);
    }

    // INV 1872 -> 4779
    submod(w[4779], one, w[1872]);

    // AND 623 1653 -> 4780
    mulmod(w[4780], w[623], w[1653]);

    // XOR 2359 4672 -> 4781
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2359], w[4672]);
        mulmod(t2, w[2359], w[4672]);
        mulmod_constant(t2, t2, two);
        submod(w[4781], t1, t2);
    }

    // XOR 1481 4676 -> 4782
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1481], w[4676]);
        mulmod(t2, w[1481], w[4676]);
        mulmod_constant(t2, t2, two);
        submod(w[4782], t1, t2);
    }

    // XOR 2983 3592 -> 4783
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2983], w[3592]);
        mulmod(t2, w[2983], w[3592]);
        mulmod_constant(t2, t2, two);
        submod(w[4783], t1, t2);
    }

    // XOR 1375 4026 -> 4784
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1375], w[4026]);
        mulmod(t2, w[1375], w[4026]);
        mulmod_constant(t2, t2, two);
        submod(w[4784], t1, t2);
    }

    // AND 2076 3539 -> 4785
    mulmod(w[4785], w[2076], w[3539]);

    // XOR 2503 3478 -> 4786
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2503], w[3478]);
        mulmod(t2, w[2503], w[3478]);
        mulmod_constant(t2, t2, two);
        submod(w[4786], t1, t2);
    }

    // XOR 1195 4181 -> 4787
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1195], w[4181]);
        mulmod(t2, w[1195], w[4181]);
        mulmod_constant(t2, t2, two);
        submod(w[4787], t1, t2);
    }

    // XOR 4589 4419 -> 4788
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4589], w[4419]);
        mulmod(t2, w[4589], w[4419]);
        mulmod_constant(t2, t2, two);
        submod(w[4788], t1, t2);
    }

    // XOR 3040 3080 -> 4789
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3040], w[3080]);
        mulmod(t2, w[3040], w[3080]);
        mulmod_constant(t2, t2, two);
        submod(w[4789], t1, t2);
    }

    // AND 3815 721 -> 4790
    mulmod(w[4790], w[3815], w[721]);

    // XOR 4631 4172 -> 4791
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4631], w[4172]);
        mulmod(t2, w[4631], w[4172]);
        mulmod_constant(t2, t2, two);
        submod(w[4791], t1, t2);
    }

    // XOR 4426 3729 -> 4792
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4426], w[3729]);
        mulmod(t2, w[4426], w[3729]);
        mulmod_constant(t2, t2, two);
        submod(w[4792], t1, t2);
    }

    // XOR 4704 4002 -> 4793
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4704], w[4002]);
        mulmod(t2, w[4704], w[4002]);
        mulmod_constant(t2, t2, two);
        submod(w[4793], t1, t2);
    }

    // XOR 4363 4012 -> 4794
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4363], w[4012]);
        mulmod(t2, w[4363], w[4012]);
        mulmod_constant(t2, t2, two);
        submod(w[4794], t1, t2);
    }

    // AND 284 1270 -> 4795
    mulmod(w[4795], w[284], w[1270]);

    // INV 4165 -> 4796
    submod(w[4796], one, w[4165]);

    // XOR 1715 1440 -> 4797
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1715], w[1440]);
        mulmod(t2, w[1715], w[1440]);
        mulmod_constant(t2, t2, two);
        submod(w[4797], t1, t2);
    }

    // AND 4527 3458 -> 4798
    mulmod(w[4798], w[4527], w[3458]);

    // AND 1883 3066 -> 4799
    mulmod(w[4799], w[1883], w[3066]);

    // XOR 4087 1279 -> 4800
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4087], w[1279]);
        mulmod(t2, w[4087], w[1279]);
        mulmod_constant(t2, t2, two);
        submod(w[4800], t1, t2);
    }

    // XOR 1129 1575 -> 4801
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1129], w[1575]);
        mulmod(t2, w[1129], w[1575]);
        mulmod_constant(t2, t2, two);
        submod(w[4801], t1, t2);
    }

    // XOR 1697 2811 -> 4802
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1697], w[2811]);
        mulmod(t2, w[1697], w[2811]);
        mulmod_constant(t2, t2, two);
        submod(w[4802], t1, t2);
    }

    // XOR 515 776 -> 4803
    {
        bn254fr_class t1, t2;
        addmod(t1, w[515], w[776]);
        mulmod(t2, w[515], w[776]);
        mulmod_constant(t2, t2, two);
        submod(w[4803], t1, t2);
    }

    // XOR 4238 1304 -> 4804
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4238], w[1304]);
        mulmod(t2, w[4238], w[1304]);
        mulmod_constant(t2, t2, two);
        submod(w[4804], t1, t2);
    }

    // XOR 1448 842 -> 4805
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1448], w[842]);
        mulmod(t2, w[1448], w[842]);
        mulmod_constant(t2, t2, two);
        submod(w[4805], t1, t2);
    }

    // AND 3220 1774 -> 4806
    mulmod(w[4806], w[3220], w[1774]);

    // AND 4594 381 -> 4807
    mulmod(w[4807], w[4594], w[381]);

    // AND 3074 338 -> 4808
    mulmod(w[4808], w[3074], w[338]);

    // AND 4577 2181 -> 4809
    mulmod(w[4809], w[4577], w[2181]);

    // XOR 3861 3887 -> 4810
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3861], w[3887]);
        mulmod(t2, w[3861], w[3887]);
        mulmod_constant(t2, t2, two);
        submod(w[4810], t1, t2);
    }

    // XOR 2114 3191 -> 4811
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2114], w[3191]);
        mulmod(t2, w[2114], w[3191]);
        mulmod_constant(t2, t2, two);
        submod(w[4811], t1, t2);
    }

    // AND 884 3433 -> 4812
    mulmod(w[4812], w[884], w[3433]);

    // AND 960 2370 -> 4813
    mulmod(w[4813], w[960], w[2370]);

    // AND 1478 3324 -> 4814
    mulmod(w[4814], w[1478], w[3324]);

    // XOR 3030 3351 -> 4815
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3030], w[3351]);
        mulmod(t2, w[3030], w[3351]);
        mulmod_constant(t2, t2, two);
        submod(w[4815], t1, t2);
    }

    // XOR 2421 2937 -> 4816
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2421], w[2937]);
        mulmod(t2, w[2421], w[2937]);
        mulmod_constant(t2, t2, two);
        submod(w[4816], t1, t2);
    }

    // AND 576 76 -> 4817
    mulmod(w[4817], w[576], w[76]);

    // XOR 2637 3577 -> 4818
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2637], w[3577]);
        mulmod(t2, w[2637], w[3577]);
        mulmod_constant(t2, t2, two);
        submod(w[4818], t1, t2);
    }

    // XOR 1415 2361 -> 4819
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1415], w[2361]);
        mulmod(t2, w[1415], w[2361]);
        mulmod_constant(t2, t2, two);
        submod(w[4819], t1, t2);
    }

    // AND 554 3490 -> 4820
    mulmod(w[4820], w[554], w[3490]);

    // XOR 3343 3869 -> 4821
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3343], w[3869]);
        mulmod(t2, w[3343], w[3869]);
        mulmod_constant(t2, t2, two);
        submod(w[4821], t1, t2);
    }

    // AND 3898 2181 -> 4822
    mulmod(w[4822], w[3898], w[2181]);

    // AND 1050 873 -> 4823
    mulmod(w[4823], w[1050], w[873]);

    // XOR 4595 3636 -> 4824
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4595], w[3636]);
        mulmod(t2, w[4595], w[3636]);
        mulmod_constant(t2, t2, two);
        submod(w[4824], t1, t2);
    }

    // XOR 3745 938 -> 4825
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3745], w[938]);
        mulmod(t2, w[3745], w[938]);
        mulmod_constant(t2, t2, two);
        submod(w[4825], t1, t2);
    }

    // XOR 2614 2306 -> 4826
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2614], w[2306]);
        mulmod(t2, w[2614], w[2306]);
        mulmod_constant(t2, t2, two);
        submod(w[4826], t1, t2);
    }

    // XOR 2164 1399 -> 4827
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2164], w[1399]);
        mulmod(t2, w[2164], w[1399]);
        mulmod_constant(t2, t2, two);
        submod(w[4827], t1, t2);
    }

    // XOR 1615 1309 -> 4828
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1615], w[1309]);
        mulmod(t2, w[1615], w[1309]);
        mulmod_constant(t2, t2, two);
        submod(w[4828], t1, t2);
    }

    // AND 4239 2665 -> 4829
    mulmod(w[4829], w[4239], w[2665]);

    // INV 2527 -> 4830
    submod(w[4830], one, w[2527]);

    // AND 4664 2076 -> 4831
    mulmod(w[4831], w[4664], w[2076]);

    // INV 3926 -> 4832
    submod(w[4832], one, w[3926]);

    // XOR 2561 2819 -> 4833
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2561], w[2819]);
        mulmod(t2, w[2561], w[2819]);
        mulmod_constant(t2, t2, two);
        submod(w[4833], t1, t2);
    }

    // XOR 281 1794 -> 4834
    {
        bn254fr_class t1, t2;
        addmod(t1, w[281], w[1794]);
        mulmod(t2, w[281], w[1794]);
        mulmod_constant(t2, t2, two);
        submod(w[4834], t1, t2);
    }

    // AND 1880 2577 -> 4835
    mulmod(w[4835], w[1880], w[2577]);

    // XOR 2736 4550 -> 4836
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2736], w[4550]);
        mulmod(t2, w[2736], w[4550]);
        mulmod_constant(t2, t2, two);
        submod(w[4836], t1, t2);
    }

    // AND 2155 2389 -> 4837
    mulmod(w[4837], w[2155], w[2389]);

    // XOR 1642 1554 -> 4838
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1642], w[1554]);
        mulmod(t2, w[1642], w[1554]);
        mulmod_constant(t2, t2, two);
        submod(w[4838], t1, t2);
    }

    // AND 1780 4669 -> 4839
    mulmod(w[4839], w[1780], w[4669]);

    // AND 4573 1883 -> 4840
    mulmod(w[4840], w[4573], w[1883]);

    // AND 1361 4795 -> 4841
    mulmod(w[4841], w[1361], w[4795]);

    // XOR 3587 3589 -> 4842
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3587], w[3589]);
        mulmod(t2, w[3587], w[3589]);
        mulmod_constant(t2, t2, two);
        submod(w[4842], t1, t2);
    }

    // XOR 2870 2213 -> 4843
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2870], w[2213]);
        mulmod(t2, w[2870], w[2213]);
        mulmod_constant(t2, t2, two);
        submod(w[4843], t1, t2);
    }

    // XOR 2895 1574 -> 4844
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2895], w[1574]);
        mulmod(t2, w[2895], w[1574]);
        mulmod_constant(t2, t2, two);
        submod(w[4844], t1, t2);
    }

    // XOR 4164 2940 -> 4845
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4164], w[2940]);
        mulmod(t2, w[4164], w[2940]);
        mulmod_constant(t2, t2, two);
        submod(w[4845], t1, t2);
    }

    // INV 1165 -> 4846
    submod(w[4846], one, w[1165]);

    // AND 3203 4165 -> 4847
    mulmod(w[4847], w[3203], w[4165]);

    // AND 153 729 -> 4848
    mulmod(w[4848], w[153], w[729]);

    // XOR 2960 2233 -> 4849
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2960], w[2233]);
        mulmod(t2, w[2960], w[2233]);
        mulmod_constant(t2, t2, two);
        submod(w[4849], t1, t2);
    }

    // INV 58 -> 4850
    submod(w[4850], one, w[58]);

    // XOR 3630 1819 -> 4851
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3630], w[1819]);
        mulmod(t2, w[3630], w[1819]);
        mulmod_constant(t2, t2, two);
        submod(w[4851], t1, t2);
    }

    // AND 3888 368 -> 4852
    mulmod(w[4852], w[3888], w[368]);

    // XOR 4441 998 -> 4853
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4441], w[998]);
        mulmod(t2, w[4441], w[998]);
        mulmod_constant(t2, t2, two);
        submod(w[4853], t1, t2);
    }

    // XOR 1349 1429 -> 4854
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1349], w[1429]);
        mulmod(t2, w[1349], w[1429]);
        mulmod_constant(t2, t2, two);
        submod(w[4854], t1, t2);
    }

    // XOR 528 2187 -> 4855
    {
        bn254fr_class t1, t2;
        addmod(t1, w[528], w[2187]);
        mulmod(t2, w[528], w[2187]);
        mulmod_constant(t2, t2, two);
        submod(w[4855], t1, t2);
    }

    // XOR 2254 1481 -> 4856
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2254], w[1481]);
        mulmod(t2, w[2254], w[1481]);
        mulmod_constant(t2, t2, two);
        submod(w[4856], t1, t2);
    }

    // XOR 1608 2999 -> 4857
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1608], w[2999]);
        mulmod(t2, w[1608], w[2999]);
        mulmod_constant(t2, t2, two);
        submod(w[4857], t1, t2);
    }

    // AND 3124 3803 -> 4858
    mulmod(w[4858], w[3124], w[3803]);

    // AND 76 2279 -> 4859
    mulmod(w[4859], w[76], w[2279]);

    // AND 2807 3286 -> 4860
    mulmod(w[4860], w[2807], w[3286]);

    // XOR 4718 1980 -> 4861
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4718], w[1980]);
        mulmod(t2, w[4718], w[1980]);
        mulmod_constant(t2, t2, two);
        submod(w[4861], t1, t2);
    }

    // XOR 1161 1550 -> 4862
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1161], w[1550]);
        mulmod(t2, w[1161], w[1550]);
        mulmod_constant(t2, t2, two);
        submod(w[4862], t1, t2);
    }

    // AND 1160 4237 -> 4863
    mulmod(w[4863], w[1160], w[4237]);

    // XOR 1763 3778 -> 4864
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1763], w[3778]);
        mulmod(t2, w[1763], w[3778]);
        mulmod_constant(t2, t2, two);
        submod(w[4864], t1, t2);
    }

    // XOR 3888 3039 -> 4865
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3888], w[3039]);
        mulmod(t2, w[3888], w[3039]);
        mulmod_constant(t2, t2, two);
        submod(w[4865], t1, t2);
    }

    // AND 4522 3665 -> 4866
    mulmod(w[4866], w[4522], w[3665]);

    // XOR 547 4536 -> 4867
    {
        bn254fr_class t1, t2;
        addmod(t1, w[547], w[4536]);
        mulmod(t2, w[547], w[4536]);
        mulmod_constant(t2, t2, two);
        submod(w[4867], t1, t2);
    }

    // XOR 2466 115 -> 4868
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2466], w[115]);
        mulmod(t2, w[2466], w[115]);
        mulmod_constant(t2, t2, two);
        submod(w[4868], t1, t2);
    }

    // XOR 2777 2735 -> 4869
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2777], w[2735]);
        mulmod(t2, w[2777], w[2735]);
        mulmod_constant(t2, t2, two);
        submod(w[4869], t1, t2);
    }

    // XOR 3710 2540 -> 4870
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3710], w[2540]);
        mulmod(t2, w[3710], w[2540]);
        mulmod_constant(t2, t2, two);
        submod(w[4870], t1, t2);
    }

    // AND 3468 4718 -> 4871
    mulmod(w[4871], w[3468], w[4718]);

    // XOR 1540 3708 -> 4872
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1540], w[3708]);
        mulmod(t2, w[1540], w[3708]);
        mulmod_constant(t2, t2, two);
        submod(w[4872], t1, t2);
    }

    // INV 2088 -> 4873
    submod(w[4873], one, w[2088]);

    // INV 2886 -> 4874
    submod(w[4874], one, w[2886]);

    // XOR 3700 125 -> 4875
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3700], w[125]);
        mulmod(t2, w[3700], w[125]);
        mulmod_constant(t2, t2, two);
        submod(w[4875], t1, t2);
    }

    // XOR 4357 755 -> 4876
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4357], w[755]);
        mulmod(t2, w[4357], w[755]);
        mulmod_constant(t2, t2, two);
        submod(w[4876], t1, t2);
    }

    // INV 2927 -> 4877
    submod(w[4877], one, w[2927]);

    // XOR 1881 1187 -> 4878
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1881], w[1187]);
        mulmod(t2, w[1881], w[1187]);
        mulmod_constant(t2, t2, two);
        submod(w[4878], t1, t2);
    }

    // INV 3296 -> 4879
    submod(w[4879], one, w[3296]);

    // AND 348 2267 -> 4880
    mulmod(w[4880], w[348], w[2267]);

    // AND 1691 4656 -> 4881
    mulmod(w[4881], w[1691], w[4656]);

    // INV 2883 -> 4882
    submod(w[4882], one, w[2883]);

    // XOR 2556 3960 -> 4883
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2556], w[3960]);
        mulmod(t2, w[2556], w[3960]);
        mulmod_constant(t2, t2, two);
        submod(w[4883], t1, t2);
    }

    // AND 845 4136 -> 4884
    mulmod(w[4884], w[845], w[4136]);

    // XOR 2177 4314 -> 4885
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2177], w[4314]);
        mulmod(t2, w[2177], w[4314]);
        mulmod_constant(t2, t2, two);
        submod(w[4885], t1, t2);
    }

    // XOR 4233 2563 -> 4886
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4233], w[2563]);
        mulmod(t2, w[4233], w[2563]);
        mulmod_constant(t2, t2, two);
        submod(w[4886], t1, t2);
    }

    // AND 4477 945 -> 4887
    mulmod(w[4887], w[4477], w[945]);

    // XOR 3938 333 -> 4888
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3938], w[333]);
        mulmod(t2, w[3938], w[333]);
        mulmod_constant(t2, t2, two);
        submod(w[4888], t1, t2);
    }

    // AND 771 3582 -> 4889
    mulmod(w[4889], w[771], w[3582]);

    // XOR 249 1127 -> 4890
    {
        bn254fr_class t1, t2;
        addmod(t1, w[249], w[1127]);
        mulmod(t2, w[249], w[1127]);
        mulmod_constant(t2, t2, two);
        submod(w[4890], t1, t2);
    }

    // AND 3403 2454 -> 4891
    mulmod(w[4891], w[3403], w[2454]);

    // XOR 1327 3992 -> 4892
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1327], w[3992]);
        mulmod(t2, w[1327], w[3992]);
        mulmod_constant(t2, t2, two);
        submod(w[4892], t1, t2);
    }

    // AND 1020 4278 -> 4893
    mulmod(w[4893], w[1020], w[4278]);

    // AND 1199 1413 -> 4894
    mulmod(w[4894], w[1199], w[1413]);

    // XOR 3247 1160 -> 4895
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3247], w[1160]);
        mulmod(t2, w[3247], w[1160]);
        mulmod_constant(t2, t2, two);
        submod(w[4895], t1, t2);
    }

    // XOR 628 3158 -> 4896
    {
        bn254fr_class t1, t2;
        addmod(t1, w[628], w[3158]);
        mulmod(t2, w[628], w[3158]);
        mulmod_constant(t2, t2, two);
        submod(w[4896], t1, t2);
    }

    // AND 886 2846 -> 4897
    mulmod(w[4897], w[886], w[2846]);

    // INV 1869 -> 4898
    submod(w[4898], one, w[1869]);

    // XOR 4022 2611 -> 4899
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4022], w[2611]);
        mulmod(t2, w[4022], w[2611]);
        mulmod_constant(t2, t2, two);
        submod(w[4899], t1, t2);
    }

    // AND 4505 1770 -> 4900
    mulmod(w[4900], w[4505], w[1770]);

    // XOR 2865 1733 -> 4901
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2865], w[1733]);
        mulmod(t2, w[2865], w[1733]);
        mulmod_constant(t2, t2, two);
        submod(w[4901], t1, t2);
    }

    // XOR 3869 2227 -> 4902
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3869], w[2227]);
        mulmod(t2, w[3869], w[2227]);
        mulmod_constant(t2, t2, two);
        submod(w[4902], t1, t2);
    }

    // AND 2736 3588 -> 4903
    mulmod(w[4903], w[2736], w[3588]);

    // XOR 2829 4052 -> 4904
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2829], w[4052]);
        mulmod(t2, w[2829], w[4052]);
        mulmod_constant(t2, t2, two);
        submod(w[4904], t1, t2);
    }

    // AND 181 3 -> 4905
    mulmod(w[4905], w[181], w[3]);

    // XOR 2009 3606 -> 4906
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2009], w[3606]);
        mulmod(t2, w[2009], w[3606]);
        mulmod_constant(t2, t2, two);
        submod(w[4906], t1, t2);
    }

    // INV 318 -> 4907
    submod(w[4907], one, w[318]);

    // XOR 4583 3879 -> 4908
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4583], w[3879]);
        mulmod(t2, w[4583], w[3879]);
        mulmod_constant(t2, t2, two);
        submod(w[4908], t1, t2);
    }

    // XOR 65 1336 -> 4909
    {
        bn254fr_class t1, t2;
        addmod(t1, w[65], w[1336]);
        mulmod(t2, w[65], w[1336]);
        mulmod_constant(t2, t2, two);
        submod(w[4909], t1, t2);
    }

    // AND 371 4461 -> 4910
    mulmod(w[4910], w[371], w[4461]);

    // XOR 4819 4824 -> 4911
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4819], w[4824]);
        mulmod(t2, w[4819], w[4824]);
        mulmod_constant(t2, t2, two);
        submod(w[4911], t1, t2);
    }

    // XOR 2179 1904 -> 4912
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2179], w[1904]);
        mulmod(t2, w[2179], w[1904]);
        mulmod_constant(t2, t2, two);
        submod(w[4912], t1, t2);
    }

    // AND 4644 2380 -> 4913
    mulmod(w[4913], w[4644], w[2380]);

    // XOR 1585 2101 -> 4914
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1585], w[2101]);
        mulmod(t2, w[1585], w[2101]);
        mulmod_constant(t2, t2, two);
        submod(w[4914], t1, t2);
    }

    // AND 2904 1987 -> 4915
    mulmod(w[4915], w[2904], w[1987]);

    // XOR 3483 2244 -> 4916
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3483], w[2244]);
        mulmod(t2, w[3483], w[2244]);
        mulmod_constant(t2, t2, two);
        submod(w[4916], t1, t2);
    }

    // XOR 1382 2960 -> 4917
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1382], w[2960]);
        mulmod(t2, w[1382], w[2960]);
        mulmod_constant(t2, t2, two);
        submod(w[4917], t1, t2);
    }

    // AND 1359 2768 -> 4918
    mulmod(w[4918], w[1359], w[2768]);

    // AND 1183 2777 -> 4919
    mulmod(w[4919], w[1183], w[2777]);

    // XOR 3380 316 -> 4920
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3380], w[316]);
        mulmod(t2, w[3380], w[316]);
        mulmod_constant(t2, t2, two);
        submod(w[4920], t1, t2);
    }

    // XOR 1345 17 -> 4921
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1345], w[17]);
        mulmod(t2, w[1345], w[17]);
        mulmod_constant(t2, t2, two);
        submod(w[4921], t1, t2);
    }

    // XOR 763 2376 -> 4922
    {
        bn254fr_class t1, t2;
        addmod(t1, w[763], w[2376]);
        mulmod(t2, w[763], w[2376]);
        mulmod_constant(t2, t2, two);
        submod(w[4922], t1, t2);
    }

    // XOR 3633 1269 -> 4923
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3633], w[1269]);
        mulmod(t2, w[3633], w[1269]);
        mulmod_constant(t2, t2, two);
        submod(w[4923], t1, t2);
    }

    // XOR 1076 4061 -> 4924
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1076], w[4061]);
        mulmod(t2, w[1076], w[4061]);
        mulmod_constant(t2, t2, two);
        submod(w[4924], t1, t2);
    }

    // XOR 892 1811 -> 4925
    {
        bn254fr_class t1, t2;
        addmod(t1, w[892], w[1811]);
        mulmod(t2, w[892], w[1811]);
        mulmod_constant(t2, t2, two);
        submod(w[4925], t1, t2);
    }

    // AND 4161 64 -> 4926
    mulmod(w[4926], w[4161], w[64]);

    // XOR 127 1406 -> 4927
    {
        bn254fr_class t1, t2;
        addmod(t1, w[127], w[1406]);
        mulmod(t2, w[127], w[1406]);
        mulmod_constant(t2, t2, two);
        submod(w[4927], t1, t2);
    }

    // XOR 982 3551 -> 4928
    {
        bn254fr_class t1, t2;
        addmod(t1, w[982], w[3551]);
        mulmod(t2, w[982], w[3551]);
        mulmod_constant(t2, t2, two);
        submod(w[4928], t1, t2);
    }

    // INV 1683 -> 4929
    submod(w[4929], one, w[1683]);

    // INV 3599 -> 4930
    submod(w[4930], one, w[3599]);

    // AND 4327 1021 -> 4931
    mulmod(w[4931], w[4327], w[1021]);

    // INV 3255 -> 4932
    submod(w[4932], one, w[3255]);

    // XOR 4018 1380 -> 4933
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4018], w[1380]);
        mulmod(t2, w[4018], w[1380]);
        mulmod_constant(t2, t2, two);
        submod(w[4933], t1, t2);
    }

    // AND 1713 332 -> 4934
    mulmod(w[4934], w[1713], w[332]);

    // AND 1955 457 -> 4935
    mulmod(w[4935], w[1955], w[457]);

    // AND 2262 894 -> 4936
    mulmod(w[4936], w[2262], w[894]);

    // AND 98 3788 -> 4937
    mulmod(w[4937], w[98], w[3788]);

    // XOR 1027 1683 -> 4938
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1027], w[1683]);
        mulmod(t2, w[1027], w[1683]);
        mulmod_constant(t2, t2, two);
        submod(w[4938], t1, t2);
    }

    // XOR 444 1908 -> 4939
    {
        bn254fr_class t1, t2;
        addmod(t1, w[444], w[1908]);
        mulmod(t2, w[444], w[1908]);
        mulmod_constant(t2, t2, two);
        submod(w[4939], t1, t2);
    }

    // AND 623 4231 -> 4940
    mulmod(w[4940], w[623], w[4231]);

    // AND 1903 4762 -> 4941
    mulmod(w[4941], w[1903], w[4762]);

    // XOR 412 736 -> 4942
    {
        bn254fr_class t1, t2;
        addmod(t1, w[412], w[736]);
        mulmod(t2, w[412], w[736]);
        mulmod_constant(t2, t2, two);
        submod(w[4942], t1, t2);
    }

    // XOR 1953 2464 -> 4943
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1953], w[2464]);
        mulmod(t2, w[1953], w[2464]);
        mulmod_constant(t2, t2, two);
        submod(w[4943], t1, t2);
    }

    // AND 1912 3500 -> 4944
    mulmod(w[4944], w[1912], w[3500]);

    // XOR 1518 2517 -> 4945
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1518], w[2517]);
        mulmod(t2, w[1518], w[2517]);
        mulmod_constant(t2, t2, two);
        submod(w[4945], t1, t2);
    }

    // AND 2241 3798 -> 4946
    mulmod(w[4946], w[2241], w[3798]);

    // INV 720 -> 4947
    submod(w[4947], one, w[720]);

    // AND 2386 4690 -> 4948
    mulmod(w[4948], w[2386], w[4690]);

    // XOR 283 2469 -> 4949
    {
        bn254fr_class t1, t2;
        addmod(t1, w[283], w[2469]);
        mulmod(t2, w[283], w[2469]);
        mulmod_constant(t2, t2, two);
        submod(w[4949], t1, t2);
    }

    // AND 550 4501 -> 4950
    mulmod(w[4950], w[550], w[4501]);

    // AND 65 452 -> 4951
    mulmod(w[4951], w[65], w[452]);

    // INV 4608 -> 4952
    submod(w[4952], one, w[4608]);

    // AND 4320 3206 -> 4953
    mulmod(w[4953], w[4320], w[3206]);

    // AND 1163 4280 -> 4954
    mulmod(w[4954], w[1163], w[4280]);

    // AND 1993 1966 -> 4955
    mulmod(w[4955], w[1993], w[1966]);

    // XOR 4109 752 -> 4956
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4109], w[752]);
        mulmod(t2, w[4109], w[752]);
        mulmod_constant(t2, t2, two);
        submod(w[4956], t1, t2);
    }

    // INV 1960 -> 4957
    submod(w[4957], one, w[1960]);

    // INV 1112 -> 4958
    submod(w[4958], one, w[1112]);

    // AND 3044 808 -> 4959
    mulmod(w[4959], w[3044], w[808]);

    // INV 1129 -> 4960
    submod(w[4960], one, w[1129]);

    // XOR 4880 1016 -> 4961
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4880], w[1016]);
        mulmod(t2, w[4880], w[1016]);
        mulmod_constant(t2, t2, two);
        submod(w[4961], t1, t2);
    }

    // XOR 3531 3650 -> 4962
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3531], w[3650]);
        mulmod(t2, w[3531], w[3650]);
        mulmod_constant(t2, t2, two);
        submod(w[4962], t1, t2);
    }

    // XOR 4122 4492 -> 4963
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4122], w[4492]);
        mulmod(t2, w[4122], w[4492]);
        mulmod_constant(t2, t2, two);
        submod(w[4963], t1, t2);
    }

    // AND 2527 3107 -> 4964
    mulmod(w[4964], w[2527], w[3107]);

    // AND 3599 230 -> 4965
    mulmod(w[4965], w[3599], w[230]);

    // INV 286 -> 4966
    submod(w[4966], one, w[286]);

    // XOR 2385 1865 -> 4967
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2385], w[1865]);
        mulmod(t2, w[2385], w[1865]);
        mulmod_constant(t2, t2, two);
        submod(w[4967], t1, t2);
    }

    // XOR 3898 3953 -> 4968
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3898], w[3953]);
        mulmod(t2, w[3898], w[3953]);
        mulmod_constant(t2, t2, two);
        submod(w[4968], t1, t2);
    }

    // AND 3192 3575 -> 4969
    mulmod(w[4969], w[3192], w[3575]);

    // XOR 2560 1460 -> 4970
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2560], w[1460]);
        mulmod(t2, w[2560], w[1460]);
        mulmod_constant(t2, t2, two);
        submod(w[4970], t1, t2);
    }

    // AND 182 2359 -> 4971
    mulmod(w[4971], w[182], w[2359]);

    // XOR 2223 4229 -> 4972
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2223], w[4229]);
        mulmod(t2, w[2223], w[4229]);
        mulmod_constant(t2, t2, two);
        submod(w[4972], t1, t2);
    }

    // XOR 862 1837 -> 4973
    {
        bn254fr_class t1, t2;
        addmod(t1, w[862], w[1837]);
        mulmod(t2, w[862], w[1837]);
        mulmod_constant(t2, t2, two);
        submod(w[4973], t1, t2);
    }

    // AND 2041 727 -> 4974
    mulmod(w[4974], w[2041], w[727]);

    // AND 239 816 -> 4975
    mulmod(w[4975], w[239], w[816]);

    // XOR 3242 1339 -> 4976
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3242], w[1339]);
        mulmod(t2, w[3242], w[1339]);
        mulmod_constant(t2, t2, two);
        submod(w[4976], t1, t2);
    }

    // XOR 1137 593 -> 4977
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1137], w[593]);
        mulmod(t2, w[1137], w[593]);
        mulmod_constant(t2, t2, two);
        submod(w[4977], t1, t2);
    }

    // AND 3274 4011 -> 4978
    mulmod(w[4978], w[3274], w[4011]);

    // XOR 3045 3603 -> 4979
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3045], w[3603]);
        mulmod(t2, w[3045], w[3603]);
        mulmod_constant(t2, t2, two);
        submod(w[4979], t1, t2);
    }

    // XOR 98 2134 -> 4980
    {
        bn254fr_class t1, t2;
        addmod(t1, w[98], w[2134]);
        mulmod(t2, w[98], w[2134]);
        mulmod_constant(t2, t2, two);
        submod(w[4980], t1, t2);
    }

    // XOR 740 3978 -> 4981
    {
        bn254fr_class t1, t2;
        addmod(t1, w[740], w[3978]);
        mulmod(t2, w[740], w[3978]);
        mulmod_constant(t2, t2, two);
        submod(w[4981], t1, t2);
    }

    // XOR 4914 4542 -> 4982
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4914], w[4542]);
        mulmod(t2, w[4914], w[4542]);
        mulmod_constant(t2, t2, two);
        submod(w[4982], t1, t2);
    }

    // XOR 2289 1427 -> 4983
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2289], w[1427]);
        mulmod(t2, w[2289], w[1427]);
        mulmod_constant(t2, t2, two);
        submod(w[4983], t1, t2);
    }

    // XOR 2017 734 -> 4984
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2017], w[734]);
        mulmod(t2, w[2017], w[734]);
        mulmod_constant(t2, t2, two);
        submod(w[4984], t1, t2);
    }

    // XOR 3851 828 -> 4985
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3851], w[828]);
        mulmod(t2, w[3851], w[828]);
        mulmod_constant(t2, t2, two);
        submod(w[4985], t1, t2);
    }

    // AND 1399 996 -> 4986
    mulmod(w[4986], w[1399], w[996]);

    // INV 348 -> 4987
    submod(w[4987], one, w[348]);

    // INV 1812 -> 4988
    submod(w[4988], one, w[1812]);

    // XOR 3439 4489 -> 4989
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3439], w[4489]);
        mulmod(t2, w[3439], w[4489]);
        mulmod_constant(t2, t2, two);
        submod(w[4989], t1, t2);
    }

    // XOR 4456 4527 -> 4990
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4456], w[4527]);
        mulmod(t2, w[4456], w[4527]);
        mulmod_constant(t2, t2, two);
        submod(w[4990], t1, t2);
    }

    // XOR 254 1438 -> 4991
    {
        bn254fr_class t1, t2;
        addmod(t1, w[254], w[1438]);
        mulmod(t2, w[254], w[1438]);
        mulmod_constant(t2, t2, two);
        submod(w[4991], t1, t2);
    }

    // XOR 1470 3699 -> 4992
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1470], w[3699]);
        mulmod(t2, w[1470], w[3699]);
        mulmod_constant(t2, t2, two);
        submod(w[4992], t1, t2);
    }

    // XOR 1821 4830 -> 4993
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1821], w[4830]);
        mulmod(t2, w[1821], w[4830]);
        mulmod_constant(t2, t2, two);
        submod(w[4993], t1, t2);
    }

    // XOR 537 3456 -> 4994
    {
        bn254fr_class t1, t2;
        addmod(t1, w[537], w[3456]);
        mulmod(t2, w[537], w[3456]);
        mulmod_constant(t2, t2, two);
        submod(w[4994], t1, t2);
    }

    // XOR 3177 1434 -> 4995
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3177], w[1434]);
        mulmod(t2, w[3177], w[1434]);
        mulmod_constant(t2, t2, two);
        submod(w[4995], t1, t2);
    }

    // XOR 4787 4909 -> 4996
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4787], w[4909]);
        mulmod(t2, w[4787], w[4909]);
        mulmod_constant(t2, t2, two);
        submod(w[4996], t1, t2);
    }

    // XOR 2690 1911 -> 4997
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2690], w[1911]);
        mulmod(t2, w[2690], w[1911]);
        mulmod_constant(t2, t2, two);
        submod(w[4997], t1, t2);
    }

    // XOR 613 2402 -> 4998
    {
        bn254fr_class t1, t2;
        addmod(t1, w[613], w[2402]);
        mulmod(t2, w[613], w[2402]);
        mulmod_constant(t2, t2, two);
        submod(w[4998], t1, t2);
    }

    // XOR 2953 337 -> 4999
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2953], w[337]);
        mulmod(t2, w[2953], w[337]);
        mulmod_constant(t2, t2, two);
        submod(w[4999], t1, t2);
    }

    // AND 1513 336 -> 5000
    mulmod(w[5000], w[1513], w[336]);

    // XOR 3696 150 -> 5001
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3696], w[150]);
        mulmod(t2, w[3696], w[150]);
        mulmod_constant(t2, t2, two);
        submod(w[5001], t1, t2);
    }

    // XOR 2364 4631 -> 5002
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2364], w[4631]);
        mulmod(t2, w[2364], w[4631]);
        mulmod_constant(t2, t2, two);
        submod(w[5002], t1, t2);
    }

    // INV 2934 -> 5003
    submod(w[5003], one, w[2934]);

    // XOR 1148 3931 -> 5004
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1148], w[3931]);
        mulmod(t2, w[1148], w[3931]);
        mulmod_constant(t2, t2, two);
        submod(w[5004], t1, t2);
    }

    // XOR 4408 949 -> 5005
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4408], w[949]);
        mulmod(t2, w[4408], w[949]);
        mulmod_constant(t2, t2, two);
        submod(w[5005], t1, t2);
    }

    // AND 4386 2547 -> 5006
    mulmod(w[5006], w[4386], w[2547]);

    // INV 1315 -> 5007
    submod(w[5007], one, w[1315]);

    // XOR 4747 441 -> 5008
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4747], w[441]);
        mulmod(t2, w[4747], w[441]);
        mulmod_constant(t2, t2, two);
        submod(w[5008], t1, t2);
    }

    // AND 2397 1946 -> 5009
    mulmod(w[5009], w[2397], w[1946]);

    // AND 4904 3178 -> 5010
    mulmod(w[5010], w[4904], w[3178]);

    // XOR 2054 1994 -> 5011
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2054], w[1994]);
        mulmod(t2, w[2054], w[1994]);
        mulmod_constant(t2, t2, two);
        submod(w[5011], t1, t2);
    }

    // XOR 2693 2806 -> 5012
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2693], w[2806]);
        mulmod(t2, w[2693], w[2806]);
        mulmod_constant(t2, t2, two);
        submod(w[5012], t1, t2);
    }

    // AND 931 3910 -> 5013
    mulmod(w[5013], w[931], w[3910]);

    // XOR 4675 3856 -> 5014
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4675], w[3856]);
        mulmod(t2, w[4675], w[3856]);
        mulmod_constant(t2, t2, two);
        submod(w[5014], t1, t2);
    }

    // XOR 446 4735 -> 5015
    {
        bn254fr_class t1, t2;
        addmod(t1, w[446], w[4735]);
        mulmod(t2, w[446], w[4735]);
        mulmod_constant(t2, t2, two);
        submod(w[5015], t1, t2);
    }

    // XOR 1515 1469 -> 5016
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1515], w[1469]);
        mulmod(t2, w[1515], w[1469]);
        mulmod_constant(t2, t2, two);
        submod(w[5016], t1, t2);
    }

    // INV 2910 -> 5017
    submod(w[5017], one, w[2910]);

    // XOR 958 1210 -> 5018
    {
        bn254fr_class t1, t2;
        addmod(t1, w[958], w[1210]);
        mulmod(t2, w[958], w[1210]);
        mulmod_constant(t2, t2, two);
        submod(w[5018], t1, t2);
    }

    // AND 923 3578 -> 5019
    mulmod(w[5019], w[923], w[3578]);

    // INV 1539 -> 5020
    submod(w[5020], one, w[1539]);

    // XOR 2150 1120 -> 5021
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2150], w[1120]);
        mulmod(t2, w[2150], w[1120]);
        mulmod_constant(t2, t2, two);
        submod(w[5021], t1, t2);
    }

    // AND 2548 186 -> 5022
    mulmod(w[5022], w[2548], w[186]);

    // AND 3233 2176 -> 5023
    mulmod(w[5023], w[3233], w[2176]);

    // XOR 4199 3281 -> 5024
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4199], w[3281]);
        mulmod(t2, w[4199], w[3281]);
        mulmod_constant(t2, t2, two);
        submod(w[5024], t1, t2);
    }

    // AND 2329 2287 -> 5025
    mulmod(w[5025], w[2329], w[2287]);

    // XOR 4693 1635 -> 5026
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4693], w[1635]);
        mulmod(t2, w[4693], w[1635]);
        mulmod_constant(t2, t2, two);
        submod(w[5026], t1, t2);
    }

    // XOR 1174 4565 -> 5027
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1174], w[4565]);
        mulmod(t2, w[1174], w[4565]);
        mulmod_constant(t2, t2, two);
        submod(w[5027], t1, t2);
    }

    // AND 1023 2283 -> 5028
    mulmod(w[5028], w[1023], w[2283]);

    // AND 2554 2520 -> 5029
    mulmod(w[5029], w[2554], w[2520]);

    // XOR 4477 2918 -> 5030
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4477], w[2918]);
        mulmod(t2, w[4477], w[2918]);
        mulmod_constant(t2, t2, two);
        submod(w[5030], t1, t2);
    }

    // XOR 1422 4632 -> 5031
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1422], w[4632]);
        mulmod(t2, w[1422], w[4632]);
        mulmod_constant(t2, t2, two);
        submod(w[5031], t1, t2);
    }

    // AND 116 3538 -> 5032
    mulmod(w[5032], w[116], w[3538]);

    // XOR 348 4836 -> 5033
    {
        bn254fr_class t1, t2;
        addmod(t1, w[348], w[4836]);
        mulmod(t2, w[348], w[4836]);
        mulmod_constant(t2, t2, two);
        submod(w[5033], t1, t2);
    }

    // XOR 428 3190 -> 5034
    {
        bn254fr_class t1, t2;
        addmod(t1, w[428], w[3190]);
        mulmod(t2, w[428], w[3190]);
        mulmod_constant(t2, t2, two);
        submod(w[5034], t1, t2);
    }

    // XOR 4090 760 -> 5035
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4090], w[760]);
        mulmod(t2, w[4090], w[760]);
        mulmod_constant(t2, t2, two);
        submod(w[5035], t1, t2);
    }

    // XOR 3405 3074 -> 5036
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3405], w[3074]);
        mulmod(t2, w[3405], w[3074]);
        mulmod_constant(t2, t2, two);
        submod(w[5036], t1, t2);
    }

    // XOR 2216 1887 -> 5037
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2216], w[1887]);
        mulmod(t2, w[2216], w[1887]);
        mulmod_constant(t2, t2, two);
        submod(w[5037], t1, t2);
    }

    // XOR 3026 1106 -> 5038
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3026], w[1106]);
        mulmod(t2, w[3026], w[1106]);
        mulmod_constant(t2, t2, two);
        submod(w[5038], t1, t2);
    }

    // AND 3461 1293 -> 5039
    mulmod(w[5039], w[3461], w[1293]);

    // XOR 4517 307 -> 5040
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4517], w[307]);
        mulmod(t2, w[4517], w[307]);
        mulmod_constant(t2, t2, two);
        submod(w[5040], t1, t2);
    }

    // AND 4763 3412 -> 5041
    mulmod(w[5041], w[4763], w[3412]);

    // INV 2859 -> 5042
    submod(w[5042], one, w[2859]);

    // AND 4320 1543 -> 5043
    mulmod(w[5043], w[4320], w[1543]);

    // AND 1859 1199 -> 5044
    mulmod(w[5044], w[1859], w[1199]);

    // AND 84 2167 -> 5045
    mulmod(w[5045], w[84], w[2167]);

    // AND 3506 3038 -> 5046
    mulmod(w[5046], w[3506], w[3038]);

    // XOR 2498 3987 -> 5047
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2498], w[3987]);
        mulmod(t2, w[2498], w[3987]);
        mulmod_constant(t2, t2, two);
        submod(w[5047], t1, t2);
    }

    // XOR 2230 1228 -> 5048
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2230], w[1228]);
        mulmod(t2, w[2230], w[1228]);
        mulmod_constant(t2, t2, two);
        submod(w[5048], t1, t2);
    }

    // AND 2182 3689 -> 5049
    mulmod(w[5049], w[2182], w[3689]);

    // XOR 1671 2808 -> 5050
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1671], w[2808]);
        mulmod(t2, w[1671], w[2808]);
        mulmod_constant(t2, t2, two);
        submod(w[5050], t1, t2);
    }

    // XOR 1205 1294 -> 5051
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1205], w[1294]);
        mulmod(t2, w[1205], w[1294]);
        mulmod_constant(t2, t2, two);
        submod(w[5051], t1, t2);
    }

    // INV 4799 -> 5052
    submod(w[5052], one, w[4799]);

    // XOR 4539 2103 -> 5053
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4539], w[2103]);
        mulmod(t2, w[4539], w[2103]);
        mulmod_constant(t2, t2, two);
        submod(w[5053], t1, t2);
    }

    // AND 3146 591 -> 5054
    mulmod(w[5054], w[3146], w[591]);

    // XOR 2804 4842 -> 5055
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2804], w[4842]);
        mulmod(t2, w[2804], w[4842]);
        mulmod_constant(t2, t2, two);
        submod(w[5055], t1, t2);
    }

    // XOR 1492 1311 -> 5056
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1492], w[1311]);
        mulmod(t2, w[1492], w[1311]);
        mulmod_constant(t2, t2, two);
        submod(w[5056], t1, t2);
    }

    // INV 970 -> 5057
    submod(w[5057], one, w[970]);

    // AND 2543 3276 -> 5058
    mulmod(w[5058], w[2543], w[3276]);

    // AND 1034 1417 -> 5059
    mulmod(w[5059], w[1034], w[1417]);

    // XOR 4044 639 -> 5060
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4044], w[639]);
        mulmod(t2, w[4044], w[639]);
        mulmod_constant(t2, t2, two);
        submod(w[5060], t1, t2);
    }

    // AND 1279 3334 -> 5061
    mulmod(w[5061], w[1279], w[3334]);

    // AND 4691 1859 -> 5062
    mulmod(w[5062], w[4691], w[1859]);

    // XOR 1934 2328 -> 5063
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1934], w[2328]);
        mulmod(t2, w[1934], w[2328]);
        mulmod_constant(t2, t2, two);
        submod(w[5063], t1, t2);
    }

    // XOR 3263 2485 -> 5064
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3263], w[2485]);
        mulmod(t2, w[3263], w[2485]);
        mulmod_constant(t2, t2, two);
        submod(w[5064], t1, t2);
    }

    // XOR 1106 40 -> 5065
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1106], w[40]);
        mulmod(t2, w[1106], w[40]);
        mulmod_constant(t2, t2, two);
        submod(w[5065], t1, t2);
    }

    // XOR 3309 2741 -> 5066
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3309], w[2741]);
        mulmod(t2, w[3309], w[2741]);
        mulmod_constant(t2, t2, two);
        submod(w[5066], t1, t2);
    }

    // XOR 1718 2256 -> 5067
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1718], w[2256]);
        mulmod(t2, w[1718], w[2256]);
        mulmod_constant(t2, t2, two);
        submod(w[5067], t1, t2);
    }

    // XOR 2927 1460 -> 5068
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2927], w[1460]);
        mulmod(t2, w[2927], w[1460]);
        mulmod_constant(t2, t2, two);
        submod(w[5068], t1, t2);
    }

    // INV 1928 -> 5069
    submod(w[5069], one, w[1928]);

    // XOR 774 4437 -> 5070
    {
        bn254fr_class t1, t2;
        addmod(t1, w[774], w[4437]);
        mulmod(t2, w[774], w[4437]);
        mulmod_constant(t2, t2, two);
        submod(w[5070], t1, t2);
    }

    // XOR 407 4461 -> 5071
    {
        bn254fr_class t1, t2;
        addmod(t1, w[407], w[4461]);
        mulmod(t2, w[407], w[4461]);
        mulmod_constant(t2, t2, two);
        submod(w[5071], t1, t2);
    }

    // XOR 3457 3252 -> 5072
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3457], w[3252]);
        mulmod(t2, w[3457], w[3252]);
        mulmod_constant(t2, t2, two);
        submod(w[5072], t1, t2);
    }

    // XOR 936 1651 -> 5073
    {
        bn254fr_class t1, t2;
        addmod(t1, w[936], w[1651]);
        mulmod(t2, w[936], w[1651]);
        mulmod_constant(t2, t2, two);
        submod(w[5073], t1, t2);
    }

    // AND 2583 1498 -> 5074
    mulmod(w[5074], w[2583], w[1498]);

    // INV 403 -> 5075
    submod(w[5075], one, w[403]);

    // AND 3725 1129 -> 5076
    mulmod(w[5076], w[3725], w[1129]);

    // AND 1989 3120 -> 5077
    mulmod(w[5077], w[1989], w[3120]);

    // INV 4780 -> 5078
    submod(w[5078], one, w[4780]);

    // XOR 492 4583 -> 5079
    {
        bn254fr_class t1, t2;
        addmod(t1, w[492], w[4583]);
        mulmod(t2, w[492], w[4583]);
        mulmod_constant(t2, t2, two);
        submod(w[5079], t1, t2);
    }

    // AND 3732 2801 -> 5080
    mulmod(w[5080], w[3732], w[2801]);

    // XOR 1327 4205 -> 5081
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1327], w[4205]);
        mulmod(t2, w[1327], w[4205]);
        mulmod_constant(t2, t2, two);
        submod(w[5081], t1, t2);
    }

    // XOR 2963 726 -> 5082
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2963], w[726]);
        mulmod(t2, w[2963], w[726]);
        mulmod_constant(t2, t2, two);
        submod(w[5082], t1, t2);
    }

    // XOR 48 3624 -> 5083
    {
        bn254fr_class t1, t2;
        addmod(t1, w[48], w[3624]);
        mulmod(t2, w[48], w[3624]);
        mulmod_constant(t2, t2, two);
        submod(w[5083], t1, t2);
    }

    // INV 949 -> 5084
    submod(w[5084], one, w[949]);

    // XOR 1820 2754 -> 5085
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1820], w[2754]);
        mulmod(t2, w[1820], w[2754]);
        mulmod_constant(t2, t2, two);
        submod(w[5085], t1, t2);
    }

    // AND 124 1411 -> 5086
    mulmod(w[5086], w[124], w[1411]);

    // XOR 4708 269 -> 5087
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4708], w[269]);
        mulmod(t2, w[4708], w[269]);
        mulmod_constant(t2, t2, two);
        submod(w[5087], t1, t2);
    }

    // AND 3292 2257 -> 5088
    mulmod(w[5088], w[3292], w[2257]);

    // XOR 2660 1077 -> 5089
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2660], w[1077]);
        mulmod(t2, w[2660], w[1077]);
        mulmod_constant(t2, t2, two);
        submod(w[5089], t1, t2);
    }

    // XOR 3948 3333 -> 5090
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3948], w[3333]);
        mulmod(t2, w[3948], w[3333]);
        mulmod_constant(t2, t2, two);
        submod(w[5090], t1, t2);
    }

    // XOR 604 5069 -> 5091
    {
        bn254fr_class t1, t2;
        addmod(t1, w[604], w[5069]);
        mulmod(t2, w[604], w[5069]);
        mulmod_constant(t2, t2, two);
        submod(w[5091], t1, t2);
    }

    // AND 479 2768 -> 5092
    mulmod(w[5092], w[479], w[2768]);

    // INV 4371 -> 5093
    submod(w[5093], one, w[4371]);

    // XOR 660 32 -> 5094
    {
        bn254fr_class t1, t2;
        addmod(t1, w[660], w[32]);
        mulmod(t2, w[660], w[32]);
        mulmod_constant(t2, t2, two);
        submod(w[5094], t1, t2);
    }

    // XOR 49 2855 -> 5095
    {
        bn254fr_class t1, t2;
        addmod(t1, w[49], w[2855]);
        mulmod(t2, w[49], w[2855]);
        mulmod_constant(t2, t2, two);
        submod(w[5095], t1, t2);
    }

    // AND 2072 3638 -> 5096
    mulmod(w[5096], w[2072], w[3638]);

    // XOR 1104 3388 -> 5097
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1104], w[3388]);
        mulmod(t2, w[1104], w[3388]);
        mulmod_constant(t2, t2, two);
        submod(w[5097], t1, t2);
    }

    // INV 2678 -> 5098
    submod(w[5098], one, w[2678]);

    // XOR 2312 3900 -> 5099
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2312], w[3900]);
        mulmod(t2, w[2312], w[3900]);
        mulmod_constant(t2, t2, two);
        submod(w[5099], t1, t2);
    }

    // AND 3913 3600 -> 5100
    mulmod(w[5100], w[3913], w[3600]);

    // AND 231 4498 -> 5101
    mulmod(w[5101], w[231], w[4498]);

    // XOR 4201 4961 -> 5102
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4201], w[4961]);
        mulmod(t2, w[4201], w[4961]);
        mulmod_constant(t2, t2, two);
        submod(w[5102], t1, t2);
    }

    // AND 4212 3434 -> 5103
    mulmod(w[5103], w[4212], w[3434]);

    // AND 2802 915 -> 5104
    mulmod(w[5104], w[2802], w[915]);

    // XOR 4264 3567 -> 5105
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4264], w[3567]);
        mulmod(t2, w[4264], w[3567]);
        mulmod_constant(t2, t2, two);
        submod(w[5105], t1, t2);
    }

    // XOR 1849 5027 -> 5106
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1849], w[5027]);
        mulmod(t2, w[1849], w[5027]);
        mulmod_constant(t2, t2, two);
        submod(w[5106], t1, t2);
    }

    // XOR 2107 188 -> 5107
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2107], w[188]);
        mulmod(t2, w[2107], w[188]);
        mulmod_constant(t2, t2, two);
        submod(w[5107], t1, t2);
    }

    // XOR 2438 2664 -> 5108
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2438], w[2664]);
        mulmod(t2, w[2438], w[2664]);
        mulmod_constant(t2, t2, two);
        submod(w[5108], t1, t2);
    }

    // XOR 2278 1573 -> 5109
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2278], w[1573]);
        mulmod(t2, w[2278], w[1573]);
        mulmod_constant(t2, t2, two);
        submod(w[5109], t1, t2);
    }

    // XOR 4441 3924 -> 5110
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4441], w[3924]);
        mulmod(t2, w[4441], w[3924]);
        mulmod_constant(t2, t2, two);
        submod(w[5110], t1, t2);
    }

    // XOR 409 419 -> 5111
    {
        bn254fr_class t1, t2;
        addmod(t1, w[409], w[419]);
        mulmod(t2, w[409], w[419]);
        mulmod_constant(t2, t2, two);
        submod(w[5111], t1, t2);
    }

    // AND 4613 4945 -> 5112
    mulmod(w[5112], w[4613], w[4945]);

    // XOR 3003 155 -> 5113
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3003], w[155]);
        mulmod(t2, w[3003], w[155]);
        mulmod_constant(t2, t2, two);
        submod(w[5113], t1, t2);
    }

    // AND 1090 2760 -> 5114
    mulmod(w[5114], w[1090], w[2760]);

    // XOR 4222 3245 -> 5115
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4222], w[3245]);
        mulmod(t2, w[4222], w[3245]);
        mulmod_constant(t2, t2, two);
        submod(w[5115], t1, t2);
    }

    // XOR 4030 2294 -> 5116
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4030], w[2294]);
        mulmod(t2, w[4030], w[2294]);
        mulmod_constant(t2, t2, two);
        submod(w[5116], t1, t2);
    }

    // AND 1640 1447 -> 5117
    mulmod(w[5117], w[1640], w[1447]);

    // XOR 4037 4310 -> 5118
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4037], w[4310]);
        mulmod(t2, w[4037], w[4310]);
        mulmod_constant(t2, t2, two);
        submod(w[5118], t1, t2);
    }

    // AND 1585 150 -> 5119
    mulmod(w[5119], w[1585], w[150]);

    // XOR 1174 2997 -> 5120
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1174], w[2997]);
        mulmod(t2, w[1174], w[2997]);
        mulmod_constant(t2, t2, two);
        submod(w[5120], t1, t2);
    }

    // XOR 3981 4772 -> 5121
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3981], w[4772]);
        mulmod(t2, w[3981], w[4772]);
        mulmod_constant(t2, t2, two);
        submod(w[5121], t1, t2);
    }

    // XOR 3513 2705 -> 5122
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3513], w[2705]);
        mulmod(t2, w[3513], w[2705]);
        mulmod_constant(t2, t2, two);
        submod(w[5122], t1, t2);
    }

    // XOR 1896 1907 -> 5123
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1896], w[1907]);
        mulmod(t2, w[1896], w[1907]);
        mulmod_constant(t2, t2, two);
        submod(w[5123], t1, t2);
    }

    // XOR 2242 3788 -> 5124
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2242], w[3788]);
        mulmod(t2, w[2242], w[3788]);
        mulmod_constant(t2, t2, two);
        submod(w[5124], t1, t2);
    }

    // XOR 1866 481 -> 5125
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1866], w[481]);
        mulmod(t2, w[1866], w[481]);
        mulmod_constant(t2, t2, two);
        submod(w[5125], t1, t2);
    }

    // AND 2461 1266 -> 5126
    mulmod(w[5126], w[2461], w[1266]);

    // AND 287 4967 -> 5127
    mulmod(w[5127], w[287], w[4967]);

    // XOR 1403 4401 -> 5128
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1403], w[4401]);
        mulmod(t2, w[1403], w[4401]);
        mulmod_constant(t2, t2, two);
        submod(w[5128], t1, t2);
    }

    // XOR 4700 770 -> 5129
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4700], w[770]);
        mulmod(t2, w[4700], w[770]);
        mulmod_constant(t2, t2, two);
        submod(w[5129], t1, t2);
    }

    // XOR 3184 4121 -> 5130
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3184], w[4121]);
        mulmod(t2, w[3184], w[4121]);
        mulmod_constant(t2, t2, two);
        submod(w[5130], t1, t2);
    }

    // XOR 1837 2723 -> 5131
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1837], w[2723]);
        mulmod(t2, w[1837], w[2723]);
        mulmod_constant(t2, t2, two);
        submod(w[5131], t1, t2);
    }

    // INV 3521 -> 5132
    submod(w[5132], one, w[3521]);

    // AND 2531 4277 -> 5133
    mulmod(w[5133], w[2531], w[4277]);

    // XOR 4644 3162 -> 5134
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4644], w[3162]);
        mulmod(t2, w[4644], w[3162]);
        mulmod_constant(t2, t2, two);
        submod(w[5134], t1, t2);
    }

    // XOR 3345 3529 -> 5135
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3345], w[3529]);
        mulmod(t2, w[3345], w[3529]);
        mulmod_constant(t2, t2, two);
        submod(w[5135], t1, t2);
    }

    // XOR 4762 2816 -> 5136
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4762], w[2816]);
        mulmod(t2, w[4762], w[2816]);
        mulmod_constant(t2, t2, two);
        submod(w[5136], t1, t2);
    }

    // XOR 3135 4433 -> 5137
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3135], w[4433]);
        mulmod(t2, w[3135], w[4433]);
        mulmod_constant(t2, t2, two);
        submod(w[5137], t1, t2);
    }

    // AND 779 1923 -> 5138
    mulmod(w[5138], w[779], w[1923]);

    // XOR 3799 3090 -> 5139
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3799], w[3090]);
        mulmod(t2, w[3799], w[3090]);
        mulmod_constant(t2, t2, two);
        submod(w[5139], t1, t2);
    }

    // INV 3577 -> 5140
    submod(w[5140], one, w[3577]);

    // AND 3700 608 -> 5141
    mulmod(w[5141], w[3700], w[608]);

    // AND 1075 1760 -> 5142
    mulmod(w[5142], w[1075], w[1760]);

    // XOR 3517 671 -> 5143
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3517], w[671]);
        mulmod(t2, w[3517], w[671]);
        mulmod_constant(t2, t2, two);
        submod(w[5143], t1, t2);
    }

    // XOR 2863 3632 -> 5144
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2863], w[3632]);
        mulmod(t2, w[2863], w[3632]);
        mulmod_constant(t2, t2, two);
        submod(w[5144], t1, t2);
    }

    // XOR 2786 4200 -> 5145
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2786], w[4200]);
        mulmod(t2, w[2786], w[4200]);
        mulmod_constant(t2, t2, two);
        submod(w[5145], t1, t2);
    }

    // XOR 1908 4728 -> 5146
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1908], w[4728]);
        mulmod(t2, w[1908], w[4728]);
        mulmod_constant(t2, t2, two);
        submod(w[5146], t1, t2);
    }

    // XOR 1317 1811 -> 5147
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1317], w[1811]);
        mulmod(t2, w[1317], w[1811]);
        mulmod_constant(t2, t2, two);
        submod(w[5147], t1, t2);
    }

    // XOR 3988 3097 -> 5148
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3988], w[3097]);
        mulmod(t2, w[3988], w[3097]);
        mulmod_constant(t2, t2, two);
        submod(w[5148], t1, t2);
    }

    // XOR 3002 2820 -> 5149
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3002], w[2820]);
        mulmod(t2, w[3002], w[2820]);
        mulmod_constant(t2, t2, two);
        submod(w[5149], t1, t2);
    }

    // XOR 1742 3906 -> 5150
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1742], w[3906]);
        mulmod(t2, w[1742], w[3906]);
        mulmod_constant(t2, t2, two);
        submod(w[5150], t1, t2);
    }

    // XOR 2313 4570 -> 5151
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2313], w[4570]);
        mulmod(t2, w[2313], w[4570]);
        mulmod_constant(t2, t2, two);
        submod(w[5151], t1, t2);
    }

    // AND 3800 688 -> 5152
    mulmod(w[5152], w[3800], w[688]);

    // XOR 4635 1423 -> 5153
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4635], w[1423]);
        mulmod(t2, w[4635], w[1423]);
        mulmod_constant(t2, t2, two);
        submod(w[5153], t1, t2);
    }

    // AND 3906 1658 -> 5154
    mulmod(w[5154], w[3906], w[1658]);

    // XOR 1340 3391 -> 5155
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1340], w[3391]);
        mulmod(t2, w[1340], w[3391]);
        mulmod_constant(t2, t2, two);
        submod(w[5155], t1, t2);
    }

    // AND 2776 465 -> 5156
    mulmod(w[5156], w[2776], w[465]);

    // XOR 2232 362 -> 5157
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2232], w[362]);
        mulmod(t2, w[2232], w[362]);
        mulmod_constant(t2, t2, two);
        submod(w[5157], t1, t2);
    }

    // XOR 2928 421 -> 5158
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2928], w[421]);
        mulmod(t2, w[2928], w[421]);
        mulmod_constant(t2, t2, two);
        submod(w[5158], t1, t2);
    }

    // AND 358 3827 -> 5159
    mulmod(w[5159], w[358], w[3827]);

    // XOR 1774 1800 -> 5160
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1774], w[1800]);
        mulmod(t2, w[1774], w[1800]);
        mulmod_constant(t2, t2, two);
        submod(w[5160], t1, t2);
    }

    // INV 919 -> 5161
    submod(w[5161], one, w[919]);

    // XOR 3236 1629 -> 5162
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3236], w[1629]);
        mulmod(t2, w[3236], w[1629]);
        mulmod_constant(t2, t2, two);
        submod(w[5162], t1, t2);
    }

    // AND 609 791 -> 5163
    mulmod(w[5163], w[609], w[791]);

    // XOR 3481 2709 -> 5164
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3481], w[2709]);
        mulmod(t2, w[3481], w[2709]);
        mulmod_constant(t2, t2, two);
        submod(w[5164], t1, t2);
    }

    // XOR 4544 840 -> 5165
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4544], w[840]);
        mulmod(t2, w[4544], w[840]);
        mulmod_constant(t2, t2, two);
        submod(w[5165], t1, t2);
    }

    // AND 4855 4823 -> 5166
    mulmod(w[5166], w[4855], w[4823]);

    // XOR 372 1354 -> 5167
    {
        bn254fr_class t1, t2;
        addmod(t1, w[372], w[1354]);
        mulmod(t2, w[372], w[1354]);
        mulmod_constant(t2, t2, two);
        submod(w[5167], t1, t2);
    }

    // AND 4542 1189 -> 5168
    mulmod(w[5168], w[4542], w[1189]);

    // XOR 3165 2424 -> 5169
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3165], w[2424]);
        mulmod(t2, w[3165], w[2424]);
        mulmod_constant(t2, t2, two);
        submod(w[5169], t1, t2);
    }

    // XOR 755 2277 -> 5170
    {
        bn254fr_class t1, t2;
        addmod(t1, w[755], w[2277]);
        mulmod(t2, w[755], w[2277]);
        mulmod_constant(t2, t2, two);
        submod(w[5170], t1, t2);
    }

    // XOR 146 3047 -> 5171
    {
        bn254fr_class t1, t2;
        addmod(t1, w[146], w[3047]);
        mulmod(t2, w[146], w[3047]);
        mulmod_constant(t2, t2, two);
        submod(w[5171], t1, t2);
    }

    // INV 1778 -> 5172
    submod(w[5172], one, w[1778]);

    // XOR 1813 3750 -> 5173
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1813], w[3750]);
        mulmod(t2, w[1813], w[3750]);
        mulmod_constant(t2, t2, two);
        submod(w[5173], t1, t2);
    }

    // AND 4381 678 -> 5174
    mulmod(w[5174], w[4381], w[678]);

    // XOR 3775 2924 -> 5175
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3775], w[2924]);
        mulmod(t2, w[3775], w[2924]);
        mulmod_constant(t2, t2, two);
        submod(w[5175], t1, t2);
    }

    // INV 134 -> 5176
    submod(w[5176], one, w[134]);

    // AND 1302 1350 -> 5177
    mulmod(w[5177], w[1302], w[1350]);

    // AND 3125 2564 -> 5178
    mulmod(w[5178], w[3125], w[2564]);

    // XOR 2841 1901 -> 5179
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2841], w[1901]);
        mulmod(t2, w[2841], w[1901]);
        mulmod_constant(t2, t2, two);
        submod(w[5179], t1, t2);
    }

    // XOR 1515 3874 -> 5180
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1515], w[3874]);
        mulmod(t2, w[1515], w[3874]);
        mulmod_constant(t2, t2, two);
        submod(w[5180], t1, t2);
    }

    // XOR 2674 1425 -> 5181
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2674], w[1425]);
        mulmod(t2, w[2674], w[1425]);
        mulmod_constant(t2, t2, two);
        submod(w[5181], t1, t2);
    }

    // XOR 3892 1183 -> 5182
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3892], w[1183]);
        mulmod(t2, w[3892], w[1183]);
        mulmod_constant(t2, t2, two);
        submod(w[5182], t1, t2);
    }

    // INV 1230 -> 5183
    submod(w[5183], one, w[1230]);

    // XOR 3061 4382 -> 5184
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3061], w[4382]);
        mulmod(t2, w[3061], w[4382]);
        mulmod_constant(t2, t2, two);
        submod(w[5184], t1, t2);
    }

    // XOR 3874 2300 -> 5185
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3874], w[2300]);
        mulmod(t2, w[3874], w[2300]);
        mulmod_constant(t2, t2, two);
        submod(w[5185], t1, t2);
    }

    // XOR 2210 4218 -> 5186
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2210], w[4218]);
        mulmod(t2, w[2210], w[4218]);
        mulmod_constant(t2, t2, two);
        submod(w[5186], t1, t2);
    }

    // XOR 1899 4992 -> 5187
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1899], w[4992]);
        mulmod(t2, w[1899], w[4992]);
        mulmod_constant(t2, t2, two);
        submod(w[5187], t1, t2);
    }

    // XOR 54 4854 -> 5188
    {
        bn254fr_class t1, t2;
        addmod(t1, w[54], w[4854]);
        mulmod(t2, w[54], w[4854]);
        mulmod_constant(t2, t2, two);
        submod(w[5188], t1, t2);
    }

    // XOR 733 1079 -> 5189
    {
        bn254fr_class t1, t2;
        addmod(t1, w[733], w[1079]);
        mulmod(t2, w[733], w[1079]);
        mulmod_constant(t2, t2, two);
        submod(w[5189], t1, t2);
    }

    // INV 3484 -> 5190
    submod(w[5190], one, w[3484]);

    // XOR 2284 633 -> 5191
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2284], w[633]);
        mulmod(t2, w[2284], w[633]);
        mulmod_constant(t2, t2, two);
        submod(w[5191], t1, t2);
    }

    // XOR 3331 3249 -> 5192
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3331], w[3249]);
        mulmod(t2, w[3331], w[3249]);
        mulmod_constant(t2, t2, two);
        submod(w[5192], t1, t2);
    }

    // XOR 4194 4673 -> 5193
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4194], w[4673]);
        mulmod(t2, w[4194], w[4673]);
        mulmod_constant(t2, t2, two);
        submod(w[5193], t1, t2);
    }

    // XOR 1992 3806 -> 5194
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1992], w[3806]);
        mulmod(t2, w[1992], w[3806]);
        mulmod_constant(t2, t2, two);
        submod(w[5194], t1, t2);
    }

    // XOR 1305 719 -> 5195
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1305], w[719]);
        mulmod(t2, w[1305], w[719]);
        mulmod_constant(t2, t2, two);
        submod(w[5195], t1, t2);
    }

    // AND 4101 1350 -> 5196
    mulmod(w[5196], w[4101], w[1350]);

    // XOR 4163 1509 -> 5197
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4163], w[1509]);
        mulmod(t2, w[4163], w[1509]);
        mulmod_constant(t2, t2, two);
        submod(w[5197], t1, t2);
    }

    // AND 822 538 -> 5198
    mulmod(w[5198], w[822], w[538]);

    // XOR 2306 1221 -> 5199
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2306], w[1221]);
        mulmod(t2, w[2306], w[1221]);
        mulmod_constant(t2, t2, two);
        submod(w[5199], t1, t2);
    }

    // XOR 2162 3186 -> 5200
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2162], w[3186]);
        mulmod(t2, w[2162], w[3186]);
        mulmod_constant(t2, t2, two);
        submod(w[5200], t1, t2);
    }

    // AND 3263 1646 -> 5201
    mulmod(w[5201], w[3263], w[1646]);

    // AND 2389 5143 -> 5202
    mulmod(w[5202], w[2389], w[5143]);

    // XOR 2007 1995 -> 5203
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2007], w[1995]);
        mulmod(t2, w[2007], w[1995]);
        mulmod_constant(t2, t2, two);
        submod(w[5203], t1, t2);
    }

    // XOR 1659 4298 -> 5204
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1659], w[4298]);
        mulmod(t2, w[1659], w[4298]);
        mulmod_constant(t2, t2, two);
        submod(w[5204], t1, t2);
    }

    // XOR 2359 3805 -> 5205
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2359], w[3805]);
        mulmod(t2, w[2359], w[3805]);
        mulmod_constant(t2, t2, two);
        submod(w[5205], t1, t2);
    }

    // XOR 1782 5057 -> 5206
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1782], w[5057]);
        mulmod(t2, w[1782], w[5057]);
        mulmod_constant(t2, t2, two);
        submod(w[5206], t1, t2);
    }

    // AND 4698 552 -> 5207
    mulmod(w[5207], w[4698], w[552]);

    // INV 3389 -> 5208
    submod(w[5208], one, w[3389]);

    // XOR 4901 577 -> 5209
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4901], w[577]);
        mulmod(t2, w[4901], w[577]);
        mulmod_constant(t2, t2, two);
        submod(w[5209], t1, t2);
    }

    // AND 2947 3739 -> 5210
    mulmod(w[5210], w[2947], w[3739]);

    // XOR 504 4753 -> 5211
    {
        bn254fr_class t1, t2;
        addmod(t1, w[504], w[4753]);
        mulmod(t2, w[504], w[4753]);
        mulmod_constant(t2, t2, two);
        submod(w[5211], t1, t2);
    }

    // AND 1096 381 -> 5212
    mulmod(w[5212], w[1096], w[381]);

    // AND 1200 2432 -> 5213
    mulmod(w[5213], w[1200], w[2432]);

    // XOR 2051 252 -> 5214
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2051], w[252]);
        mulmod(t2, w[2051], w[252]);
        mulmod_constant(t2, t2, two);
        submod(w[5214], t1, t2);
    }

    // AND 203 4056 -> 5215
    mulmod(w[5215], w[203], w[4056]);

    // XOR 3224 2299 -> 5216
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3224], w[2299]);
        mulmod(t2, w[3224], w[2299]);
        mulmod_constant(t2, t2, two);
        submod(w[5216], t1, t2);
    }

    // XOR 735 4654 -> 5217
    {
        bn254fr_class t1, t2;
        addmod(t1, w[735], w[4654]);
        mulmod(t2, w[735], w[4654]);
        mulmod_constant(t2, t2, two);
        submod(w[5217], t1, t2);
    }

    // INV 3890 -> 5218
    submod(w[5218], one, w[3890]);

    // XOR 808 1371 -> 5219
    {
        bn254fr_class t1, t2;
        addmod(t1, w[808], w[1371]);
        mulmod(t2, w[808], w[1371]);
        mulmod_constant(t2, t2, two);
        submod(w[5219], t1, t2);
    }

    // AND 235 463 -> 5220
    mulmod(w[5220], w[235], w[463]);

    // AND 1496 3373 -> 5221
    mulmod(w[5221], w[1496], w[3373]);

    // AND 1554 1597 -> 5222
    mulmod(w[5222], w[1554], w[1597]);

    // XOR 3631 3060 -> 5223
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3631], w[3060]);
        mulmod(t2, w[3631], w[3060]);
        mulmod_constant(t2, t2, two);
        submod(w[5223], t1, t2);
    }

    // XOR 367 825 -> 5224
    {
        bn254fr_class t1, t2;
        addmod(t1, w[367], w[825]);
        mulmod(t2, w[367], w[825]);
        mulmod_constant(t2, t2, two);
        submod(w[5224], t1, t2);
    }

    // AND 2218 757 -> 5225
    mulmod(w[5225], w[2218], w[757]);

    // XOR 4904 2181 -> 5226
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4904], w[2181]);
        mulmod(t2, w[4904], w[2181]);
        mulmod_constant(t2, t2, two);
        submod(w[5226], t1, t2);
    }

    // AND 4693 1847 -> 5227
    mulmod(w[5227], w[4693], w[1847]);

    // XOR 3164 1792 -> 5228
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3164], w[1792]);
        mulmod(t2, w[3164], w[1792]);
        mulmod_constant(t2, t2, two);
        submod(w[5228], t1, t2);
    }

    // AND 843 375 -> 5229
    mulmod(w[5229], w[843], w[375]);

    // AND 1365 1990 -> 5230
    mulmod(w[5230], w[1365], w[1990]);

    // XOR 5080 2046 -> 5231
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5080], w[2046]);
        mulmod(t2, w[5080], w[2046]);
        mulmod_constant(t2, t2, two);
        submod(w[5231], t1, t2);
    }

    // XOR 4147 4691 -> 5232
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4147], w[4691]);
        mulmod(t2, w[4147], w[4691]);
        mulmod_constant(t2, t2, two);
        submod(w[5232], t1, t2);
    }

    // XOR 1291 2557 -> 5233
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1291], w[2557]);
        mulmod(t2, w[1291], w[2557]);
        mulmod_constant(t2, t2, two);
        submod(w[5233], t1, t2);
    }

    // XOR 1180 335 -> 5234
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1180], w[335]);
        mulmod(t2, w[1180], w[335]);
        mulmod_constant(t2, t2, two);
        submod(w[5234], t1, t2);
    }

    // XOR 3696 2755 -> 5235
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3696], w[2755]);
        mulmod(t2, w[3696], w[2755]);
        mulmod_constant(t2, t2, two);
        submod(w[5235], t1, t2);
    }

    // XOR 4028 3307 -> 5236
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4028], w[3307]);
        mulmod(t2, w[4028], w[3307]);
        mulmod_constant(t2, t2, two);
        submod(w[5236], t1, t2);
    }

    // XOR 3236 1836 -> 5237
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3236], w[1836]);
        mulmod(t2, w[3236], w[1836]);
        mulmod_constant(t2, t2, two);
        submod(w[5237], t1, t2);
    }

    // AND 2175 2959 -> 5238
    mulmod(w[5238], w[2175], w[2959]);

    // INV 350 -> 5239
    submod(w[5239], one, w[350]);

    // AND 2604 2728 -> 5240
    mulmod(w[5240], w[2604], w[2728]);

    // XOR 2759 3400 -> 5241
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2759], w[3400]);
        mulmod(t2, w[2759], w[3400]);
        mulmod_constant(t2, t2, two);
        submod(w[5241], t1, t2);
    }

    // XOR 5088 4214 -> 5242
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5088], w[4214]);
        mulmod(t2, w[5088], w[4214]);
        mulmod_constant(t2, t2, two);
        submod(w[5242], t1, t2);
    }

    // AND 2744 627 -> 5243
    mulmod(w[5243], w[2744], w[627]);

    // AND 4728 665 -> 5244
    mulmod(w[5244], w[4728], w[665]);

    // XOR 4591 2338 -> 5245
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4591], w[2338]);
        mulmod(t2, w[4591], w[2338]);
        mulmod_constant(t2, t2, two);
        submod(w[5245], t1, t2);
    }

    // XOR 4334 636 -> 5246
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4334], w[636]);
        mulmod(t2, w[4334], w[636]);
        mulmod_constant(t2, t2, two);
        submod(w[5246], t1, t2);
    }

    // AND 4331 2821 -> 5247
    mulmod(w[5247], w[4331], w[2821]);

    // XOR 4050 4507 -> 5248
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4050], w[4507]);
        mulmod(t2, w[4050], w[4507]);
        mulmod_constant(t2, t2, two);
        submod(w[5248], t1, t2);
    }

    // AND 4848 4568 -> 5249
    mulmod(w[5249], w[4848], w[4568]);

    // INV 1846 -> 5250
    submod(w[5250], one, w[1846]);

    // XOR 1847 4446 -> 5251
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1847], w[4446]);
        mulmod(t2, w[1847], w[4446]);
        mulmod_constant(t2, t2, two);
        submod(w[5251], t1, t2);
    }

    // AND 4152 681 -> 5252
    mulmod(w[5252], w[4152], w[681]);

    // AND 3576 1919 -> 5253
    mulmod(w[5253], w[3576], w[1919]);

    // AND 4260 1012 -> 5254
    mulmod(w[5254], w[4260], w[1012]);

    // XOR 2666 7 -> 5255
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2666], w[7]);
        mulmod(t2, w[2666], w[7]);
        mulmod_constant(t2, t2, two);
        submod(w[5255], t1, t2);
    }

    // XOR 797 2218 -> 5256
    {
        bn254fr_class t1, t2;
        addmod(t1, w[797], w[2218]);
        mulmod(t2, w[797], w[2218]);
        mulmod_constant(t2, t2, two);
        submod(w[5256], t1, t2);
    }

    // XOR 2409 2362 -> 5257
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2409], w[2362]);
        mulmod(t2, w[2409], w[2362]);
        mulmod_constant(t2, t2, two);
        submod(w[5257], t1, t2);
    }

    // XOR 3220 4744 -> 5258
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3220], w[4744]);
        mulmod(t2, w[3220], w[4744]);
        mulmod_constant(t2, t2, two);
        submod(w[5258], t1, t2);
    }

    // XOR 314 2120 -> 5259
    {
        bn254fr_class t1, t2;
        addmod(t1, w[314], w[2120]);
        mulmod(t2, w[314], w[2120]);
        mulmod_constant(t2, t2, two);
        submod(w[5259], t1, t2);
    }

    // AND 2211 877 -> 5260
    mulmod(w[5260], w[2211], w[877]);

    // XOR 3190 31 -> 5261
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3190], w[31]);
        mulmod(t2, w[3190], w[31]);
        mulmod_constant(t2, t2, two);
        submod(w[5261], t1, t2);
    }

    // XOR 1460 2225 -> 5262
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1460], w[2225]);
        mulmod(t2, w[1460], w[2225]);
        mulmod_constant(t2, t2, two);
        submod(w[5262], t1, t2);
    }

    // XOR 700 2185 -> 5263
    {
        bn254fr_class t1, t2;
        addmod(t1, w[700], w[2185]);
        mulmod(t2, w[700], w[2185]);
        mulmod_constant(t2, t2, two);
        submod(w[5263], t1, t2);
    }

    // XOR 1697 4739 -> 5264
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1697], w[4739]);
        mulmod(t2, w[1697], w[4739]);
        mulmod_constant(t2, t2, two);
        submod(w[5264], t1, t2);
    }

    // XOR 4898 4743 -> 5265
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4898], w[4743]);
        mulmod(t2, w[4898], w[4743]);
        mulmod_constant(t2, t2, two);
        submod(w[5265], t1, t2);
    }

    // AND 301 2840 -> 5266
    mulmod(w[5266], w[301], w[2840]);

    // AND 3682 690 -> 5267
    mulmod(w[5267], w[3682], w[690]);

    // INV 2010 -> 5268
    submod(w[5268], one, w[2010]);

    // XOR 1019 1199 -> 5269
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1019], w[1199]);
        mulmod(t2, w[1019], w[1199]);
        mulmod_constant(t2, t2, two);
        submod(w[5269], t1, t2);
    }

    // INV 295 -> 5270
    submod(w[5270], one, w[295]);

    // XOR 3314 4566 -> 5271
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3314], w[4566]);
        mulmod(t2, w[3314], w[4566]);
        mulmod_constant(t2, t2, two);
        submod(w[5271], t1, t2);
    }

    // XOR 4886 1200 -> 5272
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4886], w[1200]);
        mulmod(t2, w[4886], w[1200]);
        mulmod_constant(t2, t2, two);
        submod(w[5272], t1, t2);
    }

    // AND 157 3608 -> 5273
    mulmod(w[5273], w[157], w[3608]);

    // XOR 3697 3917 -> 5274
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3697], w[3917]);
        mulmod(t2, w[3697], w[3917]);
        mulmod_constant(t2, t2, two);
        submod(w[5274], t1, t2);
    }

    // AND 4535 590 -> 5275
    mulmod(w[5275], w[4535], w[590]);

    // AND 2050 5170 -> 5276
    mulmod(w[5276], w[2050], w[5170]);

    // AND 1078 2713 -> 5277
    mulmod(w[5277], w[1078], w[2713]);

    // XOR 1258 4963 -> 5278
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1258], w[4963]);
        mulmod(t2, w[1258], w[4963]);
        mulmod_constant(t2, t2, two);
        submod(w[5278], t1, t2);
    }

    // AND 2251 3430 -> 5279
    mulmod(w[5279], w[2251], w[3430]);

    // XOR 1330 4518 -> 5280
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1330], w[4518]);
        mulmod(t2, w[1330], w[4518]);
        mulmod_constant(t2, t2, two);
        submod(w[5280], t1, t2);
    }

    // AND 726 1791 -> 5281
    mulmod(w[5281], w[726], w[1791]);

    // AND 4717 3493 -> 5282
    mulmod(w[5282], w[4717], w[3493]);

    // XOR 220 4242 -> 5283
    {
        bn254fr_class t1, t2;
        addmod(t1, w[220], w[4242]);
        mulmod(t2, w[220], w[4242]);
        mulmod_constant(t2, t2, two);
        submod(w[5283], t1, t2);
    }

    // XOR 12 3151 -> 5284
    {
        bn254fr_class t1, t2;
        addmod(t1, w[12], w[3151]);
        mulmod(t2, w[12], w[3151]);
        mulmod_constant(t2, t2, two);
        submod(w[5284], t1, t2);
    }

    // XOR 2424 1113 -> 5285
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2424], w[1113]);
        mulmod(t2, w[2424], w[1113]);
        mulmod_constant(t2, t2, two);
        submod(w[5285], t1, t2);
    }

    // XOR 295 2654 -> 5286
    {
        bn254fr_class t1, t2;
        addmod(t1, w[295], w[2654]);
        mulmod(t2, w[295], w[2654]);
        mulmod_constant(t2, t2, two);
        submod(w[5286], t1, t2);
    }

    // INV 1014 -> 5287
    submod(w[5287], one, w[1014]);

    // AND 4537 3322 -> 5288
    mulmod(w[5288], w[4537], w[3322]);

    // XOR 4419 3530 -> 5289
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4419], w[3530]);
        mulmod(t2, w[4419], w[3530]);
        mulmod_constant(t2, t2, two);
        submod(w[5289], t1, t2);
    }

    // AND 4633 1605 -> 5290
    mulmod(w[5290], w[4633], w[1605]);

    // AND 1181 3144 -> 5291
    mulmod(w[5291], w[1181], w[3144]);

    // XOR 2681 2554 -> 5292
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2681], w[2554]);
        mulmod(t2, w[2681], w[2554]);
        mulmod_constant(t2, t2, two);
        submod(w[5292], t1, t2);
    }

    // AND 1941 2274 -> 5293
    mulmod(w[5293], w[1941], w[2274]);

    // AND 4508 993 -> 5294
    mulmod(w[5294], w[4508], w[993]);

    // XOR 2357 3774 -> 5295
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2357], w[3774]);
        mulmod(t2, w[2357], w[3774]);
        mulmod_constant(t2, t2, two);
        submod(w[5295], t1, t2);
    }

    // XOR 1933 4047 -> 5296
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1933], w[4047]);
        mulmod(t2, w[1933], w[4047]);
        mulmod_constant(t2, t2, two);
        submod(w[5296], t1, t2);
    }

    // AND 5114 4852 -> 5297
    mulmod(w[5297], w[5114], w[4852]);

    // INV 3191 -> 5298
    submod(w[5298], one, w[3191]);

    // XOR 3461 4587 -> 5299
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3461], w[4587]);
        mulmod(t2, w[3461], w[4587]);
        mulmod_constant(t2, t2, two);
        submod(w[5299], t1, t2);
    }

    // XOR 1281 475 -> 5300
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1281], w[475]);
        mulmod(t2, w[1281], w[475]);
        mulmod_constant(t2, t2, two);
        submod(w[5300], t1, t2);
    }

    // AND 1371 123 -> 5301
    mulmod(w[5301], w[1371], w[123]);

    // XOR 1065 1432 -> 5302
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1065], w[1432]);
        mulmod(t2, w[1065], w[1432]);
        mulmod_constant(t2, t2, two);
        submod(w[5302], t1, t2);
    }

    // XOR 2788 2346 -> 5303
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2788], w[2346]);
        mulmod(t2, w[2788], w[2346]);
        mulmod_constant(t2, t2, two);
        submod(w[5303], t1, t2);
    }

    // XOR 2070 875 -> 5304
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2070], w[875]);
        mulmod(t2, w[2070], w[875]);
        mulmod_constant(t2, t2, two);
        submod(w[5304], t1, t2);
    }

    // XOR 4860 328 -> 5305
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4860], w[328]);
        mulmod(t2, w[4860], w[328]);
        mulmod_constant(t2, t2, two);
        submod(w[5305], t1, t2);
    }

    // XOR 2523 4439 -> 5306
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2523], w[4439]);
        mulmod(t2, w[2523], w[4439]);
        mulmod_constant(t2, t2, two);
        submod(w[5306], t1, t2);
    }

    // XOR 3087 1967 -> 5307
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3087], w[1967]);
        mulmod(t2, w[3087], w[1967]);
        mulmod_constant(t2, t2, two);
        submod(w[5307], t1, t2);
    }

    // XOR 57 4202 -> 5308
    {
        bn254fr_class t1, t2;
        addmod(t1, w[57], w[4202]);
        mulmod(t2, w[57], w[4202]);
        mulmod_constant(t2, t2, two);
        submod(w[5308], t1, t2);
    }

    // AND 4955 652 -> 5309
    mulmod(w[5309], w[4955], w[652]);

    // AND 4474 4479 -> 5310
    mulmod(w[5310], w[4474], w[4479]);

    // AND 3414 3968 -> 5311
    mulmod(w[5311], w[3414], w[3968]);

    // AND 1738 1826 -> 5312
    mulmod(w[5312], w[1738], w[1826]);

    // XOR 3423 1820 -> 5313
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3423], w[1820]);
        mulmod(t2, w[3423], w[1820]);
        mulmod_constant(t2, t2, two);
        submod(w[5313], t1, t2);
    }

    // XOR 795 631 -> 5314
    {
        bn254fr_class t1, t2;
        addmod(t1, w[795], w[631]);
        mulmod(t2, w[795], w[631]);
        mulmod_constant(t2, t2, two);
        submod(w[5314], t1, t2);
    }

    // AND 3520 3221 -> 5315
    mulmod(w[5315], w[3520], w[3221]);

    // AND 4045 3055 -> 5316
    mulmod(w[5316], w[4045], w[3055]);

    // AND 3884 2623 -> 5317
    mulmod(w[5317], w[3884], w[2623]);

    // XOR 884 709 -> 5318
    {
        bn254fr_class t1, t2;
        addmod(t1, w[884], w[709]);
        mulmod(t2, w[884], w[709]);
        mulmod_constant(t2, t2, two);
        submod(w[5318], t1, t2);
    }

    // XOR 1387 3310 -> 5319
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1387], w[3310]);
        mulmod(t2, w[1387], w[3310]);
        mulmod_constant(t2, t2, two);
        submod(w[5319], t1, t2);
    }

    // AND 3898 1624 -> 5320
    mulmod(w[5320], w[3898], w[1624]);

    // INV 2394 -> 5321
    submod(w[5321], one, w[2394]);

    // AND 2199 1443 -> 5322
    mulmod(w[5322], w[2199], w[1443]);

    // XOR 4863 4389 -> 5323
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4863], w[4389]);
        mulmod(t2, w[4863], w[4389]);
        mulmod_constant(t2, t2, two);
        submod(w[5323], t1, t2);
    }

    // INV 2352 -> 5324
    submod(w[5324], one, w[2352]);

    // XOR 4280 3875 -> 5325
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4280], w[3875]);
        mulmod(t2, w[4280], w[3875]);
        mulmod_constant(t2, t2, two);
        submod(w[5325], t1, t2);
    }

    // AND 4491 425 -> 5326
    mulmod(w[5326], w[4491], w[425]);

    // AND 4550 1616 -> 5327
    mulmod(w[5327], w[4550], w[1616]);

    // XOR 1899 833 -> 5328
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1899], w[833]);
        mulmod(t2, w[1899], w[833]);
        mulmod_constant(t2, t2, two);
        submod(w[5328], t1, t2);
    }

    // XOR 805 2894 -> 5329
    {
        bn254fr_class t1, t2;
        addmod(t1, w[805], w[2894]);
        mulmod(t2, w[805], w[2894]);
        mulmod_constant(t2, t2, two);
        submod(w[5329], t1, t2);
    }

    // AND 3251 2850 -> 5330
    mulmod(w[5330], w[3251], w[2850]);

    // XOR 4999 2737 -> 5331
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4999], w[2737]);
        mulmod(t2, w[4999], w[2737]);
        mulmod_constant(t2, t2, two);
        submod(w[5331], t1, t2);
    }

    // AND 1534 4082 -> 5332
    mulmod(w[5332], w[1534], w[4082]);

    // XOR 1572 1798 -> 5333
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1572], w[1798]);
        mulmod(t2, w[1572], w[1798]);
        mulmod_constant(t2, t2, two);
        submod(w[5333], t1, t2);
    }

    // AND 1880 5123 -> 5334
    mulmod(w[5334], w[1880], w[5123]);

    // AND 2793 129 -> 5335
    mulmod(w[5335], w[2793], w[129]);

    // XOR 1150 3346 -> 5336
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1150], w[3346]);
        mulmod(t2, w[1150], w[3346]);
        mulmod_constant(t2, t2, two);
        submod(w[5336], t1, t2);
    }

    // INV 621 -> 5337
    submod(w[5337], one, w[621]);

    // INV 4727 -> 5338
    submod(w[5338], one, w[4727]);

    // AND 1498 433 -> 5339
    mulmod(w[5339], w[1498], w[433]);

    // INV 4279 -> 5340
    submod(w[5340], one, w[4279]);

    // XOR 2565 1261 -> 5341
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2565], w[1261]);
        mulmod(t2, w[2565], w[1261]);
        mulmod_constant(t2, t2, two);
        submod(w[5341], t1, t2);
    }

    // XOR 3868 2161 -> 5342
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3868], w[2161]);
        mulmod(t2, w[3868], w[2161]);
        mulmod_constant(t2, t2, two);
        submod(w[5342], t1, t2);
    }

    // XOR 1695 4077 -> 5343
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1695], w[4077]);
        mulmod(t2, w[1695], w[4077]);
        mulmod_constant(t2, t2, two);
        submod(w[5343], t1, t2);
    }

    // XOR 2545 2955 -> 5344
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2545], w[2955]);
        mulmod(t2, w[2545], w[2955]);
        mulmod_constant(t2, t2, two);
        submod(w[5344], t1, t2);
    }

    // XOR 2074 699 -> 5345
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2074], w[699]);
        mulmod(t2, w[2074], w[699]);
        mulmod_constant(t2, t2, two);
        submod(w[5345], t1, t2);
    }

    // AND 1768 1433 -> 5346
    mulmod(w[5346], w[1768], w[1433]);

    // XOR 4532 1293 -> 5347
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4532], w[1293]);
        mulmod(t2, w[4532], w[1293]);
        mulmod_constant(t2, t2, two);
        submod(w[5347], t1, t2);
    }

    // XOR 4841 1136 -> 5348
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4841], w[1136]);
        mulmod(t2, w[4841], w[1136]);
        mulmod_constant(t2, t2, two);
        submod(w[5348], t1, t2);
    }

    // INV 1188 -> 5349
    submod(w[5349], one, w[1188]);

    // XOR 3433 3785 -> 5350
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3433], w[3785]);
        mulmod(t2, w[3433], w[3785]);
        mulmod_constant(t2, t2, two);
        submod(w[5350], t1, t2);
    }

    // AND 3952 3062 -> 5351
    mulmod(w[5351], w[3952], w[3062]);

    // AND 3263 3409 -> 5352
    mulmod(w[5352], w[3263], w[3409]);

    // AND 884 4663 -> 5353
    mulmod(w[5353], w[884], w[4663]);

    // INV 1557 -> 5354
    submod(w[5354], one, w[1557]);

    // XOR 979 4930 -> 5355
    {
        bn254fr_class t1, t2;
        addmod(t1, w[979], w[4930]);
        mulmod(t2, w[979], w[4930]);
        mulmod_constant(t2, t2, two);
        submod(w[5355], t1, t2);
    }

    // AND 4492 2486 -> 5356
    mulmod(w[5356], w[4492], w[2486]);

    // AND 3546 3957 -> 5357
    mulmod(w[5357], w[3546], w[3957]);

    // XOR 1062 1049 -> 5358
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1062], w[1049]);
        mulmod(t2, w[1062], w[1049]);
        mulmod_constant(t2, t2, two);
        submod(w[5358], t1, t2);
    }

    // XOR 3323 3743 -> 5359
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3323], w[3743]);
        mulmod(t2, w[3323], w[3743]);
        mulmod_constant(t2, t2, two);
        submod(w[5359], t1, t2);
    }

    // XOR 2089 367 -> 5360
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2089], w[367]);
        mulmod(t2, w[2089], w[367]);
        mulmod_constant(t2, t2, two);
        submod(w[5360], t1, t2);
    }

    // XOR 1390 2234 -> 5361
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1390], w[2234]);
        mulmod(t2, w[1390], w[2234]);
        mulmod_constant(t2, t2, two);
        submod(w[5361], t1, t2);
    }

    // XOR 3686 3766 -> 5362
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3686], w[3766]);
        mulmod(t2, w[3686], w[3766]);
        mulmod_constant(t2, t2, two);
        submod(w[5362], t1, t2);
    }

    // AND 2527 932 -> 5363
    mulmod(w[5363], w[2527], w[932]);

    // XOR 4581 4912 -> 5364
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4581], w[4912]);
        mulmod(t2, w[4581], w[4912]);
        mulmod_constant(t2, t2, two);
        submod(w[5364], t1, t2);
    }

    // XOR 1788 1476 -> 5365
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1788], w[1476]);
        mulmod(t2, w[1788], w[1476]);
        mulmod_constant(t2, t2, two);
        submod(w[5365], t1, t2);
    }

    // XOR 1611 1811 -> 5366
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1611], w[1811]);
        mulmod(t2, w[1611], w[1811]);
        mulmod_constant(t2, t2, two);
        submod(w[5366], t1, t2);
    }

    // AND 244 2790 -> 5367
    mulmod(w[5367], w[244], w[2790]);

    // XOR 2529 1032 -> 5368
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2529], w[1032]);
        mulmod(t2, w[2529], w[1032]);
        mulmod_constant(t2, t2, two);
        submod(w[5368], t1, t2);
    }

    // XOR 4186 2483 -> 5369
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4186], w[2483]);
        mulmod(t2, w[4186], w[2483]);
        mulmod_constant(t2, t2, two);
        submod(w[5369], t1, t2);
    }

    // XOR 1758 4069 -> 5370
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1758], w[4069]);
        mulmod(t2, w[1758], w[4069]);
        mulmod_constant(t2, t2, two);
        submod(w[5370], t1, t2);
    }

    // XOR 1965 1928 -> 5371
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1965], w[1928]);
        mulmod(t2, w[1965], w[1928]);
        mulmod_constant(t2, t2, two);
        submod(w[5371], t1, t2);
    }

    // AND 2694 340 -> 5372
    mulmod(w[5372], w[2694], w[340]);

    // XOR 227 4342 -> 5373
    {
        bn254fr_class t1, t2;
        addmod(t1, w[227], w[4342]);
        mulmod(t2, w[227], w[4342]);
        mulmod_constant(t2, t2, two);
        submod(w[5373], t1, t2);
    }

    // AND 1305 4803 -> 5374
    mulmod(w[5374], w[1305], w[4803]);

    // AND 1785 4678 -> 5375
    mulmod(w[5375], w[1785], w[4678]);

    // INV 5169 -> 5376
    submod(w[5376], one, w[5169]);

    // XOR 13 76 -> 5377
    {
        bn254fr_class t1, t2;
        addmod(t1, w[13], w[76]);
        mulmod(t2, w[13], w[76]);
        mulmod_constant(t2, t2, two);
        submod(w[5377], t1, t2);
    }

    // XOR 4389 3191 -> 5378
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4389], w[3191]);
        mulmod(t2, w[4389], w[3191]);
        mulmod_constant(t2, t2, two);
        submod(w[5378], t1, t2);
    }

    // XOR 3492 1401 -> 5379
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3492], w[1401]);
        mulmod(t2, w[3492], w[1401]);
        mulmod_constant(t2, t2, two);
        submod(w[5379], t1, t2);
    }

    // XOR 1858 2852 -> 5380
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1858], w[2852]);
        mulmod(t2, w[1858], w[2852]);
        mulmod_constant(t2, t2, two);
        submod(w[5380], t1, t2);
    }

    // XOR 233 715 -> 5381
    {
        bn254fr_class t1, t2;
        addmod(t1, w[233], w[715]);
        mulmod(t2, w[233], w[715]);
        mulmod_constant(t2, t2, two);
        submod(w[5381], t1, t2);
    }

    // XOR 1887 3249 -> 5382
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1887], w[3249]);
        mulmod(t2, w[1887], w[3249]);
        mulmod_constant(t2, t2, two);
        submod(w[5382], t1, t2);
    }

    // XOR 3244 4576 -> 5383
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3244], w[4576]);
        mulmod(t2, w[3244], w[4576]);
        mulmod_constant(t2, t2, two);
        submod(w[5383], t1, t2);
    }

    // XOR 3192 2726 -> 5384
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3192], w[2726]);
        mulmod(t2, w[3192], w[2726]);
        mulmod_constant(t2, t2, two);
        submod(w[5384], t1, t2);
    }

    // AND 3830 4132 -> 5385
    mulmod(w[5385], w[3830], w[4132]);

    // XOR 2082 4178 -> 5386
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2082], w[4178]);
        mulmod(t2, w[2082], w[4178]);
        mulmod_constant(t2, t2, two);
        submod(w[5386], t1, t2);
    }

    // AND 2370 2572 -> 5387
    mulmod(w[5387], w[2370], w[2572]);

    // XOR 3428 4427 -> 5388
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3428], w[4427]);
        mulmod(t2, w[3428], w[4427]);
        mulmod_constant(t2, t2, two);
        submod(w[5388], t1, t2);
    }

    // XOR 86 3586 -> 5389
    {
        bn254fr_class t1, t2;
        addmod(t1, w[86], w[3586]);
        mulmod(t2, w[86], w[3586]);
        mulmod_constant(t2, t2, two);
        submod(w[5389], t1, t2);
    }

    // XOR 4498 4440 -> 5390
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4498], w[4440]);
        mulmod(t2, w[4498], w[4440]);
        mulmod_constant(t2, t2, two);
        submod(w[5390], t1, t2);
    }

    // AND 2757 3558 -> 5391
    mulmod(w[5391], w[2757], w[3558]);

    // XOR 4737 638 -> 5392
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4737], w[638]);
        mulmod(t2, w[4737], w[638]);
        mulmod_constant(t2, t2, two);
        submod(w[5392], t1, t2);
    }

    // XOR 2991 4425 -> 5393
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2991], w[4425]);
        mulmod(t2, w[2991], w[4425]);
        mulmod_constant(t2, t2, two);
        submod(w[5393], t1, t2);
    }

    // AND 286 1462 -> 5394
    mulmod(w[5394], w[286], w[1462]);

    // XOR 3651 1095 -> 5395
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3651], w[1095]);
        mulmod(t2, w[3651], w[1095]);
        mulmod_constant(t2, t2, two);
        submod(w[5395], t1, t2);
    }

    // AND 384 4091 -> 5396
    mulmod(w[5396], w[384], w[4091]);

    // AND 1100 2271 -> 5397
    mulmod(w[5397], w[1100], w[2271]);

    // XOR 2173 1266 -> 5398
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2173], w[1266]);
        mulmod(t2, w[2173], w[1266]);
        mulmod_constant(t2, t2, two);
        submod(w[5398], t1, t2);
    }

    // XOR 2630 3974 -> 5399
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2630], w[3974]);
        mulmod(t2, w[2630], w[3974]);
        mulmod_constant(t2, t2, two);
        submod(w[5399], t1, t2);
    }

    // AND 1381 1508 -> 5400
    mulmod(w[5400], w[1381], w[1508]);

    // AND 2912 4710 -> 5401
    mulmod(w[5401], w[2912], w[4710]);

    // XOR 1752 2898 -> 5402
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1752], w[2898]);
        mulmod(t2, w[1752], w[2898]);
        mulmod_constant(t2, t2, two);
        submod(w[5402], t1, t2);
    }

    // XOR 4890 3505 -> 5403
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4890], w[3505]);
        mulmod(t2, w[4890], w[3505]);
        mulmod_constant(t2, t2, two);
        submod(w[5403], t1, t2);
    }

    // XOR 1094 1644 -> 5404
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1094], w[1644]);
        mulmod(t2, w[1094], w[1644]);
        mulmod_constant(t2, t2, two);
        submod(w[5404], t1, t2);
    }

    // XOR 4049 2717 -> 5405
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4049], w[2717]);
        mulmod(t2, w[4049], w[2717]);
        mulmod_constant(t2, t2, two);
        submod(w[5405], t1, t2);
    }

    // XOR 796 4324 -> 5406
    {
        bn254fr_class t1, t2;
        addmod(t1, w[796], w[4324]);
        mulmod(t2, w[796], w[4324]);
        mulmod_constant(t2, t2, two);
        submod(w[5406], t1, t2);
    }

    // INV 2933 -> 5407
    submod(w[5407], one, w[2933]);

    // XOR 484 3313 -> 5408
    {
        bn254fr_class t1, t2;
        addmod(t1, w[484], w[3313]);
        mulmod(t2, w[484], w[3313]);
        mulmod_constant(t2, t2, two);
        submod(w[5408], t1, t2);
    }

    // XOR 350 2206 -> 5409
    {
        bn254fr_class t1, t2;
        addmod(t1, w[350], w[2206]);
        mulmod(t2, w[350], w[2206]);
        mulmod_constant(t2, t2, two);
        submod(w[5409], t1, t2);
    }

    // XOR 1086 2002 -> 5410
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1086], w[2002]);
        mulmod(t2, w[1086], w[2002]);
        mulmod_constant(t2, t2, two);
        submod(w[5410], t1, t2);
    }

    // XOR 5252 4261 -> 5411
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5252], w[4261]);
        mulmod(t2, w[5252], w[4261]);
        mulmod_constant(t2, t2, two);
        submod(w[5411], t1, t2);
    }

    // AND 3369 2855 -> 5412
    mulmod(w[5412], w[3369], w[2855]);

    // INV 1782 -> 5413
    submod(w[5413], one, w[1782]);

    // AND 4240 581 -> 5414
    mulmod(w[5414], w[4240], w[581]);

    // AND 474 1459 -> 5415
    mulmod(w[5415], w[474], w[1459]);

    // AND 2391 365 -> 5416
    mulmod(w[5416], w[2391], w[365]);

    // AND 2042 1921 -> 5417
    mulmod(w[5417], w[2042], w[1921]);

    // XOR 1107 548 -> 5418
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1107], w[548]);
        mulmod(t2, w[1107], w[548]);
        mulmod_constant(t2, t2, two);
        submod(w[5418], t1, t2);
    }

    // INV 5254 -> 5419
    submod(w[5419], one, w[5254]);

    // XOR 2478 3573 -> 5420
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2478], w[3573]);
        mulmod(t2, w[2478], w[3573]);
        mulmod_constant(t2, t2, two);
        submod(w[5420], t1, t2);
    }

    // XOR 4832 605 -> 5421
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4832], w[605]);
        mulmod(t2, w[4832], w[605]);
        mulmod_constant(t2, t2, two);
        submod(w[5421], t1, t2);
    }

    // AND 2767 3720 -> 5422
    mulmod(w[5422], w[2767], w[3720]);

    // XOR 2114 318 -> 5423
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2114], w[318]);
        mulmod(t2, w[2114], w[318]);
        mulmod_constant(t2, t2, two);
        submod(w[5423], t1, t2);
    }

    // AND 580 1802 -> 5424
    mulmod(w[5424], w[580], w[1802]);

    // AND 4283 1968 -> 5425
    mulmod(w[5425], w[4283], w[1968]);

    // AND 2081 4350 -> 5426
    mulmod(w[5426], w[2081], w[4350]);

    // XOR 4422 4269 -> 5427
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4422], w[4269]);
        mulmod(t2, w[4422], w[4269]);
        mulmod_constant(t2, t2, two);
        submod(w[5427], t1, t2);
    }

    // XOR 3536 1149 -> 5428
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3536], w[1149]);
        mulmod(t2, w[3536], w[1149]);
        mulmod_constant(t2, t2, two);
        submod(w[5428], t1, t2);
    }

    // XOR 232 1456 -> 5429
    {
        bn254fr_class t1, t2;
        addmod(t1, w[232], w[1456]);
        mulmod(t2, w[232], w[1456]);
        mulmod_constant(t2, t2, two);
        submod(w[5429], t1, t2);
    }

    // AND 1446 1625 -> 5430
    mulmod(w[5430], w[1446], w[1625]);

    // XOR 4483 3687 -> 5431
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4483], w[3687]);
        mulmod(t2, w[4483], w[3687]);
        mulmod_constant(t2, t2, two);
        submod(w[5431], t1, t2);
    }

    // AND 3472 3110 -> 5432
    mulmod(w[5432], w[3472], w[3110]);

    // AND 1367 5075 -> 5433
    mulmod(w[5433], w[1367], w[5075]);

    // AND 3209 2045 -> 5434
    mulmod(w[5434], w[3209], w[2045]);

    // XOR 3261 1162 -> 5435
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3261], w[1162]);
        mulmod(t2, w[3261], w[1162]);
        mulmod_constant(t2, t2, two);
        submod(w[5435], t1, t2);
    }

    // XOR 4252 4400 -> 5436
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4252], w[4400]);
        mulmod(t2, w[4252], w[4400]);
        mulmod_constant(t2, t2, two);
        submod(w[5436], t1, t2);
    }

    // XOR 5342 5129 -> 5437
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5342], w[5129]);
        mulmod(t2, w[5342], w[5129]);
        mulmod_constant(t2, t2, two);
        submod(w[5437], t1, t2);
    }

    // XOR 786 2738 -> 5438
    {
        bn254fr_class t1, t2;
        addmod(t1, w[786], w[2738]);
        mulmod(t2, w[786], w[2738]);
        mulmod_constant(t2, t2, two);
        submod(w[5438], t1, t2);
    }

    // XOR 4182 5344 -> 5439
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4182], w[5344]);
        mulmod(t2, w[4182], w[5344]);
        mulmod_constant(t2, t2, two);
        submod(w[5439], t1, t2);
    }

    // XOR 2036 1682 -> 5440
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2036], w[1682]);
        mulmod(t2, w[2036], w[1682]);
        mulmod_constant(t2, t2, two);
        submod(w[5440], t1, t2);
    }

    // XOR 3040 3007 -> 5441
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3040], w[3007]);
        mulmod(t2, w[3040], w[3007]);
        mulmod_constant(t2, t2, two);
        submod(w[5441], t1, t2);
    }

    // XOR 4925 94 -> 5442
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4925], w[94]);
        mulmod(t2, w[4925], w[94]);
        mulmod_constant(t2, t2, two);
        submod(w[5442], t1, t2);
    }

    // AND 3392 3765 -> 5443
    mulmod(w[5443], w[3392], w[3765]);

    // XOR 5306 1580 -> 5444
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5306], w[1580]);
        mulmod(t2, w[5306], w[1580]);
        mulmod_constant(t2, t2, two);
        submod(w[5444], t1, t2);
    }

    // AND 2799 1237 -> 5445
    mulmod(w[5445], w[2799], w[1237]);

    // AND 1179 3780 -> 5446
    mulmod(w[5446], w[1179], w[3780]);

    // XOR 4783 2769 -> 5447
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4783], w[2769]);
        mulmod(t2, w[4783], w[2769]);
        mulmod_constant(t2, t2, two);
        submod(w[5447], t1, t2);
    }

    // XOR 5142 4417 -> 5448
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5142], w[4417]);
        mulmod(t2, w[5142], w[4417]);
        mulmod_constant(t2, t2, two);
        submod(w[5448], t1, t2);
    }

    // XOR 3926 5351 -> 5449
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3926], w[5351]);
        mulmod(t2, w[3926], w[5351]);
        mulmod_constant(t2, t2, two);
        submod(w[5449], t1, t2);
    }

    // INV 743 -> 5450
    submod(w[5450], one, w[743]);

    // XOR 2340 3526 -> 5451
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2340], w[3526]);
        mulmod(t2, w[2340], w[3526]);
        mulmod_constant(t2, t2, two);
        submod(w[5451], t1, t2);
    }

    // XOR 4864 1490 -> 5452
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4864], w[1490]);
        mulmod(t2, w[4864], w[1490]);
        mulmod_constant(t2, t2, two);
        submod(w[5452], t1, t2);
    }

    // AND 444 3169 -> 5453
    mulmod(w[5453], w[444], w[3169]);

    // XOR 5402 381 -> 5454
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5402], w[381]);
        mulmod(t2, w[5402], w[381]);
        mulmod_constant(t2, t2, two);
        submod(w[5454], t1, t2);
    }

    // AND 2147 2167 -> 5455
    mulmod(w[5455], w[2147], w[2167]);

    // INV 4391 -> 5456
    submod(w[5456], one, w[4391]);

    // AND 3176 5143 -> 5457
    mulmod(w[5457], w[3176], w[5143]);

    // XOR 1 1941 -> 5458
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1], w[1941]);
        mulmod(t2, w[1], w[1941]);
        mulmod_constant(t2, t2, two);
        submod(w[5458], t1, t2);
    }

    // XOR 2925 2711 -> 5459
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2925], w[2711]);
        mulmod(t2, w[2925], w[2711]);
        mulmod_constant(t2, t2, two);
        submod(w[5459], t1, t2);
    }

    // XOR 4998 3617 -> 5460
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4998], w[3617]);
        mulmod(t2, w[4998], w[3617]);
        mulmod_constant(t2, t2, two);
        submod(w[5460], t1, t2);
    }

    // XOR 4769 783 -> 5461
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4769], w[783]);
        mulmod(t2, w[4769], w[783]);
        mulmod_constant(t2, t2, two);
        submod(w[5461], t1, t2);
    }

    // AND 4186 535 -> 5462
    mulmod(w[5462], w[4186], w[535]);

    // AND 5077 4759 -> 5463
    mulmod(w[5463], w[5077], w[4759]);

    // XOR 2542 982 -> 5464
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2542], w[982]);
        mulmod(t2, w[2542], w[982]);
        mulmod_constant(t2, t2, two);
        submod(w[5464], t1, t2);
    }

    // XOR 1079 4352 -> 5465
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1079], w[4352]);
        mulmod(t2, w[1079], w[4352]);
        mulmod_constant(t2, t2, two);
        submod(w[5465], t1, t2);
    }

    // AND 2297 2096 -> 5466
    mulmod(w[5466], w[2297], w[2096]);

    // AND 4472 2008 -> 5467
    mulmod(w[5467], w[4472], w[2008]);

    // XOR 4127 703 -> 5468
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4127], w[703]);
        mulmod(t2, w[4127], w[703]);
        mulmod_constant(t2, t2, two);
        submod(w[5468], t1, t2);
    }

    // INV 4811 -> 5469
    submod(w[5469], one, w[4811]);

    // XOR 3305 3036 -> 5470
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3305], w[3036]);
        mulmod(t2, w[3305], w[3036]);
        mulmod_constant(t2, t2, two);
        submod(w[5470], t1, t2);
    }

    // XOR 4714 5059 -> 5471
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4714], w[5059]);
        mulmod(t2, w[4714], w[5059]);
        mulmod_constant(t2, t2, two);
        submod(w[5471], t1, t2);
    }

    // XOR 2694 4248 -> 5472
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2694], w[4248]);
        mulmod(t2, w[2694], w[4248]);
        mulmod_constant(t2, t2, two);
        submod(w[5472], t1, t2);
    }

    // AND 4299 2935 -> 5473
    mulmod(w[5473], w[4299], w[2935]);

    // AND 3084 5028 -> 5474
    mulmod(w[5474], w[3084], w[5028]);

    // INV 4489 -> 5475
    submod(w[5475], one, w[4489]);

    // XOR 5194 2305 -> 5476
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5194], w[2305]);
        mulmod(t2, w[5194], w[2305]);
        mulmod_constant(t2, t2, two);
        submod(w[5476], t1, t2);
    }

    // AND 1210 4478 -> 5477
    mulmod(w[5477], w[1210], w[4478]);

    // XOR 979 1352 -> 5478
    {
        bn254fr_class t1, t2;
        addmod(t1, w[979], w[1352]);
        mulmod(t2, w[979], w[1352]);
        mulmod_constant(t2, t2, two);
        submod(w[5478], t1, t2);
    }

    // INV 3734 -> 5479
    submod(w[5479], one, w[3734]);

    // XOR 1845 673 -> 5480
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1845], w[673]);
        mulmod(t2, w[1845], w[673]);
        mulmod_constant(t2, t2, two);
        submod(w[5480], t1, t2);
    }

    // XOR 2504 4682 -> 5481
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2504], w[4682]);
        mulmod(t2, w[2504], w[4682]);
        mulmod_constant(t2, t2, two);
        submod(w[5481], t1, t2);
    }

    // XOR 4816 2343 -> 5482
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4816], w[2343]);
        mulmod(t2, w[4816], w[2343]);
        mulmod_constant(t2, t2, two);
        submod(w[5482], t1, t2);
    }

    // XOR 3466 1525 -> 5483
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3466], w[1525]);
        mulmod(t2, w[3466], w[1525]);
        mulmod_constant(t2, t2, two);
        submod(w[5483], t1, t2);
    }

    // XOR 3579 1535 -> 5484
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3579], w[1535]);
        mulmod(t2, w[3579], w[1535]);
        mulmod_constant(t2, t2, two);
        submod(w[5484], t1, t2);
    }

    // XOR 4738 1304 -> 5485
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4738], w[1304]);
        mulmod(t2, w[4738], w[1304]);
        mulmod_constant(t2, t2, two);
        submod(w[5485], t1, t2);
    }

    // AND 345 2752 -> 5486
    mulmod(w[5486], w[345], w[2752]);

    // AND 3394 846 -> 5487
    mulmod(w[5487], w[3394], w[846]);

    // XOR 5321 1063 -> 5488
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5321], w[1063]);
        mulmod(t2, w[5321], w[1063]);
        mulmod_constant(t2, t2, two);
        submod(w[5488], t1, t2);
    }

    // XOR 3623 2020 -> 5489
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3623], w[2020]);
        mulmod(t2, w[3623], w[2020]);
        mulmod_constant(t2, t2, two);
        submod(w[5489], t1, t2);
    }

    // XOR 5145 3931 -> 5490
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5145], w[3931]);
        mulmod(t2, w[5145], w[3931]);
        mulmod_constant(t2, t2, two);
        submod(w[5490], t1, t2);
    }

    // AND 1926 2912 -> 5491
    mulmod(w[5491], w[1926], w[2912]);

    // INV 2152 -> 5492
    submod(w[5492], one, w[2152]);

    // XOR 2947 4574 -> 5493
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2947], w[4574]);
        mulmod(t2, w[2947], w[4574]);
        mulmod_constant(t2, t2, two);
        submod(w[5493], t1, t2);
    }

    // XOR 5365 3813 -> 5494
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5365], w[3813]);
        mulmod(t2, w[5365], w[3813]);
        mulmod_constant(t2, t2, two);
        submod(w[5494], t1, t2);
    }

    // AND 753 4154 -> 5495
    mulmod(w[5495], w[753], w[4154]);

    // XOR 1351 482 -> 5496
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1351], w[482]);
        mulmod(t2, w[1351], w[482]);
        mulmod_constant(t2, t2, two);
        submod(w[5496], t1, t2);
    }

    // INV 2105 -> 5497
    submod(w[5497], one, w[2105]);

    // AND 1947 668 -> 5498
    mulmod(w[5498], w[1947], w[668]);

    // AND 3017 1343 -> 5499
    mulmod(w[5499], w[3017], w[1343]);

    // XOR 2637 2855 -> 5500
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2637], w[2855]);
        mulmod(t2, w[2637], w[2855]);
        mulmod_constant(t2, t2, two);
        submod(w[5500], t1, t2);
    }

    // XOR 1357 944 -> 5501
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1357], w[944]);
        mulmod(t2, w[1357], w[944]);
        mulmod_constant(t2, t2, two);
        submod(w[5501], t1, t2);
    }

    // XOR 2523 2704 -> 5502
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2523], w[2704]);
        mulmod(t2, w[2523], w[2704]);
        mulmod_constant(t2, t2, two);
        submod(w[5502], t1, t2);
    }

    // XOR 4445 508 -> 5503
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4445], w[508]);
        mulmod(t2, w[4445], w[508]);
        mulmod_constant(t2, t2, two);
        submod(w[5503], t1, t2);
    }

    // AND 4440 641 -> 5504
    mulmod(w[5504], w[4440], w[641]);

    // AND 3551 2 -> 5505
    mulmod(w[5505], w[3551], w[2]);

    // INV 1185 -> 5506
    submod(w[5506], one, w[1185]);

    // XOR 4589 3069 -> 5507
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4589], w[3069]);
        mulmod(t2, w[4589], w[3069]);
        mulmod_constant(t2, t2, two);
        submod(w[5507], t1, t2);
    }

    // XOR 696 3892 -> 5508
    {
        bn254fr_class t1, t2;
        addmod(t1, w[696], w[3892]);
        mulmod(t2, w[696], w[3892]);
        mulmod_constant(t2, t2, two);
        submod(w[5508], t1, t2);
    }

    // XOR 675 4558 -> 5509
    {
        bn254fr_class t1, t2;
        addmod(t1, w[675], w[4558]);
        mulmod(t2, w[675], w[4558]);
        mulmod_constant(t2, t2, two);
        submod(w[5509], t1, t2);
    }

    // XOR 2358 1865 -> 5510
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2358], w[1865]);
        mulmod(t2, w[2358], w[1865]);
        mulmod_constant(t2, t2, two);
        submod(w[5510], t1, t2);
    }

    // XOR 3062 439 -> 5511
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3062], w[439]);
        mulmod(t2, w[3062], w[439]);
        mulmod_constant(t2, t2, two);
        submod(w[5511], t1, t2);
    }

    // XOR 1486 4025 -> 5512
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1486], w[4025]);
        mulmod(t2, w[1486], w[4025]);
        mulmod_constant(t2, t2, two);
        submod(w[5512], t1, t2);
    }

    // XOR 5002 2293 -> 5513
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5002], w[2293]);
        mulmod(t2, w[5002], w[2293]);
        mulmod_constant(t2, t2, two);
        submod(w[5513], t1, t2);
    }

    // XOR 1179 4152 -> 5514
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1179], w[4152]);
        mulmod(t2, w[1179], w[4152]);
        mulmod_constant(t2, t2, two);
        submod(w[5514], t1, t2);
    }

    // XOR 4927 2294 -> 5515
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4927], w[2294]);
        mulmod(t2, w[4927], w[2294]);
        mulmod_constant(t2, t2, two);
        submod(w[5515], t1, t2);
    }

    // XOR 3437 4997 -> 5516
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3437], w[4997]);
        mulmod(t2, w[3437], w[4997]);
        mulmod_constant(t2, t2, two);
        submod(w[5516], t1, t2);
    }

    // AND 170 2328 -> 5517
    mulmod(w[5517], w[170], w[2328]);

    // XOR 241 1087 -> 5518
    {
        bn254fr_class t1, t2;
        addmod(t1, w[241], w[1087]);
        mulmod(t2, w[241], w[1087]);
        mulmod_constant(t2, t2, two);
        submod(w[5518], t1, t2);
    }

    // XOR 1479 3353 -> 5519
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1479], w[3353]);
        mulmod(t2, w[1479], w[3353]);
        mulmod_constant(t2, t2, two);
        submod(w[5519], t1, t2);
    }

    // AND 2705 1372 -> 5520
    mulmod(w[5520], w[2705], w[1372]);

    // XOR 2022 3640 -> 5521
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2022], w[3640]);
        mulmod(t2, w[2022], w[3640]);
        mulmod_constant(t2, t2, two);
        submod(w[5521], t1, t2);
    }

    // XOR 447 4260 -> 5522
    {
        bn254fr_class t1, t2;
        addmod(t1, w[447], w[4260]);
        mulmod(t2, w[447], w[4260]);
        mulmod_constant(t2, t2, two);
        submod(w[5522], t1, t2);
    }

    // XOR 5326 1122 -> 5523
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5326], w[1122]);
        mulmod(t2, w[5326], w[1122]);
        mulmod_constant(t2, t2, two);
        submod(w[5523], t1, t2);
    }

    // XOR 3885 5408 -> 5524
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3885], w[5408]);
        mulmod(t2, w[3885], w[5408]);
        mulmod_constant(t2, t2, two);
        submod(w[5524], t1, t2);
    }

    // AND 28 1297 -> 5525
    mulmod(w[5525], w[28], w[1297]);

    // XOR 153 2360 -> 5526
    {
        bn254fr_class t1, t2;
        addmod(t1, w[153], w[2360]);
        mulmod(t2, w[153], w[2360]);
        mulmod_constant(t2, t2, two);
        submod(w[5526], t1, t2);
    }

    // INV 5478 -> 5527
    submod(w[5527], one, w[5478]);

    // AND 3507 3806 -> 5528
    mulmod(w[5528], w[3507], w[3806]);

    // AND 4980 196 -> 5529
    mulmod(w[5529], w[4980], w[196]);

    // XOR 1232 4531 -> 5530
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1232], w[4531]);
        mulmod(t2, w[1232], w[4531]);
        mulmod_constant(t2, t2, two);
        submod(w[5530], t1, t2);
    }

    // AND 679 2394 -> 5531
    mulmod(w[5531], w[679], w[2394]);

    // XOR 4892 2338 -> 5532
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4892], w[2338]);
        mulmod(t2, w[4892], w[2338]);
        mulmod_constant(t2, t2, two);
        submod(w[5532], t1, t2);
    }

    // XOR 1602 2955 -> 5533
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1602], w[2955]);
        mulmod(t2, w[1602], w[2955]);
        mulmod_constant(t2, t2, two);
        submod(w[5533], t1, t2);
    }

    // AND 3935 2515 -> 5534
    mulmod(w[5534], w[3935], w[2515]);

    // AND 2827 1569 -> 5535
    mulmod(w[5535], w[2827], w[1569]);

    // AND 1401 657 -> 5536
    mulmod(w[5536], w[1401], w[657]);

    // INV 1106 -> 5537
    submod(w[5537], one, w[1106]);

    // AND 1210 2235 -> 5538
    mulmod(w[5538], w[1210], w[2235]);

    // XOR 3140 1947 -> 5539
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3140], w[1947]);
        mulmod(t2, w[3140], w[1947]);
        mulmod_constant(t2, t2, two);
        submod(w[5539], t1, t2);
    }

    // XOR 1920 5335 -> 5540
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1920], w[5335]);
        mulmod(t2, w[1920], w[5335]);
        mulmod_constant(t2, t2, two);
        submod(w[5540], t1, t2);
    }

    // AND 2347 686 -> 5541
    mulmod(w[5541], w[2347], w[686]);

    // XOR 789 4812 -> 5542
    {
        bn254fr_class t1, t2;
        addmod(t1, w[789], w[4812]);
        mulmod(t2, w[789], w[4812]);
        mulmod_constant(t2, t2, two);
        submod(w[5542], t1, t2);
    }

    // XOR 3171 1236 -> 5543
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3171], w[1236]);
        mulmod(t2, w[3171], w[1236]);
        mulmod_constant(t2, t2, two);
        submod(w[5543], t1, t2);
    }

    // AND 1331 4641 -> 5544
    mulmod(w[5544], w[1331], w[4641]);

    // XOR 1358 4335 -> 5545
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1358], w[4335]);
        mulmod(t2, w[1358], w[4335]);
        mulmod_constant(t2, t2, two);
        submod(w[5545], t1, t2);
    }

    // AND 5457 4074 -> 5546
    mulmod(w[5546], w[5457], w[4074]);

    // AND 4690 4072 -> 5547
    mulmod(w[5547], w[4690], w[4072]);

    // AND 4285 846 -> 5548
    mulmod(w[5548], w[4285], w[846]);

    // AND 3454 4648 -> 5549
    mulmod(w[5549], w[3454], w[4648]);

    // XOR 1770 5281 -> 5550
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1770], w[5281]);
        mulmod(t2, w[1770], w[5281]);
        mulmod_constant(t2, t2, two);
        submod(w[5550], t1, t2);
    }

    // XOR 3132 1053 -> 5551
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3132], w[1053]);
        mulmod(t2, w[3132], w[1053]);
        mulmod_constant(t2, t2, two);
        submod(w[5551], t1, t2);
    }

    // AND 1714 5207 -> 5552
    mulmod(w[5552], w[1714], w[5207]);

    // XOR 2103 4493 -> 5553
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2103], w[4493]);
        mulmod(t2, w[2103], w[4493]);
        mulmod_constant(t2, t2, two);
        submod(w[5553], t1, t2);
    }

    // XOR 2784 4912 -> 5554
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2784], w[4912]);
        mulmod(t2, w[2784], w[4912]);
        mulmod_constant(t2, t2, two);
        submod(w[5554], t1, t2);
    }

    // XOR 3079 925 -> 5555
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3079], w[925]);
        mulmod(t2, w[3079], w[925]);
        mulmod_constant(t2, t2, two);
        submod(w[5555], t1, t2);
    }

    // XOR 1615 887 -> 5556
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1615], w[887]);
        mulmod(t2, w[1615], w[887]);
        mulmod_constant(t2, t2, two);
        submod(w[5556], t1, t2);
    }

    // AND 4213 1584 -> 5557
    mulmod(w[5557], w[4213], w[1584]);

    // XOR 2527 3157 -> 5558
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2527], w[3157]);
        mulmod(t2, w[2527], w[3157]);
        mulmod_constant(t2, t2, two);
        submod(w[5558], t1, t2);
    }

    // XOR 1034 4932 -> 5559
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1034], w[4932]);
        mulmod(t2, w[1034], w[4932]);
        mulmod_constant(t2, t2, two);
        submod(w[5559], t1, t2);
    }

    // AND 99 1959 -> 5560
    mulmod(w[5560], w[99], w[1959]);

    // XOR 4511 498 -> 5561
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4511], w[498]);
        mulmod(t2, w[4511], w[498]);
        mulmod_constant(t2, t2, two);
        submod(w[5561], t1, t2);
    }

    // XOR 4803 2986 -> 5562
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4803], w[2986]);
        mulmod(t2, w[4803], w[2986]);
        mulmod_constant(t2, t2, two);
        submod(w[5562], t1, t2);
    }

    // AND 2558 3292 -> 5563
    mulmod(w[5563], w[2558], w[3292]);

    // XOR 3428 3549 -> 5564
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3428], w[3549]);
        mulmod(t2, w[3428], w[3549]);
        mulmod_constant(t2, t2, two);
        submod(w[5564], t1, t2);
    }

    // AND 2770 1278 -> 5565
    mulmod(w[5565], w[2770], w[1278]);

    // XOR 4860 1122 -> 5566
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4860], w[1122]);
        mulmod(t2, w[4860], w[1122]);
        mulmod_constant(t2, t2, two);
        submod(w[5566], t1, t2);
    }

    // XOR 2447 1245 -> 5567
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2447], w[1245]);
        mulmod(t2, w[2447], w[1245]);
        mulmod_constant(t2, t2, two);
        submod(w[5567], t1, t2);
    }

    // INV 964 -> 5568
    submod(w[5568], one, w[964]);

    // INV 3101 -> 5569
    submod(w[5569], one, w[3101]);

    // XOR 2017 214 -> 5570
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2017], w[214]);
        mulmod(t2, w[2017], w[214]);
        mulmod_constant(t2, t2, two);
        submod(w[5570], t1, t2);
    }

    // XOR 32 5197 -> 5571
    {
        bn254fr_class t1, t2;
        addmod(t1, w[32], w[5197]);
        mulmod(t2, w[32], w[5197]);
        mulmod_constant(t2, t2, two);
        submod(w[5571], t1, t2);
    }

    // XOR 1770 354 -> 5572
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1770], w[354]);
        mulmod(t2, w[1770], w[354]);
        mulmod_constant(t2, t2, two);
        submod(w[5572], t1, t2);
    }

    // XOR 2405 1593 -> 5573
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2405], w[1593]);
        mulmod(t2, w[2405], w[1593]);
        mulmod_constant(t2, t2, two);
        submod(w[5573], t1, t2);
    }

    // AND 1419 5390 -> 5574
    mulmod(w[5574], w[1419], w[5390]);

    // AND 3347 515 -> 5575
    mulmod(w[5575], w[3347], w[515]);

    // AND 3189 5473 -> 5576
    mulmod(w[5576], w[3189], w[5473]);

    // XOR 5481 4223 -> 5577
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5481], w[4223]);
        mulmod(t2, w[5481], w[4223]);
        mulmod_constant(t2, t2, two);
        submod(w[5577], t1, t2);
    }

    // XOR 2835 629 -> 5578
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2835], w[629]);
        mulmod(t2, w[2835], w[629]);
        mulmod_constant(t2, t2, two);
        submod(w[5578], t1, t2);
    }

    // AND 621 4603 -> 5579
    mulmod(w[5579], w[621], w[4603]);

    // XOR 4894 1098 -> 5580
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4894], w[1098]);
        mulmod(t2, w[4894], w[1098]);
        mulmod_constant(t2, t2, two);
        submod(w[5580], t1, t2);
    }

    // XOR 1341 1735 -> 5581
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1341], w[1735]);
        mulmod(t2, w[1341], w[1735]);
        mulmod_constant(t2, t2, two);
        submod(w[5581], t1, t2);
    }

    // AND 937 3729 -> 5582
    mulmod(w[5582], w[937], w[3729]);

    // INV 4968 -> 5583
    submod(w[5583], one, w[4968]);

    // XOR 4214 1729 -> 5584
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4214], w[1729]);
        mulmod(t2, w[4214], w[1729]);
        mulmod_constant(t2, t2, two);
        submod(w[5584], t1, t2);
    }

    // XOR 5309 3630 -> 5585
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5309], w[3630]);
        mulmod(t2, w[5309], w[3630]);
        mulmod_constant(t2, t2, two);
        submod(w[5585], t1, t2);
    }

    // XOR 703 4047 -> 5586
    {
        bn254fr_class t1, t2;
        addmod(t1, w[703], w[4047]);
        mulmod(t2, w[703], w[4047]);
        mulmod_constant(t2, t2, two);
        submod(w[5586], t1, t2);
    }

    // XOR 946 3185 -> 5587
    {
        bn254fr_class t1, t2;
        addmod(t1, w[946], w[3185]);
        mulmod(t2, w[946], w[3185]);
        mulmod_constant(t2, t2, two);
        submod(w[5587], t1, t2);
    }

    // AND 5505 1849 -> 5588
    mulmod(w[5588], w[5505], w[1849]);

    // AND 4769 1194 -> 5589
    mulmod(w[5589], w[4769], w[1194]);

    // XOR 2938 1662 -> 5590
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2938], w[1662]);
        mulmod(t2, w[2938], w[1662]);
        mulmod_constant(t2, t2, two);
        submod(w[5590], t1, t2);
    }

    // XOR 4865 3916 -> 5591
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4865], w[3916]);
        mulmod(t2, w[4865], w[3916]);
        mulmod_constant(t2, t2, two);
        submod(w[5591], t1, t2);
    }

    // XOR 3416 362 -> 5592
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3416], w[362]);
        mulmod(t2, w[3416], w[362]);
        mulmod_constant(t2, t2, two);
        submod(w[5592], t1, t2);
    }

    // AND 1605 480 -> 5593
    mulmod(w[5593], w[1605], w[480]);

    // INV 2144 -> 5594
    submod(w[5594], one, w[2144]);

    // XOR 931 3695 -> 5595
    {
        bn254fr_class t1, t2;
        addmod(t1, w[931], w[3695]);
        mulmod(t2, w[931], w[3695]);
        mulmod_constant(t2, t2, two);
        submod(w[5595], t1, t2);
    }

    // XOR 416 2585 -> 5596
    {
        bn254fr_class t1, t2;
        addmod(t1, w[416], w[2585]);
        mulmod(t2, w[416], w[2585]);
        mulmod_constant(t2, t2, two);
        submod(w[5596], t1, t2);
    }

    // XOR 3293 2763 -> 5597
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3293], w[2763]);
        mulmod(t2, w[3293], w[2763]);
        mulmod_constant(t2, t2, two);
        submod(w[5597], t1, t2);
    }

    // AND 3396 828 -> 5598
    mulmod(w[5598], w[3396], w[828]);

    // XOR 2825 2781 -> 5599
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2825], w[2781]);
        mulmod(t2, w[2825], w[2781]);
        mulmod_constant(t2, t2, two);
        submod(w[5599], t1, t2);
    }

    // XOR 4898 3852 -> 5600
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4898], w[3852]);
        mulmod(t2, w[4898], w[3852]);
        mulmod_constant(t2, t2, two);
        submod(w[5600], t1, t2);
    }

    // XOR 2077 3083 -> 5601
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2077], w[3083]);
        mulmod(t2, w[2077], w[3083]);
        mulmod_constant(t2, t2, two);
        submod(w[5601], t1, t2);
    }

    // AND 5183 3917 -> 5602
    mulmod(w[5602], w[5183], w[3917]);

    // XOR 3899 217 -> 5603
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3899], w[217]);
        mulmod(t2, w[3899], w[217]);
        mulmod_constant(t2, t2, two);
        submod(w[5603], t1, t2);
    }

    // AND 805 3867 -> 5604
    mulmod(w[5604], w[805], w[3867]);

    // AND 5483 1500 -> 5605
    mulmod(w[5605], w[5483], w[1500]);

    // XOR 3227 4161 -> 5606
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3227], w[4161]);
        mulmod(t2, w[3227], w[4161]);
        mulmod_constant(t2, t2, two);
        submod(w[5606], t1, t2);
    }

    // XOR 1505 5233 -> 5607
    {
        bn254fr_class t1, t2;
        addmod(t1, w[1505], w[5233]);
        mulmod(t2, w[1505], w[5233]);
        mulmod_constant(t2, t2, two);
        submod(w[5607], t1, t2);
    }

    // XOR 3797 2438 -> 5608
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3797], w[2438]);
        mulmod(t2, w[3797], w[2438]);
        mulmod_constant(t2, t2, two);
        submod(w[5608], t1, t2);
    }

    // XOR 4833 4564 -> 5609
    {
        bn254fr_class t1, t2;
        addmod(t1, w[4833], w[4564]);
        mulmod(t2, w[4833], w[4564]);
        mulmod_constant(t2, t2, two);
        submod(w[5609], t1, t2);
    }

    // AND 147 1001 -> 5610
    mulmod(w[5610], w[147], w[1001]);

    // XOR 3767 4788 -> 5611
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3767], w[4788]);
        mulmod(t2, w[3767], w[4788]);
        mulmod_constant(t2, t2, two);
        submod(w[5611], t1, t2);
    }

    // INV 5139 -> 5612
    submod(w[5612], one, w[5139]);

    // XOR 3694 3642 -> 5613
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3694], w[3642]);
        mulmod(t2, w[3694], w[3642]);
        mulmod_constant(t2, t2, two);
        submod(w[5613], t1, t2);
    }

    // INV 4083 -> 5614
    submod(w[5614], one, w[4083]);

    // INV 3431 -> 5615
    submod(w[5615], one, w[3431]);

    // XOR 5354 1231 -> 5616
    {
        bn254fr_class t1, t2;
        addmod(t1, w[5354], w[1231]);
        mulmod(t2, w[5354], w[1231]);
        mulmod_constant(t2, t2, two);
        submod(w[5616], t1, t2);
    }

    // INV 3554 -> 5617
    submod(w[5617], one, w[3554]);

    // AND 223 4894 -> 5618
    mulmod(w[5618], w[223], w[4894]);

    // AND 3449 3243 -> 5619
    mulmod(w[5619], w[3449], w[3243]);

    // XOR 3042 4382 -> 5620
    {
        bn254fr_class t1, t2;
        addmod(t1, w[3042], w[4382]);
        mulmod(t2, w[3042], w[4382]);
        mulmod_constant(t2, t2, two);
        submod(w[5620], t1, t2);
    }

    // XOR 954 1579 -> 5621
    {
        bn254fr_class t1, t2;
        addmod(t1, w[954], w[1579]);
        mulmod(t2, w[954], w[1579]);
        mulmod_constant(t2, t2, two);
        submod(w[5621], t1, t2);
    }

    // AND 755 3577 -> 5622
    mulmod(w[5622], w[755], w[3577]);

    // XOR 841 4664 -> 5623
    {
        bn254fr_class t1, t2;
        addmod(t1, w[841], w[4664]);
        mulmod(t2, w[841], w[4664]);
        mulmod_constant(t2, t2, two);
        submod(w[5623], t1, t2);
    }

    // AND 2182 988 -> 5624
    mulmod(w[5624], w[2182], w[988]);

    // XOR 2244 1127 -> 5625
    {
        bn254fr_class t1, t2;
        addmod(t1, w[2244], w[1127]);
        mulmod(t2, w[2244], w[1127]);
        mulmod_constant(t2, t2, two);
        submod(w[5625], t1, t2);
    }

    // INV 4956 -> 5626
    submod(w[5626], one, w[4956]);

    // AND 3274 1999 -> 5627
    mulmod(w[5627], w[3274], w[1999]);


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
