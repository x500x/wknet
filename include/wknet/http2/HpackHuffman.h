#pragma once

#include <wknet/http1/HttpTypes.h>

namespace wknet
{
namespace http2
{
    // RFC 7541 Appendix B - Huffman Code Table
    // Each entry: { code (MSB-aligned in 32 bits), bit_length }
    struct HpackHuffmanSymbol final
    {
        ULONG Code;
        UCHAR BitLength;
    };

    constexpr HpackHuffmanSymbol HpackHuffmanEncodeTable[257] = {
        { 0x1ff8u,     13 }, // 0
        { 0x7fffd8u,   23 }, // 1
        { 0xfffffe2u,  28 }, // 2
        { 0xfffffe3u,  28 }, // 3
        { 0xfffffe4u,  28 }, // 4
        { 0xfffffe5u,  28 }, // 5
        { 0xfffffe6u,  28 }, // 6
        { 0xfffffe7u,  28 }, // 7
        { 0xfffffe8u,  28 }, // 8
        { 0xffffeau,   24 }, // 9
        { 0x3ffffffcu, 30 }, // 10
        { 0xfffffe9u,  28 }, // 11
        { 0xfffffeau,  28 }, // 12
        { 0x3ffffffdu, 30 }, // 13
        { 0xfffffebu,  28 }, // 14
        { 0xfffffecu,  28 }, // 15
        { 0xfffffedu,  28 }, // 16
        { 0xfffffeeu,  28 }, // 17
        { 0xfffffefu,  28 }, // 18
        { 0xffffff0u,  28 }, // 19
        { 0xffffff1u,  28 }, // 20
        { 0xffffff2u,  28 }, // 21
        { 0x3ffffffeu, 30 }, // 22
        { 0xffffff3u,  28 }, // 23
        { 0xffffff4u,  28 }, // 24
        { 0xffffff5u,  28 }, // 25
        { 0xffffff6u,  28 }, // 26
        { 0xffffff7u,  28 }, // 27
        { 0xffffff8u,  28 }, // 28
        { 0xffffff9u,  28 }, // 29
        { 0xffffffau,  28 }, // 30
        { 0xffffffbu,  28 }, // 31
        { 0x14u,        6 }, // 32 ' '
        { 0x3f8u,      10 }, // 33 '!'
        { 0x3f9u,      10 }, // 34 '"'
        { 0xffau,      12 }, // 35 '#'
        { 0x1ff9u,     13 }, // 36 '$'
        { 0x15u,        6 }, // 37 '%'
        { 0xf8u,        8 }, // 38 '&'
        { 0x7fau,      11 }, // 39 '''
        { 0x3fau,      10 }, // 40 '('
        { 0x3fbu,      10 }, // 41 ')'
        { 0xf9u,        8 }, // 42 '*'
        { 0x7fbu,      11 }, // 43 '+'
        { 0xfau,        8 }, // 44 ','
        { 0x16u,        6 }, // 45 '-'
        { 0x17u,        6 }, // 46 '.'
        { 0x18u,        6 }, // 47 '/'
        { 0x0u,         5 }, // 48 '0'
        { 0x1u,         5 }, // 49 '1'
        { 0x2u,         5 }, // 50 '2'
        { 0x19u,        6 }, // 51 '3'
        { 0x1au,        6 }, // 52 '4'
        { 0x1bu,        6 }, // 53 '5'
        { 0x1cu,        6 }, // 54 '6'
        { 0x1du,        6 }, // 55 '7'
        { 0x1eu,        6 }, // 56 '8'
        { 0x1fu,        6 }, // 57 '9'
        { 0x5cu,        7 }, // 58 ':'
        { 0xfbu,        8 }, // 59 ';'
        { 0x7ffcu,     15 }, // 60 '<'
        { 0x20u,        6 }, // 61 '='
        { 0xffbu,      12 }, // 62 '>'
        { 0x3fcu,      10 }, // 63 '?'
        { 0x1ffau,     13 }, // 64 '@'
        { 0x21u,        6 }, // 65 'A'
        { 0x5du,        7 }, // 66 'B'
        { 0x5eu,        7 }, // 67 'C'
        { 0x5fu,        7 }, // 68 'D'
        { 0x60u,        7 }, // 69 'E'
        { 0x61u,        7 }, // 70 'F'
        { 0x62u,        7 }, // 71 'G'
        { 0x63u,        7 }, // 72 'H'
        { 0x64u,        7 }, // 73 'I'
        { 0x65u,        7 }, // 74 'J'
        { 0x66u,        7 }, // 75 'K'
        { 0x67u,        7 }, // 76 'L'
        { 0x68u,        7 }, // 77 'M'
        { 0x69u,        7 }, // 78 'N'
        { 0x6au,        7 }, // 79 'O'
        { 0x6bu,        7 }, // 80 'P'
        { 0x6cu,        7 }, // 81 'Q'
        { 0x6du,        7 }, // 82 'R'
        { 0x6eu,        7 }, // 83 'S'
        { 0x6fu,        7 }, // 84 'T'
        { 0x70u,        7 }, // 85 'U'
        { 0x71u,        7 }, // 86 'V'
        { 0x72u,        7 }, // 87 'W'
        { 0xfcu,        8 }, // 88 'X'
        { 0x73u,        7 }, // 89 'Y'
        { 0xfdu,        8 }, // 90 'Z'
        { 0x1ffbu,     13 }, // 91 '['
        { 0x7fff0u,    19 }, // 92 '\'
        { 0x1ffcu,     13 }, // 93 ']'
        { 0x3ffcu,     14 }, // 94 '^'
        { 0x22u,        6 }, // 95 '_'
        { 0x7ffdu,     15 }, // 96 '`'
        { 0x3u,         5 }, // 97 'a'
        { 0x23u,        6 }, // 98 'b'
        { 0x4u,         5 }, // 99 'c'
        { 0x24u,        6 }, // 100 'd'
        { 0x5u,         5 }, // 101 'e'
        { 0x25u,        6 }, // 102 'f'
        { 0x26u,        6 }, // 103 'g'
        { 0x27u,        6 }, // 104 'h'
        { 0x6u,         5 }, // 105 'i'
        { 0x74u,        7 }, // 106 'j'
        { 0x75u,        7 }, // 107 'k'
        { 0x28u,        6 }, // 108 'l'
        { 0x29u,        6 }, // 109 'm'
        { 0x2au,        6 }, // 110 'n'
        { 0x7u,         5 }, // 111 'o'
        { 0x2bu,        6 }, // 112 'p'
        { 0x76u,        7 }, // 113 'q'
        { 0x2cu,        6 }, // 114 'r'
        { 0x8u,         5 }, // 115 's'
        { 0x9u,         5 }, // 116 't'
        { 0x2du,        6 }, // 117 'u'
        { 0x77u,        7 }, // 118 'v'
        { 0x78u,        7 }, // 119 'w'
        { 0x79u,        7 }, // 120 'x'
        { 0x7au,        7 }, // 121 'y'
        { 0x7bu,        7 }, // 122 'z'
        { 0x7ffeu,     15 }, // 123 '{'
        { 0x7fcu,      11 }, // 124 '|'
        { 0x3ffdu,     14 }, // 125 '}'
        { 0x1ffdu,     13 }, // 126 '~'
        { 0xffffffcu,  28 }, // 127
        { 0xfffe6u,    20 }, // 128
        { 0x3fffd2u,   22 }, // 129
        { 0xfffe7u,    20 }, // 130
        { 0xfffe8u,    20 }, // 131
        { 0x3fffd3u,   22 }, // 132
        { 0x3fffd4u,   22 }, // 133
        { 0x3fffd5u,   22 }, // 134
        { 0x7fffd9u,   23 }, // 135
        { 0x3fffd6u,   22 }, // 136
        { 0x7fffdau,   23 }, // 137
        { 0x7fffdbu,   23 }, // 138
        { 0x7fffdcu,   23 }, // 139
        { 0x7fffddu,   23 }, // 140
        { 0x7fffdeu,   23 }, // 141
        { 0xffffebu,   24 }, // 142
        { 0x7fffdfu,   23 }, // 143
        { 0xffffecu,   24 }, // 144
        { 0xffffedu,   24 }, // 145
        { 0x3fffd7u,   22 }, // 146
        { 0x7fffe0u,   23 }, // 147
        { 0xffffeeu,   24 }, // 148
        { 0x7fffe1u,   23 }, // 149
        { 0x7fffe2u,   23 }, // 150
        { 0x7fffe3u,   23 }, // 151
        { 0x7fffe4u,   23 }, // 152
        { 0x1fffdcu,   21 }, // 153
        { 0x3fffd8u,   22 }, // 154
        { 0x7fffe5u,   23 }, // 155
        { 0x3fffd9u,   22 }, // 156
        { 0x7fffe6u,   23 }, // 157
        { 0x7fffe7u,   23 }, // 158
        { 0xffffefu,   24 }, // 159
        { 0x3fffdau,   22 }, // 160
        { 0x1fffddu,   21 }, // 161
        { 0xfffe9u,    20 }, // 162
        { 0x3fffdbu,   22 }, // 163
        { 0x3fffdcu,   22 }, // 164
        { 0x7fffe8u,   23 }, // 165
        { 0x7fffe9u,   23 }, // 166
        { 0x1fffdeu,   21 }, // 167
        { 0x7fffeau,   23 }, // 168
        { 0x3fffddu,   22 }, // 169
        { 0x3fffdeu,   22 }, // 170
        { 0xfffff0u,   24 }, // 171
        { 0x1fffdfu,   21 }, // 172
        { 0x3fffdfu,   22 }, // 173
        { 0x7fffebu,   23 }, // 174
        { 0x7fffecu,   23 }, // 175
        { 0x1fffe0u,   21 }, // 176
        { 0x1fffe1u,   21 }, // 177
        { 0x3fffe0u,   22 }, // 178
        { 0x1fffe2u,   21 }, // 179
        { 0x7fffedu,   23 }, // 180
        { 0x3fffe1u,   22 }, // 181
        { 0x7fffeeu,   23 }, // 182
        { 0x7fffefu,   23 }, // 183
        { 0xfffeau,    20 }, // 184
        { 0x3fffe2u,   22 }, // 185
        { 0x3fffe3u,   22 }, // 186
        { 0x3fffe4u,   22 }, // 187
        { 0x7ffff0u,   23 }, // 188
        { 0x3fffe5u,   22 }, // 189
        { 0x3fffe6u,   22 }, // 190
        { 0x7ffff1u,   23 }, // 191
        { 0x3ffffe0u,  26 }, // 192
        { 0x3ffffe1u,  26 }, // 193
        { 0xfffebu,    20 }, // 194
        { 0x7fff1u,    19 }, // 195
        { 0x3fffe7u,   22 }, // 196
        { 0x7ffff2u,   23 }, // 197
        { 0x3fffe8u,   22 }, // 198
        { 0x1ffffecu,  25 }, // 199
        { 0x3ffffe2u,  26 }, // 200
        { 0x3ffffe3u,  26 }, // 201
        { 0x3ffffe4u,  26 }, // 202
        { 0x7ffffdeu,  27 }, // 203
        { 0x7ffffdfu,  27 }, // 204
        { 0x3ffffe5u,  26 }, // 205
        { 0xfffff1u,   24 }, // 206
        { 0x1ffffedu,  25 }, // 207
        { 0x7fff2u,    19 }, // 208
        { 0x1fffe3u,   21 }, // 209
        { 0x3ffffe6u,  26 }, // 210
        { 0x7ffffe0u,  27 }, // 211
        { 0x7ffffe1u,  27 }, // 212
        { 0x3ffffe7u,  26 }, // 213
        { 0x7ffffe2u,  27 }, // 214
        { 0xfffff2u,   24 }, // 215
        { 0x1fffe4u,   21 }, // 216
        { 0x1fffe5u,   21 }, // 217
        { 0x3ffffe8u,  26 }, // 218
        { 0x3ffffe9u,  26 }, // 219
        { 0xffffffdu,  28 }, // 220
        { 0x7ffffe3u,  27 }, // 221
        { 0x7ffffe4u,  27 }, // 222
        { 0x7ffffe5u,  27 }, // 223
        { 0xfffecu,    20 }, // 224
        { 0xfffff3u,   24 }, // 225
        { 0xfffedu,    20 }, // 226
        { 0x1fffe6u,   21 }, // 227
        { 0x3fffe9u,   22 }, // 228
        { 0x1fffe7u,   21 }, // 229
        { 0x1fffe8u,   21 }, // 230
        { 0x7ffff3u,   23 }, // 231
        { 0x3fffeau,   22 }, // 232
        { 0x3fffebu,   22 }, // 233
        { 0x1ffffeeu,  25 }, // 234
        { 0x1ffffefu,  25 }, // 235
        { 0xfffff4u,   24 }, // 236
        { 0xfffff5u,   24 }, // 237
        { 0x3ffffeau,  26 }, // 238
        { 0x7ffff4u,   23 }, // 239
        { 0x3ffffebu,  26 }, // 240
        { 0x7ffffe6u,  27 }, // 241
        { 0x3ffffecu,  26 }, // 242
        { 0x3ffffedu,  26 }, // 243
        { 0x7ffffe7u,  27 }, // 244
        { 0x7ffffe8u,  27 }, // 245
        { 0x7ffffe9u,  27 }, // 246
        { 0x7ffffeau,  27 }, // 247
        { 0x7ffffebu,  27 }, // 248
        { 0xffffffeu,  28 }, // 249
        { 0x7ffffecu,  27 }, // 250
        { 0x7ffffedu,  27 }, // 251
        { 0x7ffffeeu,  27 }, // 252
        { 0x7ffffefu,  27 }, // 253
        { 0x7fffff0u,  27 }, // 254
        { 0x3ffffeeu,  26 }, // 255
        { 0x3fffffffu, 30 }, // 256 (EOS)
    };

    // Huffman decode state machine
    // 4-bit nibble-based decoder: 256 states, 16 transitions per state
    // Each transition: { next_state (8 bits), flags (4 bits), symbol (8 bits) }
    // flags: bit 0 = emit symbol, bit 1 = accepted (valid end state), bit 2 = error
    struct HpackHuffmanDecodeEntry final
    {
        UCHAR NextState;
        UCHAR Flags;  // 0x01=emit, 0x02=accepted, 0x04=error
        UCHAR Symbol;
    };

    constexpr UCHAR HpackHuffmanFlagEmit = 0x01;
    constexpr UCHAR HpackHuffmanFlagAccepted = 0x02;
    constexpr UCHAR HpackHuffmanFlagError = 0x04;
}
}
