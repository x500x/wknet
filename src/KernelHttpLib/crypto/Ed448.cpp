#include <KernelHttp/crypto/Ed448.h>

// Software Ed448 (PureEdDSA, RFC 8032) verification + SHAKE256.
//
// This mirrors the Ed25519 verifier style: public-data arithmetic, heap-backed
// scratch storage, and explicit rejection of malformed encodings. Field
// arithmetic uses radix-2^16 limbs modulo p = 2^448 - 2^224 - 1, which avoids
// relying on compiler-specific 128-bit integers in kernel builds.

namespace KernelHttp
{
namespace crypto
{
    namespace
    {
        constexpr SIZE_T FieldElementLength = 28;
        constexpr SIZE_T Ed448ScalarLength = 57;
        constexpr SIZE_T Shake256Rate = 136;

        using FieldElement = long long[FieldElementLength];

        const FieldElement Gf0 = { 0 };
        const FieldElement Gf1 = { 1 };

        const FieldElement Ed448P = {
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe, 0xffff,
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            0xffff, 0xffff, 0xffff, 0xffff
        };

        const FieldElement Ed448D = {
            0x6756, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe, 0xffff,
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            0xffff, 0xffff, 0xffff, 0xffff
        };

        const FieldElement Ed448X = {
            0xc05e, 0xc70c, 0xa82b, 0x2626, 0x938e, 0x8b00, 0x80e1, 0x433b,
            0x6511, 0x2ab6, 0x1af7, 0x12ae, 0xa464, 0xa3d3, 0xe324, 0xea6d,
            0x1767, 0x470f, 0x6570, 0x9e14, 0x36da, 0x22bf, 0x15a6, 0x221d,
            0x0ded, 0x6bed, 0x70c6, 0x4f19
        };

        const FieldElement Ed448Y = {
            0xfa14, 0xf230, 0x795b, 0x9808, 0xc8ad, 0x4ed7, 0x132c, 0xfdbd,
            0x39c4, 0xe67c, 0xff1c, 0x3ad3, 0xc2d7, 0x05a0, 0x9c1e, 0x8778,
            0x9840, 0x6ca3, 0x7373, 0x4bea, 0xc762, 0x56c9, 0x2037, 0x8876,
            0xbc24, 0x6eb6, 0x4671, 0x693f
        };

        const UCHAR Ed448Order[Ed448ScalarLength] = {
            0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
            0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
            0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
            0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
            0x00
        };

        const UCHAR Ed448SqrtExponent[56] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f
        };

        const UCHAR Ed448PMinus2[56] = {
            0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };

        const UCHAR Ed448Dom4Empty[10] = {
            'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0x00, 0x00
        };

        struct Ed448Scratch final
        {
            long long Product[55] = {};
            FieldElement PackValue = {};
            FieldElement PackReduced = {};
            FieldElement AddA = {}, AddB = {}, AddC = {}, AddD = {};
            FieldElement AddT = {}, AddE = {}, AddF = {}, AddG = {}, AddH = {};
            FieldElement PowResult = {}, PowBase = {};
            FieldElement Inv = {}, Sqrt = {};
            FieldElement UnY2 = {}, UnU = {}, UnV = {}, UnX2 = {}, UnChk = {};
            FieldElement PkTx = {}, PkTy = {}, PkZi = {};
            FieldElement VP[4] = {};
            FieldElement VQ[4] = {};
            FieldElement Base[4] = {};
            UCHAR CmpA[57] = {};
            UCHAR CmpB[57] = {};
            UCHAR Hash[114] = {};
            UCHAR Scalar[Ed448ScalarLength] = {};
            UCHAR Packed[Ed448PublicKeyLength] = {};
        };

        struct Shake256Context final
        {
            unsigned long long State[25] = {};
            UCHAR Block[Shake256Rate] = {};
            SIZE_T BlockLength = 0;
            bool Finalized = false;
        };

        void Set(FieldElement out, const FieldElement in) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                out[index] = in[index];
            }
        }

        void Add(FieldElement out, const FieldElement a, const FieldElement b) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                out[index] = a[index] + b[index];
            }
        }

        void Sub(FieldElement out, const FieldElement a, const FieldElement b) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                out[index] = a[index] - b[index];
            }
        }

        long long FloorCarry(long long value) noexcept
        {
            if (value >= 0) {
                return value >> 16;
            }
            return -(((-value) + 0xffff) >> 16);
        }

        void Carry(FieldElement value) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                const long long carry = FloorCarry(value[index]);
                value[index] -= carry << 16;
                if (index + 1 < FieldElementLength) {
                    value[index + 1] += carry;
                }
                else {
                    value[0] += carry;
                    value[14] += carry;
                }
            }
        }

        bool GreaterOrEqualP(const FieldElement value) noexcept
        {
            for (int index = static_cast<int>(FieldElementLength) - 1; index >= 0; --index) {
                if (value[index] > Ed448P[index]) {
                    return true;
                }
                if (value[index] < Ed448P[index]) {
                    return false;
                }
            }
            return true;
        }

        void SubtractP(FieldElement value) noexcept
        {
            long long borrow = 0;
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                long long current = value[index] - Ed448P[index] - borrow;
                if (current < 0) {
                    current += 1LL << 16;
                    borrow = 1;
                }
                else {
                    borrow = 0;
                }
                value[index] = current;
            }
        }

        void Normalize(FieldElement value) noexcept
        {
            for (SIZE_T round = 0; round < 8; ++round) {
                Carry(value);
            }
            for (SIZE_T round = 0; round < 2; ++round) {
                if (GreaterOrEqualP(value)) {
                    SubtractP(value);
                }
            }
        }

        void Multiply(Ed448Scratch& s, FieldElement out, const FieldElement a, const FieldElement b) noexcept
        {
            long long* product = s.Product;
            for (SIZE_T index = 0; index < 55; ++index) {
                product[index] = 0;
            }
            for (SIZE_T i = 0; i < FieldElementLength; ++i) {
                for (SIZE_T j = 0; j < FieldElementLength; ++j) {
                    product[i + j] += a[i] * b[j];
                }
            }
            for (int index = 54; index >= static_cast<int>(FieldElementLength); --index) {
                product[index - FieldElementLength] += product[index];
                product[index - 14] += product[index];
                product[index] = 0;
            }
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                out[index] = product[index];
            }
            Normalize(out);
        }

        void Square(Ed448Scratch& s, FieldElement out, const FieldElement a) noexcept
        {
            Multiply(s, out, a, a);
        }

        bool Unpack(FieldElement out, const UCHAR* input, UCHAR* sign) noexcept
        {
            if ((input[56] & 0x7f) != 0) {
                return false;
            }
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                out[index] =
                    static_cast<long long>(input[2 * index]) |
                    (static_cast<long long>(input[(2 * index) + 1]) << 8);
            }
            Normalize(out);
            if (GreaterOrEqualP(out)) {
                return false;
            }
            *sign = static_cast<UCHAR>((input[56] >> 7) & 1);
            return true;
        }

        void Pack(Ed448Scratch& s, UCHAR* output, const FieldElement input) noexcept
        {
            FieldElement& value = s.PackValue;
            Set(value, input);
            Normalize(value);
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[2 * index] = static_cast<UCHAR>(value[index] & 0xff);
                output[(2 * index) + 1] = static_cast<UCHAR>((value[index] >> 8) & 0xff);
            }
            output[56] = 0;
        }

        bool FieldEquals(Ed448Scratch& s, const FieldElement a, const FieldElement b) noexcept
        {
            Pack(s, s.CmpA, a);
            Pack(s, s.CmpB, b);
            int diff = 0;
            for (SIZE_T index = 0; index < Ed448PublicKeyLength; ++index) {
                diff |= s.CmpA[index] ^ s.CmpB[index];
            }
            return diff == 0;
        }

        UCHAR Parity(Ed448Scratch& s, const FieldElement a) noexcept
        {
            Pack(s, s.CmpA, a);
            return static_cast<UCHAR>(s.CmpA[0] & 1);
        }

        void Pow(Ed448Scratch& s, FieldElement out, const FieldElement in, const UCHAR* exponent, SIZE_T exponentLength) noexcept
        {
            FieldElement& result = s.PowResult;
            FieldElement& base = s.PowBase;
            Set(result, Gf1);
            Set(base, in);
            for (int bit = static_cast<int>(exponentLength * 8) - 1; bit >= 0; --bit) {
                Square(s, result, result);
                if (((exponent[bit >> 3] >> (bit & 7)) & 1) != 0) {
                    Multiply(s, result, result, base);
                }
            }
            Set(out, result);
        }

        void Invert(Ed448Scratch& s, FieldElement out, const FieldElement in) noexcept
        {
            Pow(s, out, in, Ed448PMinus2, sizeof(Ed448PMinus2));
        }

        void Sqrt(Ed448Scratch& s, FieldElement out, const FieldElement in) noexcept
        {
            Pow(s, out, in, Ed448SqrtExponent, sizeof(Ed448SqrtExponent));
        }

        void PointAdd(Ed448Scratch& s, FieldElement p[4], FieldElement q[4]) noexcept
        {
            FieldElement& a = s.AddA;
            FieldElement& b = s.AddB;
            FieldElement& c = s.AddC;
            FieldElement& d = s.AddD;
            FieldElement& t = s.AddT;
            FieldElement& e = s.AddE;
            FieldElement& f = s.AddF;
            FieldElement& g = s.AddG;
            FieldElement& h = s.AddH;

            // Projective addition for a=1 Edwards curves:
            // x3=(x1*y2+y1*x2)/(1+d*x1*x2*y1*y2)
            // y3=(y1*y2-x1*x2)/(1-d*x1*x2*y1*y2)
            Multiply(s, a, p[2], q[2]);        // A = Z1*Z2
            Square(s, b, a);                   // B = A^2
            Multiply(s, c, p[0], q[0]);        // C = X1*X2
            Multiply(s, d, p[1], q[1]);        // D = Y1*Y2
            Multiply(s, e, c, d);
            Multiply(s, e, e, Ed448D);         // E = d*C*D
            Sub(f, b, e);                      // F = B-E
            Add(g, b, e);                      // G = B+E
            Add(h, p[0], p[1]);
            Add(t, q[0], q[1]);
            Multiply(s, h, h, t);
            Sub(h, h, c);
            Sub(h, h, d);                      // H = X1*Y2+Y1*X2
            Sub(t, d, c);                      // T = D-C
            Multiply(s, p[0], a, f);
            Multiply(s, p[0], p[0], h);
            Multiply(s, p[1], a, g);
            Multiply(s, p[1], p[1], t);
            Multiply(s, p[2], f, g);
            Set(p[3], Gf0);
        }

        void Select(FieldElement left, FieldElement right, long long swap) noexcept
        {
            const long long mask = ~(swap - 1);
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                const long long value = mask & (left[index] ^ right[index]);
                left[index] ^= value;
                right[index] ^= value;
            }
        }

        void PointSwap(FieldElement p[4], FieldElement q[4], UCHAR bit) noexcept
        {
            for (SIZE_T index = 0; index < 4; ++index) {
                Select(p[index], q[index], bit);
            }
        }

        void PointPack(Ed448Scratch& s, UCHAR* output, FieldElement p[4]) noexcept
        {
            FieldElement& tx = s.PkTx;
            FieldElement& ty = s.PkTy;
            FieldElement& zi = s.PkZi;
            Invert(s, zi, p[2]);
            Multiply(s, tx, p[0], zi);
            Multiply(s, ty, p[1], zi);
            Pack(s, output, ty);
            output[56] = static_cast<UCHAR>(Parity(s, tx) << 7);
        }

        void ScalarMult(Ed448Scratch& s, FieldElement p[4], FieldElement q[4], const UCHAR* scalar) noexcept
        {
            Set(p[0], Gf0);
            Set(p[1], Gf1);
            Set(p[2], Gf1);
            Set(p[3], Gf0);
            for (int bit = static_cast<int>(Ed448ScalarLength * 8) - 1; bit >= 0; --bit) {
                const UCHAR b = static_cast<UCHAR>((scalar[bit >> 3] >> (bit & 7)) & 1);
                PointSwap(p, q, b);
                PointAdd(s, q, p);
                PointAdd(s, p, p);
                PointSwap(p, q, b);
            }
        }

        void ScalarBase(Ed448Scratch& s, FieldElement p[4], const UCHAR* scalar) noexcept
        {
            FieldElement* base = s.Base;
            Set(base[0], Ed448X);
            Set(base[1], Ed448Y);
            Set(base[2], Gf1);
            Multiply(s, base[3], Ed448X, Ed448Y);
            ScalarMult(s, p, base, scalar);
        }

        bool UnpackNeg(Ed448Scratch& s, FieldElement r[4], const UCHAR* encoded) noexcept
        {
            UCHAR sign = 0;
            if (!Unpack(r[1], encoded, &sign)) {
                return false;
            }

            FieldElement& y2 = s.UnY2;
            FieldElement& u = s.UnU;
            FieldElement& v = s.UnV;
            FieldElement& x2 = s.UnX2;
            FieldElement& chk = s.UnChk;
            FieldElement& inv = s.Inv;
            FieldElement& root = s.Sqrt;

            Set(r[2], Gf1);
            Square(s, y2, r[1]);
            Sub(u, Gf1, y2);
            Multiply(s, v, Ed448D, y2);
            Sub(v, Gf1, v);
            Invert(s, inv, v);
            Multiply(s, x2, u, inv);
            Sqrt(s, root, x2);

            Square(s, chk, root);
            if (!FieldEquals(s, chk, x2)) {
                return false;
            }
            if (FieldEquals(s, root, Gf0) && sign != 0) {
                return false;
            }
            if (Parity(s, root) != sign) {
                Sub(root, Gf0, root);
            }

            Sub(r[0], Gf0, root);
            Multiply(s, r[3], r[0], r[1]);
            return true;
        }

        int CompareScalar(const UCHAR* left, const UCHAR* right) noexcept
        {
            for (int index = static_cast<int>(Ed448ScalarLength) - 1; index >= 0; --index) {
                if (left[index] < right[index]) {
                    return -1;
                }
                if (left[index] > right[index]) {
                    return 1;
                }
            }
            return 0;
        }

        void SubtractScalarOrder(UCHAR* scalar) noexcept
        {
            int borrow = 0;
            for (SIZE_T index = 0; index < Ed448ScalarLength; ++index) {
                int value = static_cast<int>(scalar[index]) - static_cast<int>(Ed448Order[index]) - borrow;
                if (value < 0) {
                    value += 256;
                    borrow = 1;
                }
                else {
                    borrow = 0;
                }
                scalar[index] = static_cast<UCHAR>(value);
            }
        }

        bool ScalarBelowOrder(const UCHAR* scalar) noexcept
        {
            return CompareScalar(scalar, Ed448Order) < 0;
        }

        void ScalarReduce(UCHAR* output, const UCHAR* input, SIZE_T inputLength) noexcept
        {
            for (SIZE_T index = 0; index < Ed448ScalarLength; ++index) {
                output[index] = 0;
            }

            for (int bit = static_cast<int>(inputLength * 8) - 1; bit >= 0; --bit) {
                int carry = static_cast<int>((input[bit >> 3] >> (bit & 7)) & 1);
                for (SIZE_T index = 0; index < Ed448ScalarLength; ++index) {
                    const int value = (static_cast<int>(output[index]) << 1) | carry;
                    output[index] = static_cast<UCHAR>(value & 0xff);
                    carry = (value >> 8) & 1;
                }
                if (CompareScalar(output, Ed448Order) >= 0) {
                    SubtractScalarOrder(output);
                }
            }
        }

        unsigned long long RotateLeft64(unsigned long long value, unsigned int bits) noexcept
        {
            if (bits == 0) {
                return value;
            }
            return (value << bits) | (value >> (64 - bits));
        }

        const unsigned long long KeccakRoundConstants[24] = {
            0x0000000000000001ULL, 0x0000000000008082ULL,
            0x800000000000808aULL, 0x8000000080008000ULL,
            0x000000000000808bULL, 0x0000000080000001ULL,
            0x8000000080008081ULL, 0x8000000000008009ULL,
            0x000000000000008aULL, 0x0000000000000088ULL,
            0x0000000080008009ULL, 0x000000008000000aULL,
            0x000000008000808bULL, 0x800000000000008bULL,
            0x8000000000008089ULL, 0x8000000000008003ULL,
            0x8000000000008002ULL, 0x8000000000000080ULL,
            0x000000000000800aULL, 0x800000008000000aULL,
            0x8000000080008081ULL, 0x8000000000008080ULL,
            0x0000000080000001ULL, 0x8000000080008008ULL
        };

        const unsigned int KeccakRho[25] = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
        };

        void KeccakF1600(unsigned long long* state) noexcept
        {
            unsigned long long c[5] = {};
            unsigned long long d[5] = {};
            unsigned long long b[25] = {};

            for (SIZE_T round = 0; round < 24; ++round) {
                for (SIZE_T x = 0; x < 5; ++x) {
                    c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
                }
                for (SIZE_T x = 0; x < 5; ++x) {
                    d[x] = c[(x + 4) % 5] ^ RotateLeft64(c[(x + 1) % 5], 1);
                }
                for (SIZE_T y = 0; y < 5; ++y) {
                    for (SIZE_T x = 0; x < 5; ++x) {
                        state[x + (5 * y)] ^= d[x];
                    }
                }

                for (SIZE_T y = 0; y < 5; ++y) {
                    for (SIZE_T x = 0; x < 5; ++x) {
                        const SIZE_T source = x + (5 * y);
                        const SIZE_T targetX = y;
                        const SIZE_T targetY = (2 * x + 3 * y) % 5;
                        b[targetX + (5 * targetY)] = RotateLeft64(state[source], KeccakRho[source]);
                    }
                }

                for (SIZE_T y = 0; y < 5; ++y) {
                    for (SIZE_T x = 0; x < 5; ++x) {
                        state[x + (5 * y)] =
                            b[x + (5 * y)] ^
                            ((~b[((x + 1) % 5) + (5 * y)]) & b[((x + 2) % 5) + (5 * y)]);
                    }
                }

                state[0] ^= KeccakRoundConstants[round];
            }

            RtlSecureZeroMemory(c, sizeof(c));
            RtlSecureZeroMemory(d, sizeof(d));
            RtlSecureZeroMemory(b, sizeof(b));
        }

        void ShakeAbsorbBlock(Shake256Context& ctx) noexcept
        {
            for (SIZE_T lane = 0; lane < Shake256Rate / 8; ++lane) {
                unsigned long long value = 0;
                for (SIZE_T byte = 0; byte < 8; ++byte) {
                    value |= static_cast<unsigned long long>(ctx.Block[(lane * 8) + byte]) << (8 * byte);
                }
                ctx.State[lane] ^= value;
            }
            RtlSecureZeroMemory(ctx.Block, sizeof(ctx.Block));
            ctx.BlockLength = 0;
            KeccakF1600(ctx.State);
        }

        void Shake256Init(Shake256Context& ctx) noexcept
        {
            RtlSecureZeroMemory(&ctx, sizeof(ctx));
        }

        void Shake256Update(Shake256Context& ctx, const UCHAR* data, SIZE_T length) noexcept
        {
            for (SIZE_T index = 0; index < length; ++index) {
                ctx.Block[ctx.BlockLength++] = data[index];
                if (ctx.BlockLength == Shake256Rate) {
                    ShakeAbsorbBlock(ctx);
                }
            }
        }

        void Shake256Finalize(Shake256Context& ctx) noexcept
        {
            if (ctx.Finalized) {
                return;
            }
            ctx.Block[ctx.BlockLength] ^= 0x1f;
            ctx.Block[Shake256Rate - 1] ^= 0x80;
            ShakeAbsorbBlock(ctx);
            ctx.Finalized = true;
        }

        void Shake256Squeeze(Shake256Context& ctx, UCHAR* output, SIZE_T outputLength) noexcept
        {
            Shake256Finalize(ctx);
            SIZE_T offset = 0;
            while (offset < outputLength) {
                for (SIZE_T lane = 0; lane < Shake256Rate / 8 && offset < outputLength; ++lane) {
                    const unsigned long long value = ctx.State[lane];
                    for (SIZE_T byte = 0; byte < 8 && offset < outputLength; ++byte) {
                        output[offset++] = static_cast<UCHAR>((value >> (8 * byte)) & 0xff);
                    }
                }
                if (offset < outputLength) {
                    KeccakF1600(ctx.State);
                }
            }
        }
    }

    bool Shake256Compute(const UCHAR* data, SIZE_T dataLength, UCHAR* output, SIZE_T outputLength) noexcept
    {
        if (output == nullptr || (data == nullptr && dataLength != 0)) {
            return false;
        }

        HeapObject<Shake256Context> context;
        if (!context.IsValid()) {
            return false;
        }

        Shake256Init(*context.Get());
        if (dataLength != 0) {
            Shake256Update(*context.Get(), data, dataLength);
        }
        Shake256Squeeze(*context.Get(), output, outputLength);
        RtlSecureZeroMemory(context.Get(), sizeof(Shake256Context));
        return true;
    }

    bool Ed448Verify(
        const UCHAR* publicKey,
        SIZE_T publicKeyLength,
        const UCHAR* message,
        SIZE_T messageLength,
        const UCHAR* signature,
        SIZE_T signatureLength) noexcept
    {
        if (publicKey == nullptr ||
            signature == nullptr ||
            (message == nullptr && messageLength != 0) ||
            publicKeyLength != Ed448PublicKeyLength ||
            signatureLength != Ed448SignatureLength) {
            return false;
        }

        const UCHAR* r = signature;
        const UCHAR* sBytes = signature + Ed448PublicKeyLength;
        if (!ScalarBelowOrder(sBytes)) {
            return false;
        }

        HeapObject<Ed448Scratch> scratchHolder;
        HeapObject<Shake256Context> hashHolder;
        if (!scratchHolder.IsValid() || !hashHolder.IsValid()) {
            return false;
        }

        Ed448Scratch& scratch = *scratchHolder.Get();
        Shake256Context& hash = *hashHolder.Get();
        bool result = false;

        if (UnpackNeg(scratch, scratch.VQ, publicKey)) {
            Shake256Init(hash);
            Shake256Update(hash, Ed448Dom4Empty, sizeof(Ed448Dom4Empty));
            Shake256Update(hash, r, Ed448PublicKeyLength);
            Shake256Update(hash, publicKey, Ed448PublicKeyLength);
            if (messageLength != 0) {
                Shake256Update(hash, message, messageLength);
            }
            Shake256Squeeze(hash, scratch.Hash, sizeof(scratch.Hash));
            ScalarReduce(scratch.Scalar, scratch.Hash, sizeof(scratch.Hash));

            ScalarMult(scratch, scratch.VP, scratch.VQ, scratch.Scalar);
            ScalarBase(scratch, scratch.VQ, sBytes);
            PointAdd(scratch, scratch.VP, scratch.VQ);
            PointPack(scratch, scratch.Packed, scratch.VP);

            int diff = 0;
            for (SIZE_T index = 0; index < Ed448PublicKeyLength; ++index) {
                diff |= scratch.Packed[index] ^ r[index];
            }
            result = diff == 0;
        }

        RtlSecureZeroMemory(scratchHolder.Get(), sizeof(Ed448Scratch));
        RtlSecureZeroMemory(hashHolder.Get(), sizeof(Shake256Context));
        return result;
    }
}
}
