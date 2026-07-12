#include <wknet/crypto/Ed25519.h>

// Software Ed25519 (PureEdDSA, RFC 8032) verification + SHA-512.
//
// The field arithmetic mod 2^255-19 mirrors the X25519 implementation in
// KeyExchange.cpp (same 16-limb radix-2^16 FieldElement). The twisted-Edwards
// point arithmetic, decompression, scalar reduction mod L and the verify
// equation follow the TweetNaCl reference (public-domain). All temporaries live
// in a heap-allocated scratch struct to honor the library's no-stack-buffers
// rule; this verifier touches only public data so it is not constant-time by
// design, but it strictly enforces RFC 8032 rejection conditions.

namespace wknet
{
namespace crypto
{
    namespace
    {
        constexpr SIZE_T FieldElementLength = 16;
        using FieldElement = long long[FieldElementLength];

        const FieldElement Gf0 = { 0 };
        const FieldElement Gf1 = { 1 };

        // Curve constant d (twisted Edwards), little-endian 16-bit limbs.
        const FieldElement EdD = {
            0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
            0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203
        };
        // 2*d.
        const FieldElement EdD2 = {
            0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
            0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406
        };
        // Base point coordinates X, Y.
        const FieldElement EdX = {
            0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
            0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169
        };
        const FieldElement EdY = {
            0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
            0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666
        };
        // sqrt(-1) mod p.
        const FieldElement EdI = {
            0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
            0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83
        };

        // Group order L = 2^252 + 27742317777372353535851937790883648493,
        // little-endian bytes, used by the scalar reduction.
        const long long EdL[32] = {
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x10
        };

        struct Ed25519Scratch final
        {
            long long Product[31] = {};
            FieldElement PackValue = {};
            FieldElement PackReduced = {};
            // add() temporaries
            FieldElement AddA = {}, AddB = {}, AddC = {}, AddD = {};
            FieldElement AddT = {}, AddE = {}, AddF = {}, AddG = {}, AddH = {};
            // decompression temporaries
            FieldElement UnT = {}, UnChk = {}, UnNum = {}, UnDen = {};
            FieldElement UnDen2 = {}, UnDen4 = {}, UnDen6 = {};
            FieldElement PowC = {};
            FieldElement InvC = {};
            FieldElement PkTx = {}, PkTy = {}, PkZi = {};
            // points (extended coordinates X:Y:Z:T)
            FieldElement VP[4] = {};
            FieldElement VQ[4] = {};
            FieldElement Base[4] = {};
            UCHAR CmpC[32] = {};
            UCHAR CmpD[32] = {};
            UCHAR HashScalar[64] = {};
            long long ModLx[64] = {};
            UCHAR Packed[32] = {};
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

        void Carry(FieldElement value) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                value[index] += 1LL << 16;
                const long long carry = value[index] >> 16;
                if (index < FieldElementLength - 1) {
                    value[index + 1] += carry - 1;
                }
                else {
                    value[0] += 38 * (carry - 1);
                }
                value[index] -= carry << 16;
            }
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

        void Multiply(Ed25519Scratch& s, FieldElement out, const FieldElement a, const FieldElement b) noexcept
        {
            long long* product = s.Product;
            for (SIZE_T index = 0; index < 31; ++index) {
                product[index] = 0;
            }
            for (SIZE_T i = 0; i < FieldElementLength; ++i) {
                for (SIZE_T j = 0; j < FieldElementLength; ++j) {
                    product[i + j] += a[i] * b[j];
                }
            }
            for (SIZE_T index = 0; index < FieldElementLength - 1; ++index) {
                product[index] += 38 * product[index + FieldElementLength];
            }
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                out[index] = product[index];
            }
            Carry(out);
            Carry(out);
        }

        void Square(Ed25519Scratch& s, FieldElement out, const FieldElement a) noexcept
        {
            Multiply(s, out, a, a);
        }

        void Unpack(FieldElement out, const UCHAR* input) noexcept
        {
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                out[index] =
                    static_cast<long long>(input[2 * index]) |
                    (static_cast<long long>(input[(2 * index) + 1]) << 8);
            }
            out[15] &= 0x7fff;
        }

        void Pack(Ed25519Scratch& s, UCHAR* output, const FieldElement input) noexcept
        {
            FieldElement& value = s.PackValue;
            FieldElement& reduced = s.PackReduced;
            Set(value, input);
            Carry(value);
            Carry(value);
            Carry(value);
            for (SIZE_T round = 0; round < 2; ++round) {
                Set(reduced, value);
                reduced[0] -= 0xffed;
                for (SIZE_T index = 1; index < FieldElementLength - 1; ++index) {
                    reduced[index] -= 0xffff + ((reduced[index - 1] >> 16) & 1);
                    reduced[index - 1] &= 0xffff;
                }
                reduced[15] -= 0x7fff + ((reduced[14] >> 16) & 1);
                reduced[14] &= 0xffff;
                Select(value, reduced, 1 - ((reduced[15] >> 16) & 1));
            }
            for (SIZE_T index = 0; index < FieldElementLength; ++index) {
                output[2 * index] = static_cast<UCHAR>(value[index] & 0xff);
                output[(2 * index) + 1] = static_cast<UCHAR>((value[index] >> 8) & 0xff);
            }
        }

        // Returns true if the two field elements pack to identical bytes.
        bool FieldEquals(Ed25519Scratch& s, const FieldElement a, const FieldElement b) noexcept
        {
            Pack(s, s.CmpC, a);
            Pack(s, s.CmpD, b);
            int diff = 0;
            for (SIZE_T index = 0; index < 32; ++index) {
                diff |= s.CmpC[index] ^ s.CmpD[index];
            }
            return diff == 0;
        }

        UCHAR Parity(Ed25519Scratch& s, const FieldElement a) noexcept
        {
            Pack(s, s.CmpD, a);
            return static_cast<UCHAR>(s.CmpD[0] & 1);
        }

        void Invert(Ed25519Scratch& s, FieldElement out, const FieldElement in) noexcept
        {
            FieldElement& c = s.InvC;
            Set(c, in);
            for (int index = 253; index >= 0; --index) {
                Square(s, c, c);
                if (index != 2 && index != 4) {
                    Multiply(s, c, c, in);
                }
            }
            Set(out, c);
        }

        // Exponentiation by (p-5)/8, used to compute the candidate square root.
        void Pow2523(Ed25519Scratch& s, FieldElement out, const FieldElement in) noexcept
        {
            FieldElement& c = s.PowC;
            Set(c, in);
            for (int index = 250; index >= 0; --index) {
                Square(s, c, c);
                if (index != 1) {
                    Multiply(s, c, c, in);
                }
            }
            Set(out, c);
        }

        // Point addition in extended coordinates; p := p + q. Safe for p == q.
        void PointAdd(Ed25519Scratch& s, FieldElement p[4], FieldElement q[4]) noexcept
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

            Sub(a, p[1], p[0]);
            Sub(t, q[1], q[0]);
            Multiply(s, a, a, t);
            Add(b, p[0], p[1]);
            Add(t, q[0], q[1]);
            Multiply(s, b, b, t);
            Multiply(s, c, p[3], q[3]);
            Multiply(s, c, c, EdD2);
            Multiply(s, d, p[2], q[2]);
            Add(d, d, d);
            Sub(e, b, a);
            Sub(f, d, c);
            Add(g, d, c);
            Add(h, b, a);
            Multiply(s, p[0], e, f);
            Multiply(s, p[1], h, g);
            Multiply(s, p[2], g, f);
            Multiply(s, p[3], e, h);
        }

        void PointSwap(FieldElement p[4], FieldElement q[4], UCHAR bit) noexcept
        {
            for (SIZE_T index = 0; index < 4; ++index) {
                Select(p[index], q[index], bit);
            }
        }

        void PointPack(Ed25519Scratch& s, UCHAR* output, FieldElement p[4]) noexcept
        {
            FieldElement& tx = s.PkTx;
            FieldElement& ty = s.PkTy;
            FieldElement& zi = s.PkZi;
            Invert(s, zi, p[2]);
            Multiply(s, tx, p[0], zi);
            Multiply(s, ty, p[1], zi);
            Pack(s, output, ty);
            output[31] = static_cast<UCHAR>(output[31] ^ (Parity(s, tx) << 7));
        }

        // p := [scalar] q, scalar little-endian 32 bytes.
        void ScalarMult(Ed25519Scratch& s, FieldElement p[4], FieldElement q[4], const UCHAR* scalar) noexcept
        {
            Set(p[0], Gf0);
            Set(p[1], Gf1);
            Set(p[2], Gf1);
            Set(p[3], Gf0);
            for (int bit = 255; bit >= 0; --bit) {
                const UCHAR b = static_cast<UCHAR>((scalar[bit >> 3] >> (bit & 7)) & 1);
                PointSwap(p, q, b);
                PointAdd(s, q, p);
                PointAdd(s, p, p);
                PointSwap(p, q, b);
            }
        }

        // p := [scalar] B (base point).
        void ScalarBase(Ed25519Scratch& s, FieldElement p[4], const UCHAR* scalar) noexcept
        {
            FieldElement* base = s.Base;
            Set(base[0], EdX);
            Set(base[1], EdY);
            Set(base[2], Gf1);
            Multiply(s, base[3], EdX, EdY);
            ScalarMult(s, p, base, scalar);
        }

        // Decompress a 32-byte point encoding into -P (extended coordinates).
        // Returns false if the encoding is not a valid curve point. Matches
        // TweetNaCl's unpackneg: yields the negation needed by the verify equation.
        bool UnpackNeg(Ed25519Scratch& s, FieldElement r[4], const UCHAR* encoded) noexcept
        {
            FieldElement& t = s.UnT;
            FieldElement& chk = s.UnChk;
            FieldElement& num = s.UnNum;
            FieldElement& den = s.UnDen;
            FieldElement& den2 = s.UnDen2;
            FieldElement& den4 = s.UnDen4;
            FieldElement& den6 = s.UnDen6;

            Set(r[2], Gf1);
            Unpack(r[1], encoded);
            Square(s, num, r[1]);
            Multiply(s, den, num, EdD);
            Sub(num, num, r[2]);
            Add(den, r[2], den);

            Square(s, den2, den);
            Square(s, den4, den2);
            Multiply(s, den6, den4, den2);
            Multiply(s, t, den6, num);
            Multiply(s, t, t, den);

            Pow2523(s, t, t);
            Multiply(s, t, t, num);
            Multiply(s, t, t, den);
            Multiply(s, t, t, den);
            Multiply(s, r[0], t, den);

            Square(s, chk, r[0]);
            Multiply(s, chk, chk, den);
            if (!FieldEquals(s, chk, num)) {
                Multiply(s, r[0], r[0], EdI);
            }

            Square(s, chk, r[0]);
            Multiply(s, chk, chk, den);
            if (!FieldEquals(s, chk, num)) {
                return false;
            }

            if (Parity(s, r[0]) == (encoded[31] >> 7)) {
                Sub(r[0], Gf0, r[0]);
            }

            Multiply(s, r[3], r[0], r[1]);
            return true;
        }

        // r (64 LE bytes) := r mod L, result in r[0..31].
        void ScalarReduce(Ed25519Scratch& s, UCHAR* r) noexcept
        {
            long long* x = s.ModLx;
            for (SIZE_T index = 0; index < 64; ++index) {
                x[index] = static_cast<long long>(r[index]);
                r[index] = 0;
            }
            long long carry = 0;
            for (long long i = 63; i >= 32; --i) {
                carry = 0;
                long long j = i - 32;
                for (; j < i - 12; ++j) {
                    x[j] += carry - 16 * x[i] * EdL[j - (i - 32)];
                    carry = (x[j] + 128) >> 8;
                    x[j] -= carry << 8;
                }
                x[j] += carry;
                x[i] = 0;
            }
            carry = 0;
            for (SIZE_T j = 0; j < 32; ++j) {
                x[j] += carry - (x[31] >> 4) * EdL[j];
                carry = x[j] >> 8;
                x[j] &= 255;
            }
            for (SIZE_T j = 0; j < 32; ++j) {
                x[j] -= carry * EdL[j];
            }
            for (SIZE_T i = 0; i < 32; ++i) {
                x[i + 1] += x[i] >> 8;
                r[i] = static_cast<UCHAR>(x[i] & 255);
            }
        }

        // Constant-time-ish check that a 32-byte little-endian scalar is < L.
        bool ScalarBelowOrder(const UCHAR* scalar) noexcept
        {
            for (int index = 31; index >= 0; --index) {
                const int s = scalar[index];
                const int l = static_cast<int>(EdL[index]);
                if (s < l) {
                    return true;
                }
                if (s > l) {
                    return false;
                }
            }
            // Equal to L is out of range.
            return false;
        }

        // ---- SHA-512 (FIPS 180-4) ----

        struct Sha512Context final
        {
            unsigned long long State[8] = {};
            unsigned long long TotalBytes = 0;
            unsigned long long W[80] = {};
            UCHAR Block[128] = {};
            SIZE_T BlockLength = 0;
        };

        const unsigned long long Sha512InitialState[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };

        const unsigned long long Sha512Constants[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
            0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
        };

        unsigned long long RotateRight64(unsigned long long value, unsigned int bits) noexcept
        {
            return (value >> bits) | (value << (64 - bits));
        }

        void Sha512Transform(Sha512Context& ctx, const UCHAR* block) noexcept
        {
            unsigned long long* w = ctx.W;
            for (SIZE_T index = 0; index < 16; ++index) {
                w[index] =
                    (static_cast<unsigned long long>(block[index * 8]) << 56) |
                    (static_cast<unsigned long long>(block[index * 8 + 1]) << 48) |
                    (static_cast<unsigned long long>(block[index * 8 + 2]) << 40) |
                    (static_cast<unsigned long long>(block[index * 8 + 3]) << 32) |
                    (static_cast<unsigned long long>(block[index * 8 + 4]) << 24) |
                    (static_cast<unsigned long long>(block[index * 8 + 5]) << 16) |
                    (static_cast<unsigned long long>(block[index * 8 + 6]) << 8) |
                    static_cast<unsigned long long>(block[index * 8 + 7]);
            }
            for (SIZE_T index = 16; index < 80; ++index) {
                const unsigned long long s0 =
                    RotateRight64(w[index - 15], 1) ^ RotateRight64(w[index - 15], 8) ^ (w[index - 15] >> 7);
                const unsigned long long s1 =
                    RotateRight64(w[index - 2], 19) ^ RotateRight64(w[index - 2], 61) ^ (w[index - 2] >> 6);
                w[index] = w[index - 16] + s0 + w[index - 7] + s1;
            }

            unsigned long long a = ctx.State[0];
            unsigned long long b = ctx.State[1];
            unsigned long long c = ctx.State[2];
            unsigned long long d = ctx.State[3];
            unsigned long long e = ctx.State[4];
            unsigned long long f = ctx.State[5];
            unsigned long long g = ctx.State[6];
            unsigned long long h = ctx.State[7];

            for (SIZE_T index = 0; index < 80; ++index) {
                const unsigned long long S1 =
                    RotateRight64(e, 14) ^ RotateRight64(e, 18) ^ RotateRight64(e, 41);
                const unsigned long long ch = (e & f) ^ ((~e) & g);
                const unsigned long long temp1 = h + S1 + ch + Sha512Constants[index] + w[index];
                const unsigned long long S0 =
                    RotateRight64(a, 28) ^ RotateRight64(a, 34) ^ RotateRight64(a, 39);
                const unsigned long long maj = (a & b) ^ (a & c) ^ (b & c);
                const unsigned long long temp2 = S0 + maj;
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            ctx.State[0] += a;
            ctx.State[1] += b;
            ctx.State[2] += c;
            ctx.State[3] += d;
            ctx.State[4] += e;
            ctx.State[5] += f;
            ctx.State[6] += g;
            ctx.State[7] += h;
        }

        void Sha512Init(Sha512Context& ctx) noexcept
        {
            for (SIZE_T index = 0; index < 8; ++index) {
                ctx.State[index] = Sha512InitialState[index];
            }
            ctx.TotalBytes = 0;
            ctx.BlockLength = 0;
        }

        void Sha512Update(Sha512Context& ctx, const UCHAR* data, SIZE_T length) noexcept
        {
            ctx.TotalBytes += length;
            for (SIZE_T index = 0; index < length; ++index) {
                ctx.Block[ctx.BlockLength++] = data[index];
                if (ctx.BlockLength == 128) {
                    Sha512Transform(ctx, ctx.Block);
                    ctx.BlockLength = 0;
                }
            }
        }

        void Sha512Finish(Sha512Context& ctx, UCHAR* output) noexcept
        {
            const unsigned long long totalBits = ctx.TotalBytes << 3;
            const unsigned long long totalBitsHigh = ctx.TotalBytes >> 61;

            UCHAR padByte = 0x80;
            Sha512Update(ctx, &padByte, 1);
            padByte = 0x00;
            while (ctx.BlockLength != 112) {
                Sha512Update(ctx, &padByte, 1);
            }

            UCHAR lengthBytes[16];
            for (SIZE_T index = 0; index < 8; ++index) {
                lengthBytes[index] = static_cast<UCHAR>((totalBitsHigh >> (56 - index * 8)) & 0xff);
            }
            for (SIZE_T index = 0; index < 8; ++index) {
                lengthBytes[8 + index] = static_cast<UCHAR>((totalBits >> (56 - index * 8)) & 0xff);
            }
            // Bypass the byte counter for the trailing length field.
            for (SIZE_T index = 0; index < 16; ++index) {
                ctx.Block[ctx.BlockLength++] = lengthBytes[index];
            }
            Sha512Transform(ctx, ctx.Block);
            ctx.BlockLength = 0;

            for (SIZE_T index = 0; index < 8; ++index) {
                output[index * 8] = static_cast<UCHAR>((ctx.State[index] >> 56) & 0xff);
                output[index * 8 + 1] = static_cast<UCHAR>((ctx.State[index] >> 48) & 0xff);
                output[index * 8 + 2] = static_cast<UCHAR>((ctx.State[index] >> 40) & 0xff);
                output[index * 8 + 3] = static_cast<UCHAR>((ctx.State[index] >> 32) & 0xff);
                output[index * 8 + 4] = static_cast<UCHAR>((ctx.State[index] >> 24) & 0xff);
                output[index * 8 + 5] = static_cast<UCHAR>((ctx.State[index] >> 16) & 0xff);
                output[index * 8 + 6] = static_cast<UCHAR>((ctx.State[index] >> 8) & 0xff);
                output[index * 8 + 7] = static_cast<UCHAR>(ctx.State[index] & 0xff);
            }
        }
    }

    bool Sha512Compute(const UCHAR* data, SIZE_T dataLength, UCHAR* output) noexcept
    {
        if (output == nullptr || (data == nullptr && dataLength != 0)) {
            return false;
        }

        HeapObject<Sha512Context> context;
        if (!context.IsValid()) {
            return false;
        }

        Sha512Init(*context.Get());
        Sha512Update(*context.Get(), data, dataLength);
        Sha512Finish(*context.Get(), output);
        RtlSecureZeroMemory(context.Get(), sizeof(Sha512Context));
        return true;
    }

    bool Ed25519Verify(
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
            publicKeyLength != Ed25519PublicKeyLength ||
            signatureLength != Ed25519SignatureLength) {
            return false;
        }

        const UCHAR* r = signature;
        const UCHAR* sBytes = signature + 32;

        // RFC 8032 §5.1.7: S must be in range [0, L).
        if (!ScalarBelowOrder(sBytes)) {
            return false;
        }

        HeapObject<Ed25519Scratch> scratchHolder;
        HeapObject<Sha512Context> hashHolder;
        if (!scratchHolder.IsValid() || !hashHolder.IsValid()) {
            return false;
        }
        Ed25519Scratch& scratch = *scratchHolder.Get();
        Sha512Context& hash = *hashHolder.Get();

        bool result = false;

        // Decode -A from the public key; reject non-curve encodings.
        if (UnpackNeg(scratch, scratch.VQ, publicKey)) {
            // k = SHA512(R || A || M) mod L
            Sha512Init(hash);
            Sha512Update(hash, r, 32);
            Sha512Update(hash, publicKey, 32);
            if (messageLength != 0) {
                Sha512Update(hash, message, messageLength);
            }
            Sha512Finish(hash, scratch.HashScalar);
            ScalarReduce(scratch, scratch.HashScalar);

            // [S]B - [k]A, then compare against R.
            ScalarMult(scratch, scratch.VP, scratch.VQ, scratch.HashScalar);
            ScalarBase(scratch, scratch.VQ, sBytes);
            PointAdd(scratch, scratch.VP, scratch.VQ);
            PointPack(scratch, scratch.Packed, scratch.VP);

            int diff = 0;
            for (SIZE_T index = 0; index < 32; ++index) {
                diff |= scratch.Packed[index] ^ r[index];
            }
            result = diff == 0;
        }

        RtlSecureZeroMemory(scratchHolder.Get(), sizeof(Ed25519Scratch));
        RtlSecureZeroMemory(hashHolder.Get(), sizeof(Sha512Context));
        return result;
    }
}
}
