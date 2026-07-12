#include "Pack200Codec.h"

namespace wknet
{
namespace codec
{
namespace
{
    constexpr HttpPack200Coding CanonicalCodings[] = {
        {},
        { 1, 256, 0, 0 }, { 1, 256, 1, 0 }, { 1, 256, 0, 1 }, { 1, 256, 1, 1 },
        { 2, 256, 0, 0 }, { 2, 256, 1, 0 }, { 2, 256, 0, 1 }, { 2, 256, 1, 1 },
        { 3, 256, 0, 0 }, { 3, 256, 1, 0 }, { 3, 256, 0, 1 }, { 3, 256, 1, 1 },
        { 4, 256, 0, 0 }, { 4, 256, 1, 0 }, { 4, 256, 0, 1 }, { 4, 256, 1, 1 },
        { 5, 4, 0, 0 }, { 5, 4, 1, 0 }, { 5, 4, 2, 0 },
        { 5, 16, 0, 0 }, { 5, 16, 1, 0 }, { 5, 16, 2, 0 },
        { 5, 32, 0, 0 }, { 5, 32, 1, 0 }, { 5, 32, 2, 0 },
        { 5, 64, 0, 0 }, { 5, 64, 1, 0 }, { 5, 64, 2, 0 },
        { 5, 128, 0, 0 }, { 5, 128, 1, 0 }, { 5, 128, 2, 0 },
        { 5, 4, 0, 1 }, { 5, 4, 1, 1 }, { 5, 4, 2, 1 },
        { 5, 16, 0, 1 }, { 5, 16, 1, 1 }, { 5, 16, 2, 1 },
        { 5, 32, 0, 1 }, { 5, 32, 1, 1 }, { 5, 32, 2, 1 },
        { 5, 64, 0, 1 }, { 5, 64, 1, 1 }, { 5, 64, 2, 1 },
        { 5, 128, 0, 1 }, { 5, 128, 1, 1 }, { 5, 128, 2, 1 },
        { 2, 192, 0, 0 }, { 2, 224, 0, 0 }, { 2, 240, 0, 0 }, { 2, 248, 0, 0 }, { 2, 252, 0, 0 },
        { 2, 8, 0, 1 }, { 2, 8, 1, 1 }, { 2, 16, 0, 1 }, { 2, 16, 1, 1 },
        { 2, 32, 0, 1 }, { 2, 32, 1, 1 }, { 2, 64, 0, 1 }, { 2, 64, 1, 1 },
        { 2, 128, 0, 1 }, { 2, 128, 1, 1 }, { 2, 192, 0, 1 }, { 2, 192, 1, 1 },
        { 2, 224, 0, 1 }, { 2, 224, 1, 1 }, { 2, 240, 0, 1 }, { 2, 240, 1, 1 },
        { 2, 248, 0, 1 }, { 2, 248, 1, 1 },
        { 3, 192, 0, 0 }, { 3, 224, 0, 0 }, { 3, 240, 0, 0 }, { 3, 248, 0, 0 }, { 3, 252, 0, 0 },
        { 3, 8, 0, 1 }, { 3, 8, 1, 1 }, { 3, 16, 0, 1 }, { 3, 16, 1, 1 },
        { 3, 32, 0, 1 }, { 3, 32, 1, 1 }, { 3, 64, 0, 1 }, { 3, 64, 1, 1 },
        { 3, 128, 0, 1 }, { 3, 128, 1, 1 }, { 3, 192, 0, 1 }, { 3, 192, 1, 1 },
        { 3, 224, 0, 1 }, { 3, 224, 1, 1 }, { 3, 240, 0, 1 }, { 3, 240, 1, 1 },
        { 3, 248, 0, 1 }, { 3, 248, 1, 1 },
        { 4, 192, 0, 0 }, { 4, 224, 0, 0 }, { 4, 240, 0, 0 }, { 4, 248, 0, 0 }, { 4, 252, 0, 0 },
        { 4, 8, 0, 1 }, { 4, 8, 1, 1 }, { 4, 16, 0, 1 }, { 4, 16, 1, 1 },
        { 4, 32, 0, 1 }, { 4, 32, 1, 1 }, { 4, 64, 0, 1 }, { 4, 64, 1, 1 },
        { 4, 128, 0, 1 }, { 4, 128, 1, 1 }, { 4, 192, 0, 1 }, { 4, 192, 1, 1 },
        { 4, 224, 0, 1 }, { 4, 224, 1, 1 }, { 4, 240, 0, 1 }, { 4, 240, 1, 1 },
        { 4, 248, 0, 1 }, { 4, 248, 1, 1 }
    };

    _Must_inspect_result_
    bool CanonicalCodecFromId(UCHAR id, _Out_ HttpPack200Coding* coding) noexcept
    {
        if (coding == nullptr || id == 0 || id >= sizeof(CanonicalCodings) / sizeof(CanonicalCodings[0])) {
            return false;
        }
        *coding = CanonicalCodings[id];
        return true;
    }

    constexpr UCHAR DisableRun = 1;
    constexpr UCHAR DisablePopulation = 2;

    _Must_inspect_result_
    bool CodingIsValid(HttpPack200Coding coding) noexcept
    {
        return coding.B != 0 &&
            coding.B <= 5 &&
            coding.H != 0 &&
            coding.H <= 256 &&
            coding.S <= 2 &&
            coding.D <= 1 &&
            !(coding.B == 1 && coding.H != 256) &&
            !(coding.H == 256 && coding.B == 5);
    }

    _Must_inspect_result_
    ULONGLONG CodingCardinality(HttpPack200Coding coding) noexcept
    {
        const ULONGLONG low = 256ULL - coding.H;
        ULONGLONG power = 1;
        ULONGLONG cardinality = 0;
        for (UCHAR index = 0; index < coding.B; ++index) {
            cardinality += low * power;
            power *= coding.H;
        }
        return cardinality + power;
    }

    _Must_inspect_result_
    NTSTATUS AllocateCanonicalCodec(
        HttpPack200Coding coding,
        _Inout_ HttpPack200CodecArena* arena,
        _Outptr_ const HttpPack200BandCodec** codec) noexcept
    {
        if (!CodingIsValid(coding) || arena == nullptr || codec == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        HttpPack200BandCodec* allocated = nullptr;
        NTSTATUS status = arena->Allocate(&allocated);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        allocated->Kind = HttpPack200BandCodecKind::Canonical;
        allocated->Canonical = coding;
        *codec = allocated;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseMetaCodecNode(
        _Inout_ HttpPack200BandReader* reader,
        HttpPack200Coding defaultCoding,
        LONGLONG valueCount,
        UCHAR mode,
        _Inout_ HttpPack200CodecArena* arena,
        _Outptr_ const HttpPack200BandCodec** codec) noexcept
    {
        if (reader == nullptr || arena == nullptr || codec == nullptr || !CodingIsValid(defaultCoding)) {
            return STATUS_INVALID_PARAMETER;
        }
        *codec = nullptr;

        UCHAR op = 0;
        if (!reader->ReadByte(&op)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (op == 0) {
            return AllocateCanonicalCodec(defaultCoding, arena, codec);
        }

        HttpPack200Coding canonical = {};
        if (CanonicalCodecFromId(op, &canonical)) {
            return AllocateCanonicalCodec(canonical, arena, codec);
        }
        if (op == 116) {
            UCHAR first = 0;
            UCHAR second = 0;
            if (!reader->ReadByte(&first) || !reader->ReadByte(&second)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const HttpPack200Coding arbitrary = {
                static_cast<UCHAR>((first >> 3) + 1U),
                static_cast<USHORT>(static_cast<USHORT>(second) + 1U),
                static_cast<UCHAR>((first >> 1) & 0x03U),
                static_cast<UCHAR>(first & 0x01U)
            };
            return CodingIsValid(arbitrary) ?
                AllocateCanonicalCodec(arbitrary, arena, codec) :
                STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (op >= 117 && op <= 140) {
            if ((mode & DisableRun) != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const ULONG args = op - 117;
            const ULONG kx = args & 3UL;
            const ULONG kbFlag = (args >> 2) & 1UL;
            const ULONG abDef = args >> 3;
            UCHAR kb = 3;
            if (kbFlag != 0 && !reader->ReadByte(&kb)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const ULONGLONG firstCount64 =
                (static_cast<ULONGLONG>(kb) + 1ULL) << (kx * 4);
            if (abDef > 2 || firstCount64 > 0xffffffffULL ||
                valueCount == 0 ||
                (valueCount > 0 && firstCount64 >= static_cast<ULONGLONG>(valueCount))) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const HttpPack200BandCodec* firstCodec = nullptr;
            NTSTATUS status = abDef == 1 ?
                AllocateCanonicalCodec(defaultCoding, arena, &firstCodec) :
                ParseMetaCodecNode(
                    reader,
                    defaultCoding,
                    static_cast<LONGLONG>(firstCount64),
                    static_cast<UCHAR>(mode | DisableRun),
                    arena,
                    &firstCodec);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const HttpPack200BandCodec* secondCodec = nullptr;
            const LONGLONG remainingCount = valueCount > 0 ?
                valueCount - static_cast<LONGLONG>(firstCount64) :
                valueCount;
            status = abDef == 2 ?
                AllocateCanonicalCodec(defaultCoding, arena, &secondCodec) :
                ParseMetaCodecNode(
                    reader,
                    defaultCoding,
                    remainingCount,
                    mode,
                    arena,
                    &secondCodec);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            HttpPack200BandCodec* run = nullptr;
            status = arena->Allocate(&run);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            run->Kind = HttpPack200BandCodecKind::Run;
            run->First = firstCodec;
            run->Second = secondCodec;
            run->FirstCount = static_cast<ULONG>(firstCount64);
            *codec = run;
            return STATUS_SUCCESS;
        }

        if (op >= 141 && op <= 188) {
            if ((mode & DisablePopulation) != 0 || valueCount <= 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const ULONG args = op - 141;
            const ULONG fDef = args & 1UL;
            const ULONG uDef = (args >> 1) & 1UL;
            const ULONG tokenDefL = args >> 2;
            if (tokenDefL > 11) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const HttpPack200BandCodec* favouredCodec = nullptr;
            NTSTATUS status = fDef != 0 ?
                AllocateCanonicalCodec(defaultCoding, arena, &favouredCodec) :
                ParseMetaCodecNode(
                    reader,
                    defaultCoding,
                    -2,
                    DisablePopulation,
                    arena,
                    &favouredCodec);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            const HttpPack200BandCodec* tokenCodec = nullptr;
            if (tokenDefL == 0) {
                status = ParseMetaCodecNode(
                    reader,
                    defaultCoding,
                    valueCount,
                    DisablePopulation,
                    arena,
                    &tokenCodec);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            const HttpPack200BandCodec* unfavouredCodec = nullptr;
            status = uDef != 0 ?
                AllocateCanonicalCodec(defaultCoding, arena, &unfavouredCodec) :
                ParseMetaCodecNode(
                    reader,
                    defaultCoding,
                    valueCount,
                    DisablePopulation,
                    arena,
                    &unfavouredCodec);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            HttpPack200BandCodec* population = nullptr;
            status = arena->Allocate(&population);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            population->Kind = HttpPack200BandCodecKind::Population;
            population->First = favouredCodec;
            population->Second = tokenCodec;
            population->Third = unfavouredCodec;
            population->TokenDefL = static_cast<UCHAR>(tokenDefL);
            *codec = population;
            return STATUS_SUCCESS;
        }

        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    LONG MoreCentral(LONG left, LONG right) noexcept
    {
        const ULONG leftKey =
            (static_cast<ULONG>(left) >> 31) ^ (static_cast<ULONG>(left) << 1);
        const ULONG rightKey =
            (static_cast<ULONG>(right) >> 31) ^ (static_cast<ULONG>(right) << 1);
        return leftKey < rightKey ? left : right;
    }

    _Must_inspect_result_
    NTSTATUS DecodeFavouredTail(
        _Inout_ HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        _Out_writes_(capacity) LONG* favoured,
        SIZE_T capacity,
        _Inout_ SIZE_T* favouredCount) noexcept
    {
        if (reader == nullptr || favoured == nullptr || favouredCount == nullptr ||
            *favouredCount > capacity) {
            return STATUS_INVALID_PARAMETER;
        }
        if (codec.Kind == HttpPack200BandCodecKind::Run) {
            if (codec.First == nullptr || codec.Second == nullptr ||
                codec.FirstCount > capacity - *favouredCount) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            NTSTATUS status = HttpPack200DecodeBand(
                reader,
                *codec.First,
                favoured + *favouredCount,
                codec.FirstCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            *favouredCount += codec.FirstCount;
            return DecodeFavouredTail(
                reader,
                *codec.Second,
                favoured,
                capacity,
                favouredCount);
        }
        if (codec.Kind != HttpPack200BandCodecKind::Canonical) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        reader->ResetDelta();
        LONG last = 0;
        LONG central = static_cast<LONG>(0x80000000UL);
        for (SIZE_T index = 0; index < *favouredCount; ++index) {
            last = favoured[index];
            central = MoreCentral(central, last);
        }
        for (;;) {
            LONG value = 0;
            if (!reader->ReadInt(codec.Canonical, &value)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (*favouredCount != 0 && (value == last || value == central)) {
                return STATUS_SUCCESS;
            }
            if (*favouredCount >= capacity) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            favoured[*favouredCount] = value;
            ++(*favouredCount);
            last = value;
            central = MoreCentral(central, last);
        }
    }

    _Must_inspect_result_
    NTSTATUS ImplicitTokenCoding(
        UCHAR tokenDefL,
        SIZE_T favouredCount,
        _Out_ HttpPack200BandCodec* codec) noexcept
    {
        if (codec == nullptr || tokenDefL == 0 || tokenDefL > 11) {
            return STATUS_INVALID_PARAMETER;
        }
        const ULONG tokenLow = tokenDefL <= 6 ?
            (2UL << tokenDefL) :
            (256UL - (4UL << (11 - tokenDefL)));
        const USHORT tokenHigh = static_cast<USHORT>(256UL - tokenLow);
        HttpPack200Coding coding = HttpPack200CodingFor(HttpPack200CodingKind::Byte1);
        for (UCHAR byteCount = 1; byteCount <= 5; ++byteCount) {
            if (byteCount != 1) {
                coding = { byteCount, tokenHigh, 0, 0 };
            }
            if (favouredCount < CodingCardinality(coding)) {
                codec->Kind = HttpPack200BandCodecKind::Canonical;
                codec->Canonical = coding;
                return STATUS_SUCCESS;
            }
        }
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

    NTSTATUS HttpPack200CodecArena::Initialize(SIZE_T maxCodecs) noexcept
    {
        Reset();
        if (maxCodecs == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        return codecs_.Allocate(maxCodecs);
    }

    void HttpPack200CodecArena::Reset() noexcept
    {
        codecs_.Reset();
        codecCount_ = 0;
    }

    void HttpPack200CodecArena::Rewind() noexcept
    {
        codecCount_ = 0;
    }

    NTSTATUS HttpPack200CodecArena::Allocate(HttpPack200BandCodec** codec) noexcept
    {
        if (codec == nullptr || !codecs_.IsValid() || codecCount_ >= codecs_.Count()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        codecs_[codecCount_] = {};
        *codec = &codecs_[codecCount_];
        ++codecCount_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ParseMetaCodec(HttpPack200BandReader* reader, HttpPack200BandCodec* codec) noexcept
    {
        if (reader == nullptr || codec == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *codec = {};

        UCHAR id = 0;
        if (!reader->ReadByte(&id)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        HttpPack200Coding canonical = {};
        if (CanonicalCodecFromId(id, &canonical)) {
            codec->Kind = HttpPack200BandCodecKind::Canonical;
            codec->Canonical = canonical;
            return STATUS_SUCCESS;
        }

        if (id == 116) {
            UCHAR first = 0;
            UCHAR second = 0;
            if (!reader->ReadByte(&first) || !reader->ReadByte(&second)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const HttpPack200Coding arbitrary = {
                static_cast<UCHAR>((first >> 3) + 1U),
                static_cast<USHORT>(static_cast<USHORT>(second) + 1U),
                static_cast<UCHAR>((first >> 1) & 0x03U),
                static_cast<UCHAR>(first & 0x01U)
            };
            if (arbitrary.B == 0 || arbitrary.B > 5 || arbitrary.S > 2 ||
                (arbitrary.B == 1 && arbitrary.H != 256) ||
                (arbitrary.H == 256 && arbitrary.B == 5)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            codec->Kind = HttpPack200BandCodecKind::Canonical;
            codec->Canonical = arbitrary;
            return STATUS_SUCCESS;
        }

        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS HttpPack200ParseMetaCodec(
        HttpPack200BandReader* reader,
        HttpPack200Coding defaultCoding,
        SIZE_T valueCount,
        HttpPack200CodecArena* arena,
        const HttpPack200BandCodec** codec) noexcept
    {
        if (valueCount > static_cast<SIZE_T>(0x7fffffffffffffffULL)) {
            return STATUS_INTEGER_OVERFLOW;
        }
        return ParseMetaCodecNode(
            reader,
            defaultCoding,
            static_cast<LONGLONG>(valueCount),
            0,
            arena,
            codec);
    }

    NTSTATUS HttpPack200DecodeBand(
        HttpPack200BandReader* reader,
        const HttpPack200BandCodec& codec,
        LONG* values,
        SIZE_T valueCount) noexcept
    {
        if (reader == nullptr || (values == nullptr && valueCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        switch (codec.Kind) {
        case HttpPack200BandCodecKind::Canonical:
            reader->ResetDelta();
            for (SIZE_T index = 0; index < valueCount; ++index) {
                if (!reader->ReadInt(codec.Canonical, &values[index])) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            return STATUS_SUCCESS;

        case HttpPack200BandCodecKind::Run:
            if (codec.First == nullptr || codec.Second == nullptr || codec.FirstCount > valueCount) {
                return STATUS_INVALID_PARAMETER;
            }
            {
                NTSTATUS status = HttpPack200DecodeBand(reader, *codec.First, values, codec.FirstCount);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                return HttpPack200DecodeBand(
                    reader,
                    *codec.Second,
                    values + codec.FirstCount,
                    valueCount - codec.FirstCount);
            }

        case HttpPack200BandCodecKind::Adaptive:
            if (codec.First == nullptr || codec.Second == nullptr || codec.FirstCount > valueCount) {
                return STATUS_INVALID_PARAMETER;
            }
            {
                NTSTATUS status = HttpPack200DecodeBand(reader, *codec.First, values, codec.FirstCount);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                return HttpPack200DecodeBand(
                    reader,
                    *codec.Second,
                    values + codec.FirstCount,
                    valueCount - codec.FirstCount);
            }

        case HttpPack200BandCodecKind::Population:
            if (codec.First == nullptr || codec.Third == nullptr || valueCount == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            {
                HeapArray<LONG> favoured(valueCount);
                HeapArray<LONG> tokens(valueCount);
                HeapArray<LONG> unfavoured(valueCount);
                if (!favoured.IsValid() || !tokens.IsValid() || !unfavoured.IsValid()) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }

                SIZE_T favouredCount = 0;
                NTSTATUS status = DecodeFavouredTail(
                    reader,
                    *codec.First,
                    favoured.Get(),
                    favoured.Count(),
                    &favouredCount);
                if (!NT_SUCCESS(status) || favouredCount == 0) {
                    return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
                }

                HttpPack200BandCodec implicitToken = {};
                const HttpPack200BandCodec* tokenCodec = codec.Second;
                if (tokenCodec == nullptr) {
                    status = ImplicitTokenCoding(codec.TokenDefL, favouredCount, &implicitToken);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    tokenCodec = &implicitToken;
                }
                status = HttpPack200DecodeBand(reader, *tokenCodec, tokens.Get(), valueCount);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T unfavouredCount = 0;
                for (SIZE_T index = 0; index < valueCount; ++index) {
                    if (tokens[index] < 0 || static_cast<SIZE_T>(tokens[index]) > favouredCount) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (tokens[index] == 0) {
                        ++unfavouredCount;
                    }
                }
                status = HttpPack200DecodeBand(
                    reader,
                    *codec.Third,
                    unfavoured.Get(),
                    unfavouredCount);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                SIZE_T unfavouredIndex = 0;
                for (SIZE_T index = 0; index < valueCount; ++index) {
                    const LONG token = tokens[index];
                    values[index] = token == 0 ?
                        unfavoured[unfavouredIndex++] :
                        favoured[static_cast<SIZE_T>(token) - 1];
                }
                return STATUS_SUCCESS;
            }

        default:
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
    }

    NTSTATUS HttpPack200DecodeBandWithMeta(
        HttpPack200BandReader* reader,
        HttpPack200BandReader* bandHeaderReader,
        HttpPack200Coding defaultCoding,
        LONG* values,
        SIZE_T valueCount,
        HttpPack200CodecArena* arena) noexcept
    {
        if (reader == nullptr || bandHeaderReader == nullptr || arena == nullptr ||
            (values == nullptr && valueCount != 0) || !CodingIsValid(defaultCoding)) {
            return STATUS_INVALID_PARAMETER;
        }
        if (valueCount == 0) {
            return STATUS_SUCCESS;
        }

        HttpPack200BandCodec defaultCodec = {};
        defaultCodec.Kind = HttpPack200BandCodecKind::Canonical;
        defaultCodec.Canonical = defaultCoding;
        if (defaultCoding.B == 1) {
            return HttpPack200DecodeBand(reader, defaultCodec, values, valueCount);
        }

        HttpPack200BandReader probe = *reader;
        HttpPack200Coding probeCoding = defaultCoding;
        probeCoding.D = 0;
        LONG firstValue = 0;
        if (!probe.ReadInt(probeCoding, &firstValue)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        LONGLONG metaId = 0;
        if (probeCoding.S != 0) {
            metaId = -1LL - firstValue;
        }
        else {
            metaId = static_cast<LONGLONG>(firstValue) -
                static_cast<LONGLONG>(256UL - probeCoding.H);
        }
        if (metaId < 0 || metaId > 255) {
            return HttpPack200DecodeBand(reader, defaultCodec, values, valueCount);
        }

        *reader = probe;
        const UCHAR firstMetaByte = static_cast<UCHAR>(metaId);
        const HttpPack200BandCodec* selectedCodec = nullptr;
        NTSTATUS status = STATUS_SUCCESS;
        if (firstMetaByte <= 115) {
            HttpPack200BandReader metaReader(&firstMetaByte, 1);
            status = HttpPack200ParseMetaCodec(
                &metaReader,
                defaultCoding,
                valueCount,
                arena,
                &selectedCodec);
        }
        else {
            const SIZE_T remainingMeta = bandHeaderReader->Remaining();
            if (remainingMeta == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                return STATUS_INTEGER_OVERFLOW;
            }
            HeapArray<UCHAR> metaBytes(remainingMeta + 1);
            if (!metaBytes.IsValid()) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            metaBytes[0] = firstMetaByte;
            if (remainingMeta != 0) {
                RtlCopyMemory(metaBytes.Get() + 1, bandHeaderReader->Current(), remainingMeta);
            }
            HttpPack200BandReader metaReader(metaBytes.Get(), metaBytes.Count());
            status = HttpPack200ParseMetaCodec(
                &metaReader,
                defaultCoding,
                valueCount,
                arena,
                &selectedCodec);
            if (NT_SUCCESS(status)) {
                const SIZE_T consumed = metaBytes.Count() - metaReader.Remaining();
                if (consumed == 0 || !bandHeaderReader->Skip(consumed - 1)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }
        if (!NT_SUCCESS(status) || selectedCodec == nullptr) {
            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
        }
        return HttpPack200DecodeBand(reader, *selectedCodec, values, valueCount);
    }

    NTSTATUS HttpPack200DecodePopulationBand(
        HttpPack200BandReader* tokenReader,
        const LONG* favouredValues,
        SIZE_T favouredCount,
        LONG* values,
        SIZE_T valueCount) noexcept
    {
        if (tokenReader == nullptr ||
            favouredValues == nullptr ||
            favouredCount == 0 ||
            favouredCount > 255 ||
            (values == nullptr && valueCount != 0)) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < valueCount; ++index) {
            UCHAR token = 0;
            if (!tokenReader->ReadByte(&token)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (token == 0 || token > favouredCount) {
                return STATUS_NOT_SUPPORTED;
            }
            values[index] = favouredValues[token - 1];
        }
        return STATUS_SUCCESS;
    }
}
}
