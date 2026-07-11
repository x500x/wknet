#include "HttpPack200Decoder.h"
#include <KernelHttp/http/HttpCoding.h>
#include "HttpPack200BandCodec.h"
#include "HttpPack200BandParser.h"
#include "HttpPack200Bands.h"
#include "HttpPack200ClassWriter.h"
#include "HttpPack200Codec.h"
#include "HttpPack200JarWriter.h"

namespace KernelHttp
{
namespace http
{
namespace
{
    constexpr ULONG Pack200Magic = 0xCAFED00DUL;

    struct SegmentOptions final
    {
        bool HaveSpecialFormats = false;
        bool HaveCpNumbers = false;
        bool HaveAllCodeFlags = false;
        bool HaveCpExtraCounts = false;
        bool HaveFileHeaders = false;
        bool DeflateHint = false;
        bool HaveFileModtime = false;
        bool HaveFileOptions = false;
        bool HaveFileSizeHi = false;
        bool HaveClassFlagsHi = false;
        bool HaveFieldFlagsHi = false;
        bool HaveMethodFlagsHi = false;
        bool HaveCodeFlagsHi = false;
    };

    struct SegmentHeader final
    {
        ULONG MinorVersion = 0;
        ULONG MajorVersion = 0;
        ULONG ArchiveOptions = 0;
        SegmentOptions Options = {};

        ULONG ArchiveSizeHi = 0;
        ULONG ArchiveSizeLo = 0;
        ULONG ArchiveNextCount = 0;
        ULONG ArchiveModtime = 0;
        ULONG FileCount = 0;

        ULONG BandHeadersSize = 0;
        ULONG AttributeDefinitionCount = 0;

        ULONG CpUtf8Count = 0;
        ULONG CpIntCount = 0;
        ULONG CpFloatCount = 0;
        ULONG CpLongCount = 0;
        ULONG CpDoubleCount = 0;
        ULONG CpStringCount = 0;
        ULONG CpClassCount = 0;
        ULONG CpSignatureCount = 0;
        ULONG CpDescriptorCount = 0;
        ULONG CpFieldCount = 0;
        ULONG CpMethodCount = 0;
        ULONG CpInterfaceMethodCount = 0;
        ULONG CpMethodHandleCount = 0;
        ULONG CpMethodTypeCount = 0;
        ULONG CpBootstrapMethodCount = 0;
        ULONG CpInvokeDynamicCount = 0;

        ULONG InnerClassCount = 0;
        ULONG DefaultClassMinorVersion = 0;
        ULONG DefaultClassMajorVersion = 0;
        ULONG ClassCount = 0;
    };

    using Pack200Reader = HttpPack200BandReader;

    _Must_inspect_result_
    bool ReadPack200Magic(_Inout_ Pack200Reader* reader) noexcept
    {
        ULONG magic = 0;
        return reader != nullptr && reader->ReadBigEndian32(&magic) && magic == Pack200Magic;
    }

    _Must_inspect_result_
    bool IsPack200Magic(const UCHAR* source, SIZE_T sourceLength) noexcept
    {
        return source != nullptr &&
            sourceLength >= 4 &&
            source[0] == 0xca &&
            source[1] == 0xfe &&
            source[2] == 0xd0 &&
            source[3] == 0x0d;
    }

    _Must_inspect_result_
    bool IsGzipMagic(const UCHAR* source, SIZE_T sourceLength) noexcept
    {
        return source != nullptr &&
            sourceLength >= 2 &&
            source[0] == 0x1f &&
            source[1] == 0x8b;
    }

    _Must_inspect_result_
    bool DecodeSegmentOptions(ULONG value, _Out_ SegmentOptions* options) noexcept
    {
        if (options == nullptr) {
            return false;
        }

        constexpr ULONG KnownOptionsMask =
            (1UL << 0) |
            (1UL << 1) |
            (1UL << 2) |
            (1UL << 3) |
            (1UL << 4) |
            (1UL << 5) |
            (1UL << 6) |
            (1UL << 7) |
            (1UL << 8) |
            (1UL << 9) |
            (1UL << 10) |
            (1UL << 11) |
            (1UL << 12);
        if ((value & ~KnownOptionsMask) != 0) {
            return false;
        }

        options->HaveSpecialFormats = (value & (1UL << 0)) != 0;
        options->HaveCpNumbers = (value & (1UL << 1)) != 0;
        options->HaveAllCodeFlags = (value & (1UL << 2)) != 0;
        options->HaveCpExtraCounts = (value & (1UL << 3)) != 0;
        options->HaveFileHeaders = (value & (1UL << 4)) != 0;
        options->DeflateHint = (value & (1UL << 5)) != 0;
        options->HaveFileModtime = (value & (1UL << 6)) != 0;
        options->HaveFileOptions = (value & (1UL << 7)) != 0;
        options->HaveFileSizeHi = (value & (1UL << 8)) != 0;
        options->HaveClassFlagsHi = (value & (1UL << 9)) != 0;
        options->HaveFieldFlagsHi = (value & (1UL << 10)) != 0;
        options->HaveMethodFlagsHi = (value & (1UL << 11)) != 0;
        options->HaveCodeFlagsHi = (value & (1UL << 12)) != 0;
        return true;
    }

    _Must_inspect_result_
    bool IsSupportedPack200Version(ULONG major, ULONG minor) noexcept
    {
        return (major == 150 && minor == 7) ||
            (major == 160 && minor == 1) ||
            (major == 170 && minor == 1) ||
            (major == 171 && minor == 0);
    }

    _Must_inspect_result_
    bool ReadUnsigned5(_Inout_ Pack200Reader* reader, _Out_ ULONG* value) noexcept
    {
        return reader != nullptr && reader->ReadUnsigned(HttpPack200CodingKind::Unsigned5, value);
    }

    _Must_inspect_result_
    NTSTATUS ParseSegmentHeader(_Inout_ Pack200Reader* reader, _Out_ SegmentHeader* header) noexcept
    {
        if (reader == nullptr || header == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *header = {};

        if (!ReadPack200Magic(reader) ||
            !ReadUnsigned5(reader, &header->MinorVersion) ||
            !ReadUnsigned5(reader, &header->MajorVersion)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (!IsSupportedPack200Version(header->MajorVersion, header->MinorVersion)) {
            return STATUS_NOT_SUPPORTED;
        }
        if (!ReadUnsigned5(reader, &header->ArchiveOptions) ||
            !DecodeSegmentOptions(header->ArchiveOptions, &header->Options)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (header->MajorVersion < 170 && header->Options.HaveCpExtraCounts) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (header->Options.HaveFileHeaders) {
            if (!ReadUnsigned5(reader, &header->ArchiveSizeHi) ||
                !ReadUnsigned5(reader, &header->ArchiveSizeLo) ||
                !ReadUnsigned5(reader, &header->ArchiveNextCount) ||
                !ReadUnsigned5(reader, &header->ArchiveModtime) ||
                !ReadUnsigned5(reader, &header->FileCount)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        if (header->Options.HaveSpecialFormats) {
            if (!ReadUnsigned5(reader, &header->BandHeadersSize) ||
                !ReadUnsigned5(reader, &header->AttributeDefinitionCount)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }

        if (!ReadUnsigned5(reader, &header->CpUtf8Count)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (header->Options.HaveCpNumbers &&
            (!ReadUnsigned5(reader, &header->CpIntCount) ||
                !ReadUnsigned5(reader, &header->CpFloatCount) ||
                !ReadUnsigned5(reader, &header->CpLongCount) ||
                !ReadUnsigned5(reader, &header->CpDoubleCount))) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (!ReadUnsigned5(reader, &header->CpStringCount) ||
            !ReadUnsigned5(reader, &header->CpClassCount) ||
            !ReadUnsigned5(reader, &header->CpSignatureCount) ||
            !ReadUnsigned5(reader, &header->CpDescriptorCount) ||
            !ReadUnsigned5(reader, &header->CpFieldCount) ||
            !ReadUnsigned5(reader, &header->CpMethodCount) ||
            !ReadUnsigned5(reader, &header->CpInterfaceMethodCount)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (header->Options.HaveCpExtraCounts &&
            (!ReadUnsigned5(reader, &header->CpMethodHandleCount) ||
                !ReadUnsigned5(reader, &header->CpMethodTypeCount) ||
                !ReadUnsigned5(reader, &header->CpBootstrapMethodCount) ||
                !ReadUnsigned5(reader, &header->CpInvokeDynamicCount))) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (!ReadUnsigned5(reader, &header->InnerClassCount) ||
            !ReadUnsigned5(reader, &header->DefaultClassMinorVersion) ||
            !ReadUnsigned5(reader, &header->DefaultClassMajorVersion) ||
            !ReadUnsigned5(reader, &header->ClassCount)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    HttpPack200CpCounts BuildCpCounts(const SegmentHeader& header) noexcept
    {
        HttpPack200CpCounts counts = {};
        counts.Utf8 = header.CpUtf8Count;
        counts.Int = header.CpIntCount;
        counts.Float = header.CpFloatCount;
        counts.Long = header.CpLongCount;
        counts.Double = header.CpDoubleCount;
        counts.String = header.CpStringCount;
        counts.Class = header.CpClassCount;
        counts.Signature = header.CpSignatureCount;
        counts.Descriptor = header.CpDescriptorCount;
        counts.Field = header.CpFieldCount;
        counts.Method = header.CpMethodCount;
        counts.InterfaceMethod = header.CpInterfaceMethodCount;
        counts.MethodHandle = header.CpMethodHandleCount;
        counts.MethodType = header.CpMethodTypeCount;
        counts.BootstrapMethod = header.CpBootstrapMethodCount;
        counts.InvokeDynamic = header.CpInvokeDynamicCount;
        return counts;
    }

    _Must_inspect_result_
    bool CheckedAddSize(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
    {
        if (result == nullptr || right > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - left) {
            return false;
        }
        *result = left + right;
        return true;
    }

    _Must_inspect_result_
    NTSTATUS ExpandSignature(
        const HttpPack200CpBands& cpBands,
        SIZE_T signatureIndex,
        _Inout_ HeapArray<char>* storage,
        _Out_ HttpXmlText* signature) noexcept
    {
        if (storage == nullptr || signature == nullptr ||
            signatureIndex >= cpBands.SignatureCount()) {
            return STATUS_INVALID_PARAMETER;
        }
        storage->Reset();
        *signature = {};

        const ULONG* forms = cpBands.SignatureFormIndexes();
        const ULONG* signatureClasses = cpBands.SignatureClassIndexes();
        const ULONG* classNames = cpBands.ClassNameIndexes();
        if (forms == nullptr || classNames == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T classOffset = 0;
        for (SIZE_T index = 0; index < signatureIndex; ++index) {
            HttpXmlText form = {};
            if (!cpBands.GetUtf8(forms[index], &form)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            for (SIZE_T charIndex = 0; charIndex < form.Length; ++charIndex) {
                if (form.Data[charIndex] == 'L' &&
                    !CheckedAddSize(classOffset, 1, &classOffset)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
        }

        HttpXmlText form = {};
        if (!cpBands.GetUtf8(forms[signatureIndex], &form)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        SIZE_T classCount = 0;
        SIZE_T expandedLength = form.Length;
        for (SIZE_T charIndex = 0; charIndex < form.Length; ++charIndex) {
            if (form.Data[charIndex] != 'L') {
                continue;
            }
            SIZE_T classPosition = 0;
            if (!CheckedAddSize(classOffset, classCount, &classPosition) ||
                classPosition >= cpBands.SignatureClassIndexCount() ||
                signatureClasses == nullptr ||
                signatureClasses[classPosition] >= cpBands.ClassCount()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpXmlText className = {};
            if (!cpBands.GetUtf8(classNames[signatureClasses[classPosition]], &className) ||
                !CheckedAddSize(expandedLength, className.Length, &expandedLength) ||
                !CheckedAddSize(classCount, 1, &classCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        SIZE_T classEnd = 0;
        if (!CheckedAddSize(classOffset, classCount, &classEnd) ||
            classEnd > cpBands.SignatureClassIndexCount()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (expandedLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        NTSTATUS status = storage->Allocate(expandedLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        SIZE_T outputOffset = 0;
        SIZE_T classIndex = 0;
        for (SIZE_T charIndex = 0; charIndex < form.Length; ++charIndex) {
            storage->Get()[outputOffset++] = form.Data[charIndex];
            if (form.Data[charIndex] != 'L') {
                continue;
            }
            const ULONG classReference = signatureClasses[classOffset + classIndex++];
            HttpXmlText className = {};
            if (!cpBands.GetUtf8(classNames[classReference], &className) ||
                className.Length > expandedLength - outputOffset) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            RtlCopyMemory(storage->Get() + outputOffset, className.Data, className.Length);
            outputOffset += className.Length;
        }
        if (outputOffset != expandedLength || classIndex != classCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        signature->Data = storage->Get();
        signature->Length = storage->Count();
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS CountMethodArgumentSlots(
        HttpXmlText descriptor,
        bool isStatic,
        _Out_ USHORT* slotCount) noexcept
    {
        if (slotCount == nullptr || descriptor.Data == nullptr ||
            descriptor.Length < 3 || descriptor.Data[0] != '(') {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        SIZE_T slots = isStatic ? 0 : 1;
        SIZE_T index = 1;
        while (index < descriptor.Length && descriptor.Data[index] != ')') {
            bool isArray = false;
            while (index < descriptor.Length && descriptor.Data[index] == '[') {
                isArray = true;
                ++index;
            }
            if (index >= descriptor.Length) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const char type = descriptor.Data[index++];
            SIZE_T addedSlots = 1;
            if (type == 'L') {
                const SIZE_T classStart = index;
                while (index < descriptor.Length && descriptor.Data[index] != ';') {
                    ++index;
                }
                if (index == classStart || index >= descriptor.Length) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                ++index;
            }
            else if (type == 'J' || type == 'D') {
                addedSlots = isArray ? 1 : 2;
            }
            else if (type != 'B' && type != 'C' && type != 'F' && type != 'I' &&
                type != 'S' && type != 'Z') {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (!CheckedAddSize(slots, addedSlots, &slots) || slots > 0xffffUL) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        if (index >= descriptor.Length || descriptor.Data[index] != ')' ||
            index + 1 >= descriptor.Length) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *slotCount = static_cast<USHORT>(slots);
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS FindMethodDescriptor(
        const HttpPack200CpBands& cpBands,
        ULONG classIndex,
        ULONG ordinal,
        bool initializerOnly,
        _Out_ ULONG* descriptorIndex) noexcept
    {
        if (descriptorIndex == nullptr || classIndex >= cpBands.ClassCount()) {
            return STATUS_INVALID_PARAMETER;
        }
        const ULONG* methodClasses = cpBands.MethodClassIndexes();
        const ULONG* methodDescriptors = cpBands.MethodDescriptorIndexes();
        const ULONG* descriptorNames = cpBands.DescriptorNameIndexes();
        if ((cpBands.MethodCount() != 0 &&
                (methodClasses == nullptr || methodDescriptors == nullptr)) ||
            (cpBands.DescriptorCount() != 0 && descriptorNames == nullptr)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        for (SIZE_T methodIndex = 0; methodIndex < cpBands.MethodCount(); ++methodIndex) {
            if (methodClasses[methodIndex] != classIndex ||
                methodDescriptors[methodIndex] >= cpBands.DescriptorCount()) {
                continue;
            }
            const ULONG candidateDescriptor = methodDescriptors[methodIndex];
            HttpXmlText name = {};
            if (!cpBands.GetUtf8(descriptorNames[candidateDescriptor], &name)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (initializerOnly &&
                (name.Length != 6 || RtlCompareMemory(name.Data, "<init>", 6) != 6)) {
                continue;
            }
            if (ordinal == 0) {
                *descriptorIndex = candidateDescriptor;
                return STATUS_SUCCESS;
            }
            --ordinal;
        }
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS AddAnyMemberConstant(
        const HttpPack200CpBands& cpBands,
        ULONG anyMemberIndex,
        _Inout_ HttpPack200ClassWriter* writer,
        _Inout_ HeapArray<char>* signatureStorage,
        _Out_ USHORT* constantIndex) noexcept
    {
        if (writer == nullptr || signatureStorage == nullptr || constantIndex == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        HttpPack200RelocationKind kind = HttpPack200RelocationKind::Field;
        ULONG memberIndex = anyMemberIndex;
        const ULONG* classIndexes = nullptr;
        const ULONG* descriptorIndexes = nullptr;
        if (memberIndex < cpBands.FieldCount()) {
            classIndexes = cpBands.FieldClassIndexes();
            descriptorIndexes = cpBands.FieldDescriptorIndexes();
        }
        else {
            memberIndex -= static_cast<ULONG>(cpBands.FieldCount());
            if (memberIndex < cpBands.MethodCount()) {
                kind = HttpPack200RelocationKind::Method;
                classIndexes = cpBands.MethodClassIndexes();
                descriptorIndexes = cpBands.MethodDescriptorIndexes();
            }
            else {
                memberIndex -= static_cast<ULONG>(cpBands.MethodCount());
                if (memberIndex >= cpBands.InterfaceMethodCount()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                kind = HttpPack200RelocationKind::InterfaceMethod;
                classIndexes = cpBands.InterfaceMethodClassIndexes();
                descriptorIndexes = cpBands.InterfaceMethodDescriptorIndexes();
            }
        }
        if (classIndexes == nullptr || descriptorIndexes == nullptr ||
            classIndexes[memberIndex] >= cpBands.ClassCount() ||
            descriptorIndexes[memberIndex] >= cpBands.DescriptorCount()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const ULONG* classNameIndexes = cpBands.ClassNameIndexes();
        const ULONG* descriptorNameIndexes = cpBands.DescriptorNameIndexes();
        const ULONG* descriptorTypeIndexes = cpBands.DescriptorTypeIndexes();
        if (classNameIndexes == nullptr || descriptorNameIndexes == nullptr ||
            descriptorTypeIndexes == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        HttpXmlText className = {};
        HttpXmlText memberName = {};
        HttpXmlText memberDescriptor = {};
        const ULONG descriptorIndex = descriptorIndexes[memberIndex];
        if (!cpBands.GetUtf8(classNameIndexes[classIndexes[memberIndex]], &className) ||
            !cpBands.GetUtf8(descriptorNameIndexes[descriptorIndex], &memberName)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        NTSTATUS status = ExpandSignature(
            cpBands,
            descriptorTypeIndexes[descriptorIndex],
            signatureStorage,
            &memberDescriptor);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        USHORT classUtf8Index = 0;
        USHORT classConstantIndex = 0;
        USHORT nameUtf8Index = 0;
        USHORT descriptorUtf8Index = 0;
        USHORT nameAndTypeIndex = 0;
        status = writer->AddUtf8(className, &classUtf8Index);
        if (NT_SUCCESS(status)) status = writer->AddClass(classUtf8Index, &classConstantIndex);
        if (NT_SUCCESS(status)) status = writer->AddUtf8(memberName, &nameUtf8Index);
        if (NT_SUCCESS(status)) status = writer->AddUtf8(memberDescriptor, &descriptorUtf8Index);
        if (NT_SUCCESS(status)) {
            status = writer->AddNameAndType(nameUtf8Index, descriptorUtf8Index, &nameAndTypeIndex);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (kind == HttpPack200RelocationKind::Field) {
            return writer->AddFieldref(classConstantIndex, nameAndTypeIndex, constantIndex);
        }
        if (kind == HttpPack200RelocationKind::InterfaceMethod) {
            return writer->AddInterfaceMethodref(classConstantIndex, nameAndTypeIndex, constantIndex);
        }
        return writer->AddMethodref(classConstantIndex, nameAndTypeIndex, constantIndex);
    }

    _Must_inspect_result_
    NTSTATUS ResolveLoadableValueKind(
        const HttpPack200CpBands& cpBands,
        ULONG loadableIndex,
        _Out_ HttpPack200RelocationKind* kind,
        _Out_ ULONG* referenceIndex) noexcept
    {
        if (kind == nullptr || referenceIndex == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        const struct LoadablePool final {
            SIZE_T Count;
            HttpPack200RelocationKind Kind;
        } pools[] = {
            { cpBands.IntCount(), HttpPack200RelocationKind::Integer },
            { cpBands.FloatCount(), HttpPack200RelocationKind::Float },
            { cpBands.LongCount(), HttpPack200RelocationKind::Long },
            { cpBands.DoubleCount(), HttpPack200RelocationKind::Double },
            { cpBands.StringCount(), HttpPack200RelocationKind::String },
            { cpBands.ClassCount(), HttpPack200RelocationKind::Class },
            { cpBands.MethodHandleCount(), HttpPack200RelocationKind::MethodHandle },
            { cpBands.MethodTypeCount(), HttpPack200RelocationKind::MethodType }
        };
        SIZE_T remaining = loadableIndex;
        for (SIZE_T index = 0; index < sizeof(pools) / sizeof(pools[0]); ++index) {
            if (remaining < pools[index].Count) {
                *kind = pools[index].Kind;
                *referenceIndex = static_cast<ULONG>(remaining);
                return STATUS_SUCCESS;
            }
            remaining -= pools[index].Count;
        }
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS LoadableConstantEntryCount(
        const HttpPack200CpBands& cpBands,
        ULONG loadableIndex,
        _Out_ SIZE_T* entryCount) noexcept
    {
        if (entryCount == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        HttpPack200RelocationKind kind = HttpPack200RelocationKind::Integer;
        ULONG referenceIndex = 0;
        NTSTATUS status = ResolveLoadableValueKind(
            cpBands,
            loadableIndex,
            &kind,
            &referenceIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        UNREFERENCED_PARAMETER(referenceIndex);
        if (kind == HttpPack200RelocationKind::Integer ||
            kind == HttpPack200RelocationKind::Float) {
            *entryCount = 1;
        }
        else if (kind == HttpPack200RelocationKind::MethodHandle) {
            *entryCount = 7;
        }
        else {
            *entryCount = 2;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS AddMethodHandleConstant(
        const HttpPack200CpBands& cpBands,
        ULONG methodHandleIndex,
        _Inout_ HttpPack200ClassWriter* writer,
        _Inout_ HeapArray<char>* signatureStorage,
        _Out_ USHORT* constantIndex) noexcept
    {
        const ULONG* referenceKinds = cpBands.MethodHandleReferenceKinds();
        const ULONG* memberIndexes = cpBands.MethodHandleMemberIndexes();
        if (writer == nullptr || signatureStorage == nullptr || constantIndex == nullptr ||
            methodHandleIndex >= cpBands.MethodHandleCount() ||
            referenceKinds == nullptr || memberIndexes == nullptr ||
            referenceKinds[methodHandleIndex] < 1 || referenceKinds[methodHandleIndex] > 9) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        USHORT memberConstantIndex = 0;
        NTSTATUS status = AddAnyMemberConstant(
            cpBands,
            memberIndexes[methodHandleIndex],
            writer,
            signatureStorage,
            &memberConstantIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return writer->AddMethodHandle(
            static_cast<UCHAR>(referenceKinds[methodHandleIndex]),
            memberConstantIndex,
            constantIndex);
    }

    _Must_inspect_result_
    NTSTATUS AddMethodTypeConstant(
        const HttpPack200CpBands& cpBands,
        ULONG methodTypeIndex,
        _Inout_ HttpPack200ClassWriter* writer,
        _Inout_ HeapArray<char>* signatureStorage,
        _Out_ USHORT* constantIndex) noexcept
    {
        const ULONG* signatureIndexes = cpBands.MethodTypeSignatureIndexes();
        if (writer == nullptr || signatureStorage == nullptr || constantIndex == nullptr ||
            methodTypeIndex >= cpBands.MethodTypeCount() || signatureIndexes == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        HttpXmlText descriptor = {};
        NTSTATUS status = ExpandSignature(
            cpBands,
            signatureIndexes[methodTypeIndex],
            signatureStorage,
            &descriptor);
        USHORT descriptorIndex = 0;
        if (NT_SUCCESS(status)) {
            status = writer->AddUtf8(descriptor, &descriptorIndex);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return writer->AddMethodType(descriptorIndex, constantIndex);
    }

    _Must_inspect_result_
    NTSTATUS AddLoadableConstant(
        const HttpPack200CpBands& cpBands,
        ULONG loadableIndex,
        _Inout_ HttpPack200ClassWriter* writer,
        _Inout_ HeapArray<char>* signatureStorage,
        _Out_ USHORT* constantIndex) noexcept
    {
        if (writer == nullptr || signatureStorage == nullptr || constantIndex == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        HttpPack200RelocationKind kind = HttpPack200RelocationKind::Integer;
        ULONG referenceIndex = 0;
        NTSTATUS status = ResolveLoadableValueKind(
            cpBands,
            loadableIndex,
            &kind,
            &referenceIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (kind == HttpPack200RelocationKind::Integer) {
            const ULONG* values = cpBands.IntBits();
            return values != nullptr ? writer->AddInteger(values[referenceIndex], constantIndex) :
                STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (kind == HttpPack200RelocationKind::Float) {
            const ULONG* values = cpBands.FloatBits();
            return values != nullptr ? writer->AddFloat(values[referenceIndex], constantIndex) :
                STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (kind == HttpPack200RelocationKind::Long) {
            const ULONG* high = cpBands.LongHighBits();
            const ULONG* low = cpBands.LongLowBits();
            return high != nullptr && low != nullptr ?
                writer->AddLong(high[referenceIndex], low[referenceIndex], constantIndex) :
                STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (kind == HttpPack200RelocationKind::Double) {
            const ULONG* high = cpBands.DoubleHighBits();
            const ULONG* low = cpBands.DoubleLowBits();
            return high != nullptr && low != nullptr ?
                writer->AddDouble(high[referenceIndex], low[referenceIndex], constantIndex) :
                STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (kind == HttpPack200RelocationKind::String) {
            const ULONG* strings = cpBands.StringUtf8Indexes();
            HttpXmlText value = {};
            if (strings == nullptr || !cpBands.GetUtf8(strings[referenceIndex], &value)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            USHORT utf8Index = 0;
            status = writer->AddUtf8(value, &utf8Index);
            return NT_SUCCESS(status) ? writer->AddString(utf8Index, constantIndex) : status;
        }
        if (kind == HttpPack200RelocationKind::Class) {
            const ULONG* classNames = cpBands.ClassNameIndexes();
            HttpXmlText value = {};
            if (classNames == nullptr ||
                !cpBands.GetUtf8(classNames[referenceIndex], &value)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            USHORT utf8Index = 0;
            status = writer->AddUtf8(value, &utf8Index);
            return NT_SUCCESS(status) ? writer->AddClass(utf8Index, constantIndex) : status;
        }
        if (kind == HttpPack200RelocationKind::MethodHandle) {
            return AddMethodHandleConstant(
                cpBands,
                referenceIndex,
                writer,
                signatureStorage,
                constantIndex);
        }
        return AddMethodTypeConstant(
            cpBands,
            referenceIndex,
            writer,
            signatureStorage,
            constantIndex);
    }

    _Must_inspect_result_
    NTSTATUS BuildClassFile(
        const HttpPack200CpBands& cpBands,
        const HttpPack200InnerClassBands& innerClassBands,
        _Inout_ HttpPack200CodeBands* codeBands,
        _Inout_ HttpPack200ClassBands* classBands,
        SIZE_T classIndex,
        USHORT minorVersion,
        USHORT majorVersion,
        _Inout_ HeapArray<char>* storage,
        _Out_ SIZE_T* classLength,
        _Out_ HttpXmlText* className) noexcept
    {
        if (codeBands == nullptr || classBands == nullptr || storage == nullptr || classLength == nullptr ||
            className == nullptr || classIndex >= classBands->ClassCount()) {
            return STATUS_INVALID_PARAMETER;
        }
        *classLength = 0;
        *className = {};
        ULONG* thisClasses = classBands->ThisClassIndexes();
        ULONG* superClasses = classBands->SuperClassIndexes();
        ULONG* interfaceCounts = classBands->InterfaceCounts();
        ULONG* interfaceIndexes = classBands->InterfaceIndexes();
        ULONG* fieldCounts = classBands->FieldCounts();
        ULONG* methodCounts = classBands->MethodCounts();
        ULONG* flags = classBands->FlagsLow();
        const ULONG* classNameIndexes = cpBands.ClassNameIndexes();
        if (thisClasses == nullptr || superClasses == nullptr || interfaceCounts == nullptr ||
            fieldCounts == nullptr || methodCounts == nullptr || flags == nullptr ||
            classNameIndexes == nullptr ||
            thisClasses[classIndex] >= cpBands.ClassCount() ||
            superClasses[classIndex] >= cpBands.ClassCount()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T interfaceOffset = 0;
        SIZE_T fieldOffset = 0;
        SIZE_T methodOffset = 0;
        for (SIZE_T index = 0; index < classIndex; ++index) {
            if (!CheckedAddSize(interfaceOffset, interfaceCounts[index], &interfaceOffset) ||
                !CheckedAddSize(fieldOffset, fieldCounts[index], &fieldOffset) ||
                !CheckedAddSize(methodOffset, methodCounts[index], &methodOffset)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        const SIZE_T interfaceCount = interfaceCounts[classIndex];
        const SIZE_T fieldCount = fieldCounts[classIndex];
        const SIZE_T methodCount = methodCounts[classIndex];
        SIZE_T interfaceEnd = 0;
        SIZE_T fieldEnd = 0;
        SIZE_T methodEnd = 0;
        if (!CheckedAddSize(interfaceOffset, interfaceCount, &interfaceEnd) ||
            !CheckedAddSize(fieldOffset, fieldCount, &fieldEnd) ||
            !CheckedAddSize(methodOffset, methodCount, &methodEnd) ||
            interfaceEnd > classBands->InterfaceIndexCount() ||
            fieldEnd > classBands->FieldMemberCount() ||
            methodEnd > classBands->MethodMemberCount() ||
            (interfaceCount != 0 && interfaceIndexes == nullptr)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const ULONG thisNameIndex = classNameIndexes[thisClasses[classIndex]];
        const ULONG superNameIndex = classNameIndexes[superClasses[classIndex]];
        HttpXmlText thisName = {};
        HttpXmlText superName = {};
        if (!cpBands.GetUtf8(thisNameIndex, &thisName) ||
            !cpBands.GetUtf8(superNameIndex, &superName) ||
            thisName.Length == 0 || superName.Length == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T relevantInnerClassCount = 0;
        SIZE_T relevantInnerClassPoolEntries = 0;
        SIZE_T explicitInnerClassIndex = 0;
        const ULONG* innerThisClasses = innerClassBands.ThisClassIndexes();
        const ULONG* innerFlags = innerClassBands.Flags();
        const ULONG* innerOuterClasses = innerClassBands.OuterClassIndexes();
        for (SIZE_T index = 0; index < innerClassBands.Count(); ++index) {
            if (innerThisClasses == nullptr || innerFlags == nullptr ||
                innerThisClasses[index] >= cpBands.ClassCount()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpXmlText innerName = {};
            if (!cpBands.GetUtf8(classNameIndexes[innerThisClasses[index]], &innerName)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            bool relevant = innerThisClasses[index] == thisClasses[classIndex];
            bool hasOuterName = false;
            bool hasSimpleName = false;
            if ((innerFlags[index] & 0x00010000UL) != 0) {
                if (explicitInnerClassIndex >= innerClassBands.ExplicitCount() ||
                    innerOuterClasses == nullptr) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                const ULONG outerReference = innerOuterClasses[explicitInnerClassIndex];
                if (outerReference != 0) {
                    hasOuterName = true;
                    const ULONG outerClass = outerReference - 1;
                    if (outerClass >= cpBands.ClassCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    HttpXmlText outerName = {};
                    if (!cpBands.GetUtf8(classNameIndexes[outerClass], &outerName)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    relevant = relevant ||
                        (outerName.Length == thisName.Length &&
                            RtlCompareMemory(outerName.Data, thisName.Data, thisName.Length) == thisName.Length);
                }
                const ULONG nameReference = innerClassBands.NameIndexes()[explicitInnerClassIndex];
                if (nameReference > cpBands.Utf8Count()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                hasSimpleName = nameReference != 0;
                ++explicitInnerClassIndex;
            }
            else {
                SIZE_T separator = innerName.Length;
                for (SIZE_T charIndex = innerName.Length; charIndex > 0; --charIndex) {
                    const UCHAR character = static_cast<UCHAR>(innerName.Data[charIndex - 1]);
                    if (character == '/' || character == '.') {
                        break;
                    }
                    if (character <= 0x2dU) {
                        separator = charIndex - 1;
                        break;
                    }
                }
                if (separator < innerName.Length) {
                    hasOuterName = true;
                    SIZE_T nameOffset = separator + 1;
                    while (nameOffset < innerName.Length &&
                        innerName.Data[nameOffset] >= '0' && innerName.Data[nameOffset] <= '9') {
                        ++nameOffset;
                    }
                    hasSimpleName = nameOffset < innerName.Length;
                    relevant = relevant ||
                        (separator == thisName.Length &&
                            RtlCompareMemory(innerName.Data, thisName.Data, thisName.Length) == thisName.Length);
                }
            }
            if (relevant) {
                SIZE_T entryCount = 2 + (hasOuterName ? 2 : 0) + (hasSimpleName ? 1 : 0);
                if (!CheckedAddSize(relevantInnerClassCount, 1, &relevantInnerClassCount) ||
                    !CheckedAddSize(
                        relevantInnerClassPoolEntries,
                        entryCount,
                        &relevantInnerClassPoolEntries)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
        }
        if (explicitInnerClassIndex != innerClassBands.ExplicitCount()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const ULONG* descriptorNames = cpBands.DescriptorNameIndexes();
        const ULONG* descriptorTypes = cpBands.DescriptorTypeIndexes();
        const ULONG* fieldDescriptors = classBands->FieldDescriptorIndexes();
        const ULONG* fieldFlags = classBands->FieldFlagsLow();
        const ULONG* fieldConstantValues = classBands->FieldConstantValueIndexes();
        const ULONG* fieldSignatures = classBands->FieldSignatureIndexes();
        const ULONG* methodDescriptors = classBands->MethodDescriptorIndexes();
        const ULONG* methodFlags = classBands->MethodFlagsLow();
        const ULONG* methodExceptionCounts = classBands->MethodExceptionCounts();
        const ULONG* methodExceptionClasses = classBands->MethodExceptionClassIndexes();
        const ULONG* methodSignatures = classBands->MethodSignatureIndexes();
        const ULONG* sourceFileIndexes = classBands->SourceFileIndexes();
        const ULONG* enclosingMethodClasses = classBands->EnclosingMethodClassIndexes();
        const ULONG* enclosingMethodDescriptors = classBands->EnclosingMethodDescriptorIndexes();
        const ULONG* classSignatures = classBands->ClassSignatureIndexes();
        if (sourceFileIndexes == nullptr || enclosingMethodClasses == nullptr ||
            enclosingMethodDescriptors == nullptr || classSignatures == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const bool hasSourceFile = sourceFileIndexes[classIndex] != 0xffffffffUL;
        const bool hasEnclosingMethod =
            enclosingMethodClasses[classIndex] != 0xffffffffUL;
        const bool hasClassSignature = classSignatures[classIndex] != 0xffffffffUL;
        SIZE_T enclosingMethodPoolEntries = 0;
        if (hasEnclosingMethod) {
            const ULONG enclosingClass = enclosingMethodClasses[classIndex];
            const ULONG enclosingDescriptor = enclosingMethodDescriptors[classIndex];
            if (enclosingClass >= cpBands.ClassCount() ||
                (enclosingDescriptor != 0 &&
                    enclosingDescriptor - 1 >= cpBands.DescriptorCount())) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            enclosingMethodPoolEntries = enclosingDescriptor == 0 ? 3 : 6;
        }
        constexpr ULONG DeprecatedFlag = 1UL << 20;
        bool hasDeprecatedAttribute = (flags[classIndex] & DeprecatedFlag) != 0;

        SIZE_T fieldSignatureCount = 0;
        SIZE_T methodSignatureCount = 0;
        for (SIZE_T index = 0; index < fieldCount; ++index) {
            if (fieldSignatures == nullptr || fieldFlags == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            hasDeprecatedAttribute = hasDeprecatedAttribute ||
                (fieldFlags[fieldOffset + index] & DeprecatedFlag) != 0;
            if (fieldSignatures[fieldOffset + index] != 0xffffffffUL &&
                !CheckedAddSize(fieldSignatureCount, 1, &fieldSignatureCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        for (SIZE_T index = 0; index < methodCount; ++index) {
            if (methodSignatures == nullptr || methodFlags == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            hasDeprecatedAttribute = hasDeprecatedAttribute ||
                (methodFlags[methodOffset + index] & DeprecatedFlag) != 0;
            if (methodSignatures[methodOffset + index] != 0xffffffffUL &&
                !CheckedAddSize(methodSignatureCount, 1, &methodSignatureCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        SIZE_T signatureAttributeCount = fieldSignatureCount;
        if (!CheckedAddSize(signatureAttributeCount, methodSignatureCount, &signatureAttributeCount) ||
            (hasClassSignature && !CheckedAddSize(signatureAttributeCount, 1, &signatureAttributeCount))) {
            return STATUS_INTEGER_OVERFLOW;
        }

        const ULONG* methodCodeIndexes = classBands->MethodCodeIndexes();
        SIZE_T classCodeCount = 0;
        if (methodCount != 0 && methodCodeIndexes == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        for (SIZE_T index = 0; index < methodCount; ++index) {
            if (methodCodeIndexes[methodOffset + index] != 0xffffffffUL &&
                !CheckedAddSize(classCodeCount, 1, &classCodeCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }

        SIZE_T classHandlerCount = 0;
        SIZE_T typedHandlerCount = 0;
        ULONG* handlerStarts = classBands->HandlerStartIndexes();
        LONG* handlerEnds = classBands->HandlerEndOffsets();
        LONG* handlerCatches = classBands->HandlerCatchOffsets();
        ULONG* handlerClasses = classBands->HandlerClassIndexes();
        if (classBands->HandlerCount() != 0 &&
            (handlerStarts == nullptr || handlerEnds == nullptr ||
                handlerCatches == nullptr || handlerClasses == nullptr)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T methodExceptionOffset = 0;
        SIZE_T classDeclaredExceptionCount = 0;
        if (methodCount != 0 && methodExceptionCounts == nullptr) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        for (SIZE_T methodIndex = 0; methodIndex < methodOffset; ++methodIndex) {
            if (!CheckedAddSize(
                    methodExceptionOffset,
                    methodExceptionCounts[methodIndex],
                    &methodExceptionOffset)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        for (SIZE_T methodIndex = 0; methodIndex < methodCount; ++methodIndex) {
            if (!CheckedAddSize(
                    classDeclaredExceptionCount,
                    methodExceptionCounts[methodOffset + methodIndex],
                    &classDeclaredExceptionCount)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        SIZE_T methodExceptionEnd = 0;
        if (!CheckedAddSize(
                methodExceptionOffset,
                classDeclaredExceptionCount,
                &methodExceptionEnd) ||
            methodExceptionEnd > classBands->MethodExceptionIndexCount() ||
            (classDeclaredExceptionCount != 0 && methodExceptionClasses == nullptr)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        for (SIZE_T index = 0; index < methodCount; ++index) {
            const ULONG codeIndex = methodCodeIndexes[methodOffset + index];
            if (codeIndex == 0xffffffffUL) {
                continue;
            }
            if (codeIndex >= classBands->CodeCount()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            SIZE_T handlerOffset = 0;
            for (SIZE_T priorCode = 0; priorCode < codeIndex; ++priorCode) {
                if (!CheckedAddSize(
                        handlerOffset,
                        classBands->CodeHandlerCounts()[priorCode],
                        &handlerOffset)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
            const SIZE_T methodHandlerCount = classBands->CodeHandlerCounts()[codeIndex];
            SIZE_T handlerEnd = 0;
            if (!CheckedAddSize(handlerOffset, methodHandlerCount, &handlerEnd) ||
                handlerEnd > classBands->HandlerCount() ||
                !CheckedAddSize(classHandlerCount, methodHandlerCount, &classHandlerCount)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            for (SIZE_T handlerIndex = handlerOffset;
                handlerIndex < handlerEnd;
                ++handlerIndex) {
                if (handlerClasses[handlerIndex] != 0 &&
                    !CheckedAddSize(typedHandlerCount, 1, &typedHandlerCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
        }
        SIZE_T classRelocationCount = 0;
        SIZE_T relocationPoolEntryCount = 0;
        SIZE_T classBootstrapMethodCount = 0;
        SIZE_T classBootstrapArgumentCount = 0;
        const HttpPack200CodeRelocation* relocations = codeBands->Relocations();
        for (SIZE_T relocationIndex = 0;
            relocationIndex < codeBands->RelocationCount();
            ++relocationIndex) {
            bool belongsToClass = false;
            for (SIZE_T methodIndex = 0; methodIndex < methodCount; ++methodIndex) {
                if (methodCodeIndexes[methodOffset + methodIndex] ==
                    relocations[relocationIndex].CodeIndex) {
                    belongsToClass = true;
                    break;
                }
            }
            if (belongsToClass) {
                HttpPack200RelocationKind relocationKind = relocations[relocationIndex].Kind;
                ULONG referenceIndex = relocations[relocationIndex].ReferenceIndex;
                if (relocationKind == HttpPack200RelocationKind::LoadableValue) {
                    NTSTATUS resolveStatus = ResolveLoadableValueKind(
                        cpBands,
                        referenceIndex,
                        &relocationKind,
                        &referenceIndex);
                    if (!NT_SUCCESS(resolveStatus)) {
                        return resolveStatus;
                    }
                }
                SIZE_T entryCount = 6;
                if (relocationKind == HttpPack200RelocationKind::Integer ||
                    relocationKind == HttpPack200RelocationKind::Float) {
                    entryCount = 1;
                }
                else if (relocationKind == HttpPack200RelocationKind::Class ||
                    relocationKind == HttpPack200RelocationKind::String ||
                    relocationKind == HttpPack200RelocationKind::Long ||
                    relocationKind == HttpPack200RelocationKind::Double ||
                    relocationKind == HttpPack200RelocationKind::MethodType) {
                    entryCount = 2;
                }
                else if (relocationKind == HttpPack200RelocationKind::MethodHandle) {
                    entryCount = 7;
                }
                else if (relocationKind == HttpPack200RelocationKind::InvokeDynamic) {
                    const ULONG* invokeBootstrapIndexes = cpBands.InvokeDynamicBootstrapIndexes();
                    const ULONG* bootstrapArgumentCounts = cpBands.BootstrapMethodArgumentCounts();
                    const ULONG* bootstrapArguments = cpBands.BootstrapMethodArgumentIndexes();
                    if (referenceIndex >= cpBands.InvokeDynamicCount() ||
                        invokeBootstrapIndexes == nullptr || bootstrapArgumentCounts == nullptr) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const ULONG bootstrapIndex = invokeBootstrapIndexes[referenceIndex];
                    if (bootstrapIndex >= cpBands.BootstrapMethodCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    SIZE_T argumentOffset = 0;
                    for (SIZE_T index = 0; index < bootstrapIndex; ++index) {
                        if (!CheckedAddSize(
                                argumentOffset,
                                bootstrapArgumentCounts[index],
                                &argumentOffset)) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                    }
                    const SIZE_T argumentCount = bootstrapArgumentCounts[bootstrapIndex];
                    if (argumentCount != 0 && bootstrapArguments == nullptr) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    entryCount = 11;
                    for (SIZE_T index = 0; index < argumentCount; ++index) {
                        SIZE_T argumentEntryCount = 0;
                        NTSTATUS countStatus = LoadableConstantEntryCount(
                            cpBands,
                            bootstrapArguments[argumentOffset + index],
                            &argumentEntryCount);
                        if (!NT_SUCCESS(countStatus) ||
                            !CheckedAddSize(entryCount, argumentEntryCount, &entryCount)) {
                            return NT_SUCCESS(countStatus) ? STATUS_INTEGER_OVERFLOW : countStatus;
                        }
                    }
                    if (!CheckedAddSize(
                            classBootstrapMethodCount,
                            1,
                            &classBootstrapMethodCount) ||
                        !CheckedAddSize(
                            classBootstrapArgumentCount,
                            argumentCount,
                            &classBootstrapArgumentCount)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                }
                if (!CheckedAddSize(classRelocationCount, 1, &classRelocationCount) ||
                    !CheckedAddSize(
                        relocationPoolEntryCount,
                        entryCount,
                        &relocationPoolEntryCount)) {
                    return STATUS_INTEGER_OVERFLOW;
                }
            }
        }
        if (classBootstrapMethodCount != 0 &&
            !CheckedAddSize(relocationPoolEntryCount, 1, &relocationPoolEntryCount)) {
            return STATUS_INTEGER_OVERFLOW;
        }

        SIZE_T constantValueFieldCount = 0;
        SIZE_T constantValuePoolSlots = 0;
        HeapArray<char> constantDescriptorStorage = {};
        for (SIZE_T fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
            if (fieldConstantValues == nullptr ||
                fieldConstantValues[fieldOffset + fieldIndex] == 0xffffffffUL) {
                continue;
            }
            if (fieldDescriptors == nullptr || descriptorTypes == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const ULONG descriptorIndex = fieldDescriptors[fieldOffset + fieldIndex];
            if (descriptorIndex >= cpBands.DescriptorCount()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpXmlText descriptor = {};
            NTSTATUS descriptorStatus = ExpandSignature(
                cpBands,
                descriptorTypes[descriptorIndex],
                &constantDescriptorStorage,
                &descriptor);
            if (!NT_SUCCESS(descriptorStatus)) {
                return descriptorStatus;
            }
            SIZE_T poolSlots = 0;
            if (descriptor.Length == 1) {
                const char type = descriptor.Data[0];
                if (type == 'B' || type == 'C' || type == 'I' ||
                    type == 'S' || type == 'Z' || type == 'F') {
                    poolSlots = 1;
                }
                else if (type == 'J' || type == 'D') {
                    poolSlots = 2;
                }
                else {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            else if (descriptor.Length == 18 &&
                RtlCompareMemory(descriptor.Data, "Ljava/lang/String;", 18) == 18) {
                poolSlots = 2;
            }
            else {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (!CheckedAddSize(constantValueFieldCount, 1, &constantValueFieldCount) ||
                !CheckedAddSize(constantValuePoolSlots, poolSlots, &constantValuePoolSlots)) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }

        SIZE_T constantPoolCount = 5;
        SIZE_T additionalCount = 0;
        SIZE_T memberCount = 0;
        if (interfaceCount > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / 2 ||
            !CheckedAddSize(fieldCount, methodCount, &memberCount) ||
            memberCount > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / 2 ||
            !CheckedAddSize(interfaceCount * 2, memberCount * 2, &additionalCount) ||
            !CheckedAddSize(constantPoolCount, additionalCount, &constantPoolCount) ||
            (classCodeCount != 0 && !CheckedAddSize(constantPoolCount, 1, &constantPoolCount)) ||
            !CheckedAddSize(constantPoolCount, relocationPoolEntryCount, &constantPoolCount) ||
            typedHandlerCount > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / 2 ||
            !CheckedAddSize(constantPoolCount, typedHandlerCount * 2, &constantPoolCount) ||
            (constantValueFieldCount != 0 &&
                !CheckedAddSize(constantPoolCount, 1, &constantPoolCount)) ||
            !CheckedAddSize(constantPoolCount, constantValuePoolSlots, &constantPoolCount) ||
            classDeclaredExceptionCount > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) / 2 ||
            (classDeclaredExceptionCount != 0 &&
                !CheckedAddSize(constantPoolCount, 1, &constantPoolCount)) ||
            !CheckedAddSize(
                constantPoolCount,
                classDeclaredExceptionCount * 2,
                &constantPoolCount) ||
            (hasSourceFile && !CheckedAddSize(constantPoolCount, 2, &constantPoolCount)) ||
            !CheckedAddSize(
                constantPoolCount,
                enclosingMethodPoolEntries,
                &constantPoolCount) ||
            (signatureAttributeCount != 0 &&
                !CheckedAddSize(constantPoolCount, 1, &constantPoolCount)) ||
            (hasDeprecatedAttribute &&
                !CheckedAddSize(constantPoolCount, 1, &constantPoolCount)) ||
            !CheckedAddSize(constantPoolCount, signatureAttributeCount, &constantPoolCount) ||
            (relevantInnerClassCount != 0 &&
                !CheckedAddSize(constantPoolCount, 1, &constantPoolCount)) ||
            !CheckedAddSize(
                constantPoolCount,
                relevantInnerClassPoolEntries,
                &constantPoolCount) ||
            constantPoolCount > 0xffffUL ||
            interfaceCount > 0xffffUL || fieldCount > 0xffffUL || methodCount > 0xffffUL) {
            return STATUS_INTEGER_OVERFLOW;
        }

        HttpPack200ClassWriter writer(storage->Get(), storage->Count());
        NTSTATUS status = writer.Begin(
            minorVersion,
            majorVersion,
            static_cast<USHORT>(constantPoolCount));
        USHORT thisUtf8 = 0;
        USHORT thisClass = 0;
        USHORT superUtf8 = 0;
        USHORT superClass = 0;
        if (NT_SUCCESS(status)) {
            status = writer.AddUtf8(thisName, &thisUtf8);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddClass(thisUtf8, &thisClass);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddUtf8(superName, &superUtf8);
        }
        if (NT_SUCCESS(status)) {
            status = writer.AddClass(superUtf8, &superClass);
        }

        HeapArray<USHORT> classInterfaces = {};
        if (NT_SUCCESS(status) && interfaceCount != 0) {
            status = classInterfaces.Allocate(interfaceCount);
        }
        for (SIZE_T index = 0; NT_SUCCESS(status) && index < interfaceCount; ++index) {
            const ULONG classReference = interfaceIndexes[interfaceOffset + index];
            if (classReference >= cpBands.ClassCount()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpXmlText interfaceName = {};
            if (!cpBands.GetUtf8(classNameIndexes[classReference], &interfaceName) ||
                interfaceName.Length == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            USHORT interfaceUtf8 = 0;
            status = writer.AddUtf8(interfaceName, &interfaceUtf8);
            if (NT_SUCCESS(status)) {
                status = writer.AddClass(interfaceUtf8, &classInterfaces[index]);
            }
        }

        HeapArray<HttpPack200ClassMember> fields = {};
        HeapArray<HttpPack200ClassMember> methods = {};
        HeapArray<HttpPack200ExceptionHandler> exceptionHandlers = {};
        HeapArray<USHORT> declaredExceptions = {};
        HeapArray<HttpPack200BootstrapMethod> bootstrapMethods = {};
        HeapArray<USHORT> bootstrapArguments = {};
        if (NT_SUCCESS(status) && fieldCount != 0) {
            status = fields.Allocate(fieldCount);
        }
        if (NT_SUCCESS(status) && methodCount != 0) {
            status = methods.Allocate(methodCount);
        }
        if (NT_SUCCESS(status) && classHandlerCount != 0) {
            status = exceptionHandlers.Allocate(classHandlerCount);
        }
        if (NT_SUCCESS(status) && classDeclaredExceptionCount != 0) {
            status = declaredExceptions.Allocate(classDeclaredExceptionCount);
        }
        if (NT_SUCCESS(status) && classBootstrapMethodCount != 0) {
            status = bootstrapMethods.Allocate(classBootstrapMethodCount);
        }
        if (NT_SUCCESS(status) && classBootstrapArgumentCount != 0) {
            status = bootstrapArguments.Allocate(classBootstrapArgumentCount);
        }
        if (NT_SUCCESS(status) && memberCount != 0 &&
            (descriptorNames == nullptr || descriptorTypes == nullptr ||
                (fieldCount != 0 && (fieldDescriptors == nullptr || fieldFlags == nullptr)) ||
                (methodCount != 0 && (methodDescriptors == nullptr || methodFlags == nullptr)))) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        HeapArray<char> signatureStorage = {};
        for (SIZE_T index = 0; NT_SUCCESS(status) && index < fieldCount; ++index) {
            const ULONG descriptorIndex = fieldDescriptors[fieldOffset + index];
            if (descriptorIndex >= cpBands.DescriptorCount()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpXmlText name = {};
            HttpXmlText descriptor = {};
            if (!cpBands.GetUtf8(descriptorNames[descriptorIndex], &name) || name.Length == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            status = ExpandSignature(
                cpBands,
                descriptorTypes[descriptorIndex],
                &signatureStorage,
                &descriptor);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            fields[index].AccessFlags = static_cast<USHORT>(fieldFlags[fieldOffset + index]);
            status = writer.AddUtf8(name, &fields[index].NameIndex);
            if (NT_SUCCESS(status)) {
                status = writer.AddUtf8(descriptor, &fields[index].DescriptorIndex);
            }
            if (NT_SUCCESS(status) && fieldSignatures[fieldOffset + index] != 0xffffffffUL) {
                HttpXmlText fieldSignature = {};
                status = ExpandSignature(
                    cpBands,
                    fieldSignatures[fieldOffset + index],
                    &signatureStorage,
                    &fieldSignature);
                if (NT_SUCCESS(status)) {
                    status = writer.AddUtf8(fieldSignature, &fields[index].SignatureIndex);
                }
            }
            const ULONG constantValue = fieldConstantValues == nullptr ?
                0xffffffffUL : fieldConstantValues[fieldOffset + index];
            if (NT_SUCCESS(status) && constantValue != 0xffffffffUL) {
                if (descriptor.Length == 1) {
                    const char type = descriptor.Data[0];
                    if (type == 'B' || type == 'C' || type == 'I' ||
                        type == 'S' || type == 'Z') {
                        const ULONG* values = cpBands.IntBits();
                        if (constantValue >= cpBands.IntCount() || values == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddInteger(
                            values[constantValue],
                            &fields[index].ConstantValueIndex);
                    }
                    else if (type == 'F') {
                        const ULONG* values = cpBands.FloatBits();
                        if (constantValue >= cpBands.FloatCount() || values == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddFloat(
                            values[constantValue],
                            &fields[index].ConstantValueIndex);
                    }
                    else if (type == 'J') {
                        const ULONG* highBits = cpBands.LongHighBits();
                        const ULONG* lowBits = cpBands.LongLowBits();
                        if (constantValue >= cpBands.LongCount() ||
                            highBits == nullptr || lowBits == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddLong(
                            highBits[constantValue],
                            lowBits[constantValue],
                            &fields[index].ConstantValueIndex);
                    }
                    else if (type == 'D') {
                        const ULONG* highBits = cpBands.DoubleHighBits();
                        const ULONG* lowBits = cpBands.DoubleLowBits();
                        if (constantValue >= cpBands.DoubleCount() ||
                            highBits == nullptr || lowBits == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddDouble(
                            highBits[constantValue],
                            lowBits[constantValue],
                            &fields[index].ConstantValueIndex);
                    }
                }
                else {
                    const ULONG* strings = cpBands.StringUtf8Indexes();
                    if (constantValue >= cpBands.StringCount() || strings == nullptr) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    HttpXmlText stringValue = {};
                    if (!cpBands.GetUtf8(strings[constantValue], &stringValue)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    USHORT stringUtf8Index = 0;
                    status = writer.AddUtf8(stringValue, &stringUtf8Index);
                    if (NT_SUCCESS(status)) {
                        status = writer.AddString(
                            stringUtf8Index,
                            &fields[index].ConstantValueIndex);
                    }
                }
            }
        }
        if (NT_SUCCESS(status) && constantValueFieldCount != 0) {
            const HttpXmlText attributeName = { "ConstantValue", 13 };
            USHORT attributeNameIndex = 0;
            status = writer.AddUtf8(attributeName, &attributeNameIndex);
            if (NT_SUCCESS(status)) {
                for (SIZE_T index = 0; index < fieldCount; ++index) {
                    if (fields[index].ConstantValueIndex != 0) {
                        fields[index].ConstantValueAttributeNameIndex = attributeNameIndex;
                    }
                }
            }
        }
        SIZE_T classHandlerIndex = 0;
        SIZE_T classDeclaredExceptionIndex = 0;
        for (SIZE_T index = 0; NT_SUCCESS(status) && index < methodCount; ++index) {
            const ULONG descriptorIndex = methodDescriptors[methodOffset + index];
            if (descriptorIndex >= cpBands.DescriptorCount()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpXmlText name = {};
            HttpXmlText descriptor = {};
            if (!cpBands.GetUtf8(descriptorNames[descriptorIndex], &name) || name.Length == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            status = ExpandSignature(
                cpBands,
                descriptorTypes[descriptorIndex],
                &signatureStorage,
                &descriptor);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            methods[index].AccessFlags = static_cast<USHORT>(methodFlags[methodOffset + index]);
            status = writer.AddUtf8(name, &methods[index].NameIndex);
            if (NT_SUCCESS(status)) {
                status = writer.AddUtf8(descriptor, &methods[index].DescriptorIndex);
            }
            if (NT_SUCCESS(status) && methodSignatures[methodOffset + index] != 0xffffffffUL) {
                HttpXmlText methodSignature = {};
                status = ExpandSignature(
                    cpBands,
                    methodSignatures[methodOffset + index],
                    &signatureStorage,
                    &methodSignature);
                if (NT_SUCCESS(status)) {
                    status = writer.AddUtf8(methodSignature, &methods[index].SignatureIndex);
                }
            }
            const ULONG codeIndex = methodCodeIndexes[methodOffset + index];
            if (NT_SUCCESS(status) && codeIndex != 0xffffffffUL) {
                const UCHAR* code = nullptr;
                SIZE_T codeLength = 0;
                if (codeIndex >= classBands->CodeCount() ||
                    codeIndex >= codeBands->CodeCount() ||
                    !codeBands->GetCode(codeIndex, &code, &codeLength) ||
                    classBands->CodeMaxStacks()[codeIndex] > 0xffffUL ||
                    codeLength > 0xffffUL) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                USHORT argumentSlots = 0;
                status = CountMethodArgumentSlots(
                    descriptor,
                    (methods[index].AccessFlags & 0x0008U) != 0,
                    &argumentSlots);
                SIZE_T maxLocals = classBands->CodeMaxNonArgumentLocals()[codeIndex];
                if (!NT_SUCCESS(status) ||
                    !CheckedAddSize(maxLocals, argumentSlots, &maxLocals) ||
                    maxLocals > 0xffffUL) {
                    return NT_SUCCESS(status) ? STATUS_INTEGER_OVERFLOW : status;
                }
                methods[index].MaxStack =
                    static_cast<USHORT>(classBands->CodeMaxStacks()[codeIndex]);
                methods[index].MaxLocals = static_cast<USHORT>(maxLocals);
                methods[index].Code = code;
                methods[index].CodeLength = codeLength;

                SIZE_T handlerOffset = 0;
                for (SIZE_T priorCode = 0; priorCode < codeIndex; ++priorCode) {
                    if (!CheckedAddSize(
                            handlerOffset,
                            classBands->CodeHandlerCounts()[priorCode],
                            &handlerOffset)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                }
                const SIZE_T methodHandlerCount = classBands->CodeHandlerCounts()[codeIndex];
                if (classHandlerIndex > classHandlerCount ||
                    methodHandlerCount > classHandlerCount - classHandlerIndex) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                methods[index].ExceptionHandlers = methodHandlerCount == 0 ?
                    nullptr : exceptionHandlers.Get() + classHandlerIndex;
                methods[index].ExceptionHandlerCount = methodHandlerCount;
                for (SIZE_T handlerIndex = 0;
                    handlerIndex < methodHandlerCount;
                    ++handlerIndex) {
                    const SIZE_T sourceIndex = handlerOffset + handlerIndex;
                    const LONGLONG startInstruction = handlerStarts[sourceIndex];
                    const LONGLONG endInstruction =
                        startInstruction + handlerEnds[sourceIndex];
                    const LONGLONG catchInstruction =
                        endInstruction + handlerCatches[sourceIndex];
                    if (startInstruction < 0 || endInstruction <= startInstruction ||
                        catchInstruction < 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    ULONG startPc = 0;
                    ULONG endPc = 0;
                    ULONG handlerPc = 0;
                    if (!codeBands->GetInstructionOffset(
                            codeIndex,
                            static_cast<SIZE_T>(startInstruction),
                            &startPc) ||
                        !codeBands->GetInstructionOffset(
                            codeIndex,
                            static_cast<SIZE_T>(endInstruction),
                            &endPc) ||
                        !codeBands->GetInstructionOffset(
                            codeIndex,
                            static_cast<SIZE_T>(catchInstruction),
                            &handlerPc) ||
                        startPc > 0xffffUL || endPc > 0xffffUL || handlerPc > 0xffffUL) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    HttpPack200ExceptionHandler& handler =
                        exceptionHandlers[classHandlerIndex++];
                    handler.StartPc = static_cast<USHORT>(startPc);
                    handler.EndPc = static_cast<USHORT>(endPc);
                    handler.HandlerPc = static_cast<USHORT>(handlerPc);
                    if (handlerClasses[sourceIndex] != 0) {
                        const ULONG catchClass = handlerClasses[sourceIndex] - 1;
                        if (catchClass >= cpBands.ClassCount()) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        HttpXmlText catchClassName = {};
                        if (!cpBands.GetUtf8(
                                classNameIndexes[catchClass],
                                &catchClassName) ||
                            catchClassName.Length == 0) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        USHORT catchUtf8Index = 0;
                        status = writer.AddUtf8(catchClassName, &catchUtf8Index);
                        if (NT_SUCCESS(status)) {
                            status = writer.AddClass(
                                catchUtf8Index,
                                &handler.CatchTypeIndex);
                        }
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                }
            }
            const SIZE_T declaredExceptionCount = methodExceptionCounts[methodOffset + index];
            if (classDeclaredExceptionIndex > classDeclaredExceptionCount ||
                declaredExceptionCount >
                    classDeclaredExceptionCount - classDeclaredExceptionIndex) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            methods[index].DeclaredExceptionIndexes = declaredExceptionCount == 0 ?
                nullptr : declaredExceptions.Get() + classDeclaredExceptionIndex;
            methods[index].DeclaredExceptionCount = declaredExceptionCount;
            for (SIZE_T exceptionIndex = 0;
                exceptionIndex < declaredExceptionCount;
                ++exceptionIndex) {
                const ULONG referencedClass = methodExceptionClasses[
                    methodExceptionOffset + classDeclaredExceptionIndex];
                if (referencedClass >= cpBands.ClassCount()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                HttpXmlText exceptionClassName = {};
                if (!cpBands.GetUtf8(
                        classNameIndexes[referencedClass],
                        &exceptionClassName) ||
                    exceptionClassName.Length == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                USHORT exceptionUtf8Index = 0;
                status = writer.AddUtf8(exceptionClassName, &exceptionUtf8Index);
                if (NT_SUCCESS(status)) {
                    status = writer.AddClass(
                        exceptionUtf8Index,
                        &declaredExceptions[classDeclaredExceptionIndex]);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                ++classDeclaredExceptionIndex;
            }
        }
        if (classHandlerIndex != classHandlerCount ||
            classDeclaredExceptionIndex != classDeclaredExceptionCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (NT_SUCCESS(status) && classCodeCount != 0) {
            const HttpXmlText codeName = { "Code", 4 };
            USHORT codeNameIndex = 0;
            status = writer.AddUtf8(codeName, &codeNameIndex);
            if (NT_SUCCESS(status)) {
                for (SIZE_T index = 0; index < methodCount; ++index) {
                    if (methods[index].Code != nullptr) {
                        methods[index].CodeAttributeNameIndex = codeNameIndex;
                    }
                }
            }
        }
        if (NT_SUCCESS(status) && classDeclaredExceptionCount != 0) {
            const HttpXmlText exceptionsName = { "Exceptions", 10 };
            USHORT exceptionsNameIndex = 0;
            status = writer.AddUtf8(exceptionsName, &exceptionsNameIndex);
            if (NT_SUCCESS(status)) {
                for (SIZE_T index = 0; index < methodCount; ++index) {
                    if (methods[index].DeclaredExceptionCount != 0) {
                        methods[index].ExceptionsAttributeNameIndex = exceptionsNameIndex;
                    }
                }
            }
        }
        USHORT signatureAttributeNameIndex = 0;
        if (NT_SUCCESS(status) && signatureAttributeCount != 0) {
            const HttpXmlText signatureName = { "Signature", 9 };
            status = writer.AddUtf8(signatureName, &signatureAttributeNameIndex);
            if (NT_SUCCESS(status)) {
                for (SIZE_T index = 0; index < fieldCount; ++index) {
                    if (fields[index].SignatureIndex != 0) {
                        fields[index].SignatureAttributeNameIndex = signatureAttributeNameIndex;
                    }
                }
                for (SIZE_T index = 0; index < methodCount; ++index) {
                    if (methods[index].SignatureIndex != 0) {
                        methods[index].SignatureAttributeNameIndex = signatureAttributeNameIndex;
                    }
                }
            }
        }
        USHORT deprecatedAttributeNameIndex = 0;
        if (NT_SUCCESS(status) && hasDeprecatedAttribute) {
            const HttpXmlText deprecatedName = { "Deprecated", 10 };
            status = writer.AddUtf8(deprecatedName, &deprecatedAttributeNameIndex);
            if (NT_SUCCESS(status)) {
                for (SIZE_T index = 0; index < fieldCount; ++index) {
                    if ((fieldFlags[fieldOffset + index] & DeprecatedFlag) != 0) {
                        fields[index].DeprecatedAttributeNameIndex = deprecatedAttributeNameIndex;
                    }
                }
                for (SIZE_T index = 0; index < methodCount; ++index) {
                    if ((methodFlags[methodOffset + index] & DeprecatedFlag) != 0) {
                        methods[index].DeprecatedAttributeNameIndex = deprecatedAttributeNameIndex;
                    }
                }
            }
        }
        USHORT bootstrapMethodsAttributeNameIndex = 0;
        SIZE_T storedBootstrapMethodCount = 0;
        SIZE_T storedBootstrapArgumentCount = 0;
        if (NT_SUCCESS(status) && classRelocationCount != 0) {
            ULONG* codeOffsets = codeBands->CodeOffsets();
            UCHAR* codeBytes = codeBands->CodeBytes();
            if (codeOffsets == nullptr || codeBytes == nullptr || relocations == nullptr) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            for (SIZE_T relocationIndex = 0;
                NT_SUCCESS(status) && relocationIndex < codeBands->RelocationCount();
                ++relocationIndex) {
                const HttpPack200CodeRelocation& relocation = relocations[relocationIndex];
                bool belongsToClass = false;
                for (SIZE_T methodIndex = 0; methodIndex < methodCount; ++methodIndex) {
                    if (methodCodeIndexes[methodOffset + methodIndex] == relocation.CodeIndex) {
                        belongsToClass = true;
                        break;
                    }
                }
                if (!belongsToClass) {
                    continue;
                }

                if (relocation.Kind == HttpPack200RelocationKind::LoadableValue) {
                    USHORT constantIndex = 0;
                    status = AddLoadableConstant(
                        cpBands,
                        relocation.ReferenceIndex,
                        &writer,
                        &signatureStorage,
                        &constantIndex);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (relocation.CodeIndex >= codeBands->CodeCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T codeOffset = codeOffsets[relocation.CodeIndex];
                    SIZE_T operandOffset = 0;
                    if (!CheckedAddSize(codeOffset, relocation.OperandOffset, &operandOffset)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    const UCHAR* code = nullptr;
                    SIZE_T codeLength = 0;
                    if (!codeBands->GetCode(relocation.CodeIndex, &code, &codeLength) ||
                        relocation.OperandWidth == 0 || relocation.OperandWidth > 2 ||
                        relocation.OperandOffset > codeLength ||
                        codeLength - relocation.OperandOffset < relocation.OperandWidth ||
                        (relocation.OperandWidth == 1 && constantIndex > 0xffU)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (relocation.OperandWidth == 1) {
                        codeBytes[operandOffset] = static_cast<UCHAR>(constantIndex);
                    }
                    else {
                        codeBytes[operandOffset] = static_cast<UCHAR>((constantIndex >> 8) & 0xff);
                        codeBytes[operandOffset + 1] = static_cast<UCHAR>(constantIndex & 0xff);
                    }
                    continue;
                }

                if (relocation.Kind == HttpPack200RelocationKind::InvokeDynamic) {
                    const ULONG* invokeBootstrapIndexes = cpBands.InvokeDynamicBootstrapIndexes();
                    const ULONG* invokeDescriptorIndexes = cpBands.InvokeDynamicDescriptorIndexes();
                    const ULONG* bootstrapReferences = cpBands.BootstrapMethodReferenceIndexes();
                    const ULONG* bootstrapArgumentCounts = cpBands.BootstrapMethodArgumentCounts();
                    const ULONG* bootstrapArgumentIndexes = cpBands.BootstrapMethodArgumentIndexes();
                    if (relocation.ReferenceIndex >= cpBands.InvokeDynamicCount() ||
                        invokeBootstrapIndexes == nullptr || invokeDescriptorIndexes == nullptr ||
                        bootstrapReferences == nullptr || bootstrapArgumentCounts == nullptr ||
                        storedBootstrapMethodCount >= bootstrapMethods.Count()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const ULONG bootstrapIndex = invokeBootstrapIndexes[relocation.ReferenceIndex];
                    const ULONG descriptorIndex = invokeDescriptorIndexes[relocation.ReferenceIndex];
                    if (bootstrapIndex >= cpBands.BootstrapMethodCount() ||
                        descriptorIndex >= cpBands.DescriptorCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    SIZE_T argumentOffset = 0;
                    for (SIZE_T index = 0; index < bootstrapIndex; ++index) {
                        if (!CheckedAddSize(
                                argumentOffset,
                                bootstrapArgumentCounts[index],
                                &argumentOffset)) {
                            return STATUS_INTEGER_OVERFLOW;
                        }
                    }
                    const SIZE_T argumentCount = bootstrapArgumentCounts[bootstrapIndex];
                    SIZE_T nextStoredArgumentCount = 0;
                    if (!CheckedAddSize(
                            storedBootstrapArgumentCount,
                            argumentCount,
                            &nextStoredArgumentCount) ||
                        nextStoredArgumentCount > bootstrapArguments.Count() ||
                        (argumentCount != 0 && bootstrapArgumentIndexes == nullptr)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    HttpPack200BootstrapMethod& bootstrapMethod =
                        bootstrapMethods[storedBootstrapMethodCount];
                    status = AddMethodHandleConstant(
                        cpBands,
                        bootstrapReferences[bootstrapIndex],
                        &writer,
                        &signatureStorage,
                        &bootstrapMethod.MethodHandleIndex);
                    bootstrapMethod.ArgumentIndexes = argumentCount == 0 ? nullptr :
                        bootstrapArguments.Get() + storedBootstrapArgumentCount;
                    bootstrapMethod.ArgumentCount = argumentCount;
                    for (SIZE_T index = 0; NT_SUCCESS(status) && index < argumentCount; ++index) {
                        status = AddLoadableConstant(
                            cpBands,
                            bootstrapArgumentIndexes[argumentOffset + index],
                            &writer,
                            &signatureStorage,
                            &bootstrapArguments[storedBootstrapArgumentCount + index]);
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    HttpXmlText memberName = {};
                    HttpXmlText memberDescriptor = {};
                    if (!cpBands.GetUtf8(descriptorNames[descriptorIndex], &memberName)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = ExpandSignature(
                        cpBands,
                        descriptorTypes[descriptorIndex],
                        &signatureStorage,
                        &memberDescriptor);
                    USHORT nameUtf8Index = 0;
                    USHORT descriptorUtf8Index = 0;
                    USHORT nameAndTypeIndex = 0;
                    USHORT constantIndex = 0;
                    if (NT_SUCCESS(status)) status = writer.AddUtf8(memberName, &nameUtf8Index);
                    if (NT_SUCCESS(status)) {
                        status = writer.AddUtf8(memberDescriptor, &descriptorUtf8Index);
                    }
                    if (NT_SUCCESS(status)) {
                        status = writer.AddNameAndType(
                            nameUtf8Index,
                            descriptorUtf8Index,
                            &nameAndTypeIndex);
                    }
                    if (NT_SUCCESS(status)) {
                        status = writer.AddInvokeDynamic(
                            static_cast<USHORT>(storedBootstrapMethodCount),
                            nameAndTypeIndex,
                            &constantIndex);
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (relocation.CodeIndex >= codeBands->CodeCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T codeOffset = codeOffsets[relocation.CodeIndex];
                    SIZE_T operandOffset = 0;
                    if (!CheckedAddSize(codeOffset, relocation.OperandOffset, &operandOffset)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    const UCHAR* code = nullptr;
                    SIZE_T codeLength = 0;
                    if (!codeBands->GetCode(relocation.CodeIndex, &code, &codeLength) ||
                        relocation.OperandWidth != 2 ||
                        relocation.OperandOffset > codeLength ||
                        codeLength - relocation.OperandOffset < 4) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    codeBytes[operandOffset] = static_cast<UCHAR>((constantIndex >> 8) & 0xff);
                    codeBytes[operandOffset + 1] = static_cast<UCHAR>(constantIndex & 0xff);
                    codeBytes[operandOffset + 2] = 0;
                    codeBytes[operandOffset + 3] = 0;
                    storedBootstrapArgumentCount = nextStoredArgumentCount;
                    ++storedBootstrapMethodCount;
                    continue;
                }

                const HttpPack200RelocationKind relocationKind = relocation.Kind;
                const ULONG relocationReferenceIndex = relocation.ReferenceIndex;
                if (relocationKind == HttpPack200RelocationKind::Integer ||
                    relocationKind == HttpPack200RelocationKind::Float ||
                    relocationKind == HttpPack200RelocationKind::Long ||
                    relocationKind == HttpPack200RelocationKind::Double ||
                    relocationKind == HttpPack200RelocationKind::String ||
                    relocationKind == HttpPack200RelocationKind::Class ||
                    relocationKind == HttpPack200RelocationKind::MethodHandle ||
                    relocationKind == HttpPack200RelocationKind::MethodType) {
                    USHORT constantIndex = 0;
                    if (relocationKind == HttpPack200RelocationKind::Integer) {
                        const ULONG* intBits = cpBands.IntBits();
                        if (relocationReferenceIndex >= cpBands.IntCount() || intBits == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddInteger(
                            intBits[relocationReferenceIndex],
                            &constantIndex);
                    }
                    else if (relocationKind == HttpPack200RelocationKind::Float) {
                        const ULONG* floatBits = cpBands.FloatBits();
                        if (relocationReferenceIndex >= cpBands.FloatCount() || floatBits == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddFloat(
                            floatBits[relocationReferenceIndex],
                            &constantIndex);
                    }
                    else if (relocationKind == HttpPack200RelocationKind::Long) {
                        const ULONG* highBits = cpBands.LongHighBits();
                        const ULONG* lowBits = cpBands.LongLowBits();
                        if (relocationReferenceIndex >= cpBands.LongCount() ||
                            highBits == nullptr || lowBits == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddLong(
                            highBits[relocationReferenceIndex],
                            lowBits[relocationReferenceIndex],
                            &constantIndex);
                    }
                    else if (relocationKind == HttpPack200RelocationKind::Double) {
                        const ULONG* highBits = cpBands.DoubleHighBits();
                        const ULONG* lowBits = cpBands.DoubleLowBits();
                        if (relocationReferenceIndex >= cpBands.DoubleCount() ||
                            highBits == nullptr || lowBits == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        status = writer.AddDouble(
                            highBits[relocationReferenceIndex],
                            lowBits[relocationReferenceIndex],
                            &constantIndex);
                    }
                    else if (relocationKind == HttpPack200RelocationKind::String) {
                        const ULONG* strings = cpBands.StringUtf8Indexes();
                        if (relocationReferenceIndex >= cpBands.StringCount() || strings == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        HttpXmlText stringValue = {};
                        if (!cpBands.GetUtf8(strings[relocationReferenceIndex], &stringValue)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        USHORT stringUtf8Index = 0;
                        status = writer.AddUtf8(stringValue, &stringUtf8Index);
                        if (NT_SUCCESS(status)) {
                            status = writer.AddString(stringUtf8Index, &constantIndex);
                        }
                    }
                    else if (relocationKind == HttpPack200RelocationKind::Class) {
                        const ULONG referencedClass = relocationReferenceIndex == 0 ?
                            thisClasses[classIndex] : relocationReferenceIndex - 1;
                        if (referencedClass >= cpBands.ClassCount()) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        HttpXmlText referencedClassName = {};
                        if (!cpBands.GetUtf8(
                                classNameIndexes[referencedClass],
                                &referencedClassName) ||
                            referencedClassName.Length == 0) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        USHORT classUtf8Index = 0;
                        status = writer.AddUtf8(referencedClassName, &classUtf8Index);
                        if (NT_SUCCESS(status)) {
                            status = writer.AddClass(classUtf8Index, &constantIndex);
                        }
                    }
                    else if (relocationKind == HttpPack200RelocationKind::MethodHandle) {
                        const ULONG* referenceKinds = cpBands.MethodHandleReferenceKinds();
                        const ULONG* memberIndexes = cpBands.MethodHandleMemberIndexes();
                        if (relocationReferenceIndex >= cpBands.MethodHandleCount() ||
                            referenceKinds == nullptr || memberIndexes == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        USHORT memberConstantIndex = 0;
                        status = AddAnyMemberConstant(
                            cpBands,
                            memberIndexes[relocationReferenceIndex],
                            &writer,
                            &signatureStorage,
                            &memberConstantIndex);
                        if (NT_SUCCESS(status)) {
                            status = writer.AddMethodHandle(
                                static_cast<UCHAR>(referenceKinds[relocationReferenceIndex]),
                                memberConstantIndex,
                                &constantIndex);
                        }
                    }
                    else {
                        const ULONG* signatureIndexes = cpBands.MethodTypeSignatureIndexes();
                        if (relocationReferenceIndex >= cpBands.MethodTypeCount() ||
                            signatureIndexes == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        HttpXmlText descriptor = {};
                        status = ExpandSignature(
                            cpBands,
                            signatureIndexes[relocationReferenceIndex],
                            &signatureStorage,
                            &descriptor);
                        USHORT descriptorIndex = 0;
                        if (NT_SUCCESS(status)) {
                            status = writer.AddUtf8(descriptor, &descriptorIndex);
                        }
                        if (NT_SUCCESS(status)) {
                            status = writer.AddMethodType(descriptorIndex, &constantIndex);
                        }
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (relocation.CodeIndex >= codeBands->CodeCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T codeOffset = codeOffsets[relocation.CodeIndex];
                    SIZE_T operandOffset = 0;
                    if (!CheckedAddSize(codeOffset, relocation.OperandOffset, &operandOffset)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    const UCHAR* code = nullptr;
                    SIZE_T codeLength = 0;
                    if (!codeBands->GetCode(relocation.CodeIndex, &code, &codeLength) ||
                        relocation.OperandWidth == 0 || relocation.OperandWidth > 2 ||
                        relocation.OperandOffset > codeLength ||
                        codeLength - relocation.OperandOffset < relocation.OperandWidth ||
                        (relocation.OperandWidth == 1 && constantIndex > 0xffU)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (relocation.OperandWidth == 1) {
                        codeBytes[operandOffset] = static_cast<UCHAR>(constantIndex);
                    }
                    else {
                        codeBytes[operandOffset] =
                            static_cast<UCHAR>((constantIndex >> 8) & 0xff);
                        codeBytes[operandOffset + 1] =
                            static_cast<UCHAR>(constantIndex & 0xff);
                    }
                    continue;
                }

                if (relocation.Kind == HttpPack200RelocationKind::Field ||
                    relocation.Kind == HttpPack200RelocationKind::Method ||
                    relocation.Kind == HttpPack200RelocationKind::InterfaceMethod) {
                    ULONG referencedClass = 0;
                    ULONG descriptorIndex = 0;
                    if (relocation.Kind == HttpPack200RelocationKind::Field) {
                        const ULONG* fieldClasses = cpBands.FieldClassIndexes();
                        const ULONG* fieldDescriptorReferences = cpBands.FieldDescriptorIndexes();
                        if (relocation.ReferenceIndex >= cpBands.FieldCount() ||
                            fieldClasses == nullptr || fieldDescriptorReferences == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        referencedClass = fieldClasses[relocation.ReferenceIndex];
                        descriptorIndex = fieldDescriptorReferences[relocation.ReferenceIndex];
                    }
                    else if (relocation.Kind == HttpPack200RelocationKind::Method) {
                        const ULONG* methodClasses = cpBands.MethodClassIndexes();
                        const ULONG* methodDescriptorIndexes = cpBands.MethodDescriptorIndexes();
                        if (relocation.ReferenceIndex >= cpBands.MethodCount() ||
                            methodClasses == nullptr || methodDescriptorIndexes == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        referencedClass = methodClasses[relocation.ReferenceIndex];
                        descriptorIndex = methodDescriptorIndexes[relocation.ReferenceIndex];
                    }
                    else {
                        const ULONG* methodClasses = cpBands.InterfaceMethodClassIndexes();
                        const ULONG* interfaceMethodDescriptors =
                            cpBands.InterfaceMethodDescriptorIndexes();
                        if (relocation.ReferenceIndex >= cpBands.InterfaceMethodCount() ||
                            methodClasses == nullptr || interfaceMethodDescriptors == nullptr) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        referencedClass = methodClasses[relocation.ReferenceIndex];
                        descriptorIndex = interfaceMethodDescriptors[relocation.ReferenceIndex];
                    }
                    if (referencedClass >= cpBands.ClassCount() ||
                        descriptorIndex >= cpBands.DescriptorCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }

                    HttpXmlText referencedClassName = {};
                    HttpXmlText memberName = {};
                    HttpXmlText memberDescriptor = {};
                    if (!cpBands.GetUtf8(
                            classNameIndexes[referencedClass],
                            &referencedClassName) ||
                        !cpBands.GetUtf8(
                            descriptorNames[descriptorIndex],
                            &memberName)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = ExpandSignature(
                        cpBands,
                        descriptorTypes[descriptorIndex],
                        &signatureStorage,
                        &memberDescriptor);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }

                    USHORT classUtf8Index = 0;
                    USHORT classConstantIndex = 0;
                    USHORT nameUtf8Index = 0;
                    USHORT descriptorUtf8Index = 0;
                    USHORT nameAndTypeIndex = 0;
                    USHORT referenceIndex = 0;
                    status = writer.AddUtf8(referencedClassName, &classUtf8Index);
                    if (NT_SUCCESS(status)) {
                        status = writer.AddClass(classUtf8Index, &classConstantIndex);
                    }
                    if (NT_SUCCESS(status)) {
                        status = writer.AddUtf8(memberName, &nameUtf8Index);
                    }
                    if (NT_SUCCESS(status)) {
                        status = writer.AddUtf8(memberDescriptor, &descriptorUtf8Index);
                    }
                    if (NT_SUCCESS(status)) {
                        status = writer.AddNameAndType(
                            nameUtf8Index,
                            descriptorUtf8Index,
                            &nameAndTypeIndex);
                    }
                    if (NT_SUCCESS(status)) {
                        if (relocation.Kind == HttpPack200RelocationKind::Field) {
                            status = writer.AddFieldref(
                                classConstantIndex,
                                nameAndTypeIndex,
                                &referenceIndex);
                        }
                        else if (relocation.Kind == HttpPack200RelocationKind::InterfaceMethod) {
                            status = writer.AddInterfaceMethodref(
                                classConstantIndex,
                                nameAndTypeIndex,
                                &referenceIndex);
                        }
                        else {
                            status = writer.AddMethodref(
                                classConstantIndex,
                                nameAndTypeIndex,
                                &referenceIndex);
                        }
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (relocation.CodeIndex >= codeBands->CodeCount()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const SIZE_T codeOffset = codeOffsets[relocation.CodeIndex];
                    SIZE_T operandOffset = 0;
                    if (!CheckedAddSize(codeOffset, relocation.OperandOffset, &operandOffset)) {
                        return STATUS_INTEGER_OVERFLOW;
                    }
                    const UCHAR* code = nullptr;
                    SIZE_T codeLength = 0;
                    if (!codeBands->GetCode(relocation.CodeIndex, &code, &codeLength) ||
                        relocation.OperandOffset > codeLength ||
                        codeLength - relocation.OperandOffset < 2) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    codeBytes[operandOffset] = static_cast<UCHAR>((referenceIndex >> 8) & 0xff);
                    codeBytes[operandOffset + 1] = static_cast<UCHAR>(referenceIndex & 0xff);
                    if (relocation.Kind == HttpPack200RelocationKind::InterfaceMethod &&
                        relocation.OperandOffset != 0 &&
                        codeBytes[operandOffset - 1] == 185) {
                        if (relocation.OperandOffset > codeLength ||
                            codeLength - relocation.OperandOffset < 4) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        USHORT invokeCount = 0;
                        status = CountMethodArgumentSlots(
                            memberDescriptor,
                            false,
                            &invokeCount);
                        if (!NT_SUCCESS(status) || invokeCount > 0xffU) {
                            return NT_SUCCESS(status) ? STATUS_INTEGER_OVERFLOW : status;
                        }
                        codeBytes[operandOffset + 2] = static_cast<UCHAR>(invokeCount);
                        codeBytes[operandOffset + 3] = 0;
                    }
                    continue;
                }

                const bool referencesThis =
                    relocation.Kind == HttpPack200RelocationKind::InitThis ||
                    relocation.Kind == HttpPack200RelocationKind::MethodThis;
                const bool initializerOnly =
                    relocation.Kind == HttpPack200RelocationKind::InitThis ||
                    relocation.Kind == HttpPack200RelocationKind::InitSuper;
                ULONG referencedClass = referencesThis ?
                    thisClasses[classIndex] : superClasses[classIndex];
                ULONG descriptorIndex = 0;
                status = FindMethodDescriptor(
                    cpBands,
                    referencedClass,
                    relocation.ReferenceIndex,
                    initializerOnly,
                    &descriptorIndex);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (descriptorIndex >= cpBands.DescriptorCount() ||
                    referencedClass >= cpBands.ClassCount()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                HttpXmlText referencedClassName = {};
                HttpXmlText initializerName = {};
                HttpXmlText initializerDescriptor = {};
                if (!cpBands.GetUtf8(
                        classNameIndexes[referencedClass],
                        &referencedClassName) ||
                    !cpBands.GetUtf8(
                        descriptorNames[descriptorIndex],
                        &initializerName)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = ExpandSignature(
                    cpBands,
                    descriptorTypes[descriptorIndex],
                    &signatureStorage,
                    &initializerDescriptor);
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                USHORT classUtf8Index = 0;
                USHORT classConstantIndex = 0;
                USHORT nameUtf8Index = 0;
                USHORT descriptorUtf8Index = 0;
                USHORT nameAndTypeIndex = 0;
                USHORT methodReferenceIndex = 0;
                status = writer.AddUtf8(referencedClassName, &classUtf8Index);
                if (NT_SUCCESS(status)) {
                    status = writer.AddClass(classUtf8Index, &classConstantIndex);
                }
                if (NT_SUCCESS(status)) {
                    status = writer.AddUtf8(initializerName, &nameUtf8Index);
                }
                if (NT_SUCCESS(status)) {
                    status = writer.AddUtf8(initializerDescriptor, &descriptorUtf8Index);
                }
                if (NT_SUCCESS(status)) {
                    status = writer.AddNameAndType(
                        nameUtf8Index,
                        descriptorUtf8Index,
                        &nameAndTypeIndex);
                }
                if (NT_SUCCESS(status)) {
                    status = writer.AddMethodref(
                        classConstantIndex,
                        nameAndTypeIndex,
                        &methodReferenceIndex);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }

                if (relocation.CodeIndex >= codeBands->CodeCount()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                const SIZE_T codeOffset = codeOffsets[relocation.CodeIndex];
                SIZE_T operandOffset = 0;
                if (!CheckedAddSize(codeOffset, relocation.OperandOffset, &operandOffset) ||
                    operandOffset > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 2) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                const UCHAR* code = nullptr;
                SIZE_T codeLength = 0;
                if (!codeBands->GetCode(relocation.CodeIndex, &code, &codeLength) ||
                    relocation.OperandOffset > codeLength ||
                    codeLength - relocation.OperandOffset < 2) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                codeBytes[operandOffset] =
                    static_cast<UCHAR>((methodReferenceIndex >> 8) & 0xff);
                codeBytes[operandOffset + 1] =
                    static_cast<UCHAR>(methodReferenceIndex & 0xff);
            }
        }
        USHORT sourceFileAttributeNameIndex = 0;
        USHORT sourceFileIndex = 0;
        HeapArray<char> generatedSourceFile = {};
        if (NT_SUCCESS(status) && hasSourceFile) {
            HttpXmlText sourceFileName = {};
            const ULONG encodedSourceFile = sourceFileIndexes[classIndex];
            if (encodedSourceFile != 0) {
                if (!cpBands.GetUtf8(encodedSourceFile - 1, &sourceFileName) ||
                    sourceFileName.Length == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
            else {
                SIZE_T nameStart = 0;
                for (SIZE_T index = 0; index < thisName.Length; ++index) {
                    if (thisName.Data[index] == '/' || thisName.Data[index] == '.') {
                        nameStart = index + 1;
                    }
                }
                SIZE_T nameLength = thisName.Length - nameStart;
                for (SIZE_T index = 0; index < nameLength; ++index) {
                    if (static_cast<UCHAR>(thisName.Data[nameStart + index]) <= 0x2dU) {
                        nameLength = index;
                        break;
                    }
                }
                if (nameLength == 0 || nameLength >
                    static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 5) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = generatedSourceFile.Allocate(nameLength + 5);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                RtlCopyMemory(
                    generatedSourceFile.Get(),
                    thisName.Data + nameStart,
                    nameLength);
                RtlCopyMemory(generatedSourceFile.Get() + nameLength, ".java", 5);
                sourceFileName.Data = generatedSourceFile.Get();
                sourceFileName.Length = generatedSourceFile.Count();
            }
            status = writer.AddUtf8(sourceFileName, &sourceFileIndex);
            if (NT_SUCCESS(status)) {
                const HttpXmlText attributeName = { "SourceFile", 10 };
                status = writer.AddUtf8(attributeName, &sourceFileAttributeNameIndex);
            }
        }
        USHORT enclosingMethodAttributeNameIndex = 0;
        USHORT enclosingClassIndex = 0;
        USHORT enclosingMethodIndex = 0;
        if (NT_SUCCESS(status) && hasEnclosingMethod) {
            const ULONG enclosingClassReference = enclosingMethodClasses[classIndex];
            HttpXmlText enclosingClassName = {};
            if (!cpBands.GetUtf8(
                    classNameIndexes[enclosingClassReference],
                    &enclosingClassName)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            USHORT enclosingClassNameIndex = 0;
            status = writer.AddUtf8(enclosingClassName, &enclosingClassNameIndex);
            if (NT_SUCCESS(status)) {
                status = writer.AddClass(enclosingClassNameIndex, &enclosingClassIndex);
            }
            const ULONG encodedDescriptor = enclosingMethodDescriptors[classIndex];
            if (NT_SUCCESS(status) && encodedDescriptor != 0) {
                const ULONG descriptorIndex = encodedDescriptor - 1;
                HttpXmlText methodName = {};
                HttpXmlText methodDescriptor = {};
                if (!cpBands.GetUtf8(descriptorNames[descriptorIndex], &methodName)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = ExpandSignature(
                    cpBands,
                    descriptorTypes[descriptorIndex],
                    &signatureStorage,
                    &methodDescriptor);
                USHORT methodNameIndex = 0;
                USHORT methodDescriptorIndex = 0;
                if (NT_SUCCESS(status)) {
                    status = writer.AddUtf8(methodName, &methodNameIndex);
                }
                if (NT_SUCCESS(status)) {
                    status = writer.AddUtf8(methodDescriptor, &methodDescriptorIndex);
                }
                if (NT_SUCCESS(status)) {
                    status = writer.AddNameAndType(
                        methodNameIndex,
                        methodDescriptorIndex,
                        &enclosingMethodIndex);
                }
            }
            if (NT_SUCCESS(status)) {
                const HttpXmlText attributeName = { "EnclosingMethod", 15 };
                status = writer.AddUtf8(attributeName, &enclosingMethodAttributeNameIndex);
            }
        }
        if (NT_SUCCESS(status) && storedBootstrapMethodCount != classBootstrapMethodCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (NT_SUCCESS(status) && storedBootstrapArgumentCount != classBootstrapArgumentCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (NT_SUCCESS(status) && storedBootstrapMethodCount != 0) {
            const HttpXmlText bootstrapMethodsName = { "BootstrapMethods", 16 };
            status = writer.AddUtf8(
                bootstrapMethodsName,
                &bootstrapMethodsAttributeNameIndex);
        }
        USHORT innerClassesAttributeNameIndex = 0;
        HeapArray<HttpPack200InnerClass> innerClasses = {};
        if (NT_SUCCESS(status) && relevantInnerClassCount != 0) {
            status = innerClasses.Allocate(relevantInnerClassCount);
        }
        SIZE_T storedInnerClassIndex = 0;
        explicitInnerClassIndex = 0;
        for (SIZE_T index = 0;
            NT_SUCCESS(status) && index < innerClassBands.Count();
            ++index) {
            HttpXmlText innerName = {};
            if (!cpBands.GetUtf8(classNameIndexes[innerThisClasses[index]], &innerName)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpXmlText outerName = {};
            HttpXmlText simpleName = {};
            bool relevant = innerThisClasses[index] == thisClasses[classIndex];
            if ((innerFlags[index] & 0x00010000UL) != 0) {
                const ULONG outerReference = innerOuterClasses[explicitInnerClassIndex];
                const ULONG nameReference = innerClassBands.NameIndexes()[explicitInnerClassIndex];
                if (outerReference != 0) {
                    const ULONG outerClass = outerReference - 1;
                    if (outerClass >= cpBands.ClassCount() ||
                        !cpBands.GetUtf8(classNameIndexes[outerClass], &outerName)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    relevant = relevant ||
                        (outerName.Length == thisName.Length &&
                            RtlCompareMemory(outerName.Data, thisName.Data, thisName.Length) == thisName.Length);
                }
                if (nameReference != 0 &&
                    !cpBands.GetUtf8(nameReference - 1, &simpleName)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                ++explicitInnerClassIndex;
            }
            else {
                SIZE_T separator = innerName.Length;
                for (SIZE_T charIndex = innerName.Length; charIndex > 0; --charIndex) {
                    const UCHAR character = static_cast<UCHAR>(innerName.Data[charIndex - 1]);
                    if (character == '/' || character == '.') {
                        break;
                    }
                    if (character <= 0x2dU) {
                        separator = charIndex - 1;
                        break;
                    }
                }
                if (separator < innerName.Length) {
                    outerName.Data = innerName.Data;
                    outerName.Length = separator;
                    SIZE_T nameOffset = separator + 1;
                    while (nameOffset < innerName.Length &&
                        innerName.Data[nameOffset] >= '0' && innerName.Data[nameOffset] <= '9') {
                        ++nameOffset;
                    }
                    if (nameOffset < innerName.Length) {
                        simpleName.Data = innerName.Data + nameOffset;
                        simpleName.Length = innerName.Length - nameOffset;
                    }
                    relevant = relevant ||
                        (outerName.Length == thisName.Length &&
                            RtlCompareMemory(outerName.Data, thisName.Data, thisName.Length) == thisName.Length);
                }
            }
            if (!relevant) {
                continue;
            }
            if (storedInnerClassIndex >= relevantInnerClassCount) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            HttpPack200InnerClass& stored = innerClasses[storedInnerClassIndex++];
            USHORT innerUtf8Index = 0;
            status = writer.AddUtf8(innerName, &innerUtf8Index);
            if (NT_SUCCESS(status)) {
                status = writer.AddClass(innerUtf8Index, &stored.InnerClassInfoIndex);
            }
            if (NT_SUCCESS(status) && outerName.Length != 0) {
                USHORT outerUtf8Index = 0;
                status = writer.AddUtf8(outerName, &outerUtf8Index);
                if (NT_SUCCESS(status)) {
                    status = writer.AddClass(outerUtf8Index, &stored.OuterClassInfoIndex);
                }
            }
            if (NT_SUCCESS(status) && simpleName.Length != 0) {
                status = writer.AddUtf8(simpleName, &stored.InnerNameIndex);
            }
            stored.AccessFlags = static_cast<USHORT>(innerFlags[index] & 0xffffUL);
        }
        if (NT_SUCCESS(status) && storedInnerClassIndex != relevantInnerClassCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (NT_SUCCESS(status) && relevantInnerClassCount != 0) {
            const HttpXmlText attributeName = { "InnerClasses", 12 };
            status = writer.AddUtf8(attributeName, &innerClassesAttributeNameIndex);
        }
        USHORT classSignatureIndex = 0;
        if (NT_SUCCESS(status) && hasClassSignature) {
            HttpXmlText classSignature = {};
            status = ExpandSignature(
                cpBands,
                classSignatures[classIndex],
                &signatureStorage,
                &classSignature);
            if (NT_SUCCESS(status)) {
                status = writer.AddUtf8(classSignature, &classSignatureIndex);
            }
        }
        if (NT_SUCCESS(status)) {
            status = writer.FinishClass(
                static_cast<USHORT>(flags[classIndex] & 0xffffUL),
                thisClass,
                superClass,
                classInterfaces.Get(),
                interfaceCount,
                fields.Get(),
                fieldCount,
                methods.Get(),
                methodCount,
                sourceFileAttributeNameIndex,
                sourceFileIndex,
                hasClassSignature ? signatureAttributeNameIndex : 0,
                classSignatureIndex,
                (flags[classIndex] & DeprecatedFlag) != 0 ? deprecatedAttributeNameIndex : 0,
                enclosingMethodAttributeNameIndex,
                enclosingClassIndex,
                enclosingMethodIndex,
                bootstrapMethodsAttributeNameIndex,
                bootstrapMethods.Get(),
                storedBootstrapMethodCount,
                innerClassesAttributeNameIndex,
                innerClasses.Get(),
                relevantInnerClassCount,
                classLength);
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }
        *className = thisName;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseSegmentBands(
        _Inout_ Pack200Reader* reader,
        const SegmentHeader& header,
        _Inout_ HttpPack200JarWriter* writer,
        SIZE_T destinationCapacity) noexcept
    {
        if (reader == nullptr || writer == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (header.BandHeadersSize > reader->Remaining()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        Pack200Reader bandHeaderReader(reader->Current(), header.BandHeadersSize);
        if (!reader->Skip(header.BandHeadersSize)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        HttpPack200CodecArena arena = {};
        NTSTATUS status = arena.Initialize(64);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        HttpPack200CpBands cpBands = {};
        status = HttpPack200ReadCpBands(
            reader,
            &bandHeaderReader,
            &arena,
            BuildCpCounts(header),
            &cpBands);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpPack200AttributeDefinitionBands attributeDefinitions = {};
        status = HttpPack200ReadAttributeDefinitionBands(
            reader,
            &bandHeaderReader,
            &arena,
            header.AttributeDefinitionCount,
            cpBands.Utf8Count(),
            &attributeDefinitions);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpPack200InnerClassBands innerClasses = {};
        status = HttpPack200ReadInnerClassBands(
            reader,
            &bandHeaderReader,
            &arena,
            header.InnerClassCount,
            cpBands.ClassCount(),
            cpBands.Utf8Count(),
            &innerClasses);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpPack200ClassBands classBands = {};
        status = HttpPack200ReadClassBandsWithMeta(
            reader,
            &bandHeaderReader,
            &arena,
            header.ClassCount,
            header.Options.HaveClassFlagsHi,
            header.Options.HaveFieldFlagsHi,
            header.Options.HaveMethodFlagsHi,
            header.Options.HaveAllCodeFlags,
            header.Options.HaveCodeFlagsHi,
            &classBands);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpPack200CodeBands codeBands = {};
        status = HttpPack200ReadBytecodeBands(
            reader,
            &bandHeaderReader,
            &arena,
            classBands.CodeCount(),
            &codeBands);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpPack200FileBands fileBands = {};
        status = HttpPack200ReadFileBands(
            reader,
            &bandHeaderReader,
            &arena,
            header.FileCount,
            header.Options.HaveFileSizeHi,
            header.Options.HaveFileModtime,
            header.Options.HaveFileOptions,
            &fileBands);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (bandHeaderReader.Remaining() != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ULONG* nameIndexes = fileBands.NameIndexes();
        ULONG* sizesHigh = fileBands.SizesHigh();
        ULONG* sizesLow = fileBands.SizesLow();
        LONG* modtimes = fileBands.Modtimes();
        ULONG* fileOptions = fileBands.Options();
        if (header.FileCount != 0 &&
            (nameIndexes == nullptr || sizesHigh == nullptr || sizesLow == nullptr ||
                modtimes == nullptr || fileOptions == nullptr)) {
            return STATUS_INVALID_PARAMETER;
        }

        HeapArray<char> classStorage = {};
        if (header.ClassCount != 0) {
            status = classStorage.Allocate(destinationCapacity);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        SIZE_T classIndex = 0;
        for (SIZE_T fileIndex = 0; fileIndex < header.FileCount; ++fileIndex) {
            if (nameIndexes[fileIndex] >= cpBands.Utf8Count() ||
                (fileOptions[fileIndex] & ~3UL) != 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const ULONGLONG fileSize =
                (static_cast<ULONGLONG>(sizesHigh[fileIndex]) << 32) |
                static_cast<ULONGLONG>(sizesLow[fileIndex]);
            if (fileSize > static_cast<ULONGLONG>(~static_cast<SIZE_T>(0))) {
                return STATUS_INTEGER_OVERFLOW;
            }
            const SIZE_T contentLength = static_cast<SIZE_T>(fileSize);
            if (contentLength > reader->Remaining()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const LONGLONG modificationTime =
                static_cast<LONGLONG>(header.ArchiveModtime) +
                static_cast<LONGLONG>(modtimes[fileIndex]);
            if (modificationTime < 0 || modificationTime > 0xffffffffLL) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            HttpXmlText name = {};
            if (!cpBands.GetUtf8(nameIndexes[fileIndex], &name)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const bool deflate = header.Options.DeflateHint || (fileOptions[fileIndex] & 1UL) != 0;
            const bool isClass = (fileOptions[fileIndex] & 2UL) != 0 || name.Length == 0;
            if (isClass) {
                if (contentLength != 0 || classIndex >= header.ClassCount) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                SIZE_T classLength = 0;
                HttpXmlText className = {};
                    status = BuildClassFile(
                        cpBands,
                        innerClasses,
                        &codeBands,
                    &classBands,
                    classIndex,
                    static_cast<USHORT>(header.DefaultClassMinorVersion),
                    static_cast<USHORT>(header.DefaultClassMajorVersion),
                    &classStorage,
                    &classLength,
                    &className);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (className.Length > static_cast<SIZE_T>(~static_cast<SIZE_T>(0)) - 6) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                HeapArray<char> generatedName(className.Length + 6);
                if (!generatedName.IsValid()) {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                RtlCopyMemory(generatedName.Get(), className.Data, className.Length);
                RtlCopyMemory(generatedName.Get() + className.Length, ".class", 6);
                HttpXmlText jarName = {};
                jarName.Data = generatedName.Get();
                jarName.Length = generatedName.Count();
                status = writer->AddEntry(
                    jarName,
                    reinterpret_cast<const UCHAR*>(classStorage.Get()),
                    classLength,
                    deflate,
                    static_cast<ULONG>(modificationTime));
                if (!NT_SUCCESS(status)) {
                    return status == STATUS_INVALID_PARAMETER ?
                        STATUS_INVALID_NETWORK_RESPONSE : status;
                }
                ++classIndex;
                continue;
            }
            status = writer->AddEntry(
                name,
                reader->Current(),
                contentLength,
                deflate,
                static_cast<ULONG>(modificationTime));
            if (status == STATUS_INVALID_PARAMETER) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!reader->Skip(contentLength)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        return classIndex == header.ClassCount ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS ParsePack200Segments(
        const UCHAR* source,
        SIZE_T sourceLength,
        char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength) noexcept
    {
        if (source == nullptr || destination == nullptr || decodedLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *decodedLength = 0;
        Pack200Reader reader(source, sourceLength);
        SIZE_T maxEntries = destinationCapacity / 76;
        if (maxEntries == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
            return STATUS_INTEGER_OVERFLOW;
        }
        ++maxEntries;
        if (sourceLength < maxEntries) {
            maxEntries = sourceLength;
        }
        if (maxEntries == 0) {
            maxEntries = 1;
        }
        HttpPack200JarWriter writer(destination, destinationCapacity);
        NTSTATUS status = writer.Initialize(maxEntries);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG expectedNextCount = 0xffffffffUL;
        for (;;) {
            SegmentHeader header = {};
            status = ParseSegmentHeader(&reader, &header);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (expectedNextCount != 0xffffffffUL &&
                header.ArchiveNextCount != expectedNextCount) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            status = ParseSegmentBands(&reader, header, &writer, destinationCapacity);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (reader.Remaining() == 0) {
                if (header.ArchiveNextCount != 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                break;
            }
            if (!IsPack200Magic(reader.Current(), reader.Remaining())) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            expectedNextCount = header.ArchiveNextCount == 0 ?
                0xffffffffUL :
                header.ArchiveNextCount - 1;
        }
        return writer.Finish(decodedLength);
    }

    _Must_inspect_result_
    bool ReadGzipIsize(const UCHAR* source, SIZE_T sourceLength, _Out_ ULONG* value) noexcept
    {
        if (source == nullptr || value == nullptr || sourceLength < 4) {
            return false;
        }
        const UCHAR* trailer = source + sourceLength - 4;
        *value =
            static_cast<ULONG>(trailer[0]) |
            (static_cast<ULONG>(trailer[1]) << 8) |
            (static_cast<ULONG>(trailer[2]) << 16) |
            (static_cast<ULONG>(trailer[3]) << 24);
        return true;
    }
}

NTSTATUS DecodePack200GzipContent(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    if (decodedLength == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *decodedLength = 0;
    if (source == nullptr || destination == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }

    if (IsPack200Magic(source, sourceLength)) {
        return ParsePack200Segments(
            source,
            sourceLength,
            destination,
            destinationCapacity,
            decodedLength);
    }

    if (IsGzipMagic(source, sourceLength)) {
        ULONG uncompressedSize = 0;
        if (!ReadGzipIsize(source, sourceLength, &uncompressedSize) || uncompressedSize == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        HeapArray<char> segment(uncompressedSize);
        if (!segment.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T segmentLength = 0;
        NTSTATUS status = HttpCodingCodec::DecodeOne(
            HttpCoding::Gzip,
            reinterpret_cast<const char*>(source),
            sourceLength,
            segment.Get(),
            segment.Count(),
            &segmentLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (!IsPack200Magic(reinterpret_cast<const UCHAR*>(segment.Get()), segmentLength)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return ParsePack200Segments(
            reinterpret_cast<const UCHAR*>(segment.Get()),
            segmentLength,
            destination,
            destinationCapacity,
            decodedLength);
    }

    return STATUS_INVALID_NETWORK_RESPONSE;
}
}
}
