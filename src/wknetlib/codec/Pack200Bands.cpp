#include "Pack200Bands.h"

namespace wknet
{
namespace codec
{
namespace
{
    _Must_inspect_result_
    NTSTATUS AllocateUlongBand(HeapArray<ULONG>* band, SIZE_T count) noexcept
    {
        if (band == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        band->Reset();
        if (count == 0) {
            return STATUS_SUCCESS;
        }
        return band->Allocate(count);
    }
}

    NTSTATUS HttpPack200CpBands::Initialize(const HttpPack200CpCounts& counts) noexcept
    {
        Reset();
        NTSTATUS status = AllocateUlongBand(&utf8SuffixLengths_, counts.Utf8);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&utf8CharOffsets_, counts.Utf8);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&utf8ByteLengths_, counts.Utf8);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&utf16CharOffsets_, counts.Utf8);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&utf16CharLengths_, counts.Utf8);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&intBits_, counts.Int);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&floatBits_, counts.Float);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&longHighBits_, counts.Long);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&longLowBits_, counts.Long);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&doubleHighBits_, counts.Double);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&doubleLowBits_, counts.Double);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&stringUtf8Indexes_, counts.String);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&classNameIndexes_, counts.Class);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&signatureFormIndexes_, counts.Signature);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&descriptorNameIndexes_, counts.Descriptor);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&descriptorTypeIndexes_, counts.Descriptor);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&fieldClassIndexes_, counts.Field);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&fieldDescriptorIndexes_, counts.Field);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodClassIndexes_, counts.Method);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodDescriptorIndexes_, counts.Method);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&interfaceMethodClassIndexes_, counts.InterfaceMethod);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&interfaceMethodDescriptorIndexes_, counts.InterfaceMethod);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&methodHandleReferenceKinds_, counts.MethodHandle);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&methodHandleMemberIndexes_, counts.MethodHandle);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&methodTypeSignatureIndexes_, counts.MethodType);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&bootstrapMethodReferenceIndexes_, counts.BootstrapMethod);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&bootstrapMethodArgumentCounts_, counts.BootstrapMethod);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&invokeDynamicBootstrapIndexes_, counts.InvokeDynamic);
        if (!NT_SUCCESS(status)) return status;
        return AllocateUlongBand(&invokeDynamicDescriptorIndexes_, counts.InvokeDynamic);
    }

    void HttpPack200CpBands::Reset() noexcept
    {
        utf8SuffixLengths_.Reset();
        utf8CharOffsets_.Reset();
        utf8ByteLengths_.Reset();
        utf8Chars_.Reset();
        utf16CharOffsets_.Reset();
        utf16CharLengths_.Reset();
        utf16Chars_.Reset();
        intBits_.Reset();
        floatBits_.Reset();
        longHighBits_.Reset();
        longLowBits_.Reset();
        doubleHighBits_.Reset();
        doubleLowBits_.Reset();
        stringUtf8Indexes_.Reset();
        classNameIndexes_.Reset();
        signatureFormIndexes_.Reset();
        signatureClassIndexes_.Reset();
        descriptorNameIndexes_.Reset();
        descriptorTypeIndexes_.Reset();
        fieldClassIndexes_.Reset();
        fieldDescriptorIndexes_.Reset();
        methodClassIndexes_.Reset();
        methodDescriptorIndexes_.Reset();
        interfaceMethodClassIndexes_.Reset();
        interfaceMethodDescriptorIndexes_.Reset();
        methodHandleReferenceKinds_.Reset();
        methodHandleMemberIndexes_.Reset();
        methodTypeSignatureIndexes_.Reset();
        bootstrapMethodReferenceIndexes_.Reset();
        bootstrapMethodArgumentCounts_.Reset();
        bootstrapMethodArgumentIndexes_.Reset();
        invokeDynamicBootstrapIndexes_.Reset();
        invokeDynamicDescriptorIndexes_.Reset();
    }

    SIZE_T HttpPack200CpBands::Utf8Count() const noexcept
    {
        return utf8SuffixLengths_.Count();
    }

    SIZE_T HttpPack200CpBands::ClassCount() const noexcept
    {
        return classNameIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::IntCount() const noexcept
    {
        return intBits_.Count();
    }

    SIZE_T HttpPack200CpBands::FloatCount() const noexcept
    {
        return floatBits_.Count();
    }

    SIZE_T HttpPack200CpBands::LongCount() const noexcept
    {
        return longHighBits_.Count();
    }

    SIZE_T HttpPack200CpBands::DoubleCount() const noexcept
    {
        return doubleHighBits_.Count();
    }

    SIZE_T HttpPack200CpBands::SignatureCount() const noexcept
    {
        return signatureFormIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::DescriptorCount() const noexcept
    {
        return descriptorNameIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::MethodCount() const noexcept
    {
        return methodClassIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::StringCount() const noexcept
    {
        return stringUtf8Indexes_.Count();
    }

    SIZE_T HttpPack200CpBands::FieldCount() const noexcept
    {
        return fieldClassIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::InterfaceMethodCount() const noexcept
    {
        return interfaceMethodClassIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::MethodHandleCount() const noexcept
    {
        return methodHandleReferenceKinds_.Count();
    }

    SIZE_T HttpPack200CpBands::MethodTypeCount() const noexcept
    {
        return methodTypeSignatureIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::BootstrapMethodCount() const noexcept
    {
        return bootstrapMethodReferenceIndexes_.Count();
    }

    SIZE_T HttpPack200CpBands::InvokeDynamicCount() const noexcept
    {
        return invokeDynamicBootstrapIndexes_.Count();
    }

    ULONG* HttpPack200CpBands::Utf8SuffixLengths() noexcept
    {
        return utf8SuffixLengths_.Get();
    }

    ULONG* HttpPack200CpBands::Utf8CharOffsets() noexcept
    {
        return utf8CharOffsets_.Get();
    }

    ULONG* HttpPack200CpBands::Utf8ByteLengths() noexcept
    {
        return utf8ByteLengths_.Get();
    }

    char* HttpPack200CpBands::Utf8Chars() noexcept
    {
        return utf8Chars_.Get();
    }

    SIZE_T HttpPack200CpBands::Utf8CharCount() const noexcept
    {
        return utf8Chars_.Count();
    }

    NTSTATUS HttpPack200CpBands::AllocateUtf8Chars(SIZE_T charCount) noexcept
    {
        utf8Chars_.Reset();
        if (charCount == 0) {
            return STATUS_SUCCESS;
        }
        return utf8Chars_.Allocate(charCount);
    }

    ULONG* HttpPack200CpBands::Utf16CharOffsets() noexcept
    {
        return utf16CharOffsets_.Get();
    }

    ULONG* HttpPack200CpBands::Utf16CharLengths() noexcept
    {
        return utf16CharLengths_.Get();
    }

    USHORT* HttpPack200CpBands::Utf16Chars() noexcept
    {
        return utf16Chars_.Get();
    }

    NTSTATUS HttpPack200CpBands::AllocateUtf16Chars(SIZE_T charCount) noexcept
    {
        utf16Chars_.Reset();
        if (charCount == 0) {
            return STATUS_SUCCESS;
        }
        return utf16Chars_.Allocate(charCount);
    }

    bool HttpPack200CpBands::GetUtf8(SIZE_T index, HttpXmlText* value) const noexcept
    {
        if (value == nullptr || index >= Utf8Count()) {
            return false;
        }
        const ULONG offset = utf8CharOffsets_[index];
        const ULONG length = utf8ByteLengths_[index];
        if (static_cast<SIZE_T>(offset) > utf8Chars_.Count() ||
            static_cast<SIZE_T>(length) > utf8Chars_.Count() - static_cast<SIZE_T>(offset)) {
            return false;
        }
        value->Data = length == 0 ? nullptr : utf8Chars_.Get() + offset;
        value->Length = length;
        return true;
    }

    ULONG* HttpPack200CpBands::ClassNameIndexes() noexcept
    {
        return classNameIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::ClassNameIndexes() const noexcept
    {
        return classNameIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::IntBits() noexcept
    {
        return intBits_.Get();
    }

    const ULONG* HttpPack200CpBands::IntBits() const noexcept
    {
        return intBits_.Get();
    }

    ULONG* HttpPack200CpBands::FloatBits() noexcept
    {
        return floatBits_.Get();
    }

    const ULONG* HttpPack200CpBands::FloatBits() const noexcept
    {
        return floatBits_.Get();
    }

    ULONG* HttpPack200CpBands::LongHighBits() noexcept
    {
        return longHighBits_.Get();
    }

    const ULONG* HttpPack200CpBands::LongHighBits() const noexcept
    {
        return longHighBits_.Get();
    }

    ULONG* HttpPack200CpBands::LongLowBits() noexcept
    {
        return longLowBits_.Get();
    }

    const ULONG* HttpPack200CpBands::LongLowBits() const noexcept
    {
        return longLowBits_.Get();
    }

    ULONG* HttpPack200CpBands::DoubleHighBits() noexcept
    {
        return doubleHighBits_.Get();
    }

    const ULONG* HttpPack200CpBands::DoubleHighBits() const noexcept
    {
        return doubleHighBits_.Get();
    }

    ULONG* HttpPack200CpBands::DoubleLowBits() noexcept
    {
        return doubleLowBits_.Get();
    }

    const ULONG* HttpPack200CpBands::DoubleLowBits() const noexcept
    {
        return doubleLowBits_.Get();
    }

    ULONG* HttpPack200CpBands::StringUtf8Indexes() noexcept
    {
        return stringUtf8Indexes_.Get();
    }

    const ULONG* HttpPack200CpBands::StringUtf8Indexes() const noexcept
    {
        return stringUtf8Indexes_.Get();
    }

    ULONG* HttpPack200CpBands::SignatureFormIndexes() noexcept
    {
        return signatureFormIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::SignatureFormIndexes() const noexcept
    {
        return signatureFormIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::SignatureClassIndexes() noexcept
    {
        return signatureClassIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::SignatureClassIndexes() const noexcept
    {
        return signatureClassIndexes_.Get();
    }

    SIZE_T HttpPack200CpBands::SignatureClassIndexCount() const noexcept
    {
        return signatureClassIndexes_.Count();
    }

    NTSTATUS HttpPack200CpBands::AllocateSignatureClassIndexes(SIZE_T count) noexcept
    {
        return AllocateUlongBand(&signatureClassIndexes_, count);
    }

    ULONG* HttpPack200CpBands::DescriptorNameIndexes() noexcept
    {
        return descriptorNameIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::DescriptorNameIndexes() const noexcept
    {
        return descriptorNameIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::DescriptorTypeIndexes() noexcept
    {
        return descriptorTypeIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::DescriptorTypeIndexes() const noexcept
    {
        return descriptorTypeIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::FieldClassIndexes() noexcept
    {
        return fieldClassIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::FieldClassIndexes() const noexcept
    {
        return fieldClassIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::FieldDescriptorIndexes() noexcept
    {
        return fieldDescriptorIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::FieldDescriptorIndexes() const noexcept
    {
        return fieldDescriptorIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::MethodClassIndexes() noexcept
    {
        return methodClassIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::MethodClassIndexes() const noexcept
    {
        return methodClassIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::MethodDescriptorIndexes() noexcept
    {
        return methodDescriptorIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::MethodDescriptorIndexes() const noexcept
    {
        return methodDescriptorIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::InterfaceMethodClassIndexes() noexcept
    {
        return interfaceMethodClassIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::InterfaceMethodClassIndexes() const noexcept
    {
        return interfaceMethodClassIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::InterfaceMethodDescriptorIndexes() noexcept
    {
        return interfaceMethodDescriptorIndexes_.Get();
    }

    const ULONG* HttpPack200CpBands::InterfaceMethodDescriptorIndexes() const noexcept
    {
        return interfaceMethodDescriptorIndexes_.Get();
    }

    ULONG* HttpPack200CpBands::MethodHandleReferenceKinds() noexcept { return methodHandleReferenceKinds_.Get(); }
    const ULONG* HttpPack200CpBands::MethodHandleReferenceKinds() const noexcept { return methodHandleReferenceKinds_.Get(); }
    ULONG* HttpPack200CpBands::MethodHandleMemberIndexes() noexcept { return methodHandleMemberIndexes_.Get(); }
    const ULONG* HttpPack200CpBands::MethodHandleMemberIndexes() const noexcept { return methodHandleMemberIndexes_.Get(); }
    ULONG* HttpPack200CpBands::MethodTypeSignatureIndexes() noexcept { return methodTypeSignatureIndexes_.Get(); }
    const ULONG* HttpPack200CpBands::MethodTypeSignatureIndexes() const noexcept { return methodTypeSignatureIndexes_.Get(); }
    ULONG* HttpPack200CpBands::BootstrapMethodReferenceIndexes() noexcept { return bootstrapMethodReferenceIndexes_.Get(); }
    const ULONG* HttpPack200CpBands::BootstrapMethodReferenceIndexes() const noexcept { return bootstrapMethodReferenceIndexes_.Get(); }
    ULONG* HttpPack200CpBands::BootstrapMethodArgumentCounts() noexcept { return bootstrapMethodArgumentCounts_.Get(); }
    const ULONG* HttpPack200CpBands::BootstrapMethodArgumentCounts() const noexcept { return bootstrapMethodArgumentCounts_.Get(); }
    ULONG* HttpPack200CpBands::BootstrapMethodArgumentIndexes() noexcept { return bootstrapMethodArgumentIndexes_.Get(); }
    const ULONG* HttpPack200CpBands::BootstrapMethodArgumentIndexes() const noexcept { return bootstrapMethodArgumentIndexes_.Get(); }
    NTSTATUS HttpPack200CpBands::AllocateBootstrapMethodArgumentIndexes(SIZE_T count) noexcept
    {
        return AllocateUlongBand(&bootstrapMethodArgumentIndexes_, count);
    }
    ULONG* HttpPack200CpBands::InvokeDynamicBootstrapIndexes() noexcept { return invokeDynamicBootstrapIndexes_.Get(); }
    const ULONG* HttpPack200CpBands::InvokeDynamicBootstrapIndexes() const noexcept { return invokeDynamicBootstrapIndexes_.Get(); }
    ULONG* HttpPack200CpBands::InvokeDynamicDescriptorIndexes() noexcept { return invokeDynamicDescriptorIndexes_.Get(); }
    const ULONG* HttpPack200CpBands::InvokeDynamicDescriptorIndexes() const noexcept { return invokeDynamicDescriptorIndexes_.Get(); }

    NTSTATUS HttpPack200FileBands::Initialize(SIZE_T fileCount) noexcept
    {
        Reset();
        NTSTATUS status = AllocateUlongBand(&nameIndexes_, fileCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&sizesLow_, fileCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&sizesHigh_, fileCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        modtimes_.Reset();
        if (fileCount != 0) {
            status = modtimes_.Allocate(fileCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return AllocateUlongBand(&options_, fileCount);
    }

    void HttpPack200FileBands::Reset() noexcept
    {
        nameIndexes_.Reset();
        sizesLow_.Reset();
        sizesHigh_.Reset();
        modtimes_.Reset();
        options_.Reset();
    }

    ULONG* HttpPack200FileBands::NameIndexes() noexcept
    {
        return nameIndexes_.Get();
    }

    ULONG* HttpPack200FileBands::SizesLow() noexcept
    {
        return sizesLow_.Get();
    }

    ULONG* HttpPack200FileBands::SizesHigh() noexcept
    {
        return sizesHigh_.Get();
    }

    LONG* HttpPack200FileBands::Modtimes() noexcept
    {
        return modtimes_.Get();
    }

    ULONG* HttpPack200FileBands::Options() noexcept
    {
        return options_.Get();
    }

    NTSTATUS HttpPack200ClassBands::Initialize(SIZE_T classCount) noexcept
    {
        Reset();
        NTSTATUS status = AllocateUlongBand(&thisClassIndexes_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&superClassIndexes_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&interfaceCounts_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&fieldCounts_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodCounts_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&flagsLow_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&flagsHigh_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&sourceFileIndexes_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&enclosingMethodClassIndexes_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&enclosingMethodDescriptorIndexes_, classCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&classSignatureIndexes_, classCount);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&classMinorVersions_, classCount);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&classMajorVersions_, classCount);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&localInnerClassCounts_, classCount);
        if (!NT_SUCCESS(status)) return status;
        return AllocateUlongBand(&localInnerClassOffsets_, classCount);
    }

    void HttpPack200ClassBands::Reset() noexcept
    {
        thisClassIndexes_.Reset();
        superClassIndexes_.Reset();
        interfaceCounts_.Reset();
        interfaceIndexes_.Reset();
        fieldCounts_.Reset();
        methodCounts_.Reset();
        flagsLow_.Reset();
        flagsHigh_.Reset();
        sourceFileIndexes_.Reset();
        enclosingMethodClassIndexes_.Reset();
        enclosingMethodDescriptorIndexes_.Reset();
        classSignatureIndexes_.Reset();
        classMinorVersions_.Reset();
        classMajorVersions_.Reset();
        localInnerClassCounts_.Reset();
        localInnerClassOffsets_.Reset();
        localInnerClassIndexes_.Reset();
        localInnerClassFlags_.Reset();
        localInnerClassOuterIndexes_.Reset();
        localInnerClassNameIndexes_.Reset();
        fieldDescriptorIndexes_.Reset();
        fieldFlagsLow_.Reset();
        fieldFlagsHigh_.Reset();
        fieldConstantValueIndexes_.Reset();
        fieldSignatureIndexes_.Reset();
        methodDescriptorIndexes_.Reset();
        methodFlagsLow_.Reset();
        methodFlagsHigh_.Reset();
        methodExceptionCounts_.Reset();
        methodSignatureIndexes_.Reset();
        methodExceptionClassIndexes_.Reset();
        methodCodeIndexes_.Reset();
        codeMaxStacks_.Reset();
        codeMaxNonArgumentLocals_.Reset();
        codeHandlerCounts_.Reset();
        codeFlagsLow_.Reset();
        codeFlagsHigh_.Reset();
        lineNumberCounts_.Reset();
        lineNumberOffsets_.Reset();
        lineNumberBcis_.Reset();
        lineNumbers_.Reset();
        localVariableCounts_.Reset();
        localVariableOffsets_.Reset();
        localVariableBcis_.Reset();
        localVariableSpans_.Reset();
        localVariableNameIndexes_.Reset();
        localVariableTypeIndexes_.Reset();
        localVariableSlots_.Reset();
        localVariableTypeCounts_.Reset();
        localVariableTypeOffsets_.Reset();
        localVariableTypeBcis_.Reset();
        localVariableTypeSpans_.Reset();
        localVariableTypeNameIndexes_.Reset();
        localVariableTypeSignatureIndexes_.Reset();
        localVariableTypeSlots_.Reset();
        classVisibleAnnotations_.Reset();
        classInvisibleAnnotations_.Reset();
        fieldVisibleAnnotations_.Reset();
        fieldInvisibleAnnotations_.Reset();
        methodVisibleAnnotations_.Reset();
        methodInvisibleAnnotations_.Reset();
        methodVisibleParameterAnnotations_.Reset();
        methodInvisibleParameterAnnotations_.Reset();
        methodAnnotationDefaults_.Reset();
        handlerStartIndexes_.Reset();
        handlerEndOffsets_.Reset();
        handlerCatchOffsets_.Reset();
        handlerClassIndexes_.Reset();
    }

    ULONG* HttpPack200ClassBands::ThisClassIndexes() noexcept
    {
        return thisClassIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::SuperClassIndexes() noexcept
    {
        return superClassIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::InterfaceCounts() noexcept
    {
        return interfaceCounts_.Get();
    }

    ULONG* HttpPack200ClassBands::InterfaceIndexes() noexcept
    {
        return interfaceIndexes_.Get();
    }

    NTSTATUS HttpPack200ClassBands::AllocateInterfaceIndexes(SIZE_T count) noexcept
    {
        return AllocateUlongBand(&interfaceIndexes_, count);
    }

    ULONG* HttpPack200ClassBands::FieldCounts() noexcept
    {
        return fieldCounts_.Get();
    }

    ULONG* HttpPack200ClassBands::MethodCounts() noexcept
    {
        return methodCounts_.Get();
    }

    ULONG* HttpPack200ClassBands::FlagsLow() noexcept
    {
        return flagsLow_.Get();
    }

    ULONG* HttpPack200ClassBands::FlagsHigh() noexcept
    {
        return flagsHigh_.Get();
    }

    ULONG* HttpPack200ClassBands::SourceFileIndexes() noexcept
    {
        return sourceFileIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::SourceFileIndexes() const noexcept
    {
        return sourceFileIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::EnclosingMethodClassIndexes() noexcept
    {
        return enclosingMethodClassIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::EnclosingMethodClassIndexes() const noexcept
    {
        return enclosingMethodClassIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::EnclosingMethodDescriptorIndexes() noexcept
    {
        return enclosingMethodDescriptorIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::EnclosingMethodDescriptorIndexes() const noexcept
    {
        return enclosingMethodDescriptorIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::ClassSignatureIndexes() noexcept { return classSignatureIndexes_.Get(); }
    const ULONG* HttpPack200ClassBands::ClassSignatureIndexes() const noexcept { return classSignatureIndexes_.Get(); }
    ULONG* HttpPack200ClassBands::ClassMinorVersions() noexcept { return classMinorVersions_.Get(); }
    const ULONG* HttpPack200ClassBands::ClassMinorVersions() const noexcept { return classMinorVersions_.Get(); }
    ULONG* HttpPack200ClassBands::ClassMajorVersions() noexcept { return classMajorVersions_.Get(); }
    const ULONG* HttpPack200ClassBands::ClassMajorVersions() const noexcept { return classMajorVersions_.Get(); }
    ULONG* HttpPack200ClassBands::LocalInnerClassCounts() noexcept { return localInnerClassCounts_.Get(); }
    ULONG* HttpPack200ClassBands::LocalInnerClassOffsets() noexcept { return localInnerClassOffsets_.Get(); }
    NTSTATUS HttpPack200ClassBands::AllocateLocalInnerClasses(SIZE_T count) noexcept
    {
        localInnerClassIndexes_.Reset(); localInnerClassFlags_.Reset();
        localInnerClassOuterIndexes_.Reset(); localInnerClassNameIndexes_.Reset();
        NTSTATUS status = AllocateUlongBand(&localInnerClassIndexes_, count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localInnerClassFlags_, count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localInnerClassOuterIndexes_, count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localInnerClassNameIndexes_, count);
        return status;
    }
    ULONG* HttpPack200ClassBands::LocalInnerClassIndexes() noexcept { return localInnerClassIndexes_.Get(); }
    ULONG* HttpPack200ClassBands::LocalInnerClassFlags() noexcept { return localInnerClassFlags_.Get(); }
    ULONG* HttpPack200ClassBands::LocalInnerClassOuterIndexes() noexcept { return localInnerClassOuterIndexes_.Get(); }
    ULONG* HttpPack200ClassBands::LocalInnerClassNameIndexes() noexcept { return localInnerClassNameIndexes_.Get(); }

    NTSTATUS HttpPack200ClassBands::AllocateMemberBands(
        SIZE_T fieldCount,
        SIZE_T methodCount) noexcept
    {
        fieldDescriptorIndexes_.Reset();
        fieldFlagsLow_.Reset();
        fieldFlagsHigh_.Reset();
        fieldConstantValueIndexes_.Reset();
        fieldSignatureIndexes_.Reset();
        methodDescriptorIndexes_.Reset();
        methodFlagsLow_.Reset();
        methodFlagsHigh_.Reset();
        methodCodeIndexes_.Reset();
        methodExceptionCounts_.Reset();
        methodSignatureIndexes_.Reset();
        methodExceptionClassIndexes_.Reset();

        NTSTATUS status = AllocateUlongBand(&fieldDescriptorIndexes_, fieldCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&fieldFlagsLow_, fieldCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&fieldFlagsHigh_, fieldCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&fieldConstantValueIndexes_, fieldCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&fieldSignatureIndexes_, fieldCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodDescriptorIndexes_, methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodFlagsLow_, methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodFlagsHigh_, methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodExceptionCounts_, methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&methodSignatureIndexes_, methodCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AllocateUlongBand(&methodCodeIndexes_, methodCount);
    }

    SIZE_T HttpPack200ClassBands::ClassCount() const noexcept
    {
        return thisClassIndexes_.Count();
    }

    SIZE_T HttpPack200ClassBands::InterfaceIndexCount() const noexcept
    {
        return interfaceIndexes_.Count();
    }

    SIZE_T HttpPack200ClassBands::FieldMemberCount() const noexcept
    {
        return fieldDescriptorIndexes_.Count();
    }

    SIZE_T HttpPack200ClassBands::MethodMemberCount() const noexcept
    {
        return methodDescriptorIndexes_.Count();
    }

    ULONG* HttpPack200ClassBands::FieldDescriptorIndexes() noexcept
    {
        return fieldDescriptorIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::FieldDescriptorIndexes() const noexcept
    {
        return fieldDescriptorIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::FieldFlagsLow() noexcept
    {
        return fieldFlagsLow_.Get();
    }

    const ULONG* HttpPack200ClassBands::FieldFlagsLow() const noexcept
    {
        return fieldFlagsLow_.Get();
    }

    ULONG* HttpPack200ClassBands::FieldFlagsHigh() noexcept
    {
        return fieldFlagsHigh_.Get();
    }

    ULONG* HttpPack200ClassBands::FieldConstantValueIndexes() noexcept
    {
        return fieldConstantValueIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::FieldConstantValueIndexes() const noexcept
    {
        return fieldConstantValueIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::FieldSignatureIndexes() noexcept { return fieldSignatureIndexes_.Get(); }
    const ULONG* HttpPack200ClassBands::FieldSignatureIndexes() const noexcept { return fieldSignatureIndexes_.Get(); }

    ULONG* HttpPack200ClassBands::MethodDescriptorIndexes() noexcept
    {
        return methodDescriptorIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::MethodDescriptorIndexes() const noexcept
    {
        return methodDescriptorIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::MethodFlagsLow() noexcept
    {
        return methodFlagsLow_.Get();
    }

    const ULONG* HttpPack200ClassBands::MethodFlagsLow() const noexcept
    {
        return methodFlagsLow_.Get();
    }

    ULONG* HttpPack200ClassBands::MethodFlagsHigh() noexcept
    {
        return methodFlagsHigh_.Get();
    }

    ULONG* HttpPack200ClassBands::MethodExceptionCounts() noexcept
    {
        return methodExceptionCounts_.Get();
    }

    const ULONG* HttpPack200ClassBands::MethodExceptionCounts() const noexcept
    {
        return methodExceptionCounts_.Get();
    }

    ULONG* HttpPack200ClassBands::MethodSignatureIndexes() noexcept { return methodSignatureIndexes_.Get(); }
    const ULONG* HttpPack200ClassBands::MethodSignatureIndexes() const noexcept { return methodSignatureIndexes_.Get(); }

    NTSTATUS HttpPack200ClassBands::AllocateMethodExceptionIndexes(SIZE_T count) noexcept
    {
        return AllocateUlongBand(&methodExceptionClassIndexes_, count);
    }

    ULONG* HttpPack200ClassBands::MethodExceptionClassIndexes() noexcept
    {
        return methodExceptionClassIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::MethodExceptionClassIndexes() const noexcept
    {
        return methodExceptionClassIndexes_.Get();
    }

    SIZE_T HttpPack200ClassBands::MethodExceptionIndexCount() const noexcept
    {
        return methodExceptionClassIndexes_.Count();
    }

    NTSTATUS HttpPack200ClassBands::AllocateCodeBands(SIZE_T codeCount) noexcept
    {
        codeMaxStacks_.Reset();
        codeMaxNonArgumentLocals_.Reset();
        codeHandlerCounts_.Reset();
        codeFlagsLow_.Reset();
        codeFlagsHigh_.Reset();
        lineNumberCounts_.Reset();
        lineNumberOffsets_.Reset();
        localVariableCounts_.Reset();
        localVariableOffsets_.Reset();
        localVariableTypeCounts_.Reset();
        localVariableTypeOffsets_.Reset();
        NTSTATUS status = AllocateUlongBand(&codeMaxStacks_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&codeMaxNonArgumentLocals_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&codeHandlerCounts_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&codeFlagsLow_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&codeFlagsHigh_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&lineNumberCounts_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&lineNumberOffsets_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&localVariableCounts_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&localVariableOffsets_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&localVariableTypeCounts_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AllocateUlongBand(&localVariableTypeOffsets_, codeCount);
    }

    ULONG* HttpPack200ClassBands::MethodCodeIndexes() noexcept
    {
        return methodCodeIndexes_.Get();
    }

    const ULONG* HttpPack200ClassBands::MethodCodeIndexes() const noexcept
    {
        return methodCodeIndexes_.Get();
    }

    ULONG* HttpPack200ClassBands::CodeMaxStacks() noexcept
    {
        return codeMaxStacks_.Get();
    }

    const ULONG* HttpPack200ClassBands::CodeMaxStacks() const noexcept
    {
        return codeMaxStacks_.Get();
    }

    ULONG* HttpPack200ClassBands::CodeMaxNonArgumentLocals() noexcept
    {
        return codeMaxNonArgumentLocals_.Get();
    }

    const ULONG* HttpPack200ClassBands::CodeMaxNonArgumentLocals() const noexcept
    {
        return codeMaxNonArgumentLocals_.Get();
    }

    ULONG* HttpPack200ClassBands::CodeHandlerCounts() noexcept
    {
        return codeHandlerCounts_.Get();
    }

    ULONG* HttpPack200ClassBands::CodeFlagsLow() noexcept { return codeFlagsLow_.Get(); }
    const ULONG* HttpPack200ClassBands::CodeFlagsLow() const noexcept { return codeFlagsLow_.Get(); }
    ULONG* HttpPack200ClassBands::CodeFlagsHigh() noexcept { return codeFlagsHigh_.Get(); }

    ULONG* HttpPack200ClassBands::LineNumberCounts() noexcept { return lineNumberCounts_.Get(); }
    ULONG* HttpPack200ClassBands::LineNumberOffsets() noexcept { return lineNumberOffsets_.Get(); }
    NTSTATUS HttpPack200ClassBands::AllocateLineNumbers(SIZE_T count) noexcept
    {
        lineNumberBcis_.Reset();
        lineNumbers_.Reset();
        NTSTATUS status = AllocateUlongBand(&lineNumberBcis_, count);
        return NT_SUCCESS(status) ? AllocateUlongBand(&lineNumbers_, count) : status;
    }
    ULONG* HttpPack200ClassBands::LineNumberBcis() noexcept { return lineNumberBcis_.Get(); }
    ULONG* HttpPack200ClassBands::LineNumbers() noexcept { return lineNumbers_.Get(); }

    ULONG* HttpPack200ClassBands::LocalVariableCounts() noexcept { return localVariableCounts_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableOffsets() noexcept { return localVariableOffsets_.Get(); }
    NTSTATUS HttpPack200ClassBands::AllocateLocalVariables(SIZE_T count) noexcept
    {
        localVariableBcis_.Reset();
        localVariableSpans_.Reset();
        localVariableNameIndexes_.Reset();
        localVariableTypeIndexes_.Reset();
        localVariableSlots_.Reset();
        NTSTATUS status = AllocateUlongBand(&localVariableBcis_, count);
        if (NT_SUCCESS(status) && count != 0) status = localVariableSpans_.Allocate(count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localVariableNameIndexes_, count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localVariableTypeIndexes_, count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localVariableSlots_, count);
        return status;
    }
    ULONG* HttpPack200ClassBands::LocalVariableBcis() noexcept { return localVariableBcis_.Get(); }
    LONG* HttpPack200ClassBands::LocalVariableSpans() noexcept { return localVariableSpans_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableNameIndexes() noexcept { return localVariableNameIndexes_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableTypeIndexes() noexcept { return localVariableTypeIndexes_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableSlots() noexcept { return localVariableSlots_.Get(); }

    ULONG* HttpPack200ClassBands::LocalVariableTypeCounts() noexcept { return localVariableTypeCounts_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableTypeOffsets() noexcept { return localVariableTypeOffsets_.Get(); }
    NTSTATUS HttpPack200ClassBands::AllocateLocalVariableTypes(SIZE_T count) noexcept
    {
        localVariableTypeBcis_.Reset();
        localVariableTypeSpans_.Reset();
        localVariableTypeNameIndexes_.Reset();
        localVariableTypeSignatureIndexes_.Reset();
        localVariableTypeSlots_.Reset();
        NTSTATUS status = AllocateUlongBand(&localVariableTypeBcis_, count);
        if (NT_SUCCESS(status) && count != 0) status = localVariableTypeSpans_.Allocate(count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localVariableTypeNameIndexes_, count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localVariableTypeSignatureIndexes_, count);
        if (NT_SUCCESS(status)) status = AllocateUlongBand(&localVariableTypeSlots_, count);
        return status;
    }
    ULONG* HttpPack200ClassBands::LocalVariableTypeBcis() noexcept { return localVariableTypeBcis_.Get(); }
    LONG* HttpPack200ClassBands::LocalVariableTypeSpans() noexcept { return localVariableTypeSpans_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableTypeNameIndexes() noexcept { return localVariableTypeNameIndexes_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableTypeSignatureIndexes() noexcept { return localVariableTypeSignatureIndexes_.Get(); }
    ULONG* HttpPack200ClassBands::LocalVariableTypeSlots() noexcept { return localVariableTypeSlots_.Get(); }

    HttpPack200MetadataBands* HttpPack200ClassBands::ClassVisibleAnnotations() noexcept { return &classVisibleAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::ClassInvisibleAnnotations() noexcept { return &classInvisibleAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::FieldVisibleAnnotations() noexcept { return &fieldVisibleAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::FieldInvisibleAnnotations() noexcept { return &fieldInvisibleAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::MethodVisibleAnnotations() noexcept { return &methodVisibleAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::MethodInvisibleAnnotations() noexcept { return &methodInvisibleAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::MethodVisibleParameterAnnotations() noexcept { return &methodVisibleParameterAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::MethodInvisibleParameterAnnotations() noexcept { return &methodInvisibleParameterAnnotations_; }
    HttpPack200MetadataBands* HttpPack200ClassBands::MethodAnnotationDefaults() noexcept { return &methodAnnotationDefaults_; }

    SIZE_T HttpPack200ClassBands::CodeCount() const noexcept
    {
        return codeMaxStacks_.Count();
    }

    NTSTATUS HttpPack200ClassBands::AllocateHandlerBands(SIZE_T handlerCount) noexcept
    {
        handlerStartIndexes_.Reset();
        handlerEndOffsets_.Reset();
        handlerCatchOffsets_.Reset();
        handlerClassIndexes_.Reset();
        NTSTATUS status = AllocateUlongBand(&handlerStartIndexes_, handlerCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (handlerCount != 0) {
            status = handlerEndOffsets_.Allocate(handlerCount);
            if (NT_SUCCESS(status)) {
                status = handlerCatchOffsets_.Allocate(handlerCount);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return AllocateUlongBand(&handlerClassIndexes_, handlerCount);
    }

    ULONG* HttpPack200ClassBands::HandlerStartIndexes() noexcept
    {
        return handlerStartIndexes_.Get();
    }

    LONG* HttpPack200ClassBands::HandlerEndOffsets() noexcept
    {
        return handlerEndOffsets_.Get();
    }

    LONG* HttpPack200ClassBands::HandlerCatchOffsets() noexcept
    {
        return handlerCatchOffsets_.Get();
    }

    ULONG* HttpPack200ClassBands::HandlerClassIndexes() noexcept
    {
        return handlerClassIndexes_.Get();
    }

    SIZE_T HttpPack200ClassBands::HandlerCount() const noexcept
    {
        return handlerStartIndexes_.Count();
    }

    NTSTATUS HttpPack200CodeBands::Initialize(SIZE_T codeCount) noexcept
    {
        Reset();
        NTSTATUS status = AllocateUlongBand(&maxStacks_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&maxLocals_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&codeOffsets_, codeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AllocateUlongBand(&codeLengths_, codeCount);
    }

    void HttpPack200CodeBands::Reset() noexcept
    {
        maxStacks_.Reset();
        maxLocals_.Reset();
        codeOffsets_.Reset();
        codeLengths_.Reset();
        codeBytes_.Reset();
        relocations_.Reset();
        instructionMapOffsets_.Reset();
        instructionCounts_.Reset();
        instructionByteOffsets_.Reset();
        codeByteCount_ = 0;
    }

    ULONG* HttpPack200CodeBands::MaxStacks() noexcept
    {
        return maxStacks_.Get();
    }

    ULONG* HttpPack200CodeBands::MaxLocals() noexcept
    {
        return maxLocals_.Get();
    }

    NTSTATUS HttpPack200CodeBands::AllocateCodeBytes(SIZE_T capacity) noexcept
    {
        codeBytes_.Reset();
        codeByteCount_ = 0;
        if (capacity == 0) {
            return STATUS_SUCCESS;
        }
        return codeBytes_.Allocate(capacity);
    }

    ULONG* HttpPack200CodeBands::CodeOffsets() noexcept
    {
        return codeOffsets_.Get();
    }

    ULONG* HttpPack200CodeBands::CodeLengths() noexcept
    {
        return codeLengths_.Get();
    }

    UCHAR* HttpPack200CodeBands::CodeBytes() noexcept
    {
        return codeBytes_.Get();
    }

    void HttpPack200CodeBands::SetCodeByteCount(SIZE_T count) noexcept
    {
        codeByteCount_ = count <= codeBytes_.Count() ? count : codeBytes_.Count();
    }

    SIZE_T HttpPack200CodeBands::CodeCount() const noexcept
    {
        return codeOffsets_.Count();
    }

    bool HttpPack200CodeBands::GetCode(
        SIZE_T index,
        const UCHAR** code,
        SIZE_T* length) const noexcept
    {
        if (code == nullptr || length == nullptr || index >= CodeCount()) {
            return false;
        }
        const SIZE_T offset = codeOffsets_[index];
        const SIZE_T codeLength = codeLengths_[index];
        if (offset > codeByteCount_ || codeLength > codeByteCount_ - offset) {
            return false;
        }
        *code = codeLength == 0 ? nullptr : codeBytes_.Get() + offset;
        *length = codeLength;
        return true;
    }

    NTSTATUS HttpPack200CodeBands::AllocateRelocations(SIZE_T count) noexcept
    {
        relocations_.Reset();
        if (count == 0) {
            return STATUS_SUCCESS;
        }
        return relocations_.Allocate(count);
    }

    HttpPack200CodeRelocation* HttpPack200CodeBands::Relocations() noexcept
    {
        return relocations_.Get();
    }

    const HttpPack200CodeRelocation* HttpPack200CodeBands::Relocations() const noexcept
    {
        return relocations_.Get();
    }

    SIZE_T HttpPack200CodeBands::RelocationCount() const noexcept
    {
        return relocations_.Count();
    }

    NTSTATUS HttpPack200CodeBands::AllocateInstructionMap(SIZE_T instructionOffsetCount) noexcept
    {
        instructionMapOffsets_.Reset();
        instructionCounts_.Reset();
        instructionByteOffsets_.Reset();
        NTSTATUS status = AllocateUlongBand(&instructionMapOffsets_, CodeCount());
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AllocateUlongBand(&instructionCounts_, CodeCount());
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AllocateUlongBand(&instructionByteOffsets_, instructionOffsetCount);
    }

    ULONG* HttpPack200CodeBands::InstructionMapOffsets() noexcept
    {
        return instructionMapOffsets_.Get();
    }

    ULONG* HttpPack200CodeBands::InstructionCounts() noexcept
    {
        return instructionCounts_.Get();
    }

    ULONG* HttpPack200CodeBands::InstructionByteOffsets() noexcept
    {
        return instructionByteOffsets_.Get();
    }

    bool HttpPack200CodeBands::GetInstructionOffset(
        SIZE_T codeIndex,
        SIZE_T instructionIndex,
        ULONG* byteOffset) const noexcept
    {
        if (byteOffset == nullptr || codeIndex >= CodeCount() ||
            instructionIndex > instructionCounts_[codeIndex]) {
            return false;
        }
        const SIZE_T mapOffset = instructionMapOffsets_[codeIndex];
        if (mapOffset >= instructionByteOffsets_.Count() ||
            instructionIndex >= instructionByteOffsets_.Count() - mapOffset) {
            return false;
        }
        *byteOffset = instructionByteOffsets_[mapOffset + instructionIndex];
        return true;
    }

    NTSTATUS HttpPack200AttributeBands::Initialize(SIZE_T attributeLayoutCount) noexcept
    {
        Reset();
        return AllocateUlongBand(&layoutNameIndexes_, attributeLayoutCount);
    }

    void HttpPack200AttributeBands::Reset() noexcept
    {
        layoutNameIndexes_.Reset();
    }

    ULONG* HttpPack200AttributeBands::LayoutNameIndexes() noexcept
    {
        return layoutNameIndexes_.Get();
    }

    NTSTATUS HttpPack200AttributeDefinitionBands::Initialize(SIZE_T definitionCount) noexcept
    {
        Reset();
        NTSTATUS status = AllocateUlongBand(&headers_, definitionCount);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&nameIndexes_, definitionCount);
        if (!NT_SUCCESS(status)) return status;
        status = AllocateUlongBand(&layoutIndexes_, definitionCount);
        if (!NT_SUCCESS(status)) return status;
        return AllocateUlongBand(&indexes_, definitionCount);
    }

    void HttpPack200AttributeDefinitionBands::Reset() noexcept
    {
        headers_.Reset();
        nameIndexes_.Reset();
        layoutIndexes_.Reset();
        indexes_.Reset();
    }

    ULONG* HttpPack200AttributeDefinitionBands::Headers() noexcept { return headers_.Get(); }
    const ULONG* HttpPack200AttributeDefinitionBands::Headers() const noexcept { return headers_.Get(); }
    ULONG* HttpPack200AttributeDefinitionBands::NameIndexes() noexcept { return nameIndexes_.Get(); }
    const ULONG* HttpPack200AttributeDefinitionBands::NameIndexes() const noexcept { return nameIndexes_.Get(); }
    ULONG* HttpPack200AttributeDefinitionBands::LayoutIndexes() noexcept { return layoutIndexes_.Get(); }
    const ULONG* HttpPack200AttributeDefinitionBands::LayoutIndexes() const noexcept { return layoutIndexes_.Get(); }
    ULONG* HttpPack200AttributeDefinitionBands::Indexes() noexcept { return indexes_.Get(); }
    const ULONG* HttpPack200AttributeDefinitionBands::Indexes() const noexcept { return indexes_.Get(); }
    SIZE_T HttpPack200AttributeDefinitionBands::Count() const noexcept { return headers_.Count(); }

    NTSTATUS HttpPack200AttributeDefinitionBands::ResolveIndexes(bool haveClassFlagsHigh) noexcept
    {
        ULONG overflowIndex = haveClassFlagsHigh ? 63UL : 32UL;
        for (SIZE_T definitionIndex = 0; definitionIndex < Count(); ++definitionIndex) {
            const ULONG encodedIndex = Headers()[definitionIndex] >> 2;
            if (encodedIndex == 0) {
                if (overflowIndex == 0xffffffffUL) return STATUS_INTEGER_OVERFLOW;
                Indexes()[definitionIndex] = overflowIndex++;
            }
            else {
                Indexes()[definitionIndex] = encodedIndex - 1;
            }
            for (SIZE_T prior = 0; prior < definitionIndex; ++prior) {
                if ((Headers()[prior] & 0x03UL) == (Headers()[definitionIndex] & 0x03UL) &&
                    Indexes()[prior] == Indexes()[definitionIndex]) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
            }
        }
        return STATUS_SUCCESS;
    }

    bool HttpPack200AttributeDefinitionBands::Find(
        SIZE_T context,
        SIZE_T index,
        SIZE_T* definitionIndex) const noexcept
    {
        if (definitionIndex == nullptr || context > 3) return false;
        for (SIZE_T candidate = 0; candidate < Count(); ++candidate) {
            if ((Headers()[candidate] & 0x03UL) == context && Indexes()[candidate] == index) {
                *definitionIndex = candidate;
                return true;
            }
        }
        return false;
    }

    NTSTATUS HttpPack200InnerClassBands::Initialize(SIZE_T innerClassCount) noexcept
    {
        Reset();
        NTSTATUS status = AllocateUlongBand(&thisClassIndexes_, innerClassCount);
        if (!NT_SUCCESS(status)) return status;
        return AllocateUlongBand(&flags_, innerClassCount);
    }

    void HttpPack200InnerClassBands::Reset() noexcept
    {
        thisClassIndexes_.Reset();
        flags_.Reset();
        outerClassIndexes_.Reset();
        nameIndexes_.Reset();
    }

    ULONG* HttpPack200InnerClassBands::ThisClassIndexes() noexcept { return thisClassIndexes_.Get(); }
    const ULONG* HttpPack200InnerClassBands::ThisClassIndexes() const noexcept { return thisClassIndexes_.Get(); }
    ULONG* HttpPack200InnerClassBands::Flags() noexcept { return flags_.Get(); }
    const ULONG* HttpPack200InnerClassBands::Flags() const noexcept { return flags_.Get(); }
    ULONG* HttpPack200InnerClassBands::OuterClassIndexes() noexcept { return outerClassIndexes_.Get(); }
    const ULONG* HttpPack200InnerClassBands::OuterClassIndexes() const noexcept { return outerClassIndexes_.Get(); }
    ULONG* HttpPack200InnerClassBands::NameIndexes() noexcept { return nameIndexes_.Get(); }
    const ULONG* HttpPack200InnerClassBands::NameIndexes() const noexcept { return nameIndexes_.Get(); }

    NTSTATUS HttpPack200InnerClassBands::AllocateExplicitBands(SIZE_T explicitCount) noexcept
    {
        outerClassIndexes_.Reset();
        nameIndexes_.Reset();
        NTSTATUS status = AllocateUlongBand(&outerClassIndexes_, explicitCount);
        if (!NT_SUCCESS(status)) return status;
        return AllocateUlongBand(&nameIndexes_, explicitCount);
    }

    SIZE_T HttpPack200InnerClassBands::Count() const noexcept { return thisClassIndexes_.Count(); }
    SIZE_T HttpPack200InnerClassBands::ExplicitCount() const noexcept { return outerClassIndexes_.Count(); }
}
}
