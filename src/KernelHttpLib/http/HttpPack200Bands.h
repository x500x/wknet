#pragma once

#include <KernelHttp/http/HttpTypes.h>
#include "HttpXmlWriter.h"

namespace KernelHttp
{
namespace http
{
    struct HttpPack200CpCounts final
    {
        ULONG Utf8 = 0;
        ULONG Int = 0;
        ULONG Float = 0;
        ULONG Long = 0;
        ULONG Double = 0;
        ULONG String = 0;
        ULONG Class = 0;
        ULONG Signature = 0;
        ULONG Descriptor = 0;
        ULONG Field = 0;
        ULONG Method = 0;
        ULONG InterfaceMethod = 0;
        ULONG MethodHandle = 0;
        ULONG MethodType = 0;
        ULONG BootstrapMethod = 0;
        ULONG InvokeDynamic = 0;
    };

    class HttpPack200CpBands final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(const HttpPack200CpCounts& counts) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        SIZE_T Utf8Count() const noexcept;

        _Must_inspect_result_
        SIZE_T ClassCount() const noexcept;

        _Must_inspect_result_
        SIZE_T IntCount() const noexcept;

        _Must_inspect_result_
        SIZE_T FloatCount() const noexcept;

        _Must_inspect_result_
        SIZE_T LongCount() const noexcept;

        _Must_inspect_result_
        SIZE_T DoubleCount() const noexcept;

        _Must_inspect_result_
        SIZE_T SignatureCount() const noexcept;

        _Must_inspect_result_
        SIZE_T DescriptorCount() const noexcept;

        _Must_inspect_result_
        SIZE_T MethodCount() const noexcept;

        _Must_inspect_result_
        SIZE_T StringCount() const noexcept;

        _Must_inspect_result_
        SIZE_T FieldCount() const noexcept;

        _Must_inspect_result_
        SIZE_T InterfaceMethodCount() const noexcept;

        _Must_inspect_result_
        SIZE_T MethodHandleCount() const noexcept;

        _Must_inspect_result_
        SIZE_T MethodTypeCount() const noexcept;

        _Must_inspect_result_
        SIZE_T BootstrapMethodCount() const noexcept;

        _Must_inspect_result_
        SIZE_T InvokeDynamicCount() const noexcept;

        _Ret_maybenull_
        ULONG* Utf8SuffixLengths() noexcept;

        _Ret_maybenull_
        ULONG* Utf8CharOffsets() noexcept;

        _Ret_maybenull_
        ULONG* Utf8ByteLengths() noexcept;

        _Ret_maybenull_
        char* Utf8Chars() noexcept;

        _Must_inspect_result_
        SIZE_T Utf8CharCount() const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateUtf8Chars(SIZE_T charCount) noexcept;

        _Ret_maybenull_
        ULONG* Utf16CharOffsets() noexcept;

        _Ret_maybenull_
        ULONG* Utf16CharLengths() noexcept;

        _Ret_maybenull_
        USHORT* Utf16Chars() noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateUtf16Chars(SIZE_T charCount) noexcept;

        _Must_inspect_result_
        bool GetUtf8(SIZE_T index, _Out_ HttpXmlText* value) const noexcept;

        _Ret_maybenull_
        ULONG* ClassNameIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* ClassNameIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* IntBits() noexcept;

        _Ret_maybenull_
        const ULONG* IntBits() const noexcept;

        _Ret_maybenull_
        ULONG* FloatBits() noexcept;

        _Ret_maybenull_
        const ULONG* FloatBits() const noexcept;

        _Ret_maybenull_
        ULONG* LongHighBits() noexcept;

        _Ret_maybenull_
        const ULONG* LongHighBits() const noexcept;

        _Ret_maybenull_
        ULONG* LongLowBits() noexcept;

        _Ret_maybenull_
        const ULONG* LongLowBits() const noexcept;

        _Ret_maybenull_
        ULONG* DoubleHighBits() noexcept;

        _Ret_maybenull_
        const ULONG* DoubleHighBits() const noexcept;

        _Ret_maybenull_
        ULONG* DoubleLowBits() noexcept;

        _Ret_maybenull_
        const ULONG* DoubleLowBits() const noexcept;

        _Ret_maybenull_
        ULONG* StringUtf8Indexes() noexcept;

        _Ret_maybenull_
        const ULONG* StringUtf8Indexes() const noexcept;

        _Ret_maybenull_
        ULONG* SignatureFormIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* SignatureFormIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* SignatureClassIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* SignatureClassIndexes() const noexcept;

        _Must_inspect_result_
        SIZE_T SignatureClassIndexCount() const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateSignatureClassIndexes(SIZE_T count) noexcept;

        _Ret_maybenull_
        ULONG* DescriptorNameIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* DescriptorNameIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* DescriptorTypeIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* DescriptorTypeIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* FieldClassIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* FieldClassIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* FieldDescriptorIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* FieldDescriptorIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* MethodClassIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* MethodClassIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* MethodDescriptorIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* MethodDescriptorIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* InterfaceMethodClassIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* InterfaceMethodClassIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* InterfaceMethodDescriptorIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* InterfaceMethodDescriptorIndexes() const noexcept;

        _Ret_maybenull_ ULONG* MethodHandleReferenceKinds() noexcept;
        _Ret_maybenull_ const ULONG* MethodHandleReferenceKinds() const noexcept;
        _Ret_maybenull_ ULONG* MethodHandleMemberIndexes() noexcept;
        _Ret_maybenull_ const ULONG* MethodHandleMemberIndexes() const noexcept;
        _Ret_maybenull_ ULONG* MethodTypeSignatureIndexes() noexcept;
        _Ret_maybenull_ const ULONG* MethodTypeSignatureIndexes() const noexcept;
        _Ret_maybenull_ ULONG* BootstrapMethodReferenceIndexes() noexcept;
        _Ret_maybenull_ const ULONG* BootstrapMethodReferenceIndexes() const noexcept;
        _Ret_maybenull_ ULONG* BootstrapMethodArgumentCounts() noexcept;
        _Ret_maybenull_ const ULONG* BootstrapMethodArgumentCounts() const noexcept;
        _Ret_maybenull_ ULONG* BootstrapMethodArgumentIndexes() noexcept;
        _Ret_maybenull_ const ULONG* BootstrapMethodArgumentIndexes() const noexcept;
        _Must_inspect_result_ NTSTATUS AllocateBootstrapMethodArgumentIndexes(SIZE_T count) noexcept;
        _Ret_maybenull_ ULONG* InvokeDynamicBootstrapIndexes() noexcept;
        _Ret_maybenull_ const ULONG* InvokeDynamicBootstrapIndexes() const noexcept;
        _Ret_maybenull_ ULONG* InvokeDynamicDescriptorIndexes() noexcept;
        _Ret_maybenull_ const ULONG* InvokeDynamicDescriptorIndexes() const noexcept;

    private:
        HeapArray<ULONG> utf8SuffixLengths_ = {};
        HeapArray<ULONG> utf8CharOffsets_ = {};
        HeapArray<ULONG> utf8ByteLengths_ = {};
        HeapArray<char> utf8Chars_ = {};
        HeapArray<ULONG> utf16CharOffsets_ = {};
        HeapArray<ULONG> utf16CharLengths_ = {};
        HeapArray<USHORT> utf16Chars_ = {};
        HeapArray<ULONG> intBits_ = {};
        HeapArray<ULONG> floatBits_ = {};
        HeapArray<ULONG> longHighBits_ = {};
        HeapArray<ULONG> longLowBits_ = {};
        HeapArray<ULONG> doubleHighBits_ = {};
        HeapArray<ULONG> doubleLowBits_ = {};
        HeapArray<ULONG> stringUtf8Indexes_ = {};
        HeapArray<ULONG> classNameIndexes_ = {};
        HeapArray<ULONG> signatureFormIndexes_ = {};
        HeapArray<ULONG> signatureClassIndexes_ = {};
        HeapArray<ULONG> descriptorNameIndexes_ = {};
        HeapArray<ULONG> descriptorTypeIndexes_ = {};
        HeapArray<ULONG> fieldClassIndexes_ = {};
        HeapArray<ULONG> fieldDescriptorIndexes_ = {};
        HeapArray<ULONG> methodClassIndexes_ = {};
        HeapArray<ULONG> methodDescriptorIndexes_ = {};
        HeapArray<ULONG> interfaceMethodClassIndexes_ = {};
        HeapArray<ULONG> interfaceMethodDescriptorIndexes_ = {};
        HeapArray<ULONG> methodHandleReferenceKinds_ = {};
        HeapArray<ULONG> methodHandleMemberIndexes_ = {};
        HeapArray<ULONG> methodTypeSignatureIndexes_ = {};
        HeapArray<ULONG> bootstrapMethodReferenceIndexes_ = {};
        HeapArray<ULONG> bootstrapMethodArgumentCounts_ = {};
        HeapArray<ULONG> bootstrapMethodArgumentIndexes_ = {};
        HeapArray<ULONG> invokeDynamicBootstrapIndexes_ = {};
        HeapArray<ULONG> invokeDynamicDescriptorIndexes_ = {};
    };

    class HttpPack200FileBands final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T fileCount) noexcept;

        void Reset() noexcept;

        _Ret_maybenull_
        ULONG* NameIndexes() noexcept;

        _Ret_maybenull_
        ULONG* SizesLow() noexcept;

        _Ret_maybenull_
        ULONG* SizesHigh() noexcept;

        _Ret_maybenull_
        LONG* Modtimes() noexcept;

        _Ret_maybenull_
        ULONG* Options() noexcept;

    private:
        HeapArray<ULONG> nameIndexes_ = {};
        HeapArray<ULONG> sizesLow_ = {};
        HeapArray<ULONG> sizesHigh_ = {};
        HeapArray<LONG> modtimes_ = {};
        HeapArray<ULONG> options_ = {};
    };

    struct HttpPack200MetadataBands final
    {
        void Reset() noexcept
        {
            ParamCounts.Reset(); AnnotationCounts.Reset(); TypeIndexes.Reset(); PairCounts.Reset();
            NameIndexes.Reset(); Tags.Reset(); IntegerIndexes.Reset(); DoubleIndexes.Reset();
            FloatIndexes.Reset(); LongIndexes.Reset(); ClassSignatureIndexes.Reset();
            EnumTypeIndexes.Reset(); EnumNameIndexes.Reset(); StringIndexes.Reset();
            ArrayCounts.Reset(); NestedTypeIndexes.Reset(); NestedPairCounts.Reset();
            NestedNameIndexes.Reset(); OccurrenceCount = 0;
        }

        SIZE_T OccurrenceCount = 0;
        HeapArray<ULONG> ParamCounts = {};
        HeapArray<ULONG> AnnotationCounts = {};
        HeapArray<ULONG> TypeIndexes = {};
        HeapArray<ULONG> PairCounts = {};
        HeapArray<ULONG> NameIndexes = {};
        HeapArray<ULONG> Tags = {};
        HeapArray<ULONG> IntegerIndexes = {};
        HeapArray<ULONG> DoubleIndexes = {};
        HeapArray<ULONG> FloatIndexes = {};
        HeapArray<ULONG> LongIndexes = {};
        HeapArray<ULONG> ClassSignatureIndexes = {};
        HeapArray<ULONG> EnumTypeIndexes = {};
        HeapArray<ULONG> EnumNameIndexes = {};
        HeapArray<ULONG> StringIndexes = {};
        HeapArray<ULONG> ArrayCounts = {};
        HeapArray<ULONG> NestedTypeIndexes = {};
        HeapArray<ULONG> NestedPairCounts = {};
        HeapArray<ULONG> NestedNameIndexes = {};
    };

    class HttpPack200ClassBands final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T classCount) noexcept;

        void Reset() noexcept;

        _Ret_maybenull_
        ULONG* ThisClassIndexes() noexcept;

        _Ret_maybenull_
        ULONG* SuperClassIndexes() noexcept;

        _Ret_maybenull_
        ULONG* InterfaceCounts() noexcept;

        _Ret_maybenull_
        ULONG* InterfaceIndexes() noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateInterfaceIndexes(SIZE_T count) noexcept;

        _Ret_maybenull_
        ULONG* FieldCounts() noexcept;

        _Ret_maybenull_
        ULONG* MethodCounts() noexcept;

        _Ret_maybenull_
        ULONG* FlagsLow() noexcept;

        _Ret_maybenull_
        ULONG* FlagsHigh() noexcept;

        _Ret_maybenull_
        ULONG* SourceFileIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* SourceFileIndexes() const noexcept;

        _Ret_maybenull_ ULONG* EnclosingMethodClassIndexes() noexcept;
        _Ret_maybenull_ const ULONG* EnclosingMethodClassIndexes() const noexcept;
        _Ret_maybenull_ ULONG* EnclosingMethodDescriptorIndexes() noexcept;
        _Ret_maybenull_ const ULONG* EnclosingMethodDescriptorIndexes() const noexcept;

        _Ret_maybenull_ ULONG* ClassSignatureIndexes() noexcept;
        _Ret_maybenull_ const ULONG* ClassSignatureIndexes() const noexcept;
        _Ret_maybenull_ ULONG* ClassMinorVersions() noexcept;
        _Ret_maybenull_ const ULONG* ClassMinorVersions() const noexcept;
        _Ret_maybenull_ ULONG* ClassMajorVersions() noexcept;
        _Ret_maybenull_ const ULONG* ClassMajorVersions() const noexcept;
        _Ret_maybenull_ ULONG* LocalInnerClassCounts() noexcept;
        _Ret_maybenull_ ULONG* LocalInnerClassOffsets() noexcept;
        _Must_inspect_result_ NTSTATUS AllocateLocalInnerClasses(SIZE_T count) noexcept;
        _Ret_maybenull_ ULONG* LocalInnerClassIndexes() noexcept;
        _Ret_maybenull_ ULONG* LocalInnerClassFlags() noexcept;
        _Ret_maybenull_ ULONG* LocalInnerClassOuterIndexes() noexcept;
        _Ret_maybenull_ ULONG* LocalInnerClassNameIndexes() noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateMemberBands(SIZE_T fieldCount, SIZE_T methodCount) noexcept;

        _Must_inspect_result_
        SIZE_T ClassCount() const noexcept;

        _Must_inspect_result_
        SIZE_T InterfaceIndexCount() const noexcept;

        _Must_inspect_result_
        SIZE_T FieldMemberCount() const noexcept;

        _Must_inspect_result_
        SIZE_T MethodMemberCount() const noexcept;

        _Ret_maybenull_
        ULONG* FieldDescriptorIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* FieldDescriptorIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* FieldFlagsLow() noexcept;

        _Ret_maybenull_
        const ULONG* FieldFlagsLow() const noexcept;

        _Ret_maybenull_
        ULONG* FieldFlagsHigh() noexcept;

        _Ret_maybenull_
        ULONG* FieldConstantValueIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* FieldConstantValueIndexes() const noexcept;

        _Ret_maybenull_ ULONG* FieldSignatureIndexes() noexcept;
        _Ret_maybenull_ const ULONG* FieldSignatureIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* MethodDescriptorIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* MethodDescriptorIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* MethodFlagsLow() noexcept;

        _Ret_maybenull_
        const ULONG* MethodFlagsLow() const noexcept;

        _Ret_maybenull_
        ULONG* MethodFlagsHigh() noexcept;

        _Ret_maybenull_
        ULONG* MethodExceptionCounts() noexcept;

        _Ret_maybenull_
        const ULONG* MethodExceptionCounts() const noexcept;

        _Ret_maybenull_ ULONG* MethodSignatureIndexes() noexcept;
        _Ret_maybenull_ const ULONG* MethodSignatureIndexes() const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateMethodExceptionIndexes(SIZE_T count) noexcept;

        _Ret_maybenull_
        ULONG* MethodExceptionClassIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* MethodExceptionClassIndexes() const noexcept;

        _Must_inspect_result_
        SIZE_T MethodExceptionIndexCount() const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateCodeBands(SIZE_T codeCount) noexcept;

        _Ret_maybenull_
        ULONG* MethodCodeIndexes() noexcept;

        _Ret_maybenull_
        const ULONG* MethodCodeIndexes() const noexcept;

        _Ret_maybenull_
        ULONG* CodeMaxStacks() noexcept;

        _Ret_maybenull_
        const ULONG* CodeMaxStacks() const noexcept;

        _Ret_maybenull_
        ULONG* CodeMaxNonArgumentLocals() noexcept;

        _Ret_maybenull_
        const ULONG* CodeMaxNonArgumentLocals() const noexcept;

        _Ret_maybenull_
        ULONG* CodeHandlerCounts() noexcept;

        _Ret_maybenull_ ULONG* CodeFlagsLow() noexcept;
        _Ret_maybenull_ const ULONG* CodeFlagsLow() const noexcept;
        _Ret_maybenull_ ULONG* CodeFlagsHigh() noexcept;

        _Ret_maybenull_ ULONG* LineNumberCounts() noexcept;
        _Ret_maybenull_ ULONG* LineNumberOffsets() noexcept;
        _Must_inspect_result_ NTSTATUS AllocateLineNumbers(SIZE_T count) noexcept;
        _Ret_maybenull_ ULONG* LineNumberBcis() noexcept;
        _Ret_maybenull_ ULONG* LineNumbers() noexcept;

        _Ret_maybenull_ ULONG* LocalVariableCounts() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableOffsets() noexcept;
        _Must_inspect_result_ NTSTATUS AllocateLocalVariables(SIZE_T count) noexcept;
        _Ret_maybenull_ ULONG* LocalVariableBcis() noexcept;
        _Ret_maybenull_ LONG* LocalVariableSpans() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableNameIndexes() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableTypeIndexes() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableSlots() noexcept;

        _Ret_maybenull_ ULONG* LocalVariableTypeCounts() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableTypeOffsets() noexcept;
        _Must_inspect_result_ NTSTATUS AllocateLocalVariableTypes(SIZE_T count) noexcept;
        _Ret_maybenull_ ULONG* LocalVariableTypeBcis() noexcept;
        _Ret_maybenull_ LONG* LocalVariableTypeSpans() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableTypeNameIndexes() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableTypeSignatureIndexes() noexcept;
        _Ret_maybenull_ ULONG* LocalVariableTypeSlots() noexcept;

        HttpPack200MetadataBands* ClassVisibleAnnotations() noexcept;
        HttpPack200MetadataBands* ClassInvisibleAnnotations() noexcept;
        HttpPack200MetadataBands* FieldVisibleAnnotations() noexcept;
        HttpPack200MetadataBands* FieldInvisibleAnnotations() noexcept;
        HttpPack200MetadataBands* MethodVisibleAnnotations() noexcept;
        HttpPack200MetadataBands* MethodInvisibleAnnotations() noexcept;
        HttpPack200MetadataBands* MethodVisibleParameterAnnotations() noexcept;
        HttpPack200MetadataBands* MethodInvisibleParameterAnnotations() noexcept;
        HttpPack200MetadataBands* MethodAnnotationDefaults() noexcept;

        _Must_inspect_result_
        SIZE_T CodeCount() const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateHandlerBands(SIZE_T handlerCount) noexcept;

        _Ret_maybenull_
        ULONG* HandlerStartIndexes() noexcept;

        _Ret_maybenull_
        LONG* HandlerEndOffsets() noexcept;

        _Ret_maybenull_
        LONG* HandlerCatchOffsets() noexcept;

        _Ret_maybenull_
        ULONG* HandlerClassIndexes() noexcept;

        _Must_inspect_result_
        SIZE_T HandlerCount() const noexcept;

    private:
        HeapArray<ULONG> thisClassIndexes_ = {};
        HeapArray<ULONG> superClassIndexes_ = {};
        HeapArray<ULONG> interfaceCounts_ = {};
        HeapArray<ULONG> interfaceIndexes_ = {};
        HeapArray<ULONG> fieldCounts_ = {};
        HeapArray<ULONG> methodCounts_ = {};
        HeapArray<ULONG> flagsLow_ = {};
        HeapArray<ULONG> flagsHigh_ = {};
        HeapArray<ULONG> sourceFileIndexes_ = {};
        HeapArray<ULONG> enclosingMethodClassIndexes_ = {};
        HeapArray<ULONG> enclosingMethodDescriptorIndexes_ = {};
        HeapArray<ULONG> classSignatureIndexes_ = {};
        HeapArray<ULONG> classMinorVersions_ = {};
        HeapArray<ULONG> classMajorVersions_ = {};
        HeapArray<ULONG> localInnerClassCounts_ = {};
        HeapArray<ULONG> localInnerClassOffsets_ = {};
        HeapArray<ULONG> localInnerClassIndexes_ = {};
        HeapArray<ULONG> localInnerClassFlags_ = {};
        HeapArray<ULONG> localInnerClassOuterIndexes_ = {};
        HeapArray<ULONG> localInnerClassNameIndexes_ = {};
        HeapArray<ULONG> fieldDescriptorIndexes_ = {};
        HeapArray<ULONG> fieldFlagsLow_ = {};
        HeapArray<ULONG> fieldFlagsHigh_ = {};
        HeapArray<ULONG> fieldConstantValueIndexes_ = {};
        HeapArray<ULONG> fieldSignatureIndexes_ = {};
        HeapArray<ULONG> methodDescriptorIndexes_ = {};
        HeapArray<ULONG> methodFlagsLow_ = {};
        HeapArray<ULONG> methodFlagsHigh_ = {};
        HeapArray<ULONG> methodExceptionCounts_ = {};
        HeapArray<ULONG> methodSignatureIndexes_ = {};
        HeapArray<ULONG> methodExceptionClassIndexes_ = {};
        HeapArray<ULONG> methodCodeIndexes_ = {};
        HeapArray<ULONG> codeMaxStacks_ = {};
        HeapArray<ULONG> codeMaxNonArgumentLocals_ = {};
        HeapArray<ULONG> codeHandlerCounts_ = {};
        HeapArray<ULONG> codeFlagsLow_ = {};
        HeapArray<ULONG> codeFlagsHigh_ = {};
        HeapArray<ULONG> lineNumberCounts_ = {};
        HeapArray<ULONG> lineNumberOffsets_ = {};
        HeapArray<ULONG> lineNumberBcis_ = {};
        HeapArray<ULONG> lineNumbers_ = {};
        HeapArray<ULONG> localVariableCounts_ = {};
        HeapArray<ULONG> localVariableOffsets_ = {};
        HeapArray<ULONG> localVariableBcis_ = {};
        HeapArray<LONG> localVariableSpans_ = {};
        HeapArray<ULONG> localVariableNameIndexes_ = {};
        HeapArray<ULONG> localVariableTypeIndexes_ = {};
        HeapArray<ULONG> localVariableSlots_ = {};
        HeapArray<ULONG> localVariableTypeCounts_ = {};
        HeapArray<ULONG> localVariableTypeOffsets_ = {};
        HeapArray<ULONG> localVariableTypeBcis_ = {};
        HeapArray<LONG> localVariableTypeSpans_ = {};
        HeapArray<ULONG> localVariableTypeNameIndexes_ = {};
        HeapArray<ULONG> localVariableTypeSignatureIndexes_ = {};
        HeapArray<ULONG> localVariableTypeSlots_ = {};
        HttpPack200MetadataBands classVisibleAnnotations_ = {};
        HttpPack200MetadataBands classInvisibleAnnotations_ = {};
        HttpPack200MetadataBands fieldVisibleAnnotations_ = {};
        HttpPack200MetadataBands fieldInvisibleAnnotations_ = {};
        HttpPack200MetadataBands methodVisibleAnnotations_ = {};
        HttpPack200MetadataBands methodInvisibleAnnotations_ = {};
        HttpPack200MetadataBands methodVisibleParameterAnnotations_ = {};
        HttpPack200MetadataBands methodInvisibleParameterAnnotations_ = {};
        HttpPack200MetadataBands methodAnnotationDefaults_ = {};
        HeapArray<ULONG> handlerStartIndexes_ = {};
        HeapArray<LONG> handlerEndOffsets_ = {};
        HeapArray<LONG> handlerCatchOffsets_ = {};
        HeapArray<ULONG> handlerClassIndexes_ = {};
    };

    enum class HttpPack200RelocationKind : UCHAR
    {
        InitThis,
        InitSuper,
        MethodThis,
        MethodSuper,
        Class,
        String,
        Integer,
        Float,
        Long,
        Double,
        LoadableValue,
        MethodHandle,
        MethodType,
        Field,
        Method,
        InterfaceMethod,
        InvokeDynamic
    };

    struct HttpPack200CodeRelocation final
    {
        ULONG CodeIndex = 0;
        ULONG OperandOffset = 0;
        ULONG ReferenceIndex = 0;
        HttpPack200RelocationKind Kind = HttpPack200RelocationKind::InitThis;
        UCHAR OperandWidth = 2;
    };

    class HttpPack200CodeBands final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T codeCount) noexcept;

        void Reset() noexcept;

        _Ret_maybenull_
        ULONG* MaxStacks() noexcept;

        _Ret_maybenull_
        ULONG* MaxLocals() noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateCodeBytes(SIZE_T capacity) noexcept;

        _Ret_maybenull_
        ULONG* CodeOffsets() noexcept;

        _Ret_maybenull_
        ULONG* CodeLengths() noexcept;

        _Ret_maybenull_
        UCHAR* CodeBytes() noexcept;

        void SetCodeByteCount(SIZE_T count) noexcept;

        _Must_inspect_result_
        SIZE_T CodeCount() const noexcept;

        _Must_inspect_result_
        bool GetCode(SIZE_T index, _Out_ const UCHAR** code, _Out_ SIZE_T* length) const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateRelocations(SIZE_T count) noexcept;

        _Ret_maybenull_
        HttpPack200CodeRelocation* Relocations() noexcept;

        _Ret_maybenull_
        const HttpPack200CodeRelocation* Relocations() const noexcept;

        _Must_inspect_result_
        SIZE_T RelocationCount() const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateInstructionMap(SIZE_T instructionOffsetCount) noexcept;

        _Ret_maybenull_
        ULONG* InstructionMapOffsets() noexcept;

        _Ret_maybenull_
        ULONG* InstructionCounts() noexcept;

        _Ret_maybenull_
        ULONG* InstructionByteOffsets() noexcept;

        _Must_inspect_result_
        bool GetInstructionOffset(
            SIZE_T codeIndex,
            SIZE_T instructionIndex,
            _Out_ ULONG* byteOffset) const noexcept;

    private:
        HeapArray<ULONG> maxStacks_ = {};
        HeapArray<ULONG> maxLocals_ = {};
        HeapArray<ULONG> codeOffsets_ = {};
        HeapArray<ULONG> codeLengths_ = {};
        HeapArray<UCHAR> codeBytes_ = {};
        HeapArray<HttpPack200CodeRelocation> relocations_ = {};
        HeapArray<ULONG> instructionMapOffsets_ = {};
        HeapArray<ULONG> instructionCounts_ = {};
        HeapArray<ULONG> instructionByteOffsets_ = {};
        SIZE_T codeByteCount_ = 0;
    };

    class HttpPack200AttributeBands final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T attributeLayoutCount) noexcept;

        void Reset() noexcept;

        _Ret_maybenull_
        ULONG* LayoutNameIndexes() noexcept;

    private:
        HeapArray<ULONG> layoutNameIndexes_ = {};
    };

    class HttpPack200AttributeDefinitionBands final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T definitionCount) noexcept;

        void Reset() noexcept;

        _Ret_maybenull_ ULONG* Headers() noexcept;
        _Ret_maybenull_ const ULONG* Headers() const noexcept;
        _Ret_maybenull_ ULONG* NameIndexes() noexcept;
        _Ret_maybenull_ const ULONG* NameIndexes() const noexcept;
        _Ret_maybenull_ ULONG* LayoutIndexes() noexcept;
        _Ret_maybenull_ const ULONG* LayoutIndexes() const noexcept;
        _Ret_maybenull_ ULONG* Indexes() noexcept;
        _Ret_maybenull_ const ULONG* Indexes() const noexcept;

        _Must_inspect_result_
        NTSTATUS ResolveIndexes(bool haveClassFlagsHigh) noexcept;

        _Must_inspect_result_
        bool Find(SIZE_T context, SIZE_T index, _Out_ SIZE_T* definitionIndex) const noexcept;

        _Must_inspect_result_
        SIZE_T Count() const noexcept;

    private:
        HeapArray<ULONG> headers_ = {};
        HeapArray<ULONG> nameIndexes_ = {};
        HeapArray<ULONG> layoutIndexes_ = {};
        HeapArray<ULONG> indexes_ = {};
    };

    class HttpPack200InnerClassBands final
    {
    public:
        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T innerClassCount) noexcept;

        void Reset() noexcept;

        _Ret_maybenull_ ULONG* ThisClassIndexes() noexcept;
        _Ret_maybenull_ const ULONG* ThisClassIndexes() const noexcept;
        _Ret_maybenull_ ULONG* Flags() noexcept;
        _Ret_maybenull_ const ULONG* Flags() const noexcept;
        _Ret_maybenull_ ULONG* OuterClassIndexes() noexcept;
        _Ret_maybenull_ const ULONG* OuterClassIndexes() const noexcept;
        _Ret_maybenull_ ULONG* NameIndexes() noexcept;
        _Ret_maybenull_ const ULONG* NameIndexes() const noexcept;

        _Must_inspect_result_
        NTSTATUS AllocateExplicitBands(SIZE_T explicitCount) noexcept;

        _Must_inspect_result_
        SIZE_T Count() const noexcept;

        _Must_inspect_result_
        SIZE_T ExplicitCount() const noexcept;

    private:
        HeapArray<ULONG> thisClassIndexes_ = {};
        HeapArray<ULONG> flags_ = {};
        HeapArray<ULONG> outerClassIndexes_ = {};
        HeapArray<ULONG> nameIndexes_ = {};
    };
}
}
