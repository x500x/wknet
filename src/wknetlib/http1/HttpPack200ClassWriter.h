#pragma once

#include "http1/HttpTypes.h"
#include "HttpXmlWriter.h"

namespace wknet
{
namespace http1
{
    struct HttpPack200ExceptionHandler final
    {
        USHORT StartPc = 0;
        USHORT EndPc = 0;
        USHORT HandlerPc = 0;
        USHORT CatchTypeIndex = 0;
    };

    struct HttpPack200LineNumber final
    {
        USHORT StartPc = 0;
        USHORT LineNumber = 0;
    };

    struct HttpPack200LocalVariable final
    {
        USHORT StartPc = 0;
        USHORT Length = 0;
        USHORT NameIndex = 0;
        USHORT TypeIndex = 0;
        USHORT Slot = 0;
    };

    struct HttpPack200RawAttribute final
    {
        USHORT NameIndex = 0;
        const UCHAR* Data = nullptr;
        SIZE_T Length = 0;
    };

    struct HttpPack200ClassMember final
    {
        USHORT AccessFlags = 0;
        USHORT NameIndex = 0;
        USHORT DescriptorIndex = 0;
        USHORT ConstantValueAttributeNameIndex = 0;
        USHORT ConstantValueIndex = 0;
        USHORT SignatureAttributeNameIndex = 0;
        USHORT SignatureIndex = 0;
        USHORT DeprecatedAttributeNameIndex = 0;
        USHORT CodeAttributeNameIndex = 0;
        USHORT MaxStack = 0;
        USHORT MaxLocals = 0;
        const UCHAR* Code = nullptr;
        SIZE_T CodeLength = 0;
        const HttpPack200ExceptionHandler* ExceptionHandlers = nullptr;
        SIZE_T ExceptionHandlerCount = 0;
        USHORT LineNumberTableAttributeNameIndex = 0;
        const HttpPack200LineNumber* LineNumbers = nullptr;
        SIZE_T LineNumberCount = 0;
        USHORT LocalVariableTableAttributeNameIndex = 0;
        const HttpPack200LocalVariable* LocalVariables = nullptr;
        SIZE_T LocalVariableCount = 0;
        USHORT LocalVariableTypeTableAttributeNameIndex = 0;
        const HttpPack200LocalVariable* LocalVariableTypes = nullptr;
        SIZE_T LocalVariableTypeCount = 0;
        USHORT ExceptionsAttributeNameIndex = 0;
        const USHORT* DeclaredExceptionIndexes = nullptr;
        SIZE_T DeclaredExceptionCount = 0;
        const HttpPack200RawAttribute* Attributes = nullptr;
        SIZE_T AttributeCount = 0;
        const HttpPack200RawAttribute* CodeAttributes = nullptr;
        SIZE_T CodeAttributeCount = 0;
    };

    struct HttpPack200InnerClass final
    {
        USHORT InnerClassInfoIndex = 0;
        USHORT OuterClassInfoIndex = 0;
        USHORT InnerNameIndex = 0;
        USHORT AccessFlags = 0;
    };

    struct HttpPack200BootstrapMethod final
    {
        USHORT MethodHandleIndex = 0;
        const USHORT* ArgumentIndexes = nullptr;
        SIZE_T ArgumentCount = 0;
    };

    class HttpPack200ClassWriter final
    {
    public:
        HttpPack200ClassWriter(_Out_writes_bytes_(capacity) char* destination, SIZE_T capacity) noexcept;

        _Must_inspect_result_
        NTSTATUS Begin(USHORT minorVersion, USHORT majorVersion, USHORT maxConstantPoolEntries) noexcept;

        _Must_inspect_result_
        NTSTATUS AddUtf8(HttpXmlText value, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddClass(USHORT nameIndex, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddString(USHORT utf8Index, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddInteger(ULONG value, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddFloat(ULONG bits, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddLong(ULONG highBits, ULONG lowBits, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddDouble(ULONG highBits, ULONG lowBits, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddNameAndType(USHORT nameIndex, USHORT descriptorIndex, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddFieldref(USHORT classIndex, USHORT nameAndTypeIndex, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddMethodref(USHORT classIndex, USHORT nameAndTypeIndex, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddInterfaceMethodref(
            USHORT classIndex,
            USHORT nameAndTypeIndex,
            _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddMethodHandle(UCHAR referenceKind, USHORT referenceIndex, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddMethodType(USHORT descriptorIndex, _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS AddInvokeDynamic(
            USHORT bootstrapMethodIndex,
            USHORT nameAndTypeIndex,
            _Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS FinishHeader(
            USHORT accessFlags,
            USHORT thisClass,
            USHORT superClass,
            _Out_ SIZE_T* classLength) noexcept;

        _Must_inspect_result_
        NTSTATUS FinishClass(
            USHORT accessFlags,
            USHORT thisClass,
            USHORT superClass,
            _In_reads_(interfaceCount) const USHORT* interfaces,
            SIZE_T interfaceCount,
            _In_reads_(fieldCount) const HttpPack200ClassMember* fields,
            SIZE_T fieldCount,
            _In_reads_(methodCount) const HttpPack200ClassMember* methods,
            SIZE_T methodCount,
            USHORT sourceFileAttributeNameIndex,
            USHORT sourceFileIndex,
            USHORT signatureAttributeNameIndex,
            USHORT signatureIndex,
            USHORT deprecatedAttributeNameIndex,
            USHORT enclosingMethodAttributeNameIndex,
            USHORT enclosingClassIndex,
            USHORT enclosingMethodIndex,
            USHORT bootstrapMethodsAttributeNameIndex,
            _In_reads_(bootstrapMethodCount) const HttpPack200BootstrapMethod* bootstrapMethods,
            SIZE_T bootstrapMethodCount,
            USHORT innerClassesAttributeNameIndex,
            _In_reads_(innerClassCount) const HttpPack200InnerClass* innerClasses,
            SIZE_T innerClassCount,
            _In_reads_opt_(classAttributeCount) const HttpPack200RawAttribute* classAttributes,
            SIZE_T classAttributeCount,
            _Out_ SIZE_T* classLength) noexcept;

    private:
        _Must_inspect_result_
        NTSTATUS AppendByte(UCHAR value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendBytes(const void* value, SIZE_T valueLength) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendBe16(USHORT value) noexcept;

        _Must_inspect_result_
        NTSTATUS AppendBe32(ULONG value) noexcept;

        _Must_inspect_result_
        NTSTATUS ReserveConstantPoolIndex(_Out_ USHORT* index) noexcept;

        _Must_inspect_result_
        NTSTATUS ReserveConstantPoolSlots(USHORT slotCount, _Out_ USHORT* index) noexcept;

        char* destination_ = nullptr;
        SIZE_T capacity_ = 0;
        SIZE_T length_ = 0;
        USHORT constantPoolCount_ = 1;
        USHORT maxConstantPoolEntries_ = 0;
        bool begun_ = false;
        bool headerFinished_ = false;
    };
}
}
