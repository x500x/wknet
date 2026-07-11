#include "HttpPack200ClassWriter.h"

namespace KernelHttp
{
namespace http
{
    HttpPack200ClassWriter::HttpPack200ClassWriter(char* destination, SIZE_T capacity) noexcept :
        destination_(destination),
        capacity_(capacity)
    {
    }

    NTSTATUS HttpPack200ClassWriter::Begin(
        USHORT minorVersion,
        USHORT majorVersion,
        USHORT maxConstantPoolEntries) noexcept
    {
        if (destination_ == nullptr || maxConstantPoolEntries == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        length_ = 0;
        constantPoolCount_ = 1;
        maxConstantPoolEntries_ = maxConstantPoolEntries;
        begun_ = true;
        headerFinished_ = false;

        NTSTATUS status = AppendBe32(0xcafebabeUL);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(minorVersion);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(majorVersion);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe16(maxConstantPoolEntries);
    }

    NTSTATUS HttpPack200ClassWriter::AddUtf8(HttpXmlText value, USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || index == nullptr || value.Length > 0xffffUL || (value.Data == nullptr && value.Length != 0)) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(1);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(static_cast<USHORT>(value.Length));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBytes(value.Data, value.Length);
    }

    NTSTATUS HttpPack200ClassWriter::AddClass(USHORT nameIndex, USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || nameIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(7);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe16(nameIndex);
    }

    NTSTATUS HttpPack200ClassWriter::AddString(USHORT utf8Index, USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || utf8Index == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(8);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe16(utf8Index);
    }

    NTSTATUS HttpPack200ClassWriter::AddInteger(ULONG value, USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(3);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe32(value);
    }

    NTSTATUS HttpPack200ClassWriter::AddFloat(ULONG bits, USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(4);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe32(bits);
    }

    NTSTATUS HttpPack200ClassWriter::AddLong(
        ULONG highBits,
        ULONG lowBits,
        USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolSlots(2, index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(5);
        if (NT_SUCCESS(status)) {
            status = AppendBe32(highBits);
        }
        if (NT_SUCCESS(status)) {
            status = AppendBe32(lowBits);
        }
        return status;
    }

    NTSTATUS HttpPack200ClassWriter::AddDouble(
        ULONG highBits,
        ULONG lowBits,
        USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolSlots(2, index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(6);
        if (NT_SUCCESS(status)) {
            status = AppendBe32(highBits);
        }
        if (NT_SUCCESS(status)) {
            status = AppendBe32(lowBits);
        }
        return status;
    }

    NTSTATUS HttpPack200ClassWriter::AddNameAndType(
        USHORT nameIndex,
        USHORT descriptorIndex,
        USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || nameIndex == 0 || descriptorIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(12);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(nameIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe16(descriptorIndex);
    }

    NTSTATUS HttpPack200ClassWriter::AddFieldref(USHORT classIndex, USHORT nameAndTypeIndex, USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || classIndex == 0 || nameAndTypeIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(9);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(classIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe16(nameAndTypeIndex);
    }

    NTSTATUS HttpPack200ClassWriter::AddMethodref(USHORT classIndex, USHORT nameAndTypeIndex, USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || classIndex == 0 || nameAndTypeIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(10);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(classIndex);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe16(nameAndTypeIndex);
    }

    NTSTATUS HttpPack200ClassWriter::AddInterfaceMethodref(
        USHORT classIndex,
        USHORT nameAndTypeIndex,
        USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || classIndex == 0 || nameAndTypeIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(11);
        if (NT_SUCCESS(status)) {
            status = AppendBe16(classIndex);
        }
        if (NT_SUCCESS(status)) {
            status = AppendBe16(nameAndTypeIndex);
        }
        return status;
    }

    NTSTATUS HttpPack200ClassWriter::AddMethodHandle(
        UCHAR referenceKind,
        USHORT referenceIndex,
        USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || referenceKind < 1 || referenceKind > 9 ||
            referenceIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(15);
        if (NT_SUCCESS(status)) {
            status = AppendByte(referenceKind);
        }
        if (NT_SUCCESS(status)) {
            status = AppendBe16(referenceIndex);
        }
        return status;
    }

    NTSTATUS HttpPack200ClassWriter::AddMethodType(
        USHORT descriptorIndex,
        USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || descriptorIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(16);
        if (NT_SUCCESS(status)) {
            status = AppendBe16(descriptorIndex);
        }
        return status;
    }

    NTSTATUS HttpPack200ClassWriter::AddInvokeDynamic(
        USHORT bootstrapMethodIndex,
        USHORT nameAndTypeIndex,
        USHORT* index) noexcept
    {
        if (!begun_ || headerFinished_ || nameAndTypeIndex == 0 || index == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        NTSTATUS status = ReserveConstantPoolIndex(index);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendByte(18);
        if (NT_SUCCESS(status)) status = AppendBe16(bootstrapMethodIndex);
        if (NT_SUCCESS(status)) status = AppendBe16(nameAndTypeIndex);
        return status;
    }

    NTSTATUS HttpPack200ClassWriter::FinishHeader(
        USHORT accessFlags,
        USHORT thisClass,
        USHORT superClass,
        SIZE_T* classLength) noexcept
    {
        return FinishClass(
            accessFlags,
            thisClass,
            superClass,
            nullptr,
            0,
            nullptr,
            0,
            nullptr,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            nullptr,
            0,
            0,
            nullptr,
            0,
            nullptr,
            0,
            classLength);
    }

    NTSTATUS HttpPack200ClassWriter::FinishClass(
        USHORT accessFlags,
        USHORT thisClass,
        USHORT superClass,
        const USHORT* interfaces,
        SIZE_T interfaceCount,
        const HttpPack200ClassMember* fields,
        SIZE_T fieldCount,
        const HttpPack200ClassMember* methods,
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
        const HttpPack200BootstrapMethod* bootstrapMethods,
        SIZE_T bootstrapMethodCount,
        USHORT innerClassesAttributeNameIndex,
        const HttpPack200InnerClass* innerClasses,
        SIZE_T innerClassCount,
        const HttpPack200RawAttribute* classAttributes,
        SIZE_T classAttributeCount,
        SIZE_T* classLength) noexcept
    {
        if (!begun_ ||
            headerFinished_ ||
            classLength == nullptr ||
            thisClass == 0 ||
            interfaceCount > 0xffffUL ||
            fieldCount > 0xffffUL ||
            methodCount > 0xffffUL ||
            (interfaces == nullptr && interfaceCount != 0) ||
            (fields == nullptr && fieldCount != 0) ||
            (methods == nullptr && methodCount != 0) ||
            ((sourceFileAttributeNameIndex == 0) != (sourceFileIndex == 0)) ||
            ((signatureAttributeNameIndex == 0) != (signatureIndex == 0)) ||
            ((enclosingMethodAttributeNameIndex == 0) != (enclosingClassIndex == 0)) ||
            (enclosingMethodAttributeNameIndex == 0 && enclosingMethodIndex != 0) ||
            ((bootstrapMethodsAttributeNameIndex == 0) != (bootstrapMethodCount == 0)) ||
            (bootstrapMethods == nullptr && bootstrapMethodCount != 0) ||
            bootstrapMethodCount > 0xffffUL ||
            ((innerClassesAttributeNameIndex == 0) != (innerClassCount == 0)) ||
            (innerClasses == nullptr && innerClassCount != 0) ||
            innerClassCount > 0xffffUL ||
            (classAttributes == nullptr && classAttributeCount != 0) ||
            classAttributeCount > 0xffffUL ||
            constantPoolCount_ > maxConstantPoolEntries_) {
            return STATUS_INVALID_PARAMETER;
        }

        destination_[8] = static_cast<char>(constantPoolCount_ >> 8);
        destination_[9] = static_cast<char>(constantPoolCount_);

        NTSTATUS status = AppendBe16(accessFlags);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(thisClass);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(superClass);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = AppendBe16(static_cast<USHORT>(interfaceCount));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < interfaceCount; ++index) {
            if (interfaces[index] == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            status = AppendBe16(interfaces[index]);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        auto appendRawAttributes = [&](const HttpPack200RawAttribute* attributes,
                                       SIZE_T count) noexcept -> NTSTATUS {
            if ((attributes == nullptr && count != 0) || count > 0xffffUL) {
                return STATUS_INVALID_PARAMETER;
            }
            NTSTATUS localStatus = STATUS_SUCCESS;
            for (SIZE_T attributeIndex = 0;
                NT_SUCCESS(localStatus) && attributeIndex < count;
                ++attributeIndex) {
                const HttpPack200RawAttribute& attribute = attributes[attributeIndex];
                if (attribute.NameIndex == 0 || attribute.Length > 0xffffffffULL ||
                    (attribute.Data == nullptr && attribute.Length != 0)) {
                    return STATUS_INVALID_PARAMETER;
                }
                localStatus = AppendBe16(attribute.NameIndex);
                if (NT_SUCCESS(localStatus)) {
                    localStatus = AppendBe32(static_cast<ULONG>(attribute.Length));
                }
                if (NT_SUCCESS(localStatus)) {
                    localStatus = AppendBytes(attribute.Data, attribute.Length);
                }
            }
            return localStatus;
        };

        status = AppendBe16(static_cast<USHORT>(fieldCount));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < fieldCount; ++index) {
            if (fields[index].NameIndex == 0 || fields[index].DescriptorIndex == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            const bool hasConstantValue = fields[index].ConstantValueAttributeNameIndex != 0;
            const bool hasSignature = fields[index].SignatureAttributeNameIndex != 0;
            const bool hasDeprecated = fields[index].DeprecatedAttributeNameIndex != 0;
            const SIZE_T fieldAttributeCount = fields[index].AttributeCount +
                (hasConstantValue ? 1 : 0) + (hasSignature ? 1 : 0) + (hasDeprecated ? 1 : 0);
            if (fieldAttributeCount > 0xffffUL ||
                (fields[index].Attributes == nullptr && fields[index].AttributeCount != 0) ||
                hasConstantValue != (fields[index].ConstantValueIndex != 0)) {
                return STATUS_INVALID_PARAMETER;
            }
            if (hasSignature != (fields[index].SignatureIndex != 0)) {
                return STATUS_INVALID_PARAMETER;
            }
            status = AppendBe16(fields[index].AccessFlags);
            if (NT_SUCCESS(status)) {
                status = AppendBe16(fields[index].NameIndex);
            }
            if (NT_SUCCESS(status)) {
                status = AppendBe16(fields[index].DescriptorIndex);
            }
            if (NT_SUCCESS(status)) {
                status = AppendBe16(static_cast<USHORT>(fieldAttributeCount));
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (hasConstantValue) {
                status = AppendBe16(fields[index].ConstantValueAttributeNameIndex);
                if (NT_SUCCESS(status)) {
                    status = AppendBe32(2);
                }
                if (NT_SUCCESS(status)) {
                    status = AppendBe16(fields[index].ConstantValueIndex);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            if (hasSignature) {
                status = AppendBe16(fields[index].SignatureAttributeNameIndex);
                if (NT_SUCCESS(status)) status = AppendBe32(2);
                if (NT_SUCCESS(status)) status = AppendBe16(fields[index].SignatureIndex);
                if (!NT_SUCCESS(status)) return status;
            }
            if (hasDeprecated) {
                status = AppendBe16(fields[index].DeprecatedAttributeNameIndex);
                if (NT_SUCCESS(status)) status = AppendBe32(0);
                if (!NT_SUCCESS(status)) return status;
            }
            status = appendRawAttributes(fields[index].Attributes, fields[index].AttributeCount);
            if (!NT_SUCCESS(status)) return status;
        }

        status = AppendBe16(static_cast<USHORT>(methodCount));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < methodCount; ++index) {
            if (methods[index].NameIndex == 0 || methods[index].DescriptorIndex == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            const bool hasCode = methods[index].CodeAttributeNameIndex != 0;
            const bool hasExceptions = methods[index].ExceptionsAttributeNameIndex != 0;
            const bool hasSignature = methods[index].SignatureAttributeNameIndex != 0;
            const bool hasDeprecated = methods[index].DeprecatedAttributeNameIndex != 0;
            const bool hasLineNumbers = methods[index].LineNumberTableAttributeNameIndex != 0;
            const bool hasLocalVariables = methods[index].LocalVariableTableAttributeNameIndex != 0;
            const bool hasLocalVariableTypes =
                methods[index].LocalVariableTypeTableAttributeNameIndex != 0;
            ULONGLONG rawCodeAttributeBytes = 0;
            if (methods[index].CodeAttributes == nullptr &&
                methods[index].CodeAttributeCount != 0) {
                return STATUS_INVALID_PARAMETER;
            }
            for (SIZE_T attributeIndex = 0;
                attributeIndex < methods[index].CodeAttributeCount;
                ++attributeIndex) {
                const HttpPack200RawAttribute& attribute = methods[index].CodeAttributes[attributeIndex];
                if (attribute.Length > 0xffffffffULL ||
                    rawCodeAttributeBytes > 0xffffffffULL - 6ULL - attribute.Length) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                rawCodeAttributeBytes += 6ULL + attribute.Length;
            }
            const ULONGLONG lineNumberBytes = hasLineNumbers ?
                8ULL + methods[index].LineNumberCount * 4ULL : 0ULL;
            const ULONGLONG localVariableBytes = hasLocalVariables ?
                8ULL + methods[index].LocalVariableCount * 10ULL : 0ULL;
            const ULONGLONG localVariableTypeBytes = hasLocalVariableTypes ?
                8ULL + methods[index].LocalVariableTypeCount * 10ULL : 0ULL;
            const ULONGLONG codeAttributeLength =
                static_cast<ULONGLONG>(methods[index].CodeLength) + 12ULL +
                methods[index].ExceptionHandlerCount * 8ULL +
                lineNumberBytes + localVariableBytes + localVariableTypeBytes + rawCodeAttributeBytes;
            const SIZE_T methodAttributeCount = methods[index].AttributeCount +
                (hasCode ? 1 : 0) + (hasExceptions ? 1 : 0) +
                (hasSignature ? 1 : 0) + (hasDeprecated ? 1 : 0);
            if ((!hasCode && (methods[index].Code != nullptr || methods[index].CodeLength != 0)) ||
                (hasCode && (methods[index].Code == nullptr || methods[index].CodeLength == 0)) ||
                (!hasCode && methods[index].ExceptionHandlerCount != 0) ||
                (methods[index].ExceptionHandlers == nullptr &&
                    methods[index].ExceptionHandlerCount != 0) ||
                methods[index].ExceptionHandlerCount > 0xffffUL ||
                hasExceptions != (methods[index].DeclaredExceptionCount != 0) ||
                (methods[index].DeclaredExceptionIndexes == nullptr &&
                    methods[index].DeclaredExceptionCount != 0) ||
                methods[index].DeclaredExceptionCount > 0xffffUL ||
                hasSignature != (methods[index].SignatureIndex != 0) ||
                hasLineNumbers != (methods[index].LineNumberCount != 0) ||
                hasLocalVariables != (methods[index].LocalVariableCount != 0) ||
                hasLocalVariableTypes != (methods[index].LocalVariableTypeCount != 0) ||
                (methods[index].LineNumbers == nullptr && methods[index].LineNumberCount != 0) ||
                (methods[index].LocalVariables == nullptr && methods[index].LocalVariableCount != 0) ||
                (methods[index].LocalVariableTypes == nullptr && methods[index].LocalVariableTypeCount != 0) ||
                methods[index].LineNumberCount > 0xffffUL ||
                methods[index].LocalVariableCount > 0xffffUL ||
                methods[index].LocalVariableTypeCount > 0xffffUL ||
                methodAttributeCount > 0xffffUL ||
                methods[index].CodeAttributeCount > 0xffffUL ||
                (methods[index].Attributes == nullptr && methods[index].AttributeCount != 0) ||
                (methods[index].CodeAttributes == nullptr && methods[index].CodeAttributeCount != 0) ||
                codeAttributeLength > 0xffffffffULL) {
                return STATUS_INVALID_PARAMETER;
            }
            status = AppendBe16(methods[index].AccessFlags);
            if (NT_SUCCESS(status)) {
                status = AppendBe16(methods[index].NameIndex);
            }
            if (NT_SUCCESS(status)) {
                status = AppendBe16(methods[index].DescriptorIndex);
            }
            if (NT_SUCCESS(status)) {
                status = AppendBe16(static_cast<USHORT>(methodAttributeCount));
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (hasCode) {
                status = AppendBe16(methods[index].CodeAttributeNameIndex);
                if (NT_SUCCESS(status)) {
                    status = AppendBe32(static_cast<ULONG>(codeAttributeLength));
                }
                if (NT_SUCCESS(status)) {
                    status = AppendBe16(methods[index].MaxStack);
                }
                if (NT_SUCCESS(status)) {
                    status = AppendBe16(methods[index].MaxLocals);
                }
                if (NT_SUCCESS(status)) {
                    status = AppendBe32(static_cast<ULONG>(methods[index].CodeLength));
                }
                if (NT_SUCCESS(status)) {
                    status = AppendBytes(methods[index].Code, methods[index].CodeLength);
                }
                if (NT_SUCCESS(status)) {
                    status = AppendBe16(
                        static_cast<USHORT>(methods[index].ExceptionHandlerCount));
                }
                for (SIZE_T handlerIndex = 0;
                    NT_SUCCESS(status) &&
                    handlerIndex < methods[index].ExceptionHandlerCount;
                    ++handlerIndex) {
                    const HttpPack200ExceptionHandler& handler =
                        methods[index].ExceptionHandlers[handlerIndex];
                    if (handler.StartPc >= handler.EndPc ||
                        handler.EndPc > methods[index].CodeLength ||
                        handler.HandlerPc >= methods[index].CodeLength) {
                        return STATUS_INVALID_PARAMETER;
                    }
                    status = AppendBe16(handler.StartPc);
                    if (NT_SUCCESS(status)) {
                        status = AppendBe16(handler.EndPc);
                    }
                    if (NT_SUCCESS(status)) {
                        status = AppendBe16(handler.HandlerPc);
                    }
                    if (NT_SUCCESS(status)) {
                        status = AppendBe16(handler.CatchTypeIndex);
                    }
                }
                const USHORT nestedAttributeCount = static_cast<USHORT>(
                    (hasLineNumbers ? 1 : 0) +
                    (hasLocalVariables ? 1 : 0) +
                    (hasLocalVariableTypes ? 1 : 0) + methods[index].CodeAttributeCount);
                if (NT_SUCCESS(status)) status = AppendBe16(nestedAttributeCount);
                if (NT_SUCCESS(status) && hasLineNumbers) {
                    status = AppendBe16(methods[index].LineNumberTableAttributeNameIndex);
                    if (NT_SUCCESS(status)) status = AppendBe32(static_cast<ULONG>(
                        2ULL + methods[index].LineNumberCount * 4ULL));
                    if (NT_SUCCESS(status)) status = AppendBe16(
                        static_cast<USHORT>(methods[index].LineNumberCount));
                    for (SIZE_T entryIndex = 0;
                        NT_SUCCESS(status) && entryIndex < methods[index].LineNumberCount;
                        ++entryIndex) {
                        const HttpPack200LineNumber& entry = methods[index].LineNumbers[entryIndex];
                        if (entry.StartPc >= methods[index].CodeLength) return STATUS_INVALID_PARAMETER;
                        status = AppendBe16(entry.StartPc);
                        if (NT_SUCCESS(status)) status = AppendBe16(entry.LineNumber);
                    }
                }
                auto appendLocalVariables = [&](USHORT nameIndex,
                                                const HttpPack200LocalVariable* entries,
                                                SIZE_T count) noexcept -> NTSTATUS {
                    NTSTATUS localStatus = AppendBe16(nameIndex);
                    if (NT_SUCCESS(localStatus)) localStatus = AppendBe32(
                        static_cast<ULONG>(2ULL + count * 10ULL));
                    if (NT_SUCCESS(localStatus)) localStatus = AppendBe16(static_cast<USHORT>(count));
                    for (SIZE_T entryIndex = 0; NT_SUCCESS(localStatus) && entryIndex < count; ++entryIndex) {
                        const HttpPack200LocalVariable& entry = entries[entryIndex];
                        if (entry.NameIndex == 0 || entry.TypeIndex == 0 ||
                            entry.StartPc > methods[index].CodeLength ||
                            entry.Length > methods[index].CodeLength - entry.StartPc) {
                            return STATUS_INVALID_PARAMETER;
                        }
                        localStatus = AppendBe16(entry.StartPc);
                        if (NT_SUCCESS(localStatus)) localStatus = AppendBe16(entry.Length);
                        if (NT_SUCCESS(localStatus)) localStatus = AppendBe16(entry.NameIndex);
                        if (NT_SUCCESS(localStatus)) localStatus = AppendBe16(entry.TypeIndex);
                        if (NT_SUCCESS(localStatus)) localStatus = AppendBe16(entry.Slot);
                    }
                    return localStatus;
                };
                if (NT_SUCCESS(status) && hasLocalVariables) {
                    status = appendLocalVariables(
                        methods[index].LocalVariableTableAttributeNameIndex,
                        methods[index].LocalVariables,
                        methods[index].LocalVariableCount);
                }
                if (NT_SUCCESS(status) && hasLocalVariableTypes) {
                    status = appendLocalVariables(
                        methods[index].LocalVariableTypeTableAttributeNameIndex,
                        methods[index].LocalVariableTypes,
                        methods[index].LocalVariableTypeCount);
                }
                if (NT_SUCCESS(status)) {
                    status = appendRawAttributes(
                        methods[index].CodeAttributes,
                        methods[index].CodeAttributeCount);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            if (hasExceptions) {
                if (methods[index].DeclaredExceptionCount >
                    (0xffffffffULL - 2ULL) / 2ULL) {
                    return STATUS_INTEGER_OVERFLOW;
                }
                status = AppendBe16(methods[index].ExceptionsAttributeNameIndex);
                if (NT_SUCCESS(status)) {
                    status = AppendBe32(static_cast<ULONG>(
                        2 + methods[index].DeclaredExceptionCount * 2));
                }
                if (NT_SUCCESS(status)) {
                    status = AppendBe16(
                        static_cast<USHORT>(methods[index].DeclaredExceptionCount));
                }
                for (SIZE_T exceptionIndex = 0;
                    NT_SUCCESS(status) &&
                    exceptionIndex < methods[index].DeclaredExceptionCount;
                    ++exceptionIndex) {
                    if (methods[index].DeclaredExceptionIndexes[exceptionIndex] == 0) {
                        return STATUS_INVALID_PARAMETER;
                    }
                    status = AppendBe16(
                        methods[index].DeclaredExceptionIndexes[exceptionIndex]);
                }
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            if (hasSignature) {
                status = AppendBe16(methods[index].SignatureAttributeNameIndex);
                if (NT_SUCCESS(status)) status = AppendBe32(2);
                if (NT_SUCCESS(status)) status = AppendBe16(methods[index].SignatureIndex);
                if (!NT_SUCCESS(status)) return status;
            }
            if (hasDeprecated) {
                status = AppendBe16(methods[index].DeprecatedAttributeNameIndex);
                if (NT_SUCCESS(status)) status = AppendBe32(0);
                if (!NT_SUCCESS(status)) return status;
            }
            status = appendRawAttributes(methods[index].Attributes, methods[index].AttributeCount);
            if (!NT_SUCCESS(status)) return status;
        }

        const bool hasSourceFile = sourceFileAttributeNameIndex != 0;
        const bool hasSignature = signatureAttributeNameIndex != 0;
        const bool hasDeprecated = deprecatedAttributeNameIndex != 0;
        const bool hasEnclosingMethod = enclosingMethodAttributeNameIndex != 0;
        const bool hasBootstrapMethods = bootstrapMethodsAttributeNameIndex != 0;
        const bool hasInnerClasses = innerClassesAttributeNameIndex != 0;
        const SIZE_T totalClassAttributeCount = classAttributeCount +
            (hasSourceFile ? 1 : 0) +
            (hasSignature ? 1 : 0) + (hasBootstrapMethods ? 1 : 0) +
            (hasInnerClasses ? 1 : 0) + (hasDeprecated ? 1 : 0) +
            (hasEnclosingMethod ? 1 : 0);
        if (totalClassAttributeCount > 0xffffUL) return STATUS_INVALID_PARAMETER;
        status = AppendBe16(static_cast<USHORT>(totalClassAttributeCount));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (hasSourceFile) {
            status = AppendBe16(sourceFileAttributeNameIndex);
            if (NT_SUCCESS(status)) {
                status = AppendBe32(2);
            }
            if (NT_SUCCESS(status)) {
                status = AppendBe16(sourceFileIndex);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        if (hasSignature) {
            status = AppendBe16(signatureAttributeNameIndex);
            if (NT_SUCCESS(status)) status = AppendBe32(2);
            if (NT_SUCCESS(status)) status = AppendBe16(signatureIndex);
            if (!NT_SUCCESS(status)) return status;
        }
        if (hasDeprecated) {
            status = AppendBe16(deprecatedAttributeNameIndex);
            if (NT_SUCCESS(status)) status = AppendBe32(0);
            if (!NT_SUCCESS(status)) return status;
        }
        if (hasEnclosingMethod) {
            status = AppendBe16(enclosingMethodAttributeNameIndex);
            if (NT_SUCCESS(status)) status = AppendBe32(4);
            if (NT_SUCCESS(status)) status = AppendBe16(enclosingClassIndex);
            if (NT_SUCCESS(status)) status = AppendBe16(enclosingMethodIndex);
            if (!NT_SUCCESS(status)) return status;
        }
        if (hasBootstrapMethods) {
            if (bootstrapMethodCount > 0xffffUL ||
                (bootstrapMethods == nullptr && bootstrapMethodCount != 0)) {
                return STATUS_INVALID_PARAMETER;
            }
            SIZE_T attributeLength = 2;
            for (SIZE_T index = 0; index < bootstrapMethodCount; ++index) {
                if (bootstrapMethods[index].MethodHandleIndex == 0 ||
                    bootstrapMethods[index].ArgumentCount > 0xffffUL ||
                    (bootstrapMethods[index].ArgumentIndexes == nullptr &&
                        bootstrapMethods[index].ArgumentCount != 0) ||
                    attributeLength > 0xffffffffULL - 4ULL ||
                    bootstrapMethods[index].ArgumentCount >
                        (0xffffffffULL - attributeLength - 4ULL) / 2ULL) {
                    return STATUS_INVALID_PARAMETER;
                }
                attributeLength += 4 + bootstrapMethods[index].ArgumentCount * 2;
            }
            status = AppendBe16(bootstrapMethodsAttributeNameIndex);
            if (NT_SUCCESS(status)) status = AppendBe32(static_cast<ULONG>(attributeLength));
            if (NT_SUCCESS(status)) status = AppendBe16(static_cast<USHORT>(bootstrapMethodCount));
            for (SIZE_T index = 0; NT_SUCCESS(status) && index < bootstrapMethodCount; ++index) {
                status = AppendBe16(bootstrapMethods[index].MethodHandleIndex);
                if (NT_SUCCESS(status)) {
                    status = AppendBe16(static_cast<USHORT>(bootstrapMethods[index].ArgumentCount));
                }
                for (SIZE_T argumentIndex = 0;
                    NT_SUCCESS(status) && argumentIndex < bootstrapMethods[index].ArgumentCount;
                    ++argumentIndex) {
                    if (bootstrapMethods[index].ArgumentIndexes[argumentIndex] == 0) {
                        return STATUS_INVALID_PARAMETER;
                    }
                    status = AppendBe16(bootstrapMethods[index].ArgumentIndexes[argumentIndex]);
                }
            }
            if (!NT_SUCCESS(status)) return status;
        }
        if (hasInnerClasses) {
            if (innerClassCount > (0xffffffffULL - 2ULL) / 8ULL) {
                return STATUS_INTEGER_OVERFLOW;
            }
            status = AppendBe16(innerClassesAttributeNameIndex);
            if (NT_SUCCESS(status)) {
                status = AppendBe32(static_cast<ULONG>(2 + innerClassCount * 8));
            }
            if (NT_SUCCESS(status)) {
                status = AppendBe16(static_cast<USHORT>(innerClassCount));
            }
            for (SIZE_T index = 0; NT_SUCCESS(status) && index < innerClassCount; ++index) {
                if (innerClasses[index].InnerClassInfoIndex == 0) {
                    return STATUS_INVALID_PARAMETER;
                }
                status = AppendBe16(innerClasses[index].InnerClassInfoIndex);
                if (NT_SUCCESS(status)) status = AppendBe16(innerClasses[index].OuterClassInfoIndex);
                if (NT_SUCCESS(status)) status = AppendBe16(innerClasses[index].InnerNameIndex);
                if (NT_SUCCESS(status)) status = AppendBe16(innerClasses[index].AccessFlags);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        status = appendRawAttributes(classAttributes, classAttributeCount);
        if (!NT_SUCCESS(status)) return status;
        headerFinished_ = true;
        *classLength = length_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ClassWriter::AppendByte(UCHAR value) noexcept
    {
        if (destination_ == nullptr || length_ >= capacity_) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        destination_[length_] = static_cast<char>(value);
        ++length_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ClassWriter::AppendBytes(const void* value, SIZE_T valueLength) noexcept
    {
        if (valueLength == 0) {
            return STATUS_SUCCESS;
        }
        if (value == nullptr || destination_ == nullptr || valueLength > capacity_ || length_ > capacity_ - valueLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        RtlCopyMemory(destination_ + length_, value, valueLength);
        length_ += valueLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpPack200ClassWriter::AppendBe16(USHORT value) noexcept
    {
        NTSTATUS status = AppendByte(static_cast<UCHAR>((value >> 8) & 0xff));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendByte(static_cast<UCHAR>(value & 0xff));
    }

    NTSTATUS HttpPack200ClassWriter::AppendBe32(ULONG value) noexcept
    {
        NTSTATUS status = AppendBe16(static_cast<USHORT>((value >> 16) & 0xffffUL));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return AppendBe16(static_cast<USHORT>(value & 0xffffUL));
    }

    NTSTATUS HttpPack200ClassWriter::ReserveConstantPoolIndex(USHORT* index) noexcept
    {
        return ReserveConstantPoolSlots(1, index);
    }

    NTSTATUS HttpPack200ClassWriter::ReserveConstantPoolSlots(
        USHORT slotCount,
        USHORT* index) noexcept
    {
        if (index == nullptr || slotCount == 0 || constantPoolCount_ == 0 ||
            slotCount > maxConstantPoolEntries_ - constantPoolCount_) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        *index = constantPoolCount_;
        constantPoolCount_ = static_cast<USHORT>(constantPoolCount_ + slotCount);
        return STATUS_SUCCESS;
    }
}
}
