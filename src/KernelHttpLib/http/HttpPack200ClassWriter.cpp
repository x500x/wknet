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
            constantPoolCount_ != maxConstantPoolEntries_) {
            return STATUS_INVALID_PARAMETER;
        }

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

        status = AppendBe16(static_cast<USHORT>(fieldCount));
        if (!NT_SUCCESS(status)) {
            return status;
        }
        for (SIZE_T index = 0; index < fieldCount; ++index) {
            if (fields[index].NameIndex == 0 || fields[index].DescriptorIndex == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            const bool hasConstantValue = fields[index].ConstantValueAttributeNameIndex != 0;
            if (hasConstantValue != (fields[index].ConstantValueIndex != 0)) {
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
                status = AppendBe16(hasConstantValue ? 1 : 0);
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
                methods[index].ExceptionHandlerCount >
                    (0xffffffffULL - 12ULL - methods[index].CodeLength) / 8ULL) {
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
                status = AppendBe16(static_cast<USHORT>(
                    (hasCode ? 1 : 0) + (hasExceptions ? 1 : 0)));
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (hasCode) {
                status = AppendBe16(methods[index].CodeAttributeNameIndex);
                if (NT_SUCCESS(status)) {
                    status = AppendBe32(static_cast<ULONG>(
                        methods[index].CodeLength + 12 +
                        methods[index].ExceptionHandlerCount * 8));
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
                if (NT_SUCCESS(status)) {
                    status = AppendBe16(0);
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
        }

        const bool hasSourceFile = sourceFileAttributeNameIndex != 0;
        status = AppendBe16(hasSourceFile ? 1 : 0);
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
