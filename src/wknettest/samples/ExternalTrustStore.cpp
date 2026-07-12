#include "samples/ExternalTrustStore.h"

#if defined(WKNET_USER_MODE_TEST)
#include <stdio.h>
#include <stdlib.h>
#else
#include <wknet/WknetConfig.h>
#endif
#include "WknetTestLog.h"

namespace wknet
{
namespace samples
{
    namespace
    {
        _Ret_maybenull_
        UCHAR* AllocateBundleBytes(SIZE_T length) noexcept
        {
            if (length == 0) {
                return nullptr;
            }

#if defined(WKNET_USER_MODE_TEST)
            return static_cast<UCHAR*>(calloc(length, sizeof(UCHAR)));
#else
            return static_cast<UCHAR*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, length, PoolTag));
#endif
        }

        void FreeBundleBytes(_In_opt_ UCHAR* data) noexcept
        {
            if (data == nullptr) {
                return;
            }

#if defined(WKNET_USER_MODE_TEST)
            free(data);
#else
            ExFreePoolWithTag(data, PoolTag);
#endif
        }

        _Must_inspect_result_
        NTSTATUS ReadExternalBundleBytes(
            _In_z_ const char* bundlePath,
            SIZE_T maxBundleBytes,
            _Outptr_result_bytebuffer_(*bundleLength) UCHAR** bundleData,
            _Out_ SIZE_T* bundleLength) noexcept
        {
            if (bundleData != nullptr) {
                *bundleData = nullptr;
            }
            if (bundleLength != nullptr) {
                *bundleLength = 0;
            }

            if (bundlePath == nullptr ||
                bundlePath[0] == '\0' ||
                maxBundleBytes == 0 ||
                bundleData == nullptr ||
                bundleLength == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }

#if defined(WKNET_USER_MODE_TEST)
            FILE* file = nullptr;
            if (fopen_s(&file, bundlePath, "rb") != 0 || file == nullptr) {
                return STATUS_NOT_FOUND;
            }

            if (_fseeki64(file, 0, SEEK_END) != 0) {
                fclose(file);
                return STATUS_UNSUCCESSFUL;
            }

            const __int64 fileSize = _ftelli64(file);
            if (fileSize <= 0) {
                fclose(file);
                return STATUS_INVALID_PARAMETER;
            }

            if (_fseeki64(file, 0, SEEK_SET) != 0) {
                fclose(file);
                return STATUS_UNSUCCESSFUL;
            }

            const unsigned __int64 unsignedSize = static_cast<unsigned __int64>(fileSize);
            if (unsignedSize > static_cast<unsigned __int64>(maxBundleBytes) ||
                unsignedSize > static_cast<unsigned __int64>(~static_cast<SIZE_T>(0))) {
                fclose(file);
                return STATUS_BUFFER_TOO_SMALL;
            }

            const SIZE_T bytesToRead = static_cast<SIZE_T>(unsignedSize);
            UCHAR* data = AllocateBundleBytes(bytesToRead);
            if (data == nullptr) {
                fclose(file);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            const size_t read = fread(data, 1, bytesToRead, file);
            fclose(file);
            if (read != bytesToRead) {
                FreeBundleBytes(data);
                return STATUS_UNSUCCESSFUL;
            }

            *bundleData = data;
            *bundleLength = bytesToRead;
            return STATUS_SUCCESS;
#else
            ANSI_STRING ansiPath = {};
            RtlInitAnsiString(&ansiPath, bundlePath);

            UNICODE_STRING unicodePath = {};
            NTSTATUS status = RtlAnsiStringToUnicodeString(&unicodePath, &ansiPath, TRUE);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            OBJECT_ATTRIBUTES objectAttributes = {};
            InitializeObjectAttributes(
                &objectAttributes,
                &unicodePath,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                nullptr,
                nullptr);

            IO_STATUS_BLOCK ioStatus = {};
            HANDLE fileHandle = nullptr;
            status = ZwCreateFile(
                &fileHandle,
                GENERIC_READ,
                &objectAttributes,
                &ioStatus,
                nullptr,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                nullptr,
                0);
            if (!NT_SUCCESS(status)) {
                RtlFreeUnicodeString(&unicodePath);
                return status;
            }

            FILE_STANDARD_INFORMATION fileInfo = {};
            status = ZwQueryInformationFile(
                fileHandle,
                &ioStatus,
                &fileInfo,
                sizeof(fileInfo),
                FileStandardInformation);
            if (!NT_SUCCESS(status) || fileInfo.EndOfFile.QuadPart <= 0) {
                ZwClose(fileHandle);
                RtlFreeUnicodeString(&unicodePath);
                return NT_SUCCESS(status) ? STATUS_INVALID_PARAMETER : status;
            }

            const ULONGLONG fileSize = static_cast<ULONGLONG>(fileInfo.EndOfFile.QuadPart);
            if (fileSize > static_cast<ULONGLONG>(maxBundleBytes) ||
                fileSize > static_cast<ULONGLONG>(~static_cast<SIZE_T>(0))) {
                ZwClose(fileHandle);
                RtlFreeUnicodeString(&unicodePath);
                return STATUS_BUFFER_TOO_SMALL;
            }

            const SIZE_T bytesToRead = static_cast<SIZE_T>(fileSize);
            UCHAR* data = AllocateBundleBytes(bytesToRead);
            if (data == nullptr) {
                ZwClose(fileHandle);
                RtlFreeUnicodeString(&unicodePath);
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            SIZE_T totalRead = 0;
            while (totalRead < bytesToRead) {
                const SIZE_T remaining = bytesToRead - totalRead;
                const ULONG chunk = remaining > static_cast<SIZE_T>(0x100000) ?
                    0x100000UL :
                    static_cast<ULONG>(remaining);
                LARGE_INTEGER offset = {};
                offset.QuadPart = static_cast<LONGLONG>(totalRead);

                status = ZwReadFile(
                    fileHandle,
                    nullptr,
                    nullptr,
                    nullptr,
                    &ioStatus,
                    data + totalRead,
                    chunk,
                    &offset,
                    nullptr);
                if (!NT_SUCCESS(status)) {
                    FreeBundleBytes(data);
                    ZwClose(fileHandle);
                    RtlFreeUnicodeString(&unicodePath);
                    return status;
                }
                if (ioStatus.Information == 0) {
                    FreeBundleBytes(data);
                    ZwClose(fileHandle);
                    RtlFreeUnicodeString(&unicodePath);
                    return STATUS_UNSUCCESSFUL;
                }

                totalRead += static_cast<SIZE_T>(ioStatus.Information);
            }

            ZwClose(fileHandle);
            RtlFreeUnicodeString(&unicodePath);
            *bundleData = data;
            *bundleLength = bytesToRead;
            return STATUS_SUCCESS;
#endif
        }
    }

    NTSTATUS InitializeExternalTrustStore(
        ExternalTrustStore& trustStore,
        const char* bundlePath,
        SIZE_T maxBundleBytes) noexcept
    {
        ResetExternalTrustStore(trustStore);

        UCHAR* data = nullptr;
        SIZE_T dataLength = 0;
        NTSTATUS status = ReadExternalBundleBytes(bundlePath, maxBundleBytes, &data, &dataLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        trustStore.AuthorityBundle.Data = data;
        trustStore.AuthorityBundle.DataLength = dataLength;

        tls::CertificateStoreOptions storeOptions = {};
        storeOptions.AuthorityBundles = &trustStore.AuthorityBundle;
        storeOptions.AuthorityBundleCount = 1;

        status = trustStore.Store.Initialize(storeOptions);
        if (!NT_SUCCESS(status)) {
            FreeBundleBytes(data);
            trustStore = {};
            return status;
        }

        trustStore.BundleData = data;
        trustStore.BundleDataLength = dataLength;
        return STATUS_SUCCESS;
    }

    void ResetExternalTrustStore(ExternalTrustStore& trustStore) noexcept
    {
        if (trustStore.BundleData != nullptr && trustStore.BundleDataLength != 0) {
            RtlSecureZeroMemory(trustStore.BundleData, trustStore.BundleDataLength);
        }
        FreeBundleBytes(trustStore.BundleData);
        trustStore = {};
    }
}
}
