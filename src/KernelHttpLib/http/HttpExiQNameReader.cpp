#include "HttpExiQNameReader.h"

namespace KernelHttp
{
namespace http
{
namespace
{
    _Must_inspect_result_
    bool TablesValid(const HttpExiNameTables* tables) noexcept
    {
        return tables != nullptr &&
            tables->Uris != nullptr &&
            tables->LocalNames != nullptr &&
            tables->Prefixes != nullptr &&
            tables->QNames != nullptr;
    }

    _Must_inspect_result_
    SIZE_T LocalNameCountForUri(const HttpExiNameTables& tables, ULONG uriId) noexcept
    {
        SIZE_T count = 0;
        for (SIZE_T index = 0; index < tables.QNames->Count(); ++index) {
            HttpExiQNameEntry entry = {};
            if (!tables.QNames->Get(static_cast<ULONG>(index), &entry) ||
                entry.UriId != uriId ||
                entry.LocalNameId == 0xffffffffUL) {
                continue;
            }
            bool seen = false;
            for (SIZE_T previous = 0; previous < index; ++previous) {
                HttpExiQNameEntry previousEntry = {};
                if (tables.QNames->Get(static_cast<ULONG>(previous), &previousEntry) &&
                    previousEntry.UriId == uriId &&
                    previousEntry.LocalNameId != 0xffffffffUL &&
                    previousEntry.LocalNameId == entry.LocalNameId) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                ++count;
            }
        }
        return count;
    }

    _Must_inspect_result_
    bool LocalNameIdForOrdinal(
        const HttpExiNameTables& tables,
        ULONG uriId,
        ULONG ordinal,
        _Out_ ULONG* localNameId) noexcept
    {
        if (localNameId == nullptr) {
            return false;
        }
        ULONG current = 0;
        for (SIZE_T index = 0; index < tables.QNames->Count(); ++index) {
            HttpExiQNameEntry entry = {};
            if (!tables.QNames->Get(static_cast<ULONG>(index), &entry) ||
                entry.UriId != uriId ||
                entry.LocalNameId == 0xffffffffUL) {
                continue;
            }
            bool seen = false;
            for (SIZE_T previous = 0; previous < index; ++previous) {
                HttpExiQNameEntry previousEntry = {};
                if (tables.QNames->Get(static_cast<ULONG>(previous), &previousEntry) &&
                    previousEntry.UriId == uriId &&
                    previousEntry.LocalNameId != 0xffffffffUL &&
                    previousEntry.LocalNameId == entry.LocalNameId) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                if (current == ordinal) {
                    *localNameId = entry.LocalNameId;
                    return true;
                }
                ++current;
            }
        }
        return false;
    }

    _Must_inspect_result_
    SIZE_T PrefixCountForUri(const HttpExiNameTables& tables, ULONG uriId) noexcept
    {
        SIZE_T count = 0;
        for (SIZE_T index = 0; index < tables.QNames->Count(); ++index) {
            HttpExiQNameEntry entry = {};
            if (!tables.QNames->Get(static_cast<ULONG>(index), &entry) ||
                entry.UriId != uriId ||
                entry.PrefixId == 0xffffffffUL) {
                continue;
            }
            bool seen = false;
            for (SIZE_T previous = 0; previous < index; ++previous) {
                HttpExiQNameEntry previousEntry = {};
                if (tables.QNames->Get(static_cast<ULONG>(previous), &previousEntry) &&
                    previousEntry.UriId == uriId &&
                    previousEntry.PrefixId == entry.PrefixId) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                ++count;
            }
        }
        return count;
    }

    _Must_inspect_result_
    bool PrefixIdForOrdinal(
        const HttpExiNameTables& tables,
        ULONG uriId,
        ULONG ordinal,
        _Out_ ULONG* prefixId) noexcept
    {
        if (prefixId == nullptr) {
            return false;
        }
        ULONG current = 0;
        for (SIZE_T index = 0; index < tables.QNames->Count(); ++index) {
            HttpExiQNameEntry entry = {};
            if (!tables.QNames->Get(static_cast<ULONG>(index), &entry) ||
                entry.UriId != uriId ||
                entry.PrefixId == 0xffffffffUL) {
                continue;
            }
            bool seen = false;
            for (SIZE_T previous = 0; previous < index; ++previous) {
                HttpExiQNameEntry previousEntry = {};
                if (tables.QNames->Get(static_cast<ULONG>(previous), &previousEntry) &&
                    previousEntry.UriId == uriId &&
                    previousEntry.PrefixId == entry.PrefixId) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                if (current == ordinal) {
                    *prefixId = entry.PrefixId;
                    return true;
                }
                ++current;
            }
        }
        return false;
    }

    _Must_inspect_result_
    NTSTATUS AssociatePrefix(
        _Inout_ HttpExiNameTables* tables,
        ULONG uriId,
        ULONG prefixId) noexcept
    {
        HttpExiQNameEntry association = {};
        association.UriId = uriId;
        association.LocalNameId = 0xffffffffUL;
        association.PrefixId = prefixId;
        ULONG ignored = 0;
        return tables->QNames->Add(association, &ignored);
    }

    _Must_inspect_result_
    NTSTATUS ReadUri(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiNameTables* tables,
        _Out_ ULONG* uriId,
        _Out_ HttpXmlText* uri) noexcept
    {
        if (tables->Uris->Count() >= 0xffffffffULL) {
            return STATUS_INTEGER_OVERFLOW;
        }
        UCHAR uriBits = 0;
        if (!HttpExiBitsForProductionCount(static_cast<ULONG>(tables->Uris->Count() + 1), &uriBits)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG uriSelector = 0;
        if (uriBits != 0 && !input->ReadBits(uriBits, &uriSelector)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (uriSelector == 0) {
            const NTSTATUS status = HttpExiReadLiteralString(input, tables->Uris, uri);
            if (!NT_SUCCESS(status) || !tables->Uris->Find(*uri, uriId)) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            return STATUS_SUCCESS;
        }
        *uriId = uriSelector - 1;
        return tables->Uris->Get(*uriId, uri) ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS ReadPrefix(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiNameTables* tables,
        ULONG uriId,
        _Out_ HttpXmlText* prefix) noexcept
    {
        const SIZE_T prefixCount = PrefixCountForUri(*tables, uriId);
        if (prefixCount >= 0xffffffffULL) {
            return STATUS_INTEGER_OVERFLOW;
        }
        UCHAR prefixBits = 0;
        if (!HttpExiBitsForProductionCount(static_cast<ULONG>(prefixCount + 1), &prefixBits)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG selector = 0;
        if (prefixBits != 0 && !input->ReadBits(prefixBits, &selector)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ULONG prefixId = 0;
        if (selector == 0) {
            const NTSTATUS status = HttpExiReadLiteralString(input, tables->Prefixes, prefix);
            if (!NT_SUCCESS(status) || !tables->Prefixes->Find(*prefix, &prefixId)) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
            return AssociatePrefix(tables, uriId, prefixId);
        }
        if (!PrefixIdForOrdinal(*tables, uriId, selector - 1, &prefixId) ||
            !tables->Prefixes->Get(prefixId, prefix)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadQNamePrefix(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiNameTables* tables,
        ULONG uriId,
        _Out_ HttpXmlText* prefix,
        _Out_ bool* prefixKnown) noexcept
    {
        if (prefix == nullptr || prefixKnown == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *prefix = {};
        *prefixKnown = false;
        const SIZE_T prefixCount = PrefixCountForUri(*tables, uriId);
        if (prefixCount == 0) {
            return STATUS_SUCCESS;
        }
        if (prefixCount > 0xffffffffULL) {
            return STATUS_INTEGER_OVERFLOW;
        }
        UCHAR prefixBits = 0;
        if (!HttpExiBitsForProductionCount(static_cast<ULONG>(prefixCount), &prefixBits)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG ordinal = 0;
        if (prefixBits != 0 && !input->ReadBits(prefixBits, &ordinal)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        ULONG prefixId = 0;
        if (!PrefixIdForOrdinal(*tables, uriId, ordinal, &prefixId) ||
            !tables->Prefixes->Get(prefixId, prefix)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *prefixKnown = true;
        return STATUS_SUCCESS;
    }
}

    NTSTATUS HttpExiLearnQName(
        HttpExiNameTables* tables,
        HttpXmlText uri,
        HttpXmlText localName,
        HttpXmlText prefix,
        ULONG* qnameId,
        HttpXmlName* xmlName,
        bool storeEmptyPrefix) noexcept
    {
        if (!TablesValid(tables) ||
            qnameId == nullptr ||
            xmlName == nullptr ||
            localName.Data == nullptr ||
            localName.Length == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        *qnameId = 0;
        *xmlName = {};

        ULONG uriId = 0;
        NTSTATUS status = tables->Uris->Add(uri, &uriId);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        ULONG localNameId = 0;
        status = tables->LocalNames->Add(localName, &localNameId);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG prefixId = 0xffffffffUL;
        if (prefix.Length != 0 || storeEmptyPrefix) {
            status = tables->Prefixes->Add(prefix, &prefixId);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        HttpExiQNameEntry entry = {};
        entry.UriId = uriId;
        entry.LocalNameId = localNameId;
        entry.PrefixId = prefixId;
        status = tables->QNames->Add(entry, qnameId);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        xmlName->LocalName = {};
        if (!tables->Uris->Get(uriId, &xmlName->Uri) ||
            !tables->LocalNames->Get(localNameId, &xmlName->LocalName)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (prefixId != 0xffffffffUL &&
            !tables->Prefixes->Get(prefixId, &xmlName->Prefix)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiResolveQName(
        const HttpExiNameTables& tables,
        ULONG qnameId,
        HttpXmlName* xmlName) noexcept
    {
        if (tables.Uris == nullptr ||
            tables.LocalNames == nullptr ||
            tables.Prefixes == nullptr ||
            tables.QNames == nullptr ||
            xmlName == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *xmlName = {};

        HttpExiQNameEntry entry = {};
        if (!tables.QNames->Get(qnameId, &entry) ||
            !tables.Uris->Get(entry.UriId, &xmlName->Uri) ||
            !tables.LocalNames->Get(entry.LocalNameId, &xmlName->LocalName)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (entry.PrefixId != 0xffffffffUL &&
            !tables.Prefixes->Get(entry.PrefixId, &xmlName->Prefix)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiReadQNameLiteral(
        HttpExiBitInput* input,
        HttpExiNameTables* tables,
        bool preservePrefix,
        ULONG* qnameId,
        HttpXmlName* xmlName) noexcept
    {
        if (input == nullptr || !TablesValid(tables) || qnameId == nullptr || xmlName == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        HttpXmlText uri = {};
        ULONG uriId = 0;
        NTSTATUS status = ReadUri(input, tables, &uriId, &uri);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        ULONG localMarker = 0;
        if (!input->ReadUnsignedInteger(&localMarker)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        HttpXmlText localName = {};
        ULONG localNameId = 0;
        if (localMarker == 0) {
            const SIZE_T localCount = LocalNameCountForUri(*tables, uriId);
            if (localCount == 0 || localCount > 0xffffffffULL) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            UCHAR localBits = 0;
            if (!HttpExiBitsForProductionCount(static_cast<ULONG>(localCount), &localBits)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ULONG localOrdinal = 0;
            if (localBits != 0 && !input->ReadBits(localBits, &localOrdinal)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (!LocalNameIdForOrdinal(*tables, uriId, localOrdinal, &localNameId) ||
                !tables->LocalNames->Get(localNameId, &localName)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
        else {
            status = HttpExiReadStringOnly(input, localMarker - 1, tables->LocalNames, &localName);
            if (!NT_SUCCESS(status) || !tables->LocalNames->Find(localName, &localNameId)) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
        }

        HttpXmlText prefix = {};
        bool prefixKnown = false;
        if (preservePrefix) {
            status = ReadQNamePrefix(input, tables, uriId, &prefix, &prefixKnown);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return HttpExiLearnQName(
            tables,
            uri,
            localName,
            prefix,
            qnameId,
            xmlName,
            preservePrefix && prefixKnown);
    }

    NTSTATUS HttpExiReadNamespaceDeclaration(
        HttpExiBitInput* input,
        HttpExiNameTables* tables,
        HttpXmlText* prefix,
        HttpXmlText* uri,
        bool* localElementNamespace) noexcept
    {
        if (input == nullptr || !TablesValid(tables) || prefix == nullptr ||
            uri == nullptr || localElementNamespace == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *prefix = {};
        *uri = {};
        *localElementNamespace = false;

        ULONG uriId = 0;
        NTSTATUS status = ReadUri(input, tables, &uriId, uri);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = ReadPrefix(input, tables, uriId, prefix);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        ULONG local = 0;
        if (!input->ReadBits(1, &local)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *localElementNamespace = local != 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiReadQNameValue(
        HttpExiBitInput* input,
        HttpExiNameTables* tables,
        HttpExiStringTable* stringStorage,
        bool preservePrefix,
        HttpXmlName* value) noexcept
    {
        if (input == nullptr || !TablesValid(tables) || stringStorage == nullptr || value == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        UNREFERENCED_PARAMETER(stringStorage);
        ULONG qnameId = 0;
        return HttpExiReadQNameLiteral(
            input,
            tables,
            preservePrefix,
            &qnameId,
            value);
    }
}
}
