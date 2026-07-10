#pragma once

#include <KernelHttp/http/HttpTypes.h>
#include "HttpExiEventReader.h"

namespace KernelHttp
{
namespace http
{
    struct HttpExiNameTables final
    {
        HttpExiStringTable* Uris = nullptr;
        HttpExiStringTable* LocalNames = nullptr;
        HttpExiStringTable* Prefixes = nullptr;
        HttpExiQNameTable* QNames = nullptr;
    };

    _Must_inspect_result_
    NTSTATUS HttpExiLearnQName(
        _Inout_ HttpExiNameTables* tables,
        HttpXmlText uri,
        HttpXmlText localName,
        HttpXmlText prefix,
        _Out_ ULONG* qnameId,
        _Out_ HttpXmlName* xmlName,
        bool storeEmptyPrefix = false) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiResolveQName(
        const HttpExiNameTables& tables,
        ULONG qnameId,
        _Out_ HttpXmlName* xmlName) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadQNameLiteral(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiNameTables* tables,
        bool preservePrefix,
        _Out_ ULONG* qnameId,
        _Out_ HttpXmlName* xmlName) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadNamespaceDeclaration(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiNameTables* tables,
        _Out_ HttpXmlText* prefix,
        _Out_ HttpXmlText* uri,
        _Out_ bool* localElementNamespace) noexcept;

    _Must_inspect_result_
    NTSTATUS HttpExiReadQNameValue(
        _Inout_ HttpExiBitInput* input,
        _Inout_ HttpExiNameTables* tables,
        _Inout_ HttpExiStringTable* stringStorage,
        bool preservePrefix,
        _Out_ HttpXmlName* value) noexcept;
}
}
