#include "ExiOptions.h"
#include "ExiQNameReader.h"
#include "ExiStringTable.h"

namespace wknet
{
namespace codec
{
namespace
{
    enum class OptionElement : UCHAR
    {
        None,
        Header,
        LessCommon,
        Uncommon,
        Alignment,
        Byte,
        PreCompress,
        SelfContained,
        ValueMaxLength,
        ValuePartitionCapacity,
        DatatypeRepresentationMap,
        Preserve,
        Dtd,
        Prefixes,
        LexicalValues,
        Comments,
        Pis,
        BlockSize,
        Common,
        Compression,
        Fragment,
        SchemaId,
        Strict
    };

    enum class OptionEvent : UCHAR
    {
        StartElement,
        EndElement,
        CharactersUnsigned,
        CharactersString,
        AttributeXsiNil,
        StartElementGeneric,
        EndDocument,
        Unsupported
    };

    struct OptionProduction final
    {
        OptionEvent Event = OptionEvent::Unsupported;
        OptionElement Element = OptionElement::None;
        UCHAR ChildGrammar = 0;
        UCHAR NextGrammar = 0;
    };

    struct OptionStackEntry final
    {
        UCHAR ContinuationGrammar = 0;
        OptionElement ParentElement = OptionElement::None;
    };

    constexpr OptionProduction Start(
        OptionElement element,
        UCHAR childGrammar,
        UCHAR nextGrammar) noexcept
    {
        return { OptionEvent::StartElement, element, childGrammar, nextGrammar };
    }

    constexpr OptionProduction End() noexcept
    {
        return { OptionEvent::EndElement, OptionElement::None, 0, 0 };
    }

    constexpr OptionProduction UnsignedCharacters(UCHAR nextGrammar) noexcept
    {
        return { OptionEvent::CharactersUnsigned, OptionElement::None, 0, nextGrammar };
    }

    constexpr OptionProduction StringCharacters(UCHAR nextGrammar) noexcept
    {
        return { OptionEvent::CharactersString, OptionElement::None, 0, nextGrammar };
    }

    constexpr OptionProduction XsiNil() noexcept
    {
        return { OptionEvent::AttributeXsiNil, OptionElement::None, 0, 0 };
    }

    constexpr OptionProduction Unsupported() noexcept
    {
        return { OptionEvent::Unsupported, OptionElement::None, 0, 0 };
    }

    constexpr OptionProduction GenericStart(UCHAR childGrammar, UCHAR nextGrammar) noexcept
    {
        return { OptionEvent::StartElementGeneric, OptionElement::None, childGrammar, nextGrammar };
    }

    constexpr HttpXmlText LiteralText(const char* data, SIZE_T length) noexcept
    {
        return { data, length };
    }

    _Must_inspect_result_
    NTSTATUS AddOptionQName(
        _Inout_ HttpExiStringTable* localNames,
        _Inout_ HttpExiQNameTable* qnames,
        ULONG uriId,
        const char* name,
        SIZE_T nameLength) noexcept
    {
        ULONG localNameId = 0;
        NTSTATUS status = localNames->Add(LiteralText(name, nameLength), &localNameId);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpExiQNameEntry entry = {};
        entry.UriId = uriId;
        entry.LocalNameId = localNameId;
        entry.PrefixId = 0xffffffffUL;
        ULONG ignored = 0;
        return qnames->Add(entry, &ignored);
    }

    _Must_inspect_result_
    NTSTATUS InitializeOptionNameTables(
        _Inout_ HttpExiStringTable* uris,
        _Inout_ HttpExiStringTable* localNames,
        _Inout_ HttpExiStringTable* prefixes,
        _Inout_ HttpExiQNameTable* qnames) noexcept
    {
        if (uris == nullptr || localNames == nullptr || prefixes == nullptr || qnames == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        constexpr char Empty[] = "";
        constexpr char XmlUri[] = "http://www.w3.org/XML/1998/namespace";
        constexpr char XsiUri[] = "http://www.w3.org/2001/XMLSchema-instance";
        constexpr char XsdUri[] = "http://www.w3.org/2001/XMLSchema";
        constexpr char ExiUri[] = "http://www.w3.org/2009/exi";
        constexpr const char* XmlNames[] = { "base", "id", "lang", "space" };
        constexpr const char* XsiNames[] = { "nil", "type" };
        constexpr const char* XsdNames[] = {
            "ENTITIES", "ENTITY", "ID", "IDREF", "IDREFS", "NCName",
            "NMTOKEN", "NMTOKENS", "NOTATION", "Name", "QName",
            "anySimpleType", "anyType", "anyURI", "base64Binary", "boolean",
            "byte", "date", "dateTime", "decimal", "double", "duration",
            "float", "gDay", "gMonth", "gMonthDay", "gYear", "gYearMonth",
            "hexBinary", "int", "integer", "language", "long", "negativeInteger",
            "nonNegativeInteger", "nonPositiveInteger", "normalizedString",
            "positiveInteger", "short", "string", "time", "token", "unsignedByte",
            "unsignedInt", "unsignedLong", "unsignedShort"
        };
        constexpr const char* ExiNames[] = {
            "alignment", "base64Binary", "blockSize", "boolean", "byte",
            "comments", "common", "compression", "datatypeRepresentationMap",
            "date", "dateTime", "decimal", "double", "dtd", "fragment", "gDay",
            "gMonth", "gMonthDay", "gYear", "gYearMonth", "header", "hexBinary",
            "ieeeBinary32", "ieeeBinary64", "integer", "lesscommon", "lexicalValues",
            "pis", "pre-compress", "prefixes", "preserve", "schemaId",
            "selfContained", "strict", "string", "time", "uncommon",
            "valueMaxLength", "valuePartitionCapacity"
        };

        NTSTATUS status = uris->Initialize(8, 256);
        if (NT_SUCCESS(status)) status = localNames->Initialize(128, 2048);
        if (NT_SUCCESS(status)) status = prefixes->Initialize(4, 16);
        if (NT_SUCCESS(status)) status = qnames->Initialize(128);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        const HttpXmlText uriValues[] = {
            LiteralText(Empty, 0),
            LiteralText(XmlUri, sizeof(XmlUri) - 1),
            LiteralText(XsiUri, sizeof(XsiUri) - 1),
            LiteralText(XsdUri, sizeof(XsdUri) - 1),
            LiteralText(ExiUri, sizeof(ExiUri) - 1)
        };
        for (SIZE_T index = 0; index < sizeof(uriValues) / sizeof(uriValues[0]); ++index) {
            ULONG uriId = 0;
            status = uris->Add(uriValues[index], &uriId);
            if (!NT_SUCCESS(status) || uriId != index) {
                return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
            }
        }
        const HttpXmlText prefixValues[] = {
            LiteralText(Empty, 0), LiteralText("xml", 3), LiteralText("xsi", 3)
        };
        for (SIZE_T index = 0; index < sizeof(prefixValues) / sizeof(prefixValues[0]); ++index) {
            ULONG prefixId = 0;
            status = prefixes->Add(prefixValues[index], &prefixId);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            HttpExiQNameEntry association = {};
            association.UriId = static_cast<ULONG>(index);
            association.LocalNameId = 0xffffffffUL;
            association.PrefixId = prefixId;
            ULONG ignored = 0;
            status = qnames->Add(association, &ignored);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        const struct NameGroup final {
            ULONG UriId;
            const char* const* Names;
            SIZE_T Count;
        } groups[] = {
            { 1, XmlNames, sizeof(XmlNames) / sizeof(XmlNames[0]) },
            { 2, XsiNames, sizeof(XsiNames) / sizeof(XsiNames[0]) },
            { 3, XsdNames, sizeof(XsdNames) / sizeof(XsdNames[0]) },
            { 4, ExiNames, sizeof(ExiNames) / sizeof(ExiNames[0]) }
        };
        for (SIZE_T groupIndex = 0; groupIndex < sizeof(groups) / sizeof(groups[0]); ++groupIndex) {
            for (SIZE_T nameIndex = 0; nameIndex < groups[groupIndex].Count; ++nameIndex) {
                const char* name = groups[groupIndex].Names[nameIndex];
                SIZE_T length = 0;
                while (name[length] != '\0') {
                    ++length;
                }
                status = AddOptionQName(
                    localNames,
                    qnames,
                    groups[groupIndex].UriId,
                    name,
                    length);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    bool ReadChoice(
        _Inout_ HttpExiBitInput* input,
        ULONG productionCount,
        _Out_ ULONG* choice) noexcept
    {
        if (input == nullptr || choice == nullptr) {
            return false;
        }
        UCHAR width = 0;
        if (!HttpExiBitsForProductionCount(productionCount, &width)) {
            return false;
        }
        *choice = 0;
        return width == 0 || input->ReadBits(width, choice);
    }

    _Must_inspect_result_
    bool SelectProduction(
        UCHAR grammar,
        ULONG code,
        _Out_ OptionProduction* production) noexcept
    {
        if (production == nullptr) {
            return false;
        }
        *production = {};

        switch (grammar) {
        case 2:
            if (code == 0) *production = Start(OptionElement::LessCommon, 3, 29);
            else if (code == 1) *production = Start(OptionElement::Common, 30, 36);
            else if (code == 2) *production = Start(OptionElement::Strict, 6, 8);
            else if (code == 3) *production = End();
            else return false;
            return true;
        case 3:
            if (code == 0) *production = Start(OptionElement::Uncommon, 4, 20);
            else if (code == 1) *production = Start(OptionElement::Preserve, 21, 27);
            else if (code == 2) *production = Start(OptionElement::BlockSize, 12, 8);
            else if (code == 3) *production = End();
            else return false;
            return true;
        case 4:
        case 19:
            if (code == 0) *production = Start(OptionElement::Alignment, 5, 10);
            else if (code == 1) *production = Start(OptionElement::SelfContained, 6, 11);
            else if (code == 2) *production = Start(OptionElement::ValueMaxLength, 12, 14);
            else if (code == 3) *production = Start(OptionElement::ValuePartitionCapacity, 12, 15);
            else if (code == 4) *production = Start(OptionElement::DatatypeRepresentationMap, 16, 15);
            else if (grammar == 19 && code == 5) *production = Unsupported();
            else if (code == (grammar == 19 ? 6UL : 5UL)) *production = End();
            else return false;
            return true;
        case 5:
        case 9:
            if (code == 0) *production = Start(OptionElement::Byte, 6, 8);
            else if (code == 1) *production = Start(OptionElement::PreCompress, 6, 8);
            else return false;
            return true;
        case 6:
        case 8:
            if (code != 0) return false;
            *production = End();
            return true;
        case 10:
            if (code == 0) *production = Start(OptionElement::SelfContained, 6, 11);
            else if (code == 1) *production = Start(OptionElement::ValueMaxLength, 12, 14);
            else if (code == 2) *production = Start(OptionElement::ValuePartitionCapacity, 12, 15);
            else if (code == 3) *production = Start(OptionElement::DatatypeRepresentationMap, 16, 15);
            else if (code == 4) *production = End();
            else return false;
            return true;
        case 11:
            if (code == 0) *production = Start(OptionElement::ValueMaxLength, 12, 14);
            else if (code == 1) *production = Start(OptionElement::ValuePartitionCapacity, 12, 15);
            else if (code == 2) *production = Start(OptionElement::DatatypeRepresentationMap, 16, 15);
            else if (code == 3) *production = End();
            else return false;
            return true;
        case 12:
        case 13:
            if (code != 0) return false;
            *production = UnsignedCharacters(8);
            return true;
        case 14:
            if (code == 0) *production = Start(OptionElement::ValuePartitionCapacity, 12, 15);
            else if (code == 1) *production = Start(OptionElement::DatatypeRepresentationMap, 16, 15);
            else if (code == 2) *production = End();
            else return false;
            return true;
        case 15:
            if (code == 0) *production = Start(OptionElement::DatatypeRepresentationMap, 16, 15);
            else if (code == 1) *production = End();
            else return false;
            return true;
        case 16:
            if (code != 0) return false;
            *production = GenericStart(6, 17);
            return true;
        case 17:
            if (code != 0) return false;
            *production = GenericStart(6, 18);
            return true;
        case 18:
            if (code != 0) return false;
            *production = End();
            return true;
        case 20:
            if (code == 0) *production = Start(OptionElement::Preserve, 21, 27);
            else if (code == 1) *production = Start(OptionElement::BlockSize, 12, 8);
            else if (code == 2) *production = End();
            else return false;
            return true;
        case 27:
            if (code == 0) *production = Start(OptionElement::BlockSize, 12, 8);
            else if (code == 1) *production = End();
            else return false;
            return true;
        case 21:
        case 26:
            if (code == 0) *production = Start(OptionElement::Dtd, 6, 22);
            else if (code == 1) *production = Start(OptionElement::Prefixes, 6, 23);
            else if (code == 2) *production = Start(OptionElement::LexicalValues, 6, 24);
            else if (code == 3) *production = Start(OptionElement::Comments, 6, 25);
            else if (code == 4) *production = Start(OptionElement::Pis, 6, 8);
            else if (code == 5) *production = End();
            else return false;
            return true;
        case 22:
            if (code == 0) *production = Start(OptionElement::Prefixes, 6, 23);
            else if (code == 1) *production = Start(OptionElement::LexicalValues, 6, 24);
            else if (code == 2) *production = Start(OptionElement::Comments, 6, 25);
            else if (code == 3) *production = Start(OptionElement::Pis, 6, 8);
            else if (code == 4) *production = End();
            else return false;
            return true;
        case 23:
            if (code == 0) *production = Start(OptionElement::LexicalValues, 6, 24);
            else if (code == 1) *production = Start(OptionElement::Comments, 6, 25);
            else if (code == 2) *production = Start(OptionElement::Pis, 6, 8);
            else if (code == 3) *production = End();
            else return false;
            return true;
        case 24:
            if (code == 0) *production = Start(OptionElement::Comments, 6, 25);
            else if (code == 1) *production = Start(OptionElement::Pis, 6, 8);
            else if (code == 2) *production = End();
            else return false;
            return true;
        case 25:
            if (code == 0) *production = Start(OptionElement::Pis, 6, 8);
            else if (code == 1) *production = End();
            else return false;
            return true;
        case 28:
            if (code == 0) *production = Start(OptionElement::Uncommon, 4, 20);
            else if (code == 1) *production = Start(OptionElement::Preserve, 21, 27);
            else if (code == 2) *production = Start(OptionElement::BlockSize, 12, 8);
            else if (code == 3) *production = End();
            else return false;
            return true;
        case 29:
            if (code == 0) *production = Start(OptionElement::Common, 30, 36);
            else if (code == 1) *production = Start(OptionElement::Strict, 6, 8);
            else if (code == 2) *production = End();
            else return false;
            return true;
        case 30:
        case 35:
            if (code == 0) *production = Start(OptionElement::Compression, 6, 31);
            else if (code == 1) *production = Start(OptionElement::Fragment, 6, 32);
            else if (code == 2) *production = Start(OptionElement::SchemaId, 33, 8);
            else if (code == 3) *production = End();
            else return false;
            return true;
        case 31:
            if (code == 0) *production = Start(OptionElement::Fragment, 6, 32);
            else if (code == 1) *production = Start(OptionElement::SchemaId, 33, 8);
            else if (code == 2) *production = End();
            else return false;
            return true;
        case 32:
            if (code == 0) *production = Start(OptionElement::SchemaId, 33, 8);
            else if (code == 1) *production = End();
            else return false;
            return true;
        case 33:
        case 34:
            if (code == 0) *production = StringCharacters(8);
            else if (code == 1) *production = XsiNil();
            else return false;
            return true;
        case 36:
            if (code == 0) *production = Start(OptionElement::Strict, 6, 8);
            else if (code == 1) *production = End();
            else return false;
            return true;
        case 37:
            if (code == 0) *production = Start(OptionElement::LessCommon, 3, 29);
            else if (code == 1) *production = Start(OptionElement::Common, 30, 36);
            else if (code == 2) *production = Start(OptionElement::Strict, 6, 8);
            else if (code == 3) *production = End();
            else return false;
            return true;
        case 38:
            if (code != 0) return false;
            *production = { OptionEvent::EndDocument, OptionElement::None, 0, 0 };
            return true;
        default:
            return false;
        }
    }

    _Must_inspect_result_
    ULONG ProductionCount(UCHAR grammar) noexcept
    {
        switch (grammar) {
        case 2: return 4;
        case 3: return 4;
        case 4: return 6;
        case 5: return 2;
        case 6: return 1;
        case 8: return 1;
        case 9: return 2;
        case 10: return 5;
        case 11: return 4;
        case 12: return 1;
        case 13: return 1;
        case 14: return 3;
        case 15: return 2;
        case 16: return 1;
        case 17: return 1;
        case 18: return 1;
        case 19: return 7;
        case 20: return 3;
        case 21: return 6;
        case 22: return 5;
        case 23: return 4;
        case 24: return 3;
        case 25: return 2;
        case 26: return 6;
        case 27: return 2;
        case 28: return 4;
        case 29: return 3;
        case 30: return 4;
        case 31: return 3;
        case 32: return 2;
        case 33: return 2;
        case 34: return 2;
        case 35: return 4;
        case 36: return 2;
        case 37: return 4;
        case 38: return 1;
        default: return 0;
        }
    }

    _Must_inspect_result_
    NTSTATUS ApplyEmptyOption(
        OptionElement element,
        _Inout_ HttpExiOptions* options) noexcept
    {
        if (options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        switch (element) {
        case OptionElement::Byte:
            if (options->Alignment != HttpExiAlignment::BitPacked) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            options->Alignment = HttpExiAlignment::ByteAligned;
            break;
        case OptionElement::PreCompress:
            if (options->Alignment != HttpExiAlignment::BitPacked) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            options->Alignment = HttpExiAlignment::PreCompression;
            break;
        case OptionElement::Compression:
            if (options->Alignment != HttpExiAlignment::BitPacked) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            options->Alignment = HttpExiAlignment::Compression;
            break;
        case OptionElement::SelfContained:
            options->SelfContained = true;
            break;
        case OptionElement::Dtd:
            options->PreserveDtd = true;
            break;
        case OptionElement::Prefixes:
            options->PreservePrefixes = true;
            break;
        case OptionElement::LexicalValues:
            options->PreserveLexicalValues = true;
            break;
        case OptionElement::Comments:
            options->PreserveComments = true;
            break;
        case OptionElement::Pis:
            options->PreservePis = true;
            break;
        case OptionElement::Fragment:
            options->Fragment = true;
            break;
        case OptionElement::Strict:
            options->Strict = true;
            break;
        case OptionElement::SchemaId:
            options->HasSchemaId = true;
            break;
        case OptionElement::DatatypeRepresentationMap:
            break;
        default:
            break;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ParseOptionsDocument(
        _Inout_ HttpExiBitInput* input,
        SIZE_T sourceLength,
        _Inout_ HttpExiOptions* options) noexcept
    {
        if (input == nullptr || options == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        if (sourceLength == maxSize || sourceLength > (maxSize - 4) / 4) {
            return STATUS_INTEGER_OVERFLOW;
        }

        ULONG rootCode = 0;
        if (!ReadChoice(input, 2, &rootCode) || rootCode != 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        HeapArray<OptionStackEntry> stack(sourceLength + 1);
        if (!stack.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        HttpExiStringTable stringValues = {};
        NTSTATUS status = stringValues.Initialize(sourceLength + 1, sourceLength * 4 + 4);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpExiStringTable optionUris = {};
        HttpExiStringTable optionLocalNames = {};
        HttpExiStringTable optionPrefixes = {};
        HttpExiQNameTable optionQNames = {};
        status = InitializeOptionNameTables(
            &optionUris,
            &optionLocalNames,
            &optionPrefixes,
            &optionQNames);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HttpExiNameTables optionNames = {};
        optionNames.Uris = &optionUris;
        optionNames.LocalNames = &optionLocalNames;
        optionNames.Prefixes = &optionPrefixes;
        optionNames.QNames = &optionQNames;

        SIZE_T depth = 1;
        stack[0].ContinuationGrammar = 38;
        stack[0].ParentElement = OptionElement::None;
        UCHAR grammar = 2;
        OptionElement currentElement = OptionElement::Header;

        for (;;) {
            const ULONG count = ProductionCount(grammar);
            ULONG code = 0;
            OptionProduction production = {};
            if (count == 0 ||
                !ReadChoice(input, count, &code) ||
                code >= count ||
                !SelectProduction(grammar, code, &production)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            switch (production.Event) {
            case OptionEvent::StartElement:
                status = ApplyEmptyOption(production.Element, options);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (depth >= stack.Count()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                stack[depth].ContinuationGrammar = production.NextGrammar;
                stack[depth].ParentElement = currentElement;
                ++depth;
                grammar = production.ChildGrammar;
                currentElement = production.Element;
                break;

            case OptionEvent::StartElementGeneric:
                {
                    if (currentElement != OptionElement::DatatypeRepresentationMap) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    ULONG ignoredQNameId = 0;
                    HttpXmlName ignoredName = {};
                    status = HttpExiReadQNameLiteral(
                        input,
                        &optionNames,
                        false,
                        &ignoredQNameId,
                        &ignoredName);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    ULONG endElementCode = 0;
                    if (!input->ReadBits(2, &endElementCode) ||
                        (endElementCode != 0 && endElementCode != 2)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    grammar = production.NextGrammar;
                }
                break;

            case OptionEvent::EndElement:
                if (depth == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                --depth;
                grammar = stack[depth].ContinuationGrammar;
                currentElement = stack[depth].ParentElement;
                break;

            case OptionEvent::CharactersUnsigned:
                {
                    ULONG value = 0;
                    if (!input->ReadUnsignedInteger(&value)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (currentElement == OptionElement::ValueMaxLength) {
                        options->ValueMaxLength = value;
                    }
                    else if (currentElement == OptionElement::ValuePartitionCapacity) {
                        options->ValuePartitionCapacity = value;
                    }
                    else if (currentElement == OptionElement::BlockSize) {
                        if (value == 0) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        options->BlockSize = value;
                    }
                    else {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    grammar = production.NextGrammar;
                }
                break;

            case OptionEvent::CharactersString:
                {
                    if (currentElement != OptionElement::SchemaId) {
                        return STATUS_NOT_SUPPORTED;
                    }
                    HttpXmlText schemaId = {};
                    status = HttpExiReadValueString(input, &stringValues, &schemaId);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    options->BuiltInSchemaTypesOnly = schemaId.Length == 0;
                    if (schemaId.Length != 0) {
                        return STATUS_NOT_SUPPORTED;
                    }
                    grammar = production.NextGrammar;
                }
                break;

            case OptionEvent::AttributeXsiNil:
                {
                    if (currentElement != OptionElement::SchemaId) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    ULONG nil = 0;
                    if (!input->ReadBits(1, &nil)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    options->BuiltInSchemaTypesOnly = false;
                    grammar = nil != 0 ? 8 : 34;
                }
                break;

            case OptionEvent::EndDocument:
                if (depth != 0 || currentElement != OptionElement::None) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (options->Strict ||
                    (options->SelfContained &&
                        (options->Alignment == HttpExiAlignment::PreCompression ||
                         options->Alignment == HttpExiAlignment::Compression))) {
                    return options->Strict ? STATUS_NOT_SUPPORTED : STATUS_INVALID_NETWORK_RESPONSE;
                }
                return STATUS_SUCCESS;

            case OptionEvent::Unsupported:
            default:
                return STATUS_NOT_SUPPORTED;
            }
        }
    }
}

    NTSTATUS HttpExiParseHeader(
        const UCHAR* source,
        SIZE_T sourceLength,
        HttpExiOptions* options,
        SIZE_T* bodyBitOffset) noexcept
    {
        if (source == nullptr || options == nullptr || bodyBitOffset == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *options = {};
        *bodyBitOffset = 0;

        SIZE_T initialBitOffset = 0;
        if (sourceLength >= 4 &&
            source[0] == '$' &&
            source[1] == 'E' &&
            source[2] == 'X' &&
            source[3] == 'I') {
            options->HasCookie = true;
            initialBitOffset = 32;
        }

        HttpExiBitInput input(source, sourceLength, HttpExiInputMode::BitPacked, initialBitOffset);
        ULONG distinguishing = 0;
        ULONG presence = 0;
        ULONG preview = 0;
        if (!input.ReadBits(2, &distinguishing) ||
            distinguishing != 2 ||
            !input.ReadBits(1, &presence) ||
            !input.ReadBits(1, &preview)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        ULONG version = 0;
        for (;;) {
            ULONG part = 0;
            if (!input.ReadBits(4, &part) || part > 15 || version > 0xffffffffUL - part) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            version += part;
            if (part != 15) {
                break;
            }
        }
        if (preview != 0 || version != 0) {
            return STATUS_NOT_SUPPORTED;
        }

        options->HasOptions = presence != 0;
        if (options->HasOptions) {
            const NTSTATUS status = ParseOptionsDocument(&input, sourceLength, options);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        if (options->Alignment != HttpExiAlignment::BitPacked && !input.AlignByte()) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *bodyBitOffset = input.BitOffset();
        return *bodyBitOffset / 8 <= sourceLength ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }
}
}
