#include "HttpExiDecoder.h"
#include "HttpDeflateDecoder.h"
#include "HttpExiEventReader.h"
#include "HttpExiGrammar.h"
#include "HttpExiGrammarTable.h"
#include "HttpExiOptions.h"
#include "HttpExiQNameReader.h"
#include "HttpExiStringTable.h"
#include "HttpExiValueDecoder.h"
#include "HttpXmlWriter.h"

namespace KernelHttp
{
namespace http
{
namespace
{
    _Must_inspect_result_
    HttpXmlText LiteralText(const char* value, SIZE_T length) noexcept
    {
        HttpXmlText text = {};
        text.Data = value;
        text.Length = length;
        return text;
    }

    _Must_inspect_result_
    bool ExiTextEquals(HttpXmlText left, HttpXmlText right) noexcept;

    _Must_inspect_result_
    bool IsXsiTypeName(HttpXmlName name) noexcept
    {
        constexpr char XsiUri[] = "http://www.w3.org/2001/XMLSchema-instance";
        constexpr char TypeName[] = "type";
        return name.Uri.Length == sizeof(XsiUri) - 1 &&
            name.LocalName.Length == sizeof(TypeName) - 1 &&
            name.Uri.Data != nullptr &&
            name.LocalName.Data != nullptr &&
            RtlCompareMemory(name.Uri.Data, XsiUri, sizeof(XsiUri) - 1) == sizeof(XsiUri) - 1 &&
            RtlCompareMemory(name.LocalName.Data, TypeName, sizeof(TypeName) - 1) == sizeof(TypeName) - 1;
    }

    _Must_inspect_result_
    HttpExiDatatypeKind BuiltInDatatypeForQName(HttpXmlName name) noexcept
    {
        constexpr char XsdUri[] = "http://www.w3.org/2001/XMLSchema";
        if (name.Uri.Data == nullptr ||
            name.Uri.Length != sizeof(XsdUri) - 1 ||
            RtlCompareMemory(name.Uri.Data, XsdUri, sizeof(XsdUri) - 1) != sizeof(XsdUri) - 1) {
            return HttpExiDatatypeKind::None;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("boolean", 7))) {
            return HttpExiDatatypeKind::Boolean;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("integer", 7))) {
            return HttpExiDatatypeKind::Integer;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("decimal", 7))) {
            return HttpExiDatatypeKind::Decimal;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("float", 5)) ||
            ExiTextEquals(name.LocalName, LiteralText("double", 6))) {
            return HttpExiDatatypeKind::Float;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("base64Binary", 12))) {
            return HttpExiDatatypeKind::Base64Binary;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("hexBinary", 9))) {
            return HttpExiDatatypeKind::HexBinary;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("string", 6))) {
            return HttpExiDatatypeKind::String;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("byte", 4))) {
            return HttpExiDatatypeKind::Byte;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("short", 5))) {
            return HttpExiDatatypeKind::Integer;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("int", 3))) {
            return HttpExiDatatypeKind::Integer;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("long", 4))) {
            return HttpExiDatatypeKind::Integer;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("unsignedByte", 12))) {
            return HttpExiDatatypeKind::UnsignedByte;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("unsignedShort", 13))) {
            return HttpExiDatatypeKind::NonNegativeInteger;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("unsignedInt", 11))) {
            return HttpExiDatatypeKind::NonNegativeInteger;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("unsignedLong", 12))) {
            return HttpExiDatatypeKind::NonNegativeInteger;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("nonNegativeInteger", 18))) {
            return HttpExiDatatypeKind::NonNegativeInteger;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("positiveInteger", 15))) {
            return HttpExiDatatypeKind::PositiveInteger;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("gYear", 5))) {
            return HttpExiDatatypeKind::GYear;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("gYearMonth", 10))) {
            return HttpExiDatatypeKind::GYearMonth;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("date", 4))) {
            return HttpExiDatatypeKind::Date;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("dateTime", 8))) {
            return HttpExiDatatypeKind::DateTime;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("gMonth", 6))) {
            return HttpExiDatatypeKind::GMonth;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("gMonthDay", 9))) {
            return HttpExiDatatypeKind::GMonthDay;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("gDay", 4))) {
            return HttpExiDatatypeKind::GDay;
        }
        if (ExiTextEquals(name.LocalName, LiteralText("time", 4))) {
            return HttpExiDatatypeKind::Time;
        }
        return HttpExiDatatypeKind::None;
    }

    _Must_inspect_result_
    bool ExiTextEquals(HttpXmlText left, HttpXmlText right) noexcept
    {
        return left.Length == right.Length &&
            (left.Length == 0 ||
                (left.Data != nullptr &&
                 right.Data != nullptr &&
                 RtlCompareMemory(left.Data, right.Data, left.Length) == left.Length));
    }

    _Must_inspect_result_
    bool ExiQNameEquals(HttpXmlName left, HttpXmlName right) noexcept
    {
        return ExiTextEquals(left.Uri, right.Uri) &&
            ExiTextEquals(left.LocalName, right.LocalName);
    }

    class ExiXmlEventSink final
    {
        struct PendingNamespace final
        {
            HttpXmlText Prefix = {};
            HttpXmlText Uri = {};
        };

        struct NamespaceBinding final
        {
            HttpXmlText Prefix = {};
            HttpXmlText Uri = {};
            SIZE_T Depth = 0;
        };

    public:
        ExiXmlEventSink(char* destination, SIZE_T destinationCapacity) noexcept :
            writer_(destination, destinationCapacity)
        {
        }

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxPendingNamespaces, bool preservePrefixes) noexcept
        {
            const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
            if (maxPendingNamespaces > maxSize / 24) {
                return STATUS_INTEGER_OVERFLOW;
            }
            NTSTATUS status = pendingNamespaces_.Allocate(maxPendingNamespaces);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = generatedBindings_.Allocate(maxPendingNamespaces);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = activeBindings_.Allocate(maxPendingNamespaces);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = elementNames_.Allocate(maxPendingNamespaces);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = generatedPrefixText_.Allocate(maxPendingNamespaces * 24);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            preservePrefixes_ = preservePrefixes;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        SIZE_T Length() const noexcept
        {
            return writer_.Length();
        }

        _Must_inspect_result_
        NTSTATUS StartElement(HttpXmlName name) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            pendingName_ = name;
            pendingNamespaceCount_ = 0;
            hasPendingStartElement_ = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS Namespace(
            HttpXmlText prefix,
            HttpXmlText uri,
            bool localElementNamespace) noexcept
        {
            if (!hasPendingStartElement_ ||
                !pendingNamespaces_.IsValid() ||
                pendingNamespaceCount_ >= pendingNamespaces_.Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (localElementNamespace) {
                pendingName_.Prefix = prefix;
            }
            pendingNamespaces_[pendingNamespaceCount_].Prefix = prefix;
            pendingNamespaces_[pendingNamespaceCount_].Uri = uri;
            ++pendingNamespaceCount_;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS Attribute(HttpXmlName name, HttpXmlText value) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            HttpXmlName resolvedName = {};
            bool declareBinding = false;
            status = ResolveName(name, &resolvedName, &declareBinding);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (declareBinding) {
                if (elementDepth_ == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = writer_.WriteNamespace(resolvedName.Prefix, resolvedName.Uri);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AddActiveBinding(
                    resolvedName.Prefix,
                    resolvedName.Uri,
                    elementDepth_ - 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            return writer_.WriteAttribute(resolvedName, value);
        }

        _Must_inspect_result_
        NTSTATUS QNameAttribute(HttpXmlName name, HttpXmlName value) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            HttpXmlName resolvedName = {};
            bool declareNameBinding = false;
            status = ResolveName(name, &resolvedName, &declareNameBinding);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (declareNameBinding) {
                if (elementDepth_ == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = writer_.WriteNamespace(resolvedName.Prefix, resolvedName.Uri);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AddActiveBinding(
                    resolvedName.Prefix,
                    resolvedName.Uri,
                    elementDepth_ - 1);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            HttpXmlName resolvedValue = value;
            if (value.Uri.Length == 0) {
                resolvedValue.Prefix = {};
            }
            else {
                bool declareValueBinding = false;
                status = ResolveName(value, &resolvedValue, &declareValueBinding);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (declareValueBinding) {
                    if (elementDepth_ == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = writer_.WriteNamespace(resolvedValue.Prefix, resolvedValue.Uri);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = AddActiveBinding(
                        resolvedValue.Prefix,
                        resolvedValue.Uri,
                        elementDepth_ - 1);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }
            return writer_.WriteQNameAttribute(resolvedName, resolvedValue);
        }

        _Must_inspect_result_
        NTSTATUS Characters(HttpXmlText value) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return writer_.WriteCharacters(value);
        }

        _Must_inspect_result_
        NTSTATUS Comment(HttpXmlText value) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return writer_.WriteComment(value);
        }

        _Must_inspect_result_
        NTSTATUS ProcessingInstruction(HttpXmlText target, HttpXmlText value) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return writer_.WriteProcessingInstruction(target, value);
        }

        _Must_inspect_result_
        NTSTATUS Dtd(
            HttpXmlText name,
            HttpXmlText publicId,
            HttpXmlText systemId,
            HttpXmlText text) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return writer_.WriteDtd(name, publicId, systemId, text);
        }

        _Must_inspect_result_
        NTSTATUS EntityReference(HttpXmlText name) noexcept
        {
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            return writer_.WriteEntityReference(name);
        }

        _Must_inspect_result_
        NTSTATUS EndElement(HttpXmlName name) noexcept
        {
            UNREFERENCED_PARAMETER(name);
            NTSTATUS status = FlushPendingStartElement();
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (elementDepth_ == 0 || !elementNames_.IsValid()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            --elementDepth_;
            status = writer_.WriteEndElement(elementNames_[elementDepth_]);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            while (activeBindingCount_ != 0 &&
                activeBindings_[activeBindingCount_ - 1].Depth >= elementDepth_) {
                --activeBindingCount_;
            }
            return STATUS_SUCCESS;
        }

    private:
        _Must_inspect_result_
        static bool TextEquals(HttpXmlText left, HttpXmlText right) noexcept
        {
            return left.Length == right.Length &&
                (left.Length == 0 ||
                    (left.Data != nullptr &&
                     right.Data != nullptr &&
                     RtlCompareMemory(left.Data, right.Data, left.Length) == left.Length));
        }

        _Must_inspect_result_
        static bool IsXmlNamespace(HttpXmlText uri) noexcept
        {
            constexpr char XmlUri[] = "http://www.w3.org/XML/1998/namespace";
            return uri.Length == sizeof(XmlUri) - 1 &&
                uri.Data != nullptr &&
                RtlCompareMemory(uri.Data, XmlUri, sizeof(XmlUri) - 1) == sizeof(XmlUri) - 1;
        }

        _Must_inspect_result_
        NTSTATUS GeneratePrefix(HttpXmlText uri, _Out_ HttpXmlText* prefix) noexcept
        {
            if (prefix == nullptr || !generatedBindings_.IsValid() ||
                !generatedPrefixText_.IsValid() ||
                generatedBindingCount_ >= generatedBindings_.Count()) {
                return STATUS_INVALID_PARAMETER;
            }
            for (SIZE_T index = 0; index < generatedBindingCount_; ++index) {
                if (TextEquals(generatedBindings_[index].Uri, uri)) {
                    *prefix = generatedBindings_[index].Prefix;
                    return STATUS_SUCCESS;
                }
            }

            SIZE_T digits = 1;
            SIZE_T value = generatedBindingCount_;
            while (value >= 10) {
                value /= 10;
                ++digits;
            }
            const SIZE_T required = 2 + digits;
            if (required > generatedPrefixText_.Count() - generatedPrefixTextLength_) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            char* output = generatedPrefixText_.Get() + generatedPrefixTextLength_;
            output[0] = 'n';
            output[1] = 's';
            value = generatedBindingCount_;
            for (SIZE_T index = 0; index < digits; ++index) {
                output[required - index - 1] = static_cast<char>('0' + (value % 10));
                value /= 10;
            }
            HttpXmlText generated = {};
            generated.Data = output;
            generated.Length = required;
            generatedPrefixTextLength_ += required;
            generatedBindings_[generatedBindingCount_].Prefix = generated;
            generatedBindings_[generatedBindingCount_].Uri = uri;
            ++generatedBindingCount_;
            *prefix = generated;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ResolveName(
            HttpXmlName name,
            _Out_ HttpXmlName* resolved,
            _Out_ bool* declareBinding) noexcept
        {
            if (resolved == nullptr || declareBinding == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            *resolved = name;
            *declareBinding = false;
            if (preservePrefixes_ || name.Uri.Length == 0 || name.Prefix.Length != 0) {
                return STATUS_SUCCESS;
            }
            if (IsXmlNamespace(name.Uri)) {
                constexpr char XmlPrefix[] = "xml";
                resolved->Prefix.Data = XmlPrefix;
                resolved->Prefix.Length = sizeof(XmlPrefix) - 1;
                return STATUS_SUCCESS;
            }
            for (SIZE_T index = activeBindingCount_; index != 0; --index) {
                if (TextEquals(activeBindings_[index - 1].Uri, name.Uri)) {
                    resolved->Prefix = activeBindings_[index - 1].Prefix;
                    return STATUS_SUCCESS;
                }
            }
            NTSTATUS status = GeneratePrefix(name.Uri, &resolved->Prefix);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            *declareBinding = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AddActiveBinding(HttpXmlText prefix, HttpXmlText uri, SIZE_T depth) noexcept
        {
            if (!activeBindings_.IsValid() || activeBindingCount_ >= activeBindings_.Count()) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            activeBindings_[activeBindingCount_].Prefix = prefix;
            activeBindings_[activeBindingCount_].Uri = uri;
            activeBindings_[activeBindingCount_].Depth = depth;
            ++activeBindingCount_;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS FlushPendingStartElement() noexcept
        {
            if (!hasPendingStartElement_) {
                return STATUS_SUCCESS;
            }
            HttpXmlName resolvedName = {};
            bool declareBinding = false;
            NTSTATUS status = ResolveName(pendingName_, &resolvedName, &declareBinding);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (!elementNames_.IsValid() || elementDepth_ >= elementNames_.Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            status = writer_.WriteStartElement(resolvedName);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (declareBinding) {
                status = writer_.WriteNamespace(resolvedName.Prefix, resolvedName.Uri);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AddActiveBinding(resolvedName.Prefix, resolvedName.Uri, elementDepth_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            for (SIZE_T index = 0; index < pendingNamespaceCount_; ++index) {
                status = writer_.WriteNamespace(
                    pendingNamespaces_[index].Prefix,
                    pendingNamespaces_[index].Uri);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = AddActiveBinding(
                    pendingNamespaces_[index].Prefix,
                    pendingNamespaces_[index].Uri,
                    elementDepth_);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            elementNames_[elementDepth_] = resolvedName;
            ++elementDepth_;
            hasPendingStartElement_ = false;
            pendingNamespaceCount_ = 0;
            return STATUS_SUCCESS;
        }

        HttpXmlWriter writer_;
        HeapArray<PendingNamespace> pendingNamespaces_ = {};
        HeapArray<NamespaceBinding> generatedBindings_ = {};
        HeapArray<NamespaceBinding> activeBindings_ = {};
        HeapArray<HttpXmlName> elementNames_ = {};
        HeapArray<char> generatedPrefixText_ = {};
        HttpXmlName pendingName_ = {};
        SIZE_T pendingNamespaceCount_ = 0;
        SIZE_T generatedBindingCount_ = 0;
        SIZE_T activeBindingCount_ = 0;
        SIZE_T generatedPrefixTextLength_ = 0;
        SIZE_T elementDepth_ = 0;
        bool hasPendingStartElement_ = false;
        bool preservePrefixes_ = false;
    };

    class ExiDecodeState final
    {
        struct GrammarFrame final
        {
            HttpExiGrammarKind Kind = HttpExiGrammarKind::Document;
            ULONG OwnerQNameId = 0xffffffffUL;
            HttpExiDatatypeKind Datatype = HttpExiDatatypeKind::None;
        };

    public:
        _Must_inspect_result_
        NTSTATUS Initialize(
            const HttpExiOptions& options,
            SIZE_T encodedLength,
            SIZE_T destinationCapacity) noexcept
        {
            const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
            if (encodedLength > maxSize - 64 ||
                encodedLength > (maxSize - 512) / 4 ||
                encodedLength > (maxSize - 1) / 8) {
                return STATUS_INTEGER_OVERFLOW;
            }
            const SIZE_T maxGrammarDepth = encodedLength + 1;
            const SIZE_T maxNameEntries = encodedLength + 64;
            const SIZE_T encodedTextCapacity = encodedLength * 4 + 512;
            const SIZE_T maxLearnedProductions = encodedLength * 8 + 1;
            const SIZE_T maxTextBytes = destinationCapacity > encodedTextCapacity ?
                destinationCapacity :
                encodedTextCapacity;
            NTSTATUS status = uris_.Initialize(maxNameEntries, maxTextBytes);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = localNames_.Initialize(maxNameEntries, maxTextBytes);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = prefixes_.Initialize(maxNameEntries, maxTextBytes);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = values_.Initialize(
                maxNameEntries,
                maxTextBytes,
                options.ValueMaxLength,
                options.ValuePartitionCapacity);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = structureStrings_.Initialize(maxNameEntries, maxTextBytes);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = qnames_.Initialize(maxNameEntries);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = grammarStack_.Allocate(maxGrammarDepth);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = learnedGrammars_.Initialize(maxLearnedProductions);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = InitializeSchemaLessNames(options.BuiltInSchemaTypesOnly);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            grammarDepth_ = 0;
            return PushGrammar(
                options.Fragment ? HttpExiGrammarKind::Fragment : HttpExiGrammarKind::Document,
                0xffffffffUL);
        }

        _Must_inspect_result_
        NTSTATUS PushGrammar(HttpExiGrammarKind grammar, ULONG ownerQNameId) noexcept
        {
            if (!grammarStack_.IsValid() || grammarDepth_ >= grammarStack_.Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            grammarStack_[grammarDepth_].Kind = grammar;
            grammarStack_[grammarDepth_].OwnerQNameId = ownerQNameId;
            grammarStack_[grammarDepth_].Datatype = HttpExiDatatypeKind::None;
            ++grammarDepth_;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool CurrentGrammar(
            _Out_ HttpExiGrammarKind* grammar,
            _Out_opt_ ULONG* ownerQNameId = nullptr) const noexcept
        {
            if (grammar == nullptr || grammarDepth_ == 0 || !grammarStack_.IsValid()) {
                return false;
            }
            *grammar = grammarStack_[grammarDepth_ - 1].Kind;
            if (ownerQNameId != nullptr) {
                *ownerQNameId = grammarStack_[grammarDepth_ - 1].OwnerQNameId;
            }
            return true;
        }

        _Must_inspect_result_
        NTSTATUS PopGrammar() noexcept
        {
            if (grammarDepth_ == 0) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            --grammarDepth_;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS ReplaceCurrentGrammar(HttpExiGrammarKind grammar) noexcept
        {
            if (grammarDepth_ == 0 || !grammarStack_.IsValid()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            grammarStack_[grammarDepth_ - 1].Kind = grammar;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS SelectSchemaSimpleType(HttpExiDatatypeKind datatype) noexcept
        {
            if (datatype == HttpExiDatatypeKind::None ||
                grammarDepth_ == 0 ||
                !grammarStack_.IsValid()) {
                return STATUS_INVALID_PARAMETER;
            }
            grammarStack_[grammarDepth_ - 1].Kind = HttpExiGrammarKind::SchemaSimpleTypeContent;
            grammarStack_[grammarDepth_ - 1].Datatype = datatype;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool CurrentDatatype(_Out_ HttpExiDatatypeKind* datatype) const noexcept
        {
            if (datatype == nullptr || grammarDepth_ == 0 || !grammarStack_.IsValid()) {
                return false;
            }
            *datatype = grammarStack_[grammarDepth_ - 1].Datatype;
            return true;
        }

        _Must_inspect_result_
        NTSTATUS LearnProduction(
            ULONG ownerQNameId,
            HttpExiGrammarKind grammar,
            HttpExiEventKind event,
            ULONG qnameId) noexcept
        {
            HttpExiGrammarKind nextGrammar = grammar;
            bool pushElementGrammar = false;
            bool popGrammar = false;
            switch (event) {
            case HttpExiEventKind::StartElement:
                nextGrammar = grammar == HttpExiGrammarKind::FragmentContent ?
                    HttpExiGrammarKind::FragmentContent :
                    HttpExiGrammarKind::ElementContent;
                pushElementGrammar = true;
                break;
            case HttpExiEventKind::Characters:
                nextGrammar = HttpExiGrammarKind::ElementContent;
                break;
            case HttpExiEventKind::EndElement:
                popGrammar = true;
                break;
            case HttpExiEventKind::Attribute:
                nextGrammar = HttpExiGrammarKind::StartTagContent;
                break;
            default:
                return STATUS_INVALID_PARAMETER;
            }
            ULONG productionIndex = 0;
            return learnedGrammars_.Learn(
                ownerQNameId,
                grammar,
                event,
                qnameId,
                nextGrammar,
                pushElementGrammar,
                popGrammar,
                &productionIndex);
        }

        _Must_inspect_result_
        SIZE_T LearnedProductionCount(ULONG ownerQNameId, HttpExiGrammarKind grammar) const noexcept
        {
            return learnedGrammars_.Count(ownerQNameId, grammar);
        }

        _Must_inspect_result_
        bool LearnedProductionByEventCode(
            ULONG ownerQNameId,
            HttpExiGrammarKind grammar,
            ULONG eventCode,
            _Out_ HttpExiLearnedProduction* production) const noexcept
        {
            return learnedGrammars_.GetByEventCode(ownerQNameId, grammar, eventCode, production);
        }

        _Must_inspect_result_
        HttpExiNameTables NameTables() noexcept
        {
            HttpExiNameTables tables = {};
            tables.Uris = &uris_;
            tables.LocalNames = &localNames_;
            tables.Prefixes = &prefixes_;
            tables.QNames = &qnames_;
            return tables;
        }

        _Must_inspect_result_
        HttpExiValueTable* ValueTable() noexcept
        {
            return &values_;
        }

        _Must_inspect_result_
        HttpExiStringTable* StructureStringTable() noexcept
        {
            return &structureStrings_;
        }

        _Must_inspect_result_
        NTSTATUS InitializeSchemaLessNames(bool includeBuiltInSchemaTypes) noexcept
        {
            constexpr char Empty[] = "";
            constexpr char XmlUri[] = "http://www.w3.org/XML/1998/namespace";
            constexpr char XsiUri[] = "http://www.w3.org/2001/XMLSchema-instance";
            constexpr char XsdUri[] = "http://www.w3.org/2001/XMLSchema";
            constexpr char XmlPrefix[] = "xml";
            constexpr char XsiPrefix[] = "xsi";
            constexpr const char* XmlNames[] = { "base", "id", "lang", "space" };
            constexpr SIZE_T XmlNameLengths[] = { 4, 2, 4, 5 };
            constexpr const char* XsiNames[] = { "nil", "type" };
            constexpr SIZE_T XsiNameLengths[] = { 3, 4 };
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
            constexpr SIZE_T XsdNameLengths[] = {
                8, 6, 2, 5, 6, 6, 7, 8, 8, 4, 5, 13, 7, 6, 12, 7,
                4, 4, 8, 7, 6, 8, 5, 4, 6, 9, 5, 10, 9, 3, 7, 8,
                4, 15, 18, 18, 16, 15, 5, 6, 4, 5, 12, 11, 12, 13
            };

            ULONG emptyUriId = 0;
            ULONG xmlUriId = 0;
            ULONG xsiUriId = 0;
            ULONG xsdUriId = 0;
            NTSTATUS status = uris_.Add(LiteralText(Empty, 0), &emptyUriId);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = uris_.Add(LiteralText(XmlUri, sizeof(XmlUri) - 1), &xmlUriId);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = uris_.Add(LiteralText(XsiUri, sizeof(XsiUri) - 1), &xsiUriId);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (includeBuiltInSchemaTypes) {
                status = uris_.Add(LiteralText(XsdUri, sizeof(XsdUri) - 1), &xsdUriId);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }

            ULONG ignored = 0;
            ULONG emptyPrefixId = 0;
            ULONG xmlPrefixId = 0;
            ULONG xsiPrefixId = 0;
            status = prefixes_.Add(LiteralText(Empty, 0), &emptyPrefixId);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = prefixes_.Add(LiteralText(XmlPrefix, sizeof(XmlPrefix) - 1), &xmlPrefixId);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = prefixes_.Add(LiteralText(XsiPrefix, sizeof(XsiPrefix) - 1), &xsiPrefixId);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            HttpExiQNameEntry prefixAssociation = {};
            prefixAssociation.LocalNameId = 0xffffffffUL;
            prefixAssociation.UriId = emptyUriId;
            prefixAssociation.PrefixId = emptyPrefixId;
            status = qnames_.Add(prefixAssociation, &ignored);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            prefixAssociation.UriId = xmlUriId;
            prefixAssociation.PrefixId = xmlPrefixId;
            status = qnames_.Add(prefixAssociation, &ignored);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            prefixAssociation.UriId = xsiUriId;
            prefixAssociation.PrefixId = xsiPrefixId;
            status = qnames_.Add(prefixAssociation, &ignored);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            for (SIZE_T index = 0; index < sizeof(XmlNames) / sizeof(XmlNames[0]); ++index) {
                ULONG localId = 0;
                status = localNames_.Add(LiteralText(XmlNames[index], XmlNameLengths[index]), &localId);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                HttpExiQNameEntry entry = {};
                entry.UriId = xmlUriId;
                entry.LocalNameId = localId;
                entry.PrefixId = 0xffffffffUL;
                status = qnames_.Add(entry, &ignored);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            for (SIZE_T index = 0; index < sizeof(XsiNames) / sizeof(XsiNames[0]); ++index) {
                ULONG localId = 0;
                status = localNames_.Add(LiteralText(XsiNames[index], XsiNameLengths[index]), &localId);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                HttpExiQNameEntry entry = {};
                entry.UriId = xsiUriId;
                entry.LocalNameId = localId;
                entry.PrefixId = 0xffffffffUL;
                status = qnames_.Add(entry, &ignored);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
            }
            if (includeBuiltInSchemaTypes) {
                for (SIZE_T index = 0; index < sizeof(XsdNames) / sizeof(XsdNames[0]); ++index) {
                    ULONG localId = 0;
                    status = localNames_.Add(LiteralText(XsdNames[index], XsdNameLengths[index]), &localId);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    HttpExiQNameEntry entry = {};
                    entry.UriId = xsdUriId;
                    entry.LocalNameId = localId;
                    entry.PrefixId = 0xffffffffUL;
                    status = qnames_.Add(entry, &ignored);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }
            return STATUS_SUCCESS;
        }

    private:
        HttpExiStringTable uris_ = {};
        HttpExiStringTable localNames_ = {};
        HttpExiStringTable prefixes_ = {};
        HttpExiValueTable values_ = {};
        HttpExiStringTable structureStrings_ = {};
        HttpExiQNameTable qnames_ = {};
        HttpExiGrammarTable learnedGrammars_ = {};
        HeapArray<GrammarFrame> grammarStack_ = {};
        SIZE_T grammarDepth_ = 0;
    };

    class ExiSelfContainedStateStack final
    {
        struct Frame final
        {
            ExiDecodeState* State = nullptr;
            HttpXmlName ExpectedRoot = {};
            SIZE_T RootDepth = 0;
            bool RootStarted = false;
        };

    public:
        ~ExiSelfContainedStateStack() noexcept
        {
            Reset();
        }

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxDepth, _Inout_ ExiDecodeState* initialState) noexcept
        {
            Reset();
            if (maxDepth == 0 || initialState == nullptr) {
                return STATUS_INVALID_PARAMETER;
            }
            NTSTATUS status = frames_.Allocate(maxDepth);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            frames_[0].State = initialState;
            frameCount_ = 1;
            return STATUS_SUCCESS;
        }

        void Reset() noexcept
        {
            while (frameCount_ > 1) {
                --frameCount_;
                FreeNonPagedObject(frames_[frameCount_].State);
                frames_[frameCount_] = {};
            }
            frames_.Reset();
            frameCount_ = 0;
        }

        _Must_inspect_result_
        bool InSelfContainedFragment() const noexcept
        {
            return frameCount_ > 1;
        }

        _Must_inspect_result_
        bool RootStarted() const noexcept
        {
            return InSelfContainedFragment() && frames_[frameCount_ - 1].RootStarted;
        }

        _Must_inspect_result_
        SIZE_T RootDepth() const noexcept
        {
            return InSelfContainedFragment() ? frames_[frameCount_ - 1].RootDepth : 0;
        }

        _Must_inspect_result_
        NTSTATUS Push(
            const HttpExiOptions& options,
            SIZE_T encodedLength,
            SIZE_T destinationCapacity,
            HttpXmlName expectedRoot,
            SIZE_T rootDepth,
            _Outptr_ ExiDecodeState** currentState) noexcept
        {
            if (currentState == nullptr || rootDepth == 0 ||
                !frames_.IsValid() || frameCount_ == 0 || frameCount_ >= frames_.Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ExiDecodeState* nestedState = AllocateNonPagedObject<ExiDecodeState>();
            if (nestedState == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            HttpExiOptions fragmentOptions = options;
            fragmentOptions.Fragment = true;
            const NTSTATUS status = nestedState->Initialize(
                fragmentOptions,
                encodedLength,
                destinationCapacity);
            if (!NT_SUCCESS(status)) {
                FreeNonPagedObject(nestedState);
                return status;
            }
            Frame& frame = frames_[frameCount_];
            frame.State = nestedState;
            frame.ExpectedRoot = expectedRoot;
            frame.RootDepth = rootDepth;
            frame.RootStarted = false;
            ++frameCount_;
            *currentState = nestedState;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        NTSTATUS AcceptRoot(HttpXmlName root, SIZE_T elementDepth) noexcept
        {
            if (!InSelfContainedFragment()) {
                return STATUS_INVALID_PARAMETER;
            }
            Frame& frame = frames_[frameCount_ - 1];
            if (frame.RootStarted || elementDepth != frame.RootDepth ||
                !ExiQNameEquals(root, frame.ExpectedRoot)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            frame.RootStarted = true;
            return STATUS_SUCCESS;
        }

        _Must_inspect_result_
        bool CanFinish(SIZE_T elementDepth) const noexcept
        {
            return InSelfContainedFragment() &&
                frames_[frameCount_ - 1].RootStarted &&
                elementDepth + 1 == frames_[frameCount_ - 1].RootDepth;
        }

        _Must_inspect_result_
        NTSTATUS Pop(_Outptr_ ExiDecodeState** currentState) noexcept
        {
            if (currentState == nullptr || !InSelfContainedFragment()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            --frameCount_;
            FreeNonPagedObject(frames_[frameCount_].State);
            frames_[frameCount_] = {};
            *currentState = frames_[frameCount_ - 1].State;
            return *currentState != nullptr ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
        }

    private:
        HeapArray<Frame> frames_ = {};
        SIZE_T frameCount_ = 0;
    };

    _Must_inspect_result_
    NTSTATUS ApplyGrammarTransition(
        _Inout_ ExiDecodeState* state,
        const HttpExiProduction& production,
        ULONG childQNameId = 0xffffffffUL) noexcept
    {
        if (state == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (production.PopGrammar) {
            return state->PopGrammar();
        }

        NTSTATUS status = state->ReplaceCurrentGrammar(production.NextGrammar);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (production.PushElementGrammar) {
            if (childQNameId == 0xffffffffUL) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            status = state->PushGrammar(HttpExiGrammarKind::StartTagContent, childQNameId);
        }
        return status;
    }

    _Must_inspect_result_
    NTSTATUS ReadEventText(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        ULONG qnameId,
        _Out_ HttpXmlText* value) noexcept
    {
        if (state == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        return HttpExiReadValueString(input, state->ValueTable(), qnameId, value);
    }

    _Must_inspect_result_
    NTSTATUS ReadStructureText(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        _Out_ HttpXmlText* value) noexcept
    {
        if (state == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        return HttpExiReadLiteralString(input, state->StructureStringTable(), value);
    }

    _Must_inspect_result_
    NTSTATUS ReadQNameEventValue(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        bool preservePrefix,
        _Out_ HttpXmlName* value) noexcept
    {
        if (state == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        HttpExiNameTables tables = state->NameTables();
        return HttpExiReadQNameValue(
            input,
            &tables,
            state->StructureStringTable(),
            preservePrefix,
            value);
    }

    _Must_inspect_result_
    NTSTATUS ReadEventName(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        bool preservePrefix,
        _Out_opt_ ULONG* qnameId,
        _Out_ HttpXmlName* name) noexcept
    {
        if (state == nullptr || name == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        HttpExiNameTables tables = state->NameTables();
        ULONG parsedQNameId = 0;
        const NTSTATUS status = HttpExiReadQNameLiteral(
            input,
            &tables,
            preservePrefix,
            &parsedQNameId,
            name);
        if (NT_SUCCESS(status) && qnameId != nullptr) {
            *qnameId = parsedQNameId;
        }
        return status;
    }

    struct DynamicExiEvent final
    {
        HttpExiProduction Production = {};
        ULONG QNameId = 0xffffffffUL;
        bool QNameEncoded = false;
        bool LearnProduction = false;
    };

    _Must_inspect_result_
    NTSTATUS ReadDynamicChoice(
        _Inout_ HttpExiBitInput* input,
        SIZE_T choiceCount,
        _Out_ ULONG* choice,
        _Out_ UCHAR* width) noexcept
    {
        if (input == nullptr || choice == nullptr || width == nullptr ||
            choiceCount == 0 || choiceCount > 0xffffffffULL) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        if (!HttpExiBitsForProductionCount(static_cast<ULONG>(choiceCount), width)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        *choice = 0;
        if (*width != 0 && !input->ReadBits(*width, choice)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return *choice < choiceCount ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
    }

    void SetDynamicProduction(
        HttpExiEventKind event,
        HttpExiGrammarKind nextGrammar,
        bool pushElementGrammar,
        bool popGrammar,
        _Out_ DynamicExiEvent* decoded) noexcept
    {
        decoded->Production.Event = event;
        decoded->Production.NextGrammar = nextGrammar;
        decoded->Production.PushElementGrammar = pushElementGrammar;
        decoded->Production.PopGrammar = popGrammar;
    }

    _Must_inspect_result_
    NTSTATUS ReadBuiltInElementEventCode(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        HttpExiGrammarKind grammar,
        ULONG ownerQNameId,
        const HttpExiOptions& options,
        _Out_ HttpExiEventCode* eventCode,
        _Out_ DynamicExiEvent* decoded) noexcept
    {
        if (input == nullptr || state == nullptr || eventCode == nullptr || decoded == nullptr ||
            ownerQNameId == 0xffffffffUL ||
            (grammar != HttpExiGrammarKind::StartTagContent &&
             grammar != HttpExiGrammarKind::ElementContent)) {
            return STATUS_INVALID_PARAMETER;
        }
        *eventCode = {};
        *decoded = {};

        const SIZE_T learnedCount = state->LearnedProductionCount(ownerQNameId, grammar);
        const SIZE_T builtInFirstLevelCount = grammar == HttpExiGrammarKind::ElementContent ? 1 : 0;
        ULONG first = 0;
        UCHAR firstWidth = 0;
        NTSTATUS status = ReadDynamicChoice(
            input,
            learnedCount + builtInFirstLevelCount + 1,
            &first,
            &firstWidth);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        eventCode->Value = first;
        eventCode->Width = firstWidth;

        if (first < learnedCount) {
            HttpExiLearnedProduction learned = {};
            if (!state->LearnedProductionByEventCode(ownerQNameId, grammar, first, &learned)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            decoded->QNameId = learned.QNameId;
            SetDynamicProduction(
                learned.Event,
                learned.NextGrammar,
                learned.PushElementGrammar,
                learned.PopGrammar,
                decoded);
            return STATUS_SUCCESS;
        }

        if (grammar == HttpExiGrammarKind::ElementContent && first == learnedCount) {
            SetDynamicProduction(
                HttpExiEventKind::EndElement,
                HttpExiGrammarKind::ElementContent,
                false,
                true,
                decoded);
            return STATUS_SUCCESS;
        }

        const bool hasThirdLevel = options.PreserveComments || options.PreservePis;
        const SIZE_T secondLevelCount = grammar == HttpExiGrammarKind::StartTagContent ?
            4 +
                (options.PreservePrefixes ? 1 : 0) +
                (options.SelfContained ? 1 : 0) +
                (options.PreserveDtd ? 1 : 0) +
                (hasThirdLevel ? 1 : 0) :
            2 +
                (options.PreserveDtd ? 1 : 0) +
                (hasThirdLevel ? 1 : 0);
        ULONG second = 0;
        UCHAR secondWidth = 0;
        status = ReadDynamicChoice(input, secondLevelCount, &second, &secondWidth);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        eventCode->Width = static_cast<UCHAR>(eventCode->Width + secondWidth);

        SIZE_T cursor = 0;
        if (grammar == HttpExiGrammarKind::StartTagContent) {
            if (second == cursor++) {
                decoded->LearnProduction = true;
                SetDynamicProduction(
                    HttpExiEventKind::EndElement,
                    HttpExiGrammarKind::StartTagContent,
                    false,
                    true,
                    decoded);
                return STATUS_SUCCESS;
            }
            if (second == cursor++) {
                decoded->QNameEncoded = true;
                decoded->LearnProduction = true;
                SetDynamicProduction(
                    HttpExiEventKind::Attribute,
                    HttpExiGrammarKind::StartTagContent,
                    false,
                    false,
                    decoded);
                return STATUS_SUCCESS;
            }
            if (options.PreservePrefixes && second == cursor++) {
                SetDynamicProduction(
                    HttpExiEventKind::NamespaceDeclaration,
                    HttpExiGrammarKind::StartTagContent,
                    false,
                    false,
                    decoded);
                return STATUS_SUCCESS;
            }
            if (options.SelfContained && second == cursor++) {
                SetDynamicProduction(
                    HttpExiEventKind::SelfContained,
                    HttpExiGrammarKind::StartTagContent,
                    false,
                    false,
                    decoded);
                return STATUS_SUCCESS;
            }
        }

        if (second == cursor++) {
            decoded->QNameEncoded = true;
            decoded->LearnProduction = true;
            SetDynamicProduction(
                HttpExiEventKind::StartElement,
                HttpExiGrammarKind::ElementContent,
                true,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        if (second == cursor++) {
            decoded->LearnProduction = true;
            SetDynamicProduction(
                HttpExiEventKind::Characters,
                HttpExiGrammarKind::ElementContent,
                false,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        if (options.PreserveDtd && second == cursor++) {
            SetDynamicProduction(
                HttpExiEventKind::EntityReference,
                HttpExiGrammarKind::ElementContent,
                false,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        if (!hasThirdLevel || second != cursor) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T thirdLevelCount =
            (options.PreserveComments ? 1 : 0) +
            (options.PreservePis ? 1 : 0);
        ULONG third = 0;
        UCHAR thirdWidth = 0;
        status = ReadDynamicChoice(input, thirdLevelCount, &third, &thirdWidth);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        eventCode->Width = static_cast<UCHAR>(eventCode->Width + thirdWidth);
        if (options.PreserveComments && third == 0) {
            SetDynamicProduction(
                HttpExiEventKind::Comment,
                HttpExiGrammarKind::ElementContent,
                false,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        if (options.PreservePis && third == (options.PreserveComments ? 1UL : 0UL)) {
            SetDynamicProduction(
                HttpExiEventKind::ProcessingInstruction,
                HttpExiGrammarKind::ElementContent,
                false,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS ReadBuiltInFragmentEventCode(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        const HttpExiOptions& options,
        _Out_ HttpExiEventCode* eventCode,
        _Out_ DynamicExiEvent* decoded) noexcept
    {
        if (input == nullptr || state == nullptr || eventCode == nullptr || decoded == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *eventCode = {};
        *decoded = {};

        constexpr ULONG FragmentOwner = 0xffffffffUL;
        const SIZE_T learnedCount = state->LearnedProductionCount(
            FragmentOwner,
            HttpExiGrammarKind::FragmentContent);
        const bool hasSecondLevel = options.PreserveComments || options.PreservePis;
        ULONG first = 0;
        UCHAR firstWidth = 0;
        NTSTATUS status = ReadDynamicChoice(
            input,
            learnedCount + 2 + (hasSecondLevel ? 1 : 0),
            &first,
            &firstWidth);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        eventCode->Value = first;
        eventCode->Width = firstWidth;

        if (first < learnedCount) {
            HttpExiLearnedProduction learned = {};
            if (!state->LearnedProductionByEventCode(
                    FragmentOwner,
                    HttpExiGrammarKind::FragmentContent,
                    first,
                    &learned)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            decoded->QNameId = learned.QNameId;
            SetDynamicProduction(
                learned.Event,
                learned.NextGrammar,
                learned.PushElementGrammar,
                learned.PopGrammar,
                decoded);
            return STATUS_SUCCESS;
        }
        if (first == learnedCount) {
            decoded->QNameEncoded = true;
            decoded->LearnProduction = true;
            SetDynamicProduction(
                HttpExiEventKind::StartElement,
                HttpExiGrammarKind::FragmentContent,
                true,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        if (first == learnedCount + 1) {
            SetDynamicProduction(
                HttpExiEventKind::EndDocument,
                HttpExiGrammarKind::FragmentContent,
                false,
                true,
                decoded);
            return STATUS_SUCCESS;
        }
        if (!hasSecondLevel || first != learnedCount + 2) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        const SIZE_T secondLevelCount =
            (options.PreserveComments ? 1 : 0) +
            (options.PreservePis ? 1 : 0);
        ULONG second = 0;
        UCHAR secondWidth = 0;
        status = ReadDynamicChoice(input, secondLevelCount, &second, &secondWidth);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        eventCode->Width = static_cast<UCHAR>(eventCode->Width + secondWidth);
        if (options.PreserveComments && second == 0) {
            SetDynamicProduction(
                HttpExiEventKind::Comment,
                HttpExiGrammarKind::FragmentContent,
                false,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        if (options.PreservePis && second == (options.PreserveComments ? 1UL : 0UL)) {
            SetDynamicProduction(
                HttpExiEventKind::ProcessingInstruction,
                HttpExiGrammarKind::FragmentContent,
                false,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS ReadExiEventCode(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        HttpExiGrammarKind grammar,
        ULONG ownerQNameId,
        const HttpExiOptions& options,
        _Out_ HttpExiEventCode* eventCode,
        _Out_ DynamicExiEvent* decoded) noexcept
    {
        if (grammar == HttpExiGrammarKind::SchemaSimpleTypeContent) {
            ULONG choice = 0;
            UCHAR width = 0;
            const NTSTATUS status = ReadDynamicChoice(input, 2, &choice, &width);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            eventCode->Value = choice;
            eventCode->Width = width;
            if (choice != 0) {
                return STATUS_NOT_SUPPORTED;
            }
            SetDynamicProduction(
                HttpExiEventKind::Characters,
                HttpExiGrammarKind::SchemaSimpleTypeEnd,
                false,
                false,
                decoded);
            return STATUS_SUCCESS;
        }
        if (grammar == HttpExiGrammarKind::SchemaSimpleTypeEnd) {
            ULONG choice = 0;
            UCHAR width = 0;
            const NTSTATUS status = ReadDynamicChoice(input, 2, &choice, &width);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            eventCode->Value = choice;
            eventCode->Width = width;
            if (choice != 0) {
                return STATUS_NOT_SUPPORTED;
            }
            *decoded = {};
            SetDynamicProduction(
                HttpExiEventKind::EndElement,
                HttpExiGrammarKind::SchemaSimpleTypeEnd,
                false,
                true,
                decoded);
            return STATUS_SUCCESS;
        }
        if (grammar == HttpExiGrammarKind::FragmentContent) {
            return ReadBuiltInFragmentEventCode(
                input,
                state,
                options,
                eventCode,
                decoded);
        }
        if (grammar == HttpExiGrammarKind::StartTagContent ||
            grammar == HttpExiGrammarKind::ElementContent) {
            return ReadBuiltInElementEventCode(
                input,
                state,
                grammar,
                ownerQNameId,
                options,
                eventCode,
                decoded);
        }

        HttpExiProduction production = {};
        const NTSTATUS status = HttpExiReadEventCode(
            input,
            grammar,
            options.PreserveComments,
            options.PreservePis,
            options.PreserveDtd,
            options.PreservePrefixes,
            options.SelfContained,
            eventCode,
            &production);
        if (NT_SUCCESS(status)) {
            decoded->Production = production;
            decoded->QNameEncoded = production.Event == HttpExiEventKind::StartElement ||
                production.Event == HttpExiEventKind::Attribute;
        }
        return status;
    }

    _Must_inspect_result_
    NTSTATUS DecodeExiEvents(
        _Inout_ HttpExiBitInput* input,
        const HttpExiOptions& options,
        _Inout_ ExiDecodeState* state,
        _Inout_ ExiXmlEventSink* sink,
        SIZE_T destinationCapacity) noexcept
    {
        if (input == nullptr || state == nullptr || sink == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T encodedLength = input->ByteLength();
        const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        if (encodedLength == maxSize || encodedLength > (maxSize - 1) / 8) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T maxElementDepth = encodedLength + 1;
        const SIZE_T maxEvents = encodedLength * 8 + 1;
        HeapArray<HttpXmlName> elementStack(maxElementDepth);
        HeapArray<ULONG> elementQNameIds(maxElementDepth);
        if (!elementStack.IsValid() || !elementQNameIds.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        ExiSelfContainedStateStack stateStack = {};
        NTSTATUS stackStatus = stateStack.Initialize(maxElementDepth, state);
        if (!NT_SUCCESS(stackStatus)) {
            return stackStatus;
        }

        SIZE_T elementDepth = 0;
        bool sawEndDocument = false;

        for (SIZE_T eventIndex = 0; eventIndex < maxEvents; ++eventIndex) {
            HttpExiGrammarKind currentGrammar = HttpExiGrammarKind::Document;
            ULONG currentOwnerQNameId = 0xffffffffUL;
            if (!state->CurrentGrammar(&currentGrammar, &currentOwnerQNameId)) {
                return sawEndDocument ? STATUS_SUCCESS : STATUS_INVALID_NETWORK_RESPONSE;
            }

            HttpExiEventCode eventCode = {};
            DynamicExiEvent decodedEvent = {};
            NTSTATUS status = ReadExiEventCode(
                input,
                state,
                currentGrammar,
                currentOwnerQNameId,
                options,
                &eventCode,
                &decodedEvent);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            UNREFERENCED_PARAMETER(eventCode);
            const HttpExiProduction& production = decodedEvent.Production;

            switch (production.Event) {
            case HttpExiEventKind::StartDocument:
                status = ApplyGrammarTransition(state, production);
                break;

            case HttpExiEventKind::EndDocument:
                if (stateStack.InSelfContainedFragment()) {
                    if (!stateStack.CanFinish(elementDepth)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = ApplyGrammarTransition(state, production);
                    if (NT_SUCCESS(status) && !input->AlignByte()) {
                        status = STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (NT_SUCCESS(status)) {
                        status = stateStack.Pop(&state);
                    }
                    if (NT_SUCCESS(status)) {
                        status = state->PopGrammar();
                    }
                    break;
                }
                if (elementDepth != 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = ApplyGrammarTransition(state, production);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                sawEndDocument = true;
                return STATUS_SUCCESS;

            case HttpExiEventKind::StartElement:
                if (stateStack.InSelfContainedFragment() &&
                    stateStack.RootStarted() &&
                    elementDepth < stateStack.RootDepth()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (elementDepth >= maxElementDepth) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                {
                    HttpXmlName name = {};
                    ULONG qnameId = decodedEvent.QNameId;
                    if (decodedEvent.QNameEncoded) {
                        status = ReadEventName(
                            input,
                            state,
                            options.PreservePrefixes,
                            &qnameId,
                            &name);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    else {
                        const HttpExiNameTables tables = state->NameTables();
                        status = HttpExiResolveQName(tables, qnameId, &name);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    if (decodedEvent.LearnProduction) {
                        status = state->LearnProduction(
                            currentOwnerQNameId,
                            currentGrammar,
                            HttpExiEventKind::StartElement,
                            qnameId);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    if (stateStack.InSelfContainedFragment() && !stateStack.RootStarted()) {
                        status = stateStack.AcceptRoot(name, elementDepth);
                        if (!NT_SUCCESS(status) || elementDepth == 0) {
                            return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
                        }
                        elementQNameIds[elementDepth - 1] = qnameId;
                    }
                    else {
                        status = sink->StartElement(name);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        elementStack[elementDepth] = name;
                        elementQNameIds[elementDepth] = qnameId;
                        ++elementDepth;
                    }
                    status = ApplyGrammarTransition(state, production, qnameId);
                }
                break;

            case HttpExiEventKind::EndElement:
                if (elementDepth == 0) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                if (decodedEvent.LearnProduction) {
                    status = state->LearnProduction(
                        currentOwnerQNameId,
                        currentGrammar,
                        HttpExiEventKind::EndElement,
                        0xffffffffUL);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
                --elementDepth;
                status = sink->EndElement(elementStack[elementDepth]);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                status = ApplyGrammarTransition(state, production);
                break;

            case HttpExiEventKind::Attribute:
                {
                    HttpXmlName name = {};
                    HttpExiDatatypeKind selectedDatatype = HttpExiDatatypeKind::None;
                    ULONG qnameId = decodedEvent.QNameId;
                    if (decodedEvent.QNameEncoded) {
                        status = ReadEventName(
                            input,
                            state,
                            options.PreservePrefixes,
                            &qnameId,
                            &name);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    else {
                        const HttpExiNameTables tables = state->NameTables();
                        status = HttpExiResolveQName(tables, qnameId, &name);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    if (decodedEvent.LearnProduction) {
                        status = state->LearnProduction(
                            currentOwnerQNameId,
                            currentGrammar,
                            HttpExiEventKind::Attribute,
                            qnameId);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    if (IsXsiTypeName(name) && !options.PreserveLexicalValues) {
                        HttpXmlName typeName = {};
                        status = ReadQNameEventValue(
                            input,
                            state,
                            options.PreservePrefixes,
                            &typeName);
                        if (NT_SUCCESS(status)) {
                            status = sink->QNameAttribute(name, typeName);
                        }
                        if (NT_SUCCESS(status) && options.BuiltInSchemaTypesOnly) {
                            selectedDatatype = BuiltInDatatypeForQName(typeName);
                        }
                    }
                    else {
                        HttpXmlText value = {};
                        status = ReadEventText(input, state, qnameId, &value);
                        if (NT_SUCCESS(status)) {
                            status = sink->Attribute(name, value);
                        }
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ApplyGrammarTransition(state, production);
                    if (NT_SUCCESS(status) && selectedDatatype != HttpExiDatatypeKind::None) {
                        status = state->SelectSchemaSimpleType(selectedDatatype);
                    }
                }
                break;

            case HttpExiEventKind::NamespaceDeclaration:
                {
                    HttpXmlText prefix = {};
                    HttpXmlText uri = {};
                    bool localElementNamespace = false;
                    HttpExiNameTables tables = state->NameTables();
                    status = HttpExiReadNamespaceDeclaration(
                        input,
                        &tables,
                        &prefix,
                        &uri,
                        &localElementNamespace);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    if (localElementNamespace) {
                        if (elementDepth == 0) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        elementStack[elementDepth - 1].Prefix = prefix;
                    }
                    status = sink->Namespace(prefix, uri, localElementNamespace);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ApplyGrammarTransition(state, production);
                }
                break;

            case HttpExiEventKind::Characters:
                {
                    if (decodedEvent.LearnProduction) {
                        status = state->LearnProduction(
                            currentOwnerQNameId,
                            currentGrammar,
                            HttpExiEventKind::Characters,
                            0xffffffffUL);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    HttpXmlText value = {};
                    if (elementDepth == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    HeapArray<char> typedStorage = {};
                    if (currentGrammar == HttpExiGrammarKind::SchemaSimpleTypeContent &&
                        !options.PreserveLexicalValues) {
                        HttpExiDatatypeKind datatype = HttpExiDatatypeKind::None;
                        if (!state->CurrentDatatype(&datatype)) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        if (datatype == HttpExiDatatypeKind::String) {
                            status = ReadEventText(
                                input,
                                state,
                                elementQNameIds[elementDepth - 1],
                                &value);
                        }
                        else {
                            status = HttpExiReadTypedValue(
                                input,
                                datatype,
                                &typedStorage,
                                &value);
                        }
                    }
                    else {
                        status = ReadEventText(
                            input,
                            state,
                            elementQNameIds[elementDepth - 1],
                            &value);
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = sink->Characters(value);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ApplyGrammarTransition(state, production);
                }
                break;

            case HttpExiEventKind::Comment:
                {
                    HttpXmlText value = {};
                    status = ReadStructureText(input, state, &value);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = sink->Comment(value);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ApplyGrammarTransition(state, production);
                }
                break;

            case HttpExiEventKind::ProcessingInstruction:
                {
                    HttpXmlText target = {};
                    status = ReadStructureText(input, state, &target);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    HttpXmlText value = {};
                    status = ReadStructureText(input, state, &value);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = sink->ProcessingInstruction(target, value);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ApplyGrammarTransition(state, production);
                }
                break;

            case HttpExiEventKind::Dtd:
                {
                    HttpXmlText name = {};
                    HttpXmlText publicId = {};
                    HttpXmlText systemId = {};
                    HttpXmlText text = {};
                    status = ReadStructureText(input, state, &name);
                    if (NT_SUCCESS(status)) {
                        status = ReadStructureText(input, state, &publicId);
                    }
                    if (NT_SUCCESS(status)) {
                        status = ReadStructureText(input, state, &systemId);
                    }
                    if (NT_SUCCESS(status)) {
                        status = ReadStructureText(input, state, &text);
                    }
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = sink->Dtd(name, publicId, systemId, text);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ApplyGrammarTransition(state, production);
                }
                break;

            case HttpExiEventKind::EntityReference:
                {
                    HttpXmlText name = {};
                    status = ReadStructureText(input, state, &name);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = sink->EntityReference(name);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    status = ApplyGrammarTransition(state, production);
                }
                break;

            case HttpExiEventKind::SelfContained:
                if (!options.SelfContained ||
                    currentGrammar != HttpExiGrammarKind::StartTagContent ||
                    elementDepth == 0 ||
                    !input->AlignByte()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                status = stateStack.Push(
                    options,
                    encodedLength,
                    destinationCapacity,
                    elementStack[elementDepth - 1],
                    elementDepth,
                    &state);
                break;
            default:
                return STATUS_NOT_SUPPORTED;
            }

            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    struct ReorderedEvent final
    {
        HttpExiEventKind Kind = HttpExiEventKind::StartDocument;
        HttpExiDatatypeKind Datatype = HttpExiDatatypeKind::None;
        HttpXmlName Name = {};
        HttpXmlText Value = {};
        HttpXmlText SecondValue = {};
        HttpXmlText ThirdValue = {};
        HttpXmlText FourthValue = {};
        HttpXmlName QNameValue = {};
        bool IsQNameValue = false;
        bool LocalElementNamespace = false;
        SIZE_T ChannelIndex = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        SIZE_T NextInChannel = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
    };

    struct ReorderedChannel final
    {
        ULONG QNameId = 0;
        SIZE_T FirstEvent = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        SIZE_T LastEvent = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
    };

    struct ExiInflatedStream final
    {
        SIZE_T Offset = 0;
        SIZE_T Length = 0;
    };

    _Must_inspect_result_
    NTSTATUS AddReorderedValueEvent(
        _Inout_ HeapArray<ReorderedEvent>* events,
        SIZE_T eventIndex,
        ULONG qnameId,
        _Inout_ HeapArray<ReorderedChannel>* channels,
        _Inout_ SIZE_T* channelCount) noexcept
    {
        if (events == nullptr ||
            channels == nullptr ||
            channelCount == nullptr ||
            eventIndex >= events->Count()) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T channelIndex = 0;
        while (channelIndex < *channelCount && (*channels)[channelIndex].QNameId != qnameId) {
            ++channelIndex;
        }
        if (channelIndex == *channelCount) {
            if (channelIndex >= channels->Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            (*channels)[channelIndex].QNameId = qnameId;
            (*channels)[channelIndex].FirstEvent = eventIndex;
            (*channels)[channelIndex].LastEvent = eventIndex;
            ++(*channelCount);
        }
        else {
            const SIZE_T previous = (*channels)[channelIndex].LastEvent;
            if (previous >= events->Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            (*events)[previous].NextInChannel = eventIndex;
            (*channels)[channelIndex].LastEvent = eventIndex;
        }
        (*events)[eventIndex].ChannelIndex = channelIndex;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReadReorderedChannelValues(
        _Inout_ HttpExiBitInput* input,
        _Inout_ ExiDecodeState* state,
        _Inout_ HeapArray<ReorderedEvent>* events,
        SIZE_T eventCount,
        const ReorderedChannel& channel,
        bool preservePrefix,
        bool preserveLexicalValues) noexcept
    {
        if (input == nullptr || state == nullptr || events == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        SIZE_T eventIndex = channel.FirstEvent;
        while (eventIndex != static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
            if (eventIndex >= eventCount ||
                eventIndex >= events->Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            NTSTATUS status = STATUS_SUCCESS;
            if ((*events)[eventIndex].IsQNameValue) {
                status = ReadQNameEventValue(
                    input,
                    state,
                    preservePrefix,
                    &(*events)[eventIndex].QNameValue);
            }
            else if ((*events)[eventIndex].Datatype == HttpExiDatatypeKind::String) {
                status = ReadEventText(
                    input,
                    state,
                    channel.QNameId,
                    &(*events)[eventIndex].Value);
            }
            else if ((*events)[eventIndex].Datatype != HttpExiDatatypeKind::None &&
                !preserveLexicalValues) {
                HeapArray<char> typedStorage = {};
                HttpXmlText typedValue = {};
                status = HttpExiReadTypedValue(
                    input,
                    (*events)[eventIndex].Datatype,
                    &typedStorage,
                    &typedValue);
                if (NT_SUCCESS(status)) {
                    ULONG storedIndex = 0;
                    status = state->StructureStringTable()->Add(typedValue, &storedIndex);
                    if (NT_SUCCESS(status) &&
                        !state->StructureStringTable()->Get(
                            storedIndex,
                            &(*events)[eventIndex].Value)) {
                        status = STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }
            }
            else {
                status = ReadEventText(
                    input,
                    state,
                    channel.QNameId,
                    &(*events)[eventIndex].Value);
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
            eventIndex = (*events)[eventIndex].NextInChannel;
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS ReplayReorderedEvents(
        const HeapArray<ReorderedEvent>& events,
        SIZE_T eventCount,
        _Inout_ ExiXmlEventSink* sink) noexcept
    {
        if (sink == nullptr || eventCount > events.Count()) {
            return STATUS_INVALID_PARAMETER;
        }
        for (SIZE_T index = 0; index < eventCount; ++index) {
            const ReorderedEvent& event = events[index];
            NTSTATUS status = STATUS_SUCCESS;
            switch (event.Kind) {
            case HttpExiEventKind::StartElement:
                status = sink->StartElement(event.Name);
                break;
            case HttpExiEventKind::EndElement:
                status = sink->EndElement(event.Name);
                break;
            case HttpExiEventKind::Attribute:
                status = event.IsQNameValue ?
                    sink->QNameAttribute(event.Name, event.QNameValue) :
                    sink->Attribute(event.Name, event.Value);
                break;
            case HttpExiEventKind::Characters:
                status = sink->Characters(event.Value);
                break;
            case HttpExiEventKind::Comment:
                status = sink->Comment(event.Value);
                break;
            case HttpExiEventKind::ProcessingInstruction:
                status = sink->ProcessingInstruction(event.Value, event.SecondValue);
                break;
            case HttpExiEventKind::Dtd:
                status = sink->Dtd(
                    event.Value,
                    event.SecondValue,
                    event.ThirdValue,
                    event.FourthValue);
                break;
            case HttpExiEventKind::EntityReference:
                status = sink->EntityReference(event.Value);
                break;
            case HttpExiEventKind::NamespaceDeclaration:
                status = sink->Namespace(
                    event.Value,
                    event.SecondValue,
                    event.LocalElementNamespace);
                break;
            case HttpExiEventKind::StartDocument:
            case HttpExiEventKind::EndDocument:
                break;
            default:
                return STATUS_NOT_SUPPORTED;
            }
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS DecodeExiPreCompression(
        _Inout_ HttpExiBitInput* input,
        const HttpExiOptions& options,
        _Inout_ ExiDecodeState* state,
        _Inout_ ExiXmlEventSink* sink,
        _In_reads_bytes_opt_(inflatedDataLength) const UCHAR* inflatedData = nullptr,
        SIZE_T inflatedDataLength = 0,
        const HeapArray<ExiInflatedStream>* compressedStreams = nullptr,
        SIZE_T compressedStreamCount = 0) noexcept
    {
        if (input == nullptr || state == nullptr || sink == nullptr || options.BlockSize == 0 ||
            (compressedStreams != nullptr &&
                (inflatedData == nullptr || compressedStreamCount > compressedStreams->Count()))) {
            return STATUS_INVALID_PARAMETER;
        }

        const SIZE_T encodedLength = input->ByteLength();
        const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        if (encodedLength == maxSize || encodedLength > (maxSize - 1) / 8) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const SIZE_T maxEvents = encodedLength * 8 + 1;
        const SIZE_T maxElementDepth = encodedLength + 1;
        HeapArray<ReorderedEvent> events(maxEvents);
        HeapArray<ReorderedChannel> channels(maxEvents);
        HeapArray<HttpXmlName> elementNames(maxElementDepth);
        HeapArray<ULONG> elementQNameIds(maxElementDepth);
        if (!events.IsValid() ||
            !channels.IsValid() ||
            !elementNames.IsValid() ||
            !elementQNameIds.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T elementDepth = 0;
        bool sawEndDocument = false;
        const bool useCompressedStreams = compressedStreams != nullptr;
        HttpExiBitInput* sequentialInput = input;
        HttpExiBitInput streamInput(nullptr, 0, HttpExiInputMode::ByteAligned);
        HttpExiBitInput channelInput(nullptr, 0, HttpExiInputMode::ByteAligned);
        SIZE_T compressedStreamIndex = 0;
        while (!sawEndDocument) {
            input = sequentialInput;
            bool hasStructureStream = false;
            if (useCompressedStreams) {
                if (compressedStreamIndex < compressedStreamCount) {
                    const ExiInflatedStream& stream = (*compressedStreams)[compressedStreamIndex];
                    if (stream.Offset > inflatedDataLength ||
                        stream.Length > inflatedDataLength - stream.Offset) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    streamInput.Reset(
                        inflatedData + stream.Offset,
                        stream.Length,
                        HttpExiInputMode::ByteAligned);
                    ++compressedStreamIndex;
                    hasStructureStream = true;
                }
                else {
                    streamInput.Reset(nullptr, 0, HttpExiInputMode::ByteAligned);
                }
                input = &streamInput;
            }
            SIZE_T eventCount = 0;
            SIZE_T channelCount = 0;
            ULONG blockValueCount = 0;

            while (!sawEndDocument && blockValueCount < options.BlockSize) {
                HttpExiGrammarKind currentGrammar = HttpExiGrammarKind::Document;
                ULONG currentOwnerQNameId = 0xffffffffUL;
                if (!state->CurrentGrammar(&currentGrammar, &currentOwnerQNameId)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }

                HttpExiEventCode eventCode = {};
                DynamicExiEvent decodedEvent = {};
                NTSTATUS status = ReadExiEventCode(
                    input,
                    state,
                    currentGrammar,
                    currentOwnerQNameId,
                    options,
                    &eventCode,
                    &decodedEvent);
                if (!NT_SUCCESS(status)) {
                    return status;
                }
                UNREFERENCED_PARAMETER(eventCode);
                const HttpExiProduction& production = decodedEvent.Production;

                if (eventCount >= events.Count()) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                ReorderedEvent& record = events[eventCount];
                record = {};
                record.Kind = production.Event;
                bool keepRecord = true;

                switch (production.Event) {
                case HttpExiEventKind::StartDocument:
                    keepRecord = false;
                    status = ApplyGrammarTransition(state, production);
                    break;

                case HttpExiEventKind::EndDocument:
                    if (elementDepth != 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    keepRecord = false;
                    status = ApplyGrammarTransition(state, production);
                    sawEndDocument = NT_SUCCESS(status);
                    break;

                case HttpExiEventKind::StartElement:
                    if (elementDepth >= elementNames.Count()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    {
                        HttpExiNameTables tables = state->NameTables();
                        ULONG qnameId = decodedEvent.QNameId;
                        if (decodedEvent.QNameEncoded) {
                            status = HttpExiReadQNameLiteral(
                                input,
                                &tables,
                                options.PreservePrefixes,
                                &qnameId,
                                &record.Name);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                        else {
                            status = HttpExiResolveQName(tables, qnameId, &record.Name);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                        if (decodedEvent.LearnProduction) {
                            status = state->LearnProduction(
                                currentOwnerQNameId,
                                currentGrammar,
                                HttpExiEventKind::StartElement,
                                qnameId);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                        elementNames[elementDepth] = record.Name;
                        elementQNameIds[elementDepth] = qnameId;
                        ++elementDepth;
                        status = ApplyGrammarTransition(state, production, qnameId);
                    }
                    break;

                case HttpExiEventKind::EndElement:
                    if (elementDepth == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (decodedEvent.LearnProduction) {
                        status = state->LearnProduction(
                            currentOwnerQNameId,
                            currentGrammar,
                            HttpExiEventKind::EndElement,
                            0xffffffffUL);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    --elementDepth;
                    record.Name = elementNames[elementDepth];
                    status = ApplyGrammarTransition(state, production);
                    break;

                case HttpExiEventKind::Attribute:
                    {
                        HttpExiNameTables tables = state->NameTables();
                        HttpExiDatatypeKind selectedDatatype = HttpExiDatatypeKind::None;
                        ULONG qnameId = decodedEvent.QNameId;
                        if (decodedEvent.QNameEncoded) {
                            status = HttpExiReadQNameLiteral(
                                input,
                                &tables,
                                options.PreservePrefixes,
                                &qnameId,
                                &record.Name);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                        else {
                            status = HttpExiResolveQName(tables, qnameId, &record.Name);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                        if (decodedEvent.LearnProduction) {
                            status = state->LearnProduction(
                                currentOwnerQNameId,
                                currentGrammar,
                                HttpExiEventKind::Attribute,
                                qnameId);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                        record.IsQNameValue =
                            IsXsiTypeName(record.Name) &&
                            !options.PreserveLexicalValues;
                        if (record.IsQNameValue) {
                            status = ReadQNameEventValue(
                                input,
                                state,
                                options.PreservePrefixes,
                                &record.QNameValue);
                            if (NT_SUCCESS(status) && options.BuiltInSchemaTypesOnly) {
                                selectedDatatype = BuiltInDatatypeForQName(record.QNameValue);
                            }
                        }
                        else {
                            status = AddReorderedValueEvent(
                                &events,
                                eventCount,
                                qnameId,
                                &channels,
                                &channelCount);
                            if (NT_SUCCESS(status)) {
                                ++blockValueCount;
                            }
                        }
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        status = ApplyGrammarTransition(state, production);
                        if (NT_SUCCESS(status) &&
                            selectedDatatype != HttpExiDatatypeKind::None) {
                            status = state->SelectSchemaSimpleType(selectedDatatype);
                        }
                    }
                    break;

                case HttpExiEventKind::Characters:
                    if (elementDepth == 0) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    if (decodedEvent.LearnProduction) {
                        status = state->LearnProduction(
                            currentOwnerQNameId,
                            currentGrammar,
                            HttpExiEventKind::Characters,
                            0xffffffffUL);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                    }
                    if (currentGrammar == HttpExiGrammarKind::SchemaSimpleTypeContent &&
                        !options.PreserveLexicalValues &&
                        !state->CurrentDatatype(&record.Datatype)) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    status = AddReorderedValueEvent(
                        &events,
                        eventCount,
                        elementQNameIds[elementDepth - 1],
                        &channels,
                        &channelCount);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                    ++blockValueCount;
                    status = ApplyGrammarTransition(state, production);
                    break;

                case HttpExiEventKind::Comment:
                    status = ReadStructureText(input, state, &record.Value);
                    if (NT_SUCCESS(status)) {
                        status = ApplyGrammarTransition(state, production);
                    }
                    break;

                case HttpExiEventKind::ProcessingInstruction:
                    status = ReadStructureText(input, state, &record.Value);
                    if (NT_SUCCESS(status)) {
                        status = ReadStructureText(input, state, &record.SecondValue);
                    }
                    if (NT_SUCCESS(status)) {
                        status = ApplyGrammarTransition(state, production);
                    }
                    break;

                case HttpExiEventKind::Dtd:
                    status = ReadStructureText(input, state, &record.Value);
                    if (NT_SUCCESS(status)) {
                        status = ReadStructureText(input, state, &record.SecondValue);
                    }
                    if (NT_SUCCESS(status)) {
                        status = ReadStructureText(input, state, &record.ThirdValue);
                    }
                    if (NT_SUCCESS(status)) {
                        status = ReadStructureText(input, state, &record.FourthValue);
                    }
                    if (NT_SUCCESS(status)) {
                        status = ApplyGrammarTransition(state, production);
                    }
                    break;

                case HttpExiEventKind::EntityReference:
                    status = ReadStructureText(input, state, &record.Value);
                    if (NT_SUCCESS(status)) {
                        status = ApplyGrammarTransition(state, production);
                    }
                    break;

                case HttpExiEventKind::NamespaceDeclaration:
                    {
                        HttpExiNameTables tables = state->NameTables();
                        status = HttpExiReadNamespaceDeclaration(
                            input,
                            &tables,
                            &record.Value,
                            &record.SecondValue,
                            &record.LocalElementNamespace);
                        if (!NT_SUCCESS(status)) {
                            return status;
                        }
                        if (record.LocalElementNamespace) {
                            if (elementDepth == 0) {
                                return STATUS_INVALID_NETWORK_RESPONSE;
                            }
                            elementNames[elementDepth - 1].Prefix = record.Value;
                        }
                        status = ApplyGrammarTransition(state, production);
                    }
                    break;

                default:
                    return STATUS_NOT_SUPPORTED;
                }

                if (!NT_SUCCESS(status)) {
                    return status;
                }
                if (keepRecord) {
                    ++eventCount;
                }
            }

            if (!useCompressedStreams || blockValueCount <= 100) {
                for (SIZE_T channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
                    const NTSTATUS status = ReadReorderedChannelValues(
                        input,
                        state,
                        &events,
                        eventCount,
                        channels[channelIndex],
                        options.PreservePrefixes,
                        options.PreserveLexicalValues);
                    if (!NT_SUCCESS(status)) {
                        return status;
                    }
                }
            }
            else {
                SIZE_T smallChannelCount = 0;
                for (SIZE_T channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
                    SIZE_T channelValueCount = 0;
                    SIZE_T eventIndex = channels[channelIndex].FirstEvent;
                    while (eventIndex != static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                        if (eventIndex >= eventCount) {
                            return STATUS_INVALID_NETWORK_RESPONSE;
                        }
                        ++channelValueCount;
                        eventIndex = events[eventIndex].NextInChannel;
                    }
                    if (channelValueCount <= 100) {
                        ++smallChannelCount;
                    }
                }

                if (smallChannelCount != 0) {
                    if (compressedStreamIndex >= compressedStreamCount) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const ExiInflatedStream& stream = (*compressedStreams)[compressedStreamIndex++];
                    if (stream.Offset > inflatedDataLength ||
                        stream.Length > inflatedDataLength - stream.Offset) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    channelInput.Reset(
                        inflatedData + stream.Offset,
                        stream.Length,
                        HttpExiInputMode::ByteAligned);
                    for (SIZE_T channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
                        SIZE_T channelValueCount = 0;
                        SIZE_T eventIndex = channels[channelIndex].FirstEvent;
                        while (eventIndex != static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                            ++channelValueCount;
                            eventIndex = events[eventIndex].NextInChannel;
                        }
                        if (channelValueCount <= 100) {
                            const NTSTATUS status = ReadReorderedChannelValues(
                                &channelInput,
                                state,
                                &events,
                                eventCount,
                                channels[channelIndex],
                                options.PreservePrefixes,
                                options.PreserveLexicalValues);
                            if (!NT_SUCCESS(status)) {
                                return status;
                            }
                        }
                    }
                    if (!channelInput.AtEnd()) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                }

                for (SIZE_T channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
                    SIZE_T channelValueCount = 0;
                    SIZE_T eventIndex = channels[channelIndex].FirstEvent;
                    while (eventIndex != static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
                        ++channelValueCount;
                        eventIndex = events[eventIndex].NextInChannel;
                    }
                    if (channelValueCount <= 100) {
                        continue;
                    }
                    if (compressedStreamIndex >= compressedStreamCount) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    const ExiInflatedStream& stream = (*compressedStreams)[compressedStreamIndex++];
                    if (stream.Offset > inflatedDataLength ||
                        stream.Length > inflatedDataLength - stream.Offset) {
                        return STATUS_INVALID_NETWORK_RESPONSE;
                    }
                    channelInput.Reset(
                        inflatedData + stream.Offset,
                        stream.Length,
                        HttpExiInputMode::ByteAligned);
                    const NTSTATUS status = ReadReorderedChannelValues(
                        &channelInput,
                        state,
                        &events,
                        eventCount,
                        channels[channelIndex],
                        options.PreservePrefixes,
                        options.PreserveLexicalValues);
                    if (!NT_SUCCESS(status) || !channelInput.AtEnd()) {
                        return NT_SUCCESS(status) ? STATUS_INVALID_NETWORK_RESPONSE : status;
                    }
                }
            }

            if (useCompressedStreams && hasStructureStream && !input->AtEnd()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            const NTSTATUS replayStatus = ReplayReorderedEvents(events, eventCount, sink);
            if (!NT_SUCCESS(replayStatus)) {
                return replayStatus;
            }
        }
        if (useCompressedStreams && compressedStreamIndex != compressedStreamCount) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        return STATUS_SUCCESS;
    }

    class ExiDeflateBitInput final
    {
    public:
        ExiDeflateBitInput(const UCHAR* data, SIZE_T length) noexcept :
            data_(data),
            length_(length)
        {
        }

        _Must_inspect_result_
        bool ReadBits(UCHAR bitCount, _Out_ ULONG* value) noexcept
        {
            if (value == nullptr || bitCount > 24) {
                return false;
            }
            ULONG result = 0;
            for (UCHAR index = 0; index < bitCount; ++index) {
                const SIZE_T byteOffset = bitOffset_ / 8;
                if (byteOffset >= length_) {
                    return false;
                }
                const UCHAR bitOffset = static_cast<UCHAR>(bitOffset_ % 8);
                result |= static_cast<ULONG>((data_[byteOffset] >> bitOffset) & 1U) << index;
                ++bitOffset_;
            }
            *value = result;
            return true;
        }

        _Must_inspect_result_
        bool AlignByte() noexcept
        {
            const SIZE_T remainder = bitOffset_ % 8;
            if (remainder != 0) {
                bitOffset_ += 8 - remainder;
            }
            return bitOffset_ / 8 <= length_;
        }

        _Must_inspect_result_
        bool SkipBytes(SIZE_T byteCount) noexcept
        {
            if ((bitOffset_ % 8) != 0) {
                return false;
            }
            const SIZE_T byteOffset = bitOffset_ / 8;
            if (byteOffset > length_ || byteCount > length_ - byteOffset) {
                return false;
            }
            bitOffset_ += byteCount * 8;
            return true;
        }

        _Must_inspect_result_
        SIZE_T ConsumedBytes() const noexcept
        {
            return (bitOffset_ + 7) / 8;
        }

    private:
        const UCHAR* data_ = nullptr;
        SIZE_T length_ = 0;
        SIZE_T bitOffset_ = 0;
    };

    struct ExiDeflateCode final
    {
        USHORT ReversedCode = 0;
        UCHAR Length = 0;
        USHORT Symbol = 0;
    };

    _Must_inspect_result_
    USHORT ReverseDeflateCode(USHORT code, UCHAR length) noexcept
    {
        USHORT reversed = 0;
        for (UCHAR index = 0; index < length; ++index) {
            reversed = static_cast<USHORT>((reversed << 1) | (code & 1U));
            code = static_cast<USHORT>(code >> 1);
        }
        return reversed;
    }

    _Must_inspect_result_
    NTSTATUS BuildDeflateCodes(
        _In_reads_(lengthCount) const UCHAR* lengths,
        SIZE_T lengthCount,
        _Inout_ HeapArray<ExiDeflateCode>* codes,
        _Out_ SIZE_T* codeCount) noexcept
    {
        if (lengths == nullptr || codes == nullptr || codeCount == nullptr || lengthCount == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        *codeCount = 0;
        NTSTATUS status = codes->Allocate(lengthCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        HeapArray<USHORT> counts(16);
        HeapArray<USHORT> nextCodes(16);
        if (!counts.IsValid() || !nextCodes.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(counts.Get(), counts.Count() * sizeof(USHORT));
        RtlZeroMemory(nextCodes.Get(), nextCodes.Count() * sizeof(USHORT));

        for (SIZE_T index = 0; index < lengthCount; ++index) {
            const UCHAR length = lengths[index];
            if (length > 15) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (length != 0) {
                ++counts[length];
            }
        }

        ULONG code = 0;
        for (UCHAR bits = 1; bits <= 15; ++bits) {
            code = (code + counts[bits - 1]) << 1;
            if (code + counts[bits] > (1UL << bits)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            nextCodes[bits] = static_cast<USHORT>(code);
        }

        for (SIZE_T symbol = 0; symbol < lengthCount; ++symbol) {
            const UCHAR length = lengths[symbol];
            if (length == 0) {
                continue;
            }
            if (symbol > 0xffffULL || *codeCount >= codes->Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ExiDeflateCode& entry = (*codes)[*codeCount];
            entry.ReversedCode = ReverseDeflateCode(nextCodes[length], length);
            entry.Length = length;
            entry.Symbol = static_cast<USHORT>(symbol);
            ++nextCodes[length];
            ++(*codeCount);
        }
        return *codeCount == 0 ? STATUS_INVALID_NETWORK_RESPONSE : STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS DecodeDeflateSymbol(
        _Inout_ ExiDeflateBitInput* input,
        const HeapArray<ExiDeflateCode>& codes,
        SIZE_T codeCount,
        _Out_ ULONG* symbol) noexcept
    {
        if (input == nullptr || symbol == nullptr || codeCount == 0 || codeCount > codes.Count()) {
            return STATUS_INVALID_PARAMETER;
        }
        ULONG code = 0;
        for (UCHAR length = 1; length <= 15; ++length) {
            ULONG bit = 0;
            if (!input->ReadBits(1, &bit)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            code |= bit << (length - 1);
            for (SIZE_T index = 0; index < codeCount; ++index) {
                const ExiDeflateCode& entry = codes[index];
                if (entry.Length == length && entry.ReversedCode == code) {
                    *symbol = entry.Symbol;
                    return STATUS_SUCCESS;
                }
            }
        }
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS BuildFixedDeflateTrees(
        _Inout_ HeapArray<ExiDeflateCode>* literalCodes,
        _Out_ SIZE_T* literalCodeCount,
        _Inout_ HeapArray<ExiDeflateCode>* distanceCodes,
        _Out_ SIZE_T* distanceCodeCount) noexcept
    {
        HeapArray<UCHAR> literalLengths(288);
        HeapArray<UCHAR> distanceLengths(32);
        if (!literalLengths.IsValid() || !distanceLengths.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        for (SIZE_T index = 0; index <= 143; ++index) literalLengths[index] = 8;
        for (SIZE_T index = 144; index <= 255; ++index) literalLengths[index] = 9;
        for (SIZE_T index = 256; index <= 279; ++index) literalLengths[index] = 7;
        for (SIZE_T index = 280; index <= 287; ++index) literalLengths[index] = 8;
        for (SIZE_T index = 0; index < distanceLengths.Count(); ++index) distanceLengths[index] = 5;

        NTSTATUS status = BuildDeflateCodes(
            literalLengths.Get(),
            literalLengths.Count(),
            literalCodes,
            literalCodeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return BuildDeflateCodes(
            distanceLengths.Get(),
            distanceLengths.Count(),
            distanceCodes,
            distanceCodeCount);
    }

    _Must_inspect_result_
    NTSTATUS BuildDynamicDeflateTrees(
        _Inout_ ExiDeflateBitInput* input,
        _Inout_ HeapArray<ExiDeflateCode>* literalCodes,
        _Out_ SIZE_T* literalCodeCount,
        _Inout_ HeapArray<ExiDeflateCode>* distanceCodes,
        _Out_ SIZE_T* distanceCodeCount) noexcept
    {
        constexpr UCHAR CodeLengthOrder[] = {
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
            11, 4, 12, 3, 13, 2, 14, 1, 15
        };
        ULONG parsed = 0;
        if (!input->ReadBits(5, &parsed)) return STATUS_INVALID_NETWORK_RESPONSE;
        const SIZE_T literalLengthCount = parsed + 257;
        if (!input->ReadBits(5, &parsed)) return STATUS_INVALID_NETWORK_RESPONSE;
        const SIZE_T distanceLengthCount = parsed + 1;
        if (!input->ReadBits(4, &parsed)) return STATUS_INVALID_NETWORK_RESPONSE;
        const SIZE_T codeLengthCount = parsed + 4;
        if (literalLengthCount > 286 || distanceLengthCount > 32 || codeLengthCount > 19) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        HeapArray<UCHAR> codeLengths(19);
        if (!codeLengths.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(codeLengths.Get(), codeLengths.Count());
        for (SIZE_T index = 0; index < codeLengthCount; ++index) {
            if (!input->ReadBits(3, &parsed)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            codeLengths[CodeLengthOrder[index]] = static_cast<UCHAR>(parsed);
        }

        HeapArray<ExiDeflateCode> codeLengthCodes = {};
        SIZE_T codeLengthCodeCount = 0;
        NTSTATUS status = BuildDeflateCodes(
            codeLengths.Get(),
            codeLengths.Count(),
            &codeLengthCodes,
            &codeLengthCodeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        const SIZE_T combinedCount = literalLengthCount + distanceLengthCount;
        HeapArray<UCHAR> combinedLengths(combinedCount);
        if (!combinedLengths.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        SIZE_T outputIndex = 0;
        while (outputIndex < combinedCount) {
            ULONG symbol = 0;
            status = DecodeDeflateSymbol(
                input,
                codeLengthCodes,
                codeLengthCodeCount,
                &symbol);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (symbol <= 15) {
                combinedLengths[outputIndex++] = static_cast<UCHAR>(symbol);
                continue;
            }

            SIZE_T repeatCount = 0;
            UCHAR repeatedLength = 0;
            if (symbol == 16) {
                if (outputIndex == 0 || !input->ReadBits(2, &parsed)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                repeatCount = parsed + 3;
                repeatedLength = combinedLengths[outputIndex - 1];
            }
            else if (symbol == 17) {
                if (!input->ReadBits(3, &parsed)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                repeatCount = parsed + 3;
            }
            else if (symbol == 18) {
                if (!input->ReadBits(7, &parsed)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                repeatCount = parsed + 11;
            }
            else {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (repeatCount > combinedCount - outputIndex) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            for (SIZE_T index = 0; index < repeatCount; ++index) {
                combinedLengths[outputIndex++] = repeatedLength;
            }
        }
        if (combinedLengths[256] == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        status = BuildDeflateCodes(
            combinedLengths.Get(),
            literalLengthCount,
            literalCodes,
            literalCodeCount);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        return BuildDeflateCodes(
            combinedLengths.Get() + literalLengthCount,
            distanceLengthCount,
            distanceCodes,
            distanceCodeCount);
    }

    _Must_inspect_result_
    NTSTATUS SkipCompressedDeflateBlock(
        _Inout_ ExiDeflateBitInput* input,
        const HeapArray<ExiDeflateCode>& literalCodes,
        SIZE_T literalCodeCount,
        const HeapArray<ExiDeflateCode>& distanceCodes,
        SIZE_T distanceCodeCount) noexcept
    {
        constexpr UCHAR LengthExtraBits[] = {
            0, 0, 0, 0, 0, 0, 0, 0,
            1, 1, 1, 1, 2, 2, 2, 2,
            3, 3, 3, 3, 4, 4, 4, 4,
            5, 5, 5, 5, 0
        };
        constexpr UCHAR DistanceExtraBits[] = {
            0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
            4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
            9, 9, 10, 10, 11, 11, 12, 12, 13, 13
        };
        for (;;) {
            ULONG symbol = 0;
            NTSTATUS status = DecodeDeflateSymbol(
                input,
                literalCodes,
                literalCodeCount,
                &symbol);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (symbol < 256) {
                continue;
            }
            if (symbol == 256) {
                return STATUS_SUCCESS;
            }
            if (symbol < 257 || symbol > 285) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            ULONG ignored = 0;
            const UCHAR lengthExtra = LengthExtraBits[symbol - 257];
            if (lengthExtra != 0 && !input->ReadBits(lengthExtra, &ignored)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            ULONG distanceSymbol = 0;
            status = DecodeDeflateSymbol(
                input,
                distanceCodes,
                distanceCodeCount,
                &distanceSymbol);
            if (!NT_SUCCESS(status) || distanceSymbol >= 30) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            const UCHAR distanceExtra = DistanceExtraBits[distanceSymbol];
            if (distanceExtra != 0 && !input->ReadBits(distanceExtra, &ignored)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
        }
    }

    _Must_inspect_result_
    NTSTATUS FindRawDeflateStreamLength(
        _In_reads_bytes_(compressedLength) const UCHAR* compressed,
        SIZE_T compressedLength,
        _Out_ SIZE_T* streamLength) noexcept
    {
        if (compressed == nullptr || streamLength == nullptr || compressedLength == 0) {
            return STATUS_INVALID_PARAMETER;
        }
        *streamLength = 0;
        ExiDeflateBitInput input(compressed, compressedLength);
        bool finalBlock = false;
        while (!finalBlock) {
            ULONG finalValue = 0;
            ULONG blockType = 0;
            if (!input.ReadBits(1, &finalValue) || !input.ReadBits(2, &blockType)) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            finalBlock = finalValue != 0;

            if (blockType == 0) {
                ULONG length = 0;
                ULONG inverseLength = 0;
                if (!input.AlignByte() ||
                    !input.ReadBits(16, &length) ||
                    !input.ReadBits(16, &inverseLength) ||
                    static_cast<USHORT>(length) !=
                        static_cast<USHORT>(~static_cast<USHORT>(inverseLength)) ||
                    !input.SkipBytes(length)) {
                    return STATUS_INVALID_NETWORK_RESPONSE;
                }
                continue;
            }
            if (blockType == 3) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }

            HeapArray<ExiDeflateCode> literalCodes = {};
            HeapArray<ExiDeflateCode> distanceCodes = {};
            SIZE_T literalCodeCount = 0;
            SIZE_T distanceCodeCount = 0;
            NTSTATUS status = blockType == 1 ?
                BuildFixedDeflateTrees(
                    &literalCodes,
                    &literalCodeCount,
                    &distanceCodes,
                    &distanceCodeCount) :
                BuildDynamicDeflateTrees(
                    &input,
                    &literalCodes,
                    &literalCodeCount,
                    &distanceCodes,
                    &distanceCodeCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            status = SkipCompressedDeflateBlock(
                &input,
                literalCodes,
                literalCodeCount,
                distanceCodes,
                distanceCodeCount);
            if (!NT_SUCCESS(status)) {
                return status;
            }
        }

        *streamLength = input.ConsumedBytes();
        return *streamLength != 0 && *streamLength <= compressedLength ?
            STATUS_SUCCESS :
            STATUS_INVALID_NETWORK_RESPONSE;
    }

    _Must_inspect_result_
    NTSTATUS DecodeConcatenatedRawDeflate(
        _In_reads_bytes_(compressedLength) const UCHAR* compressed,
        SIZE_T compressedLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* decodedLength,
        _Inout_ HeapArray<ExiInflatedStream>* streams,
        _Out_ SIZE_T* streamCount) noexcept
    {
        if (compressed == nullptr || destination == nullptr || decodedLength == nullptr ||
            streams == nullptr || streamCount == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }
        *decodedLength = 0;
        *streamCount = 0;
        if (compressedLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        SIZE_T compressedOffset = 0;
        SIZE_T destinationOffset = 0;
        while (compressedOffset < compressedLength) {
            if (destinationOffset >= destinationCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }

            SIZE_T streamLength = 0;
            NTSTATUS status = FindRawDeflateStreamLength(
                compressed + compressedOffset,
                compressedLength - compressedOffset,
                &streamLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            SIZE_T streamDecodedLength = 0;
            status = HttpDecodeRawDeflate(
                compressed + compressedOffset,
                streamLength,
                destination + destinationOffset,
                destinationCapacity - destinationOffset,
                &streamDecodedLength);
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if (streamDecodedLength > destinationCapacity - destinationOffset) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (*streamCount >= streams->Count()) {
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            (*streams)[*streamCount].Offset = destinationOffset;
            (*streams)[*streamCount].Length = streamDecodedLength;
            ++(*streamCount);
            destinationOffset += streamDecodedLength;
            compressedOffset += streamLength;
        }

        *decodedLength = destinationOffset;
        return STATUS_SUCCESS;
    }
}

NTSTATUS DecodeExiContent(
    const UCHAR* source,
    SIZE_T sourceLength,
    char* destination,
    SIZE_T destinationCapacity,
    SIZE_T* decodedLength) noexcept
{
    if (decodedLength == nullptr || source == nullptr) {
        return STATUS_INVALID_PARAMETER;
    }
    *decodedLength = 0;

    HttpExiOptions options = {};
    SIZE_T bodyBitOffset = 0;
    const NTSTATUS headerStatus = HttpExiParseHeader(source, sourceLength, &options, &bodyBitOffset);
    if (!NT_SUCCESS(headerStatus)) {
        return headerStatus;
    }
    ExiXmlEventSink sink(destination, destinationCapacity);
    HeapArray<char> inflated = {};
    HeapArray<ExiInflatedStream> inflatedStreams = {};
    SIZE_T inflatedStreamCount = 0;
    const UCHAR* eventSource = source;
    SIZE_T eventSourceLength = sourceLength;
    SIZE_T eventBitOffset = bodyBitOffset;
    HttpExiOptions decodeOptions = options;
    if (options.Alignment == HttpExiAlignment::Compression) {
        const SIZE_T compressedOffset = bodyBitOffset / 8;
        if ((bodyBitOffset % 8) != 0 || compressedOffset > sourceLength) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        const SIZE_T compressedLength = sourceLength - compressedOffset;
        if (compressedLength == 0) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
        constexpr SIZE_T MinimumInflatedCapacity = 4096;
        constexpr SIZE_T MaxDeflateExpansionRatio = 64;
        const SIZE_T maxSize = static_cast<SIZE_T>(~static_cast<SIZE_T>(0));
        if (compressedLength == maxSize ||
            destinationCapacity > 0xffffffffULL ||
            destinationCapacity > maxSize - MinimumInflatedCapacity ||
            compressedLength > (maxSize - MinimumInflatedCapacity - destinationCapacity) /
                MaxDeflateExpansionRatio) {
            return STATUS_INTEGER_OVERFLOW;
        }
        const NTSTATUS streamAllocationStatus = inflatedStreams.Allocate(compressedLength + 1);
        if (!NT_SUCCESS(streamAllocationStatus)) {
            return streamAllocationStatus;
        }
        SIZE_T maximumInflatedCapacity =
            destinationCapacity +
            compressedLength * MaxDeflateExpansionRatio +
            MinimumInflatedCapacity;
        if (maximumInflatedCapacity > 0xffffffffULL) {
            maximumInflatedCapacity = 0xffffffffULL;
        }
        SIZE_T inflatedCapacity = compressedLength <= maximumInflatedCapacity / 4 ?
            compressedLength * 4 :
            maximumInflatedCapacity;
        if (inflatedCapacity < destinationCapacity) {
            inflatedCapacity = destinationCapacity;
        }
        if (inflatedCapacity < MinimumInflatedCapacity) {
            inflatedCapacity = MinimumInflatedCapacity;
        }
        if (inflatedCapacity > maximumInflatedCapacity) {
            inflatedCapacity = maximumInflatedCapacity;
        }

        SIZE_T inflatedLength = 0;
        NTSTATUS inflateStatus = STATUS_BUFFER_TOO_SMALL;
        while (inflateStatus == STATUS_BUFFER_TOO_SMALL) {
            const NTSTATUS allocationStatus = inflated.Allocate(inflatedCapacity);
            if (!NT_SUCCESS(allocationStatus)) {
                return allocationStatus;
            }
            inflateStatus = DecodeConcatenatedRawDeflate(
                source + compressedOffset,
                compressedLength,
                inflated.Get(),
                inflated.Count(),
                &inflatedLength,
                &inflatedStreams,
                &inflatedStreamCount);
            if (inflateStatus != STATUS_BUFFER_TOO_SMALL) {
                break;
            }
            if (inflatedCapacity >= maximumInflatedCapacity) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            inflatedCapacity = inflatedCapacity > maximumInflatedCapacity / 2 ?
                maximumInflatedCapacity :
                inflatedCapacity * 2;
        }
        if (!NT_SUCCESS(inflateStatus)) {
            return inflateStatus;
        }
        eventSource = reinterpret_cast<const UCHAR*>(inflated.Get());
        eventSourceLength = inflatedLength;
        eventBitOffset = 0;
        decodeOptions.Alignment = HttpExiAlignment::PreCompression;
    }

    ExiDecodeState state = {};
    const SIZE_T bodyByteOffset = eventBitOffset / 8;
    if (eventSourceLength == static_cast<SIZE_T>(~static_cast<SIZE_T>(0))) {
        return STATUS_INTEGER_OVERFLOW;
    }
    const NTSTATUS sinkStatus = sink.Initialize(
        eventSourceLength + 1,
        decodeOptions.PreservePrefixes);
    if (!NT_SUCCESS(sinkStatus)) {
        return sinkStatus;
    }
    const NTSTATUS stateStatus = state.Initialize(
        decodeOptions,
        eventSourceLength - bodyByteOffset,
        destinationCapacity);
    if (!NT_SUCCESS(stateStatus)) {
        return stateStatus;
    }
    const HttpExiInputMode inputMode = decodeOptions.Alignment == HttpExiAlignment::BitPacked ?
        HttpExiInputMode::BitPacked :
        HttpExiInputMode::ByteAligned;
    HttpExiBitInput eventInput(eventSource, eventSourceLength, inputMode, eventBitOffset);
    const NTSTATUS eventStatus = decodeOptions.Alignment == HttpExiAlignment::PreCompression ?
        DecodeExiPreCompression(
            &eventInput,
            decodeOptions,
            &state,
            &sink,
            options.Alignment == HttpExiAlignment::Compression ? eventSource : nullptr,
            options.Alignment == HttpExiAlignment::Compression ? eventSourceLength : 0,
            options.Alignment == HttpExiAlignment::Compression ? &inflatedStreams : nullptr,
            options.Alignment == HttpExiAlignment::Compression ? inflatedStreamCount : 0) :
        DecodeExiEvents(
            &eventInput,
            decodeOptions,
            &state,
            &sink,
            destinationCapacity);
    if (!NT_SUCCESS(eventStatus)) {
        return eventStatus;
    }

    *decodedLength = sink.Length();
    return STATUS_SUCCESS;
}
}
}
