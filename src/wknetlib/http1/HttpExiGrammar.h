#pragma once

#include <wknet/http1/HttpTypes.h>

namespace wknet
{
namespace http1
{
    enum class HttpExiGrammarKind : UCHAR
    {
        Document,
        Fragment,
        FragmentContent,
        DocContent,
        DocumentEnd,
        ElementContent,
        StartTagContent,
        SchemaSimpleTypeContent,
        SchemaSimpleTypeEnd
    };

    enum class HttpExiEventKind : UCHAR
    {
        StartDocument,
        EndDocument,
        StartElement,
        EndElement,
        Attribute,
        NamespaceDeclaration,
        Characters,
        Comment,
        ProcessingInstruction,
        Dtd,
        EntityReference,
        SelfContained
    };

    struct HttpExiProduction final
    {
        HttpExiEventKind Event = HttpExiEventKind::StartDocument;
        HttpExiGrammarKind NextGrammar = HttpExiGrammarKind::Document;
        bool PushElementGrammar = false;
        bool PopGrammar = false;
    };

    _Must_inspect_result_
    bool HttpExiBuiltinProduction(
        HttpExiGrammarKind grammar,
        ULONG eventCode,
        bool preserveComments,
        bool preservePis,
        bool preserveDtd,
        _Out_ HttpExiProduction* production) noexcept;
}
}
