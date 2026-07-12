#pragma once

#include "codec/CodecInternal.h"
#include "ExiGrammar.h"

namespace wknet
{
namespace codec
{
    struct HttpExiLearnedProduction final
    {
        ULONG OwnerQNameId = 0xffffffffUL;
        HttpExiGrammarKind Grammar = HttpExiGrammarKind::ElementContent;
        HttpExiEventKind Event = HttpExiEventKind::StartElement;
        ULONG QNameId = 0xffffffffUL;
        HttpExiGrammarKind NextGrammar = HttpExiGrammarKind::ElementContent;
        bool PushElementGrammar = false;
        bool PopGrammar = false;
    };

    class HttpExiGrammarTable final
    {
    public:
        HttpExiGrammarTable() noexcept = default;

        _Must_inspect_result_
        NTSTATUS Initialize(SIZE_T maxProductions) noexcept;

        void Reset() noexcept;

        _Must_inspect_result_
        NTSTATUS Learn(HttpExiLearnedProduction production, _Out_ ULONG* productionIndex) noexcept;

        _Must_inspect_result_
        NTSTATUS Learn(
            ULONG ownerQNameId,
            HttpExiGrammarKind grammar,
            HttpExiEventKind event,
            ULONG qnameId,
            HttpExiGrammarKind nextGrammar,
            bool pushElementGrammar,
            bool popGrammar,
            _Out_ ULONG* productionIndex) noexcept;

        _Must_inspect_result_
        bool Find(
            HttpExiGrammarKind grammar,
            HttpExiEventKind event,
            ULONG qnameId,
            _Out_ ULONG* productionIndex) const noexcept;

        _Must_inspect_result_
        bool Find(
            ULONG ownerQNameId,
            HttpExiGrammarKind grammar,
            HttpExiEventKind event,
            ULONG qnameId,
            _Out_ ULONG* productionIndex) const noexcept;

        _Must_inspect_result_
        bool Get(ULONG productionIndex, _Out_ HttpExiLearnedProduction* production) const noexcept;

        _Must_inspect_result_
        bool GetByEventCode(
            ULONG ownerQNameId,
            HttpExiGrammarKind grammar,
            ULONG eventCode,
            _Out_ HttpExiLearnedProduction* production) const noexcept;

        _Must_inspect_result_
        SIZE_T Count(ULONG ownerQNameId, HttpExiGrammarKind grammar) const noexcept;

        _Must_inspect_result_
        SIZE_T Count() const noexcept;

    private:
        HeapArray<HttpExiLearnedProduction> productions_ = {};
        SIZE_T productionCount_ = 0;
    };
}
}
