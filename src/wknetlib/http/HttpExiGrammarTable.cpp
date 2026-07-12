#include "HttpExiGrammarTable.h"

namespace wknet
{
namespace http1
{
    NTSTATUS HttpExiGrammarTable::Initialize(SIZE_T maxProductions) noexcept
    {
        Reset();
        NTSTATUS status = productions_.Allocate(maxProductions);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        productionCount_ = 0;
        return STATUS_SUCCESS;
    }

    void HttpExiGrammarTable::Reset() noexcept
    {
        productions_.Reset();
        productionCount_ = 0;
    }

    NTSTATUS HttpExiGrammarTable::Learn(HttpExiLearnedProduction production, ULONG* productionIndex) noexcept
    {
        if (productionIndex == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG existing = 0;
        if (Find(
                production.OwnerQNameId,
                production.Grammar,
                production.Event,
                production.QNameId,
                &existing)) {
            *productionIndex = existing;
            return STATUS_SUCCESS;
        }

        if (!productions_.IsValid() || productionCount_ >= productions_.Count() || productionCount_ > 0xffffffffUL) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        productions_[productionCount_] = production;
        *productionIndex = static_cast<ULONG>(productionCount_);
        ++productionCount_;
        return STATUS_SUCCESS;
    }

    NTSTATUS HttpExiGrammarTable::Learn(
        ULONG ownerQNameId,
        HttpExiGrammarKind grammar,
        HttpExiEventKind event,
        ULONG qnameId,
        HttpExiGrammarKind nextGrammar,
        bool pushElementGrammar,
        bool popGrammar,
        ULONG* productionIndex) noexcept
    {
        HttpExiLearnedProduction production = {};
        production.OwnerQNameId = ownerQNameId;
        production.Grammar = grammar;
        production.Event = event;
        production.QNameId = qnameId;
        production.NextGrammar = nextGrammar;
        production.PushElementGrammar = pushElementGrammar;
        production.PopGrammar = popGrammar;
        return Learn(production, productionIndex);
    }

    bool HttpExiGrammarTable::Find(
        HttpExiGrammarKind grammar,
        HttpExiEventKind event,
        ULONG qnameId,
        ULONG* productionIndex) const noexcept
    {
        return Find(0xffffffffUL, grammar, event, qnameId, productionIndex);
    }

    bool HttpExiGrammarTable::Find(
        ULONG ownerQNameId,
        HttpExiGrammarKind grammar,
        HttpExiEventKind event,
        ULONG qnameId,
        ULONG* productionIndex) const noexcept
    {
        if (productionIndex == nullptr) {
            return false;
        }
        for (SIZE_T index = 0; index < productionCount_; ++index) {
            const HttpExiLearnedProduction& production = productions_[index];
            if (production.OwnerQNameId == ownerQNameId &&
                production.Grammar == grammar &&
                production.Event == event &&
                production.QNameId == qnameId) {
                *productionIndex = static_cast<ULONG>(index);
                return true;
            }
        }
        return false;
    }

    bool HttpExiGrammarTable::Get(ULONG productionIndex, HttpExiLearnedProduction* production) const noexcept
    {
        if (production == nullptr || productionIndex >= productionCount_) {
            return false;
        }
        *production = productions_[productionIndex];
        return true;
    }

    bool HttpExiGrammarTable::GetByEventCode(
        ULONG ownerQNameId,
        HttpExiGrammarKind grammar,
        ULONG eventCode,
        HttpExiLearnedProduction* production) const noexcept
    {
        if (production == nullptr) {
            return false;
        }

        SIZE_T matchingCount = Count(ownerQNameId, grammar);
        if (eventCode >= matchingCount) {
            return false;
        }
        SIZE_T ordinal = matchingCount - static_cast<SIZE_T>(eventCode) - 1;
        for (SIZE_T index = 0; index < productionCount_; ++index) {
            const HttpExiLearnedProduction& candidate = productions_[index];
            if (candidate.OwnerQNameId != ownerQNameId || candidate.Grammar != grammar) {
                continue;
            }
            if (ordinal == 0) {
                *production = candidate;
                return true;
            }
            --ordinal;
        }
        return false;
    }

    SIZE_T HttpExiGrammarTable::Count(ULONG ownerQNameId, HttpExiGrammarKind grammar) const noexcept
    {
        SIZE_T count = 0;
        for (SIZE_T index = 0; index < productionCount_; ++index) {
            if (productions_[index].OwnerQNameId == ownerQNameId &&
                productions_[index].Grammar == grammar) {
                ++count;
            }
        }
        return count;
    }

    SIZE_T HttpExiGrammarTable::Count() const noexcept
    {
        return productionCount_;
    }
}
}
