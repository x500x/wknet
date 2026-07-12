#include "ExiGrammar.h"

namespace wknet
{
namespace codec
{
    bool HttpExiBuiltinProduction(
        HttpExiGrammarKind grammar,
        ULONG eventCode,
        bool preserveComments,
        bool preservePis,
        bool preserveDtd,
        HttpExiProduction* production) noexcept
    {
        if (production == nullptr) {
            return false;
        }
        *production = {};
        ULONG optionalCode = 0;

        switch (grammar) {
        case HttpExiGrammarKind::Document:
            optionalCode = 1;
            if (eventCode == 0) {
                production->Event = HttpExiEventKind::StartDocument;
                production->NextGrammar = HttpExiGrammarKind::DocContent;
                return true;
            }
            break;

        case HttpExiGrammarKind::Fragment:
            if (eventCode == 0) {
                production->Event = HttpExiEventKind::StartDocument;
                production->NextGrammar = HttpExiGrammarKind::FragmentContent;
                return true;
            }
            break;

        case HttpExiGrammarKind::FragmentContent:
            optionalCode = 2;
            if (eventCode == 0) {
                production->Event = HttpExiEventKind::StartElement;
                production->NextGrammar = HttpExiGrammarKind::FragmentContent;
                production->PushElementGrammar = true;
                return true;
            }
            if (eventCode == 1) {
                production->Event = HttpExiEventKind::EndDocument;
                production->PopGrammar = true;
                return true;
            }
            break;

        case HttpExiGrammarKind::DocContent:
            optionalCode = 1;
            if (eventCode == 0) {
                production->Event = HttpExiEventKind::StartElement;
                production->NextGrammar = HttpExiGrammarKind::DocumentEnd;
                production->PushElementGrammar = true;
                return true;
            }
            break;

        case HttpExiGrammarKind::DocumentEnd:
            optionalCode = 1;
            if (eventCode == 0) {
                production->Event = HttpExiEventKind::EndDocument;
                production->PopGrammar = true;
                return true;
            }
            break;

        case HttpExiGrammarKind::StartTagContent:
            optionalCode = 5;
            if (eventCode == 0) {
                production->Event = HttpExiEventKind::Attribute;
                production->NextGrammar = HttpExiGrammarKind::StartTagContent;
                return true;
            }
            if (eventCode == 1) {
                production->Event = HttpExiEventKind::NamespaceDeclaration;
                production->NextGrammar = HttpExiGrammarKind::StartTagContent;
                return true;
            }
            if (eventCode == 2) {
                production->Event = HttpExiEventKind::StartElement;
                production->NextGrammar = HttpExiGrammarKind::ElementContent;
                production->PushElementGrammar = true;
                return true;
            }
            if (eventCode == 3) {
                production->Event = HttpExiEventKind::Characters;
                production->NextGrammar = HttpExiGrammarKind::ElementContent;
                return true;
            }
            if (eventCode == 4) {
                production->Event = HttpExiEventKind::EndElement;
                production->PopGrammar = true;
                return true;
            }
            break;

        case HttpExiGrammarKind::ElementContent:
            optionalCode = 3;
            if (eventCode == 0) {
                production->Event = HttpExiEventKind::StartElement;
                production->NextGrammar = HttpExiGrammarKind::ElementContent;
                production->PushElementGrammar = true;
                return true;
            }
            if (eventCode == 1) {
                production->Event = HttpExiEventKind::Characters;
                production->NextGrammar = HttpExiGrammarKind::ElementContent;
                return true;
            }
            if (eventCode == 2) {
                production->Event = HttpExiEventKind::EndElement;
                production->PopGrammar = true;
                return true;
            }
            break;

        default:
            return false;
        }

        if (preserveComments) {
            if (eventCode == optionalCode) {
                production->Event = HttpExiEventKind::Comment;
                production->NextGrammar = grammar;
                return true;
            }
            ++optionalCode;
        }
        if (preservePis) {
            if (eventCode == optionalCode) {
                production->Event = HttpExiEventKind::ProcessingInstruction;
                production->NextGrammar = grammar;
                return true;
            }
            ++optionalCode;
        }
        if (preserveDtd) {
            if (eventCode == optionalCode) {
                production->Event = HttpExiEventKind::Dtd;
                production->NextGrammar = grammar;
                return true;
            }
        }

        return false;
    }
}
}
