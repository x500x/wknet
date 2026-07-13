#pragma once

#include "tls/Tls13HandshakeMessages.h"

namespace wknet
{
namespace tls
{
    // TCP TLS source-compatibility facade. All record-independent TLS 1.3
    // message implementation is owned by Tls13HandshakeMessages.
    using TlsHandshake13 = Tls13HandshakeMessages;
}
}
