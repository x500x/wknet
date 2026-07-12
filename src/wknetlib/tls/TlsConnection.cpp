#include "tls/TlsConnection.h"

#include <wknet/WknetLimits.h>
#include <wknet/crypto/CngProviderCache.h>
#include <wknet/crypto/Ed25519.h>
#include <wknet/crypto/Ed448.h>
#include <wknet/crypto/KeyExchange.h>
#include "tls/TlsCapabilities.h"
#include "tls/TlsHandshake13.h"

#if defined(WKNET_USER_MODE_TEST)
#include <time.h>
#endif

namespace wknet
{
namespace tls
{
#include "TlsConnectionHelpers.inc"
#include "TlsConnectionFacade.inc"
#include "TlsConnect12.inc"
#include "TlsConnect13.inc"
#include "TlsRecordIo.inc"
#include "TlsPostHandshake.inc"
}
}
