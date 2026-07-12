#include "session/Async.h"
#include "session/ConnectionPool.h"
#include "session/EngineImpl.h"
#include "session/HandleAlloc.h"
#include "session/UrlParser.h"
#include "session/Workspace.h"
#include <wknet/crypto/CngProviderCache.h>
#include "client/Http2Client.h"
#include "client/WebSocketClient.h"
#include "http1/HttpContentEncoding.h"
#include "http1/HttpParser.h"
#include "http1/HttpRequest.h"
#include "http2/Http2Connection.h"
#include "net/WskSocket.h"
#include "tls/TlsConnection.h"
#include "ws/WebSocketFrame.h"

#if defined(WKNET_USER_MODE_TEST)
#include <stdlib.h>
#include <stdio.h>
#else
#include <ws2ipdef.h>
#endif

namespace wknet
{
namespace session
{
#include "EngineHandleTable.inc"
#include "EngineValidation.inc"
#include "EngineHandleOps.inc"
#include "EngineRequestStorage.inc"
#include "EngineResponseStorage.inc"
#include "EngineWebSocketStorage.inc"
#include "SessionLife.inc"
#include "RequestApi.inc"
#include "ResponseApi.inc"
#include "EngineAsyncApi.inc"
#include "EngineTestHooks.inc"
}
}
