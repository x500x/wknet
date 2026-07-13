#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif
#include "quic/QuicTransportParameters.h"
#include <stdio.h>
namespace
{
bool failed = false;
void E(bool c, const char *m)
{
    if (!c)
    {
        failed = true;
        printf("FAIL: %s\n", m);
    }
}
} // namespace
int main()
{
    UCHAR encoded[128] = {};
    SIZE_T written = 0;
    const UCHAR scid[] = {1, 2, 3, 4};
    E(NT_SUCCESS(
          wknet::quic::QuicEncodeClientTransportParameters({scid, sizeof(scid)}, encoded, sizeof(encoded), &written)),
      "client parameters encode");
    wknet::quic::QuicTransportParameters p = {};
    E(NT_SUCCESS(wknet::quic::QuicParseTransportParameters(encoded, written,
                                                           wknet::quic::QuicTransportParameterPeerRole::Client, &p)),
      "client parameters parse");
    E(p.MaxUdpPayloadSize == 1200 && p.DisableActiveMigration && p.InitialSourceConnectionId.Length == 4,
      "fixed client policy encoded");

    wknet::quic::QuicClientTransportParameterOptions clientOptions = {};
    clientOptions.InitialSourceConnectionId = {scid, sizeof(scid)};
    clientOptions.MaxIdleTimeout = 30000;
    clientOptions.InitialMaxData = 16 * 1024 * 1024;
    clientOptions.InitialMaxStreamDataBidiLocal = 1024 * 1024;
    clientOptions.InitialMaxStreamDataBidiRemote = 1024 * 1024;
    clientOptions.InitialMaxStreamDataUni = 1024 * 1024;
    clientOptions.InitialMaxStreamsBidi = 100;
    clientOptions.InitialMaxStreamsUni = 8;
    clientOptions.ActiveConnectionIdLimit = 8;
    written = 0;
    E(NT_SUCCESS(wknet::quic::QuicEncodeClientTransportParametersWithLimits(clientOptions, encoded, sizeof(encoded),
                                                                            &written)),
      "complete client parameters encode");
    E(NT_SUCCESS(wknet::quic::QuicParseTransportParameters(encoded, written,
                                                           wknet::quic::QuicTransportParameterPeerRole::Client, &p)),
      "complete client parameters parse");
    E(p.MaxIdleTimeout == 30000 && p.InitialMaxData == 16 * 1024 * 1024 &&
          p.InitialMaxStreamDataBidiLocal == 1024 * 1024 && p.InitialMaxStreamDataBidiRemote == 1024 * 1024 &&
          p.InitialMaxStreamDataUni == 1024 * 1024 && p.InitialMaxStreamsBidi == 100 && p.InitialMaxStreamsUni == 8 &&
          p.ActiveConnectionIdLimit == 8,
      "complete client flow-control and stream limits encoded");
    clientOptions.ActiveConnectionIdLimit = 1;
    E(wknet::quic::QuicEncodeClientTransportParametersWithLimits(clientOptions, encoded, sizeof(encoded), &written) ==
          STATUS_INVALID_PARAMETER,
      "client active CID limit below two rejected");
    const UCHAR duplicate[] = {0x03, 0x02, 0x44, 0xb0, 0x03, 0x02, 0x44, 0xb0};
    E(wknet::quic::QuicParseTransportParameters(duplicate, sizeof(duplicate),
                                                wknet::quic::QuicTransportParameterPeerRole::Server,
                                                &p) == STATUS_INVALID_NETWORK_RESPONSE,
      "duplicate rejected");
    const UCHAR badUdp[] = {0x03, 0x01, 0x3f};
    E(wknet::quic::QuicParseTransportParameters(badUdp, sizeof(badUdp),
                                                wknet::quic::QuicTransportParameterPeerRole::Server,
                                                &p) == STATUS_INVALID_NETWORK_RESPONSE,
      "UDP range enforced");
    const UCHAR illegalClient[] = {0x02, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    E(wknet::quic::QuicParseTransportParameters(illegalClient, sizeof(illegalClient),
                                                wknet::quic::QuicTransportParameterPeerRole::Client,
                                                &p) == STATUS_INVALID_NETWORK_RESPONSE,
      "server-only parameter rejected from client");
    const UCHAR badDisable[] = {0x0c, 0x01, 0};
    E(wknet::quic::QuicParseTransportParameters(badDisable, sizeof(badDisable),
                                                wknet::quic::QuicTransportParameterPeerRole::Server,
                                                &p) == STATUS_INVALID_NETWORK_RESPONSE,
      "flag length enforced");
    const UCHAR unknown[] = {0x40, 0x20, 0x02, 1, 2};
    E(NT_SUCCESS(wknet::quic::QuicParseTransportParameters(unknown, sizeof(unknown),
                                                           wknet::quic::QuicTransportParameterPeerRole::Server, &p)),
      "unknown extension ignored");
    if (failed)
    {
        printf("QUIC TRANSPORT PARAMETER TESTS FAILED\n");
        return 1;
    }
    printf("QUIC TRANSPORT PARAMETER TESTS PASSED\n");
    return 0;
}
