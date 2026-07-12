#include "session/HttpEngineInternal.hpp"

namespace wknet
{
namespace session
{
#if !defined(WKNET_USER_MODE_TEST)
    _Must_inspect_result_
    NTSTATUS CopyAsciiToWide(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept
    {
        if (source == nullptr ||
            sourceLength == 0 ||
            destination == nullptr ||
            sourceLength >= destinationCapacity) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < sourceLength; ++index) {
            destination[index] = static_cast<unsigned char>(source[index]);
        }
        destination[sourceLength] = L'\0';
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS FormatServiceName(
        USHORT port,
        _Out_writes_(destinationCapacity) wchar_t* destination,
        SIZE_T destinationCapacity) noexcept
    {
        if (port == 0 || destination == nullptr || destinationCapacity < 2) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T divisor = 1;
        while ((port / divisor) >= 10) {
            divisor *= 10;
        }

        SIZE_T digitCount = 0;
        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            ++digitCount;
        }

        if (digitCount >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T offset = 0;
        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            destination[offset++] = static_cast<wchar_t>(L'0' + ((port / currentDivisor) % 10));
        }
        destination[digitCount] = L'\0';
        return STATUS_SUCCESS;
    }

    tls::TlsProtocol ToTlsProtocol(TlsVersion version) noexcept
    {
        return version == TlsVersion::Tls13 ? tls::TlsProtocol::Tls13 : tls::TlsProtocol::Tls12;
    }

    SIZE_T DecimalDigitCount(USHORT value) noexcept
    {
        SIZE_T divisor = 1;
        while ((value / divisor) >= 10) {
            divisor *= 10;
        }

        SIZE_T digitCount = 0;
        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            ++digitCount;
        }
        return digitCount;
    }

    NTSTATUS AppendDecimalPort(
        USHORT value,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Inout_ SIZE_T* destinationLength) noexcept
    {
        if (destination == nullptr || destinationLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T divisor = 1;
        while ((value / divisor) >= 10) {
            divisor *= 10;
        }

        SIZE_T length = *destinationLength;
        const SIZE_T digitCount = DecimalDigitCount(value);
        if (length + digitCount >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        for (SIZE_T currentDivisor = divisor; currentDivisor != 0; currentDivisor /= 10) {
            destination[length++] = static_cast<char>('0' + ((value / currentDivisor) % 10));
        }

        *destinationLength = length;
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS BuildProxyConnectAuthority(
        const Request& request,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
    {
        if (destinationLength != nullptr) {
            *destinationLength = 0;
        }

        if (destination == nullptr ||
            destinationCapacity == 0 ||
            destinationLength == nullptr ||
            request.HostLength == 0 ||
            request.Port == 0) {
            return STATUS_INVALID_PARAMETER;
        }

        const bool ipv6Literal = TextContainsChar(request.Host, request.HostLength, ':');
        const SIZE_T bracketBytes = ipv6Literal ? 2 : 0;
        const SIZE_T digitCount = DecimalDigitCount(request.Port);
        if (request.HostLength + bracketBytes + 1 + digitCount >= destinationCapacity) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        SIZE_T length = 0;
        if (ipv6Literal) {
            destination[length++] = '[';
        }
        RtlCopyMemory(destination + length, request.Host, request.HostLength);
        length += request.HostLength;
        if (ipv6Literal) {
            destination[length++] = ']';
        }
        destination[length++] = ':';

        NTSTATUS status = AppendDecimalPort(request.Port, destination, destinationCapacity, &length);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        destination[length] = '\0';
        *destinationLength = length;
        return STATUS_SUCCESS;
    }

#if !defined(WKNET_USER_MODE_TEST)
#endif

    _Must_inspect_result_
    NTSTATUS ConnectSocketToAddress(
        _In_ SessionHandle session,
        _In_ const SOCKADDR* remoteAddress,
        _Inout_ PooledConnection& connection,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
    {
        if (session == nullptr || remoteAddress == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        net::WskSocket* socket = nullptr;
        NTSTATUS status = net::WskSocketCreate(&socket);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
        }

        status = net::WskSocketConnect(
            socket,
            session->WskClient,
            remoteAddress,
            nullptr,
            cancellation.IsCancellationRequested != nullptr ? &cancellation : nullptr);
        if (!NT_SUCCESS(status)) {
            net::WskSocketDestroy(socket);
            return status;
        }

        transport::Transport* rawTransport = nullptr;
        status = transport::TransportCreateWsk(socket, &rawTransport);
        if (!NT_SUCCESS(status)) {
            net::WskSocketDestroy(socket);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        status = PooledConnectionAdoptSocket(&connection, socket, rawTransport);
        if (!NT_SUCCESS(status)) {
            transport::TransportClose(rawTransport);
            net::WskSocketDestroy(socket);
        }
        return status;
    }

    _Must_inspect_result_
    NTSTATUS EstablishProxyTunnel(
        _In_ SessionHandle session,
        const Request& request,
        _Inout_ Workspace& workspace,
        _Inout_ PooledConnection& connection,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
    {
        if (session == nullptr || !session->Options.Proxy.Enabled) {
            return STATUS_SUCCESS;
        }
        if (PooledConnectionProxyTunnelEstablished(&connection)) {
            return STATUS_SUCCESS;
        }
        transport::Transport* rawTransport = PooledConnectionRawTransport(&connection);
        if (rawTransport == nullptr ||
            workspace.Response.Data == nullptr ||
            workspace.Response.Length == 0 ||
            workspace.DecodedBody.Data == nullptr ||
            workspace.DecodedBody.Length == 0 ||
            responseHeaders == nullptr ||
            responseTrailers == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        SIZE_T authorityLength = 0;
        NTSTATUS status = BuildProxyConnectAuthority(
            request,
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            workspace.DecodedBody.Length,
            &authorityLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http1::HttpHeader proxyAuthHeader = {};
        transport::ProxyConnectRequestOptions connectOptions = {};
        connectOptions.Authority = {
            reinterpret_cast<char*>(workspace.DecodedBody.Data),
            authorityLength
        };
        if (session->Options.Proxy.AuthHeader != nullptr) {
            proxyAuthHeader.Name = http1::MakeText("Proxy-Authorization");
            proxyAuthHeader.Value = {
                session->Options.Proxy.AuthHeader,
                session->Options.Proxy.AuthHeaderLength
            };
            connectOptions.Headers = &proxyAuthHeader;
            connectOptions.HeaderCount = 1;
        }

        SIZE_T connectRequestLength = 0;
        status = transport::BuildProxyConnectRequest(
            connectOptions,
            reinterpret_cast<char*>(workspace.Response.Data),
            workspace.Response.Length,
            &connectRequestLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
            transport::TransportSetCancellation(rawTransport, &cancellation);
        }

        SIZE_T sent = 0;
        status = transport::TransportSend(rawTransport,
            workspace.Response.Data,
            connectRequestLength,
            &sent);
        if (cancellationOperation != nullptr) {
            transport::TransportSetCancellation(rawTransport, nullptr);
        }
        if (NT_SUCCESS(status) && sent != connectRequestLength) {
            return STATUS_CONNECTION_DISCONNECTED;
        }
        if (!NT_SUCCESS(status)) {
            return status;
        }

        http1::HttpResponse proxyResponse = {};
        SIZE_T proxyRawResponseLength = 0;
        workspace.ResponseLength = 0;
        status = ReadHttpResponseFromSocket(
            rawTransport,
            workspace,
            true,
            nullptr,
            nullptr,
            &proxyResponse,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            &proxyRawResponseLength);
        UNREFERENCED_PARAMETER(proxyRawResponseLength);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        if (proxyResponse.StatusCode == 407) {
            return STATUS_ACCESS_DENIED;
        }
        if (!transport::IsSuccessfulProxyConnectResponse(proxyResponse)) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        workspace.ResponseLength = 0;
        PooledConnectionSetProxyTunnelEstablished(&connection, true);
        return STATUS_SUCCESS;
    }

    _Must_inspect_result_
    NTSTATUS EnsureSocketConnected(
        _In_ SessionHandle session,
        const Request& request,
        _Inout_ PooledConnection& connection,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
    {
        if (session == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        net::WskSocket* socket = PooledConnectionSocket(&connection);
        if (net::WskSocketIsConnected(socket)) {
            return STATUS_SUCCESS;
        }

        PooledConnectionCloseTransportResources(&connection);

        HeapArray<wchar_t> serverName(MaxHostLength + 1);
        HeapArray<wchar_t> serviceName(MaxServiceNameLength + 1);
        if (!serverName.IsValid() || !serviceName.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        const char* connectHost = request.Host;
        SIZE_T connectHostLength = request.HostLength;
        USHORT connectPort = request.Port;
        AddressFamily connectFamily = request.AddressFamily;
        if (session->Options.Proxy.Enabled) {
            connectHost = session->Options.Proxy.Host;
            connectHostLength = session->Options.Proxy.HostLength;
            connectPort = session->Options.Proxy.Port;
            connectFamily = session->Options.Proxy.Family;
        }

        NTSTATUS status = CopyAsciiToWide(connectHost, connectHostLength, serverName.Get(), serverName.Count());
        if (NT_SUCCESS(status)) {
            status = FormatServiceName(connectPort, serviceName.Get(), serviceName.Count());
        }

        HeapArray<SOCKADDR_STORAGE> remoteAddresses(net::WskMaxResolvedAddresses);
        if (!remoteAddresses.IsValid()) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        SIZE_T remoteAddressCount = 0;
        if (NT_SUCCESS(status)) {
            status = net::WskClientResolveAll(session->WskClient,
                serverName.Get(),
                serviceName.Get(),
                remoteAddresses.Get(),
                net::WskMaxResolvedAddresses,
                &remoteAddressCount,
                ToWskAddressFamily(connectFamily));
        }

        NTSTATUS lastStatus = status;
        if (NT_SUCCESS(status)) {
            lastStatus = STATUS_NOT_FOUND;
            for (SIZE_T addressIndex = 0; addressIndex < remoteAddressCount; ++addressIndex) {
                status = ConnectSocketToAddress(
                    session,
                    reinterpret_cast<const SOCKADDR*>(&remoteAddresses[addressIndex]),
                    connection,
                    cancellationOperation);
                if (NT_SUCCESS(status)) {
                    return STATUS_SUCCESS;
                }
                if (status == STATUS_INSUFFICIENT_RESOURCES) {
                    return status;
                }

                lastStatus = status;
                WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Warning, "HttpEngine socket connect attempt failed: 0x%08X index=%Iu family=%u\r\n",
                    static_cast<ULONG>(status),
                    addressIndex,
                    static_cast<unsigned>(remoteAddresses[addressIndex].ss_family));
            }
        }

        if (!NT_SUCCESS(lastStatus)) {
            return lastStatus;
        }

        return STATUS_NOT_FOUND;
    }

    _Must_inspect_result_
    NTSTATUS ConnectTlsOnExistingSocket(
        _In_ SessionHandle session,
        const Request& request,
        _Inout_ Workspace& workspace,
        _Inout_ PooledConnection& connection,
        TlsVersion maximumTlsVersion,
        _In_opt_ AsyncOperationHandle cancellationOperation,
        _Out_opt_ tls::TlsHandshakeFailure* failure) noexcept
    {
        if (failure != nullptr) {
            *failure = {};
        }
        net::WskSocket* socket = PooledConnectionSocket(&connection);
        transport::Transport* rawTransport = PooledConnectionRawTransport(&connection);
        if (session == nullptr || socket == nullptr || rawTransport == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        tls::TlsConnection* tlsConnection = nullptr;
        NTSTATUS createStatus = tls::TlsConnectionCreate(&tlsConnection);
        if (!NT_SUCCESS(createStatus)) {
            return createStatus;
        }

        tls::TlsAlpnProtocol explicitAlpn = {};
        static const tls::TlsAlpnProtocol automaticAlpnProtocols[] = {
            { "h2", 2 },
            { "http/1.1", 8 }
        };
        tls::TlsClientConnectionOptions tlsOptions = {};
        rtl::WorkspaceScratchAllocator* handshakeScratch = nullptr;
        rtl::WorkspaceScratchAllocator* certificateScratch = nullptr;
        handshakeScratch = AllocateNonPagedObject<rtl::WorkspaceScratchAllocator>(
            workspace,
            rtl::WorkspaceScratchAllocator::BufferKind::TlsHandshake);
        certificateScratch = AllocateNonPagedObject<rtl::WorkspaceScratchAllocator>(
            workspace,
            rtl::WorkspaceScratchAllocator::BufferKind::Certificate);
        if (handshakeScratch == nullptr || certificateScratch == nullptr) {
            FreeNonPagedObject(certificateScratch);
            FreeNonPagedObject(handshakeScratch);
            tls::TlsConnectionClose(tlsConnection);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        tlsOptions.ServerName = request.Tls.ServerName != nullptr ? request.Tls.ServerName : request.Host;
        tlsOptions.ServerNameLength = request.Tls.ServerName != nullptr ?
            request.Tls.ServerNameLength :
            request.HostLength;
        tlsOptions.CertificateStore = request.Tls.CertificateStore;
        tlsOptions.VerifyCertificate = request.Tls.CertificatePolicy == CertificatePolicy::Verify;
        tlsOptions.MinimumProtocol = ToTlsProtocol(request.Tls.MinVersion);
        tlsOptions.MaximumProtocol = ToTlsProtocol(maximumTlsVersion);
        tlsOptions.Policy = request.Tls.Policy;
        tlsOptions.ClientCredential = request.Tls.ClientCredential;
        tlsOptions.HandshakeReceiveTimeoutMilliseconds = request.Tls.HandshakeReceiveTimeoutMilliseconds;
        tlsOptions.MaxTls12Renegotiations = request.Tls.MaxTls12Renegotiations;
        tlsOptions.HandshakeScratchAllocator = handshakeScratch;
        tlsOptions.CertificateScratchAllocator = certificateScratch;
        tlsOptions.ProviderCache = session->ProviderCache;
        tlsOptions.EnableSessionResumption = true;

        if (request.Tls.Alpn != nullptr && request.Tls.AlpnLength != 0) {
            explicitAlpn.Name = request.Tls.Alpn;
            explicitAlpn.NameLength = request.Tls.AlpnLength;
            tlsOptions.AlpnProtocols = &explicitAlpn;
            tlsOptions.AlpnProtocolCount = 1;
        }
        else if (IsAutomaticHttpAlpnMode(request)) {
            tlsOptions.AlpnProtocols = automaticAlpnProtocols;
            tlsOptions.AlpnProtocolCount =
                sizeof(automaticAlpnProtocols) / sizeof(automaticAlpnProtocols[0]);
        }

        net::WskCancellationToken cancellation = {};
        if (cancellationOperation != nullptr) {
            cancellation.IsCancellationRequested = IsHttpAsyncCancellationRequested;
            cancellation.Context = cancellationOperation;
            transport::TransportSetCancellation(rawTransport, &cancellation);
        }

        NTSTATUS status = tls::TlsConnectionConnect(tlsConnection, rawTransport, &tlsOptions);
        if (cancellationOperation != nullptr) {
            transport::TransportSetCancellation(rawTransport, nullptr);
        }

        if (!NT_SUCCESS(status)) {
            if (failure != nullptr) {
                *failure = tls::TlsConnectionLastHandshakeFailure(tlsConnection);
            }
            tls::TlsConnectionClose(tlsConnection);
            FreeNonPagedObject(certificateScratch);
            FreeNonPagedObject(handshakeScratch);
            return status;
        }

        transport::Transport* tlsTransport = nullptr;
        status = transport::TransportCreateTls(rawTransport, tlsConnection, &tlsTransport);
        if (!NT_SUCCESS(status)) {
            tls::TlsConnectionClose(tlsConnection);
            FreeNonPagedObject(certificateScratch);
            FreeNonPagedObject(handshakeScratch);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        FreeNonPagedObject(certificateScratch);
        FreeNonPagedObject(handshakeScratch);
        status = PooledConnectionAdoptTls(&connection, tlsConnection, tlsTransport);
        if (!NT_SUCCESS(status)) {
            transport::TransportClose(tlsTransport);
            tls::TlsConnectionClose(tlsConnection);
        }
        return status;
    }

    _Must_inspect_result_
    NTSTATUS EnsureTlsConnected(
        _In_ SessionHandle session,
        const Request& request,
        _Inout_ Workspace& workspace,
        _Inout_ PooledConnection& connection,
        _Out_writes_(headerCapacity) http1::HttpHeader* responseHeaders,
        SIZE_T headerCapacity,
        _Out_writes_(trailerCapacity) http1::HttpHeader* responseTrailers,
        SIZE_T trailerCapacity,
        _In_opt_ AsyncOperationHandle cancellationOperation) noexcept
    {
        net::WskSocket* socket = PooledConnectionSocket(&connection);
        transport::Transport* rawTransport = PooledConnectionRawTransport(&connection);
        if (session == nullptr || socket == nullptr || rawTransport == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        tls::TlsConnection* tlsConnection = PooledConnectionTls(&connection);
        transport::Transport* activeTransport = PooledConnectionTransport(&connection);
        if (tlsConnection != nullptr &&
            tls::TlsConnectionIsEstablished(tlsConnection) &&
            activeTransport != nullptr &&
            activeTransport != rawTransport) {
            return STATUS_SUCCESS;
        }

        PooledConnectionReleaseTls(&connection);

        tls::TlsHandshakeFailure failure = {};
        NTSTATUS status = EstablishProxyTunnel(
            session,
            request,
            workspace,
            connection,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            cancellationOperation);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = ConnectTlsOnExistingSocket(
            session,
            request,
            workspace,
            connection,
            request.Tls.MaxVersion,
            cancellationOperation,
            &failure);
        if (NT_SUCCESS(status) || !IsHttpTls12ConfirmationCandidate(request, failure)) {
            return status;
        }

        const NTSTATUS originalStatus = status;
        PooledConnectionCloseTransportResources(&connection);

        status = EnsureSocketConnected(session, request, connection, cancellationOperation);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error,
                "HttpEngine TLS1.2 confirmation reconnect failed: 0x%08X original=0x%08X\r\n",
                static_cast<ULONG>(status),
                static_cast<ULONG>(originalStatus));
            return originalStatus;
        }

        status = EstablishProxyTunnel(
            session,
            request,
            workspace,
            connection,
            responseHeaders,
            headerCapacity,
            responseTrailers,
            trailerCapacity,
            cancellationOperation);
        if (!NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error,
                "HttpEngine TLS1.2 confirmation proxy CONNECT failed: 0x%08X original=0x%08X\r\n",
                static_cast<ULONG>(status),
                static_cast<ULONG>(originalStatus));
            return originalStatus;
        }

        status = ConnectTlsOnExistingSocket(
            session,
            request,
            workspace,
            connection,
            TlsVersion::Tls12,
            cancellationOperation,
            nullptr);
        if (NT_SUCCESS(status)) {
            WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Info, "HttpEngine TLS1.2 confirmed after version negotiation\r\n");
            return STATUS_SUCCESS;
        }

        WKNET_TRACE(::wknet::ComponentSession, ::wknet::TraceLevel::Error,
            "HttpEngine TLS1.2 confirmation failed: 0x%08X original=0x%08X\r\n",
            static_cast<ULONG>(status),
            static_cast<ULONG>(originalStatus));
        PooledConnectionCloseTransportResources(&connection);
        return originalStatus;
    }
#endif

}
}

