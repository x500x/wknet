
#pragma once

#include "session/EngineUtils.h"

namespace wknet
{
namespace session
{
    inline constexpr ULONG MaxConnectionPoolCapacity = 1024;
#if defined(WKNET_USER_MODE_TEST)
    inline constexpr ULONG PassiveLevel = 0;
    extern ULONG g_testCurrentIrql;
#endif

    HandleHeader* ToHandleHeader(SessionHandle session) noexcept
        ;

    HandleHeader* ToHandleHeader(RequestHandle request) noexcept
        ;

    HandleHeader* ToHandleHeader(ResponseHandle response) noexcept
        ;

    HandleHeader* ToHandleHeader(WebSocketHandle websocket) noexcept
        ;

    void EnsureActiveHandleTableLockInitialized() noexcept
        ;

    void AcquireActiveHandleTableLock() noexcept
        ;

    void ReleaseActiveHandleTableLock() noexcept
        ;

    HandleHeader** ActiveHandleList(HandleKind kind) noexcept
        ;

    HandleHeader* FindActiveHandleLocked(HandleHeader* target, HandleKind kind) noexcept
        ;

    HandleHeader** FindActiveHandleLinkLocked(HandleHeader* target, HandleKind kind) noexcept
        ;

    bool IsActiveHandle(HandleHeader* target, HandleKind kind) noexcept
        ;

    NTSTATUS RegisterActiveHandle(HandleHeader* header, HandleKind kind) noexcept
        ;

    bool TryCloseActiveHandle(HandleHeader* target, HandleKind kind) noexcept
        ;

    WebSocketHandle FirstActiveWebSocketHandle() noexcept
        ;

    SessionHandle FirstActiveSessionHandle() noexcept
        ;

    bool BeginHandleOperation(HandleHeader* target, HandleKind kind) noexcept
        ;

    void EndHandleOperation(
        HandleHeader* target,
        HandleKind kind,
        _Inout_ volatile LONG* inFlight
#if !defined(WKNET_USER_MODE_TEST)
        ,
        _Inout_ KEVENT* drainEvent
#endif
        ) noexcept
        ;

    void WaitForHandleDrain(
        _Inout_ volatile LONG* inFlight
#if !defined(WKNET_USER_MODE_TEST)
        ,
        _Inout_ KEVENT* drainEvent
#endif
        ) noexcept
        ;

    bool IsSessionHandle(SessionHandle session) noexcept
        ;

    bool IsRequestHandle(RequestHandle request) noexcept
        ;

    bool IsResponseHandle(ResponseHandle response) noexcept
        ;

    bool IsWebSocketHandle(WebSocketHandle websocket) noexcept
        ;

    NTSTATUS RegisterActiveSessionHandle(SessionHandle session) noexcept
        ;

    NTSTATUS RegisterActiveRequestHandle(RequestHandle request) noexcept
        ;

    NTSTATUS RegisterActiveResponseHandle(ResponseHandle response) noexcept
        ;

    NTSTATUS RegisterActiveWebSocketHandle(WebSocketHandle websocket) noexcept
        ;

    bool TryCloseActiveSessionHandle(SessionHandle session) noexcept
        ;

    bool TryCloseActiveRequestHandle(RequestHandle request) noexcept
        ;

    bool TryCloseActiveResponseHandle(ResponseHandle response) noexcept
        ;

    bool TryCloseActiveWebSocketHandle(WebSocketHandle websocket) noexcept
        ;

    bool SessionBeginOperation(SessionHandle session) noexcept
        ;

    void SessionEndOperation(SessionHandle session) noexcept
        ;

    bool RequestBeginOperation(RequestHandle request) noexcept
        ;

    void RequestEndOperation(RequestHandle request) noexcept
        ;

    bool ResponseBeginOperation(ResponseHandle response) noexcept
        ;

    void ResponseEndOperation(ResponseHandle response) noexcept
        ;

    bool WebSocketBeginOperation(WebSocketHandle websocket) noexcept
        ;

    void WaitForSessionDrain(SessionHandle session) noexcept
        ;

    void WaitForRequestDrain(RequestHandle request) noexcept
        ;

    void WaitForResponseDrain(ResponseHandle response) noexcept
        ;

    void ReleaseStoredHeader(_Inout_ StoredHeader& header) noexcept
        ;

    void ReleaseStoredHeaderList(_Inout_ StoredHeaderList& list) noexcept
        ;

    NTSTATUS EnsureStoredHeaderListCapacity(
        _Inout_ StoredHeaderList& list,
        SIZE_T requiredCount) noexcept
        ;

    void ReleaseOwnedBody(_Inout_ Request& request) noexcept
        ;

    void ResetOwnedBodyContent(_Inout_ Request& request) noexcept
        ;

    void AbortOwnedBodyBuild(_Inout_ Request& request) noexcept
        ;

    bool AddSize(SIZE_T left, SIZE_T right, _Out_ SIZE_T* result) noexcept
        ;

    NTSTATUS EnsureOwnedBodyCapacity(_Inout_ Request& request, SIZE_T requiredCapacity) noexcept
        ;

    NTSTATUS BeginOwnedBodyBuild(_Inout_ Request& request) noexcept
        ;

    NTSTATUS AppendOwnedBody(
        _Inout_ Request& request,
        _In_reads_bytes_opt_(dataLength) const UCHAR* data,
        SIZE_T dataLength) noexcept
        ;

    NTSTATUS AppendOwnedText(_Inout_ Request& request, _In_opt_ const char* text, SIZE_T textLength) noexcept
        ;

    NTSTATUS AppendOwnedLiteral(_Inout_ Request& request, _In_z_ const char* text) noexcept
        ;

    NTSTATUS AddStoredHeader(
        _Inout_ Request& request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
        ;

    bool IsForbiddenRequestTrailerField(const char* name, SIZE_T nameLength) noexcept
        ;

    NTSTATUS AddStoredTrailer(
        _Inout_ Request& request,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
        ;

    void RemoveStoredHeadersByName(_Inout_ Request& request, _In_z_ const char* name) noexcept
        ;

    NTSTATUS ReplaceContentType(
        _Inout_ Request& request,
        _In_reads_bytes_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept
        ;

    bool IsOptionalTextValid(const char* text, SIZE_T textLength) noexcept
        ;

    bool IsUnreservedFormChar(char value) noexcept
        ;

    NTSTATUS AppendUrlEncodedText(
        _Inout_ Request& request,
        _In_reads_bytes_opt_(textLength) const char* text,
        SIZE_T textLength) noexcept
        ;

    bool IsValidHeaderQuotedByte(char value) noexcept
        ;

    bool IsValidHeaderNameByte(char value) noexcept
        ;

    bool IsValidHeaderValueByte(char value) noexcept
        ;

    bool IsValidHeaderText(
        _In_reads_bytes_(textLength) const char* text,
        SIZE_T textLength,
        bool name) noexcept
        ;

    NTSTATUS AppendMultipartQuotedValue(
        _Inout_ Request& request,
        _In_reads_bytes_(valueLength) const char* value,
        SIZE_T valueLength) noexcept
        ;

    NTSTATUS GenerateMultipartBoundary(_Inout_ Request& request, _Out_ SIZE_T* boundaryLength) noexcept
        ;

    NTSTATUS SetMultipartContentType(
        _Inout_ Request& request,
        _In_reads_bytes_(boundaryLength) const char* boundary,
        SIZE_T boundaryLength) noexcept
        ;

    NTSTATUS AppendMultipartPartHeader(
        _Inout_ Request& request,
        _In_reads_bytes_(boundaryLength) const char* boundary,
        SIZE_T boundaryLength,
        _In_reads_bytes_(nameLength) const char* name,
        SIZE_T nameLength,
        _In_reads_bytes_opt_(fileNameLength) const char* fileName,
        SIZE_T fileNameLength,
        _In_reads_bytes_opt_(contentTypeLength) const char* contentType,
        SIZE_T contentTypeLength) noexcept
        ;

    void DeriveFileNameFromPath(
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength,
        _Outptr_result_bytebuffer_(*fileNameLength) const char** fileName,
        _Out_ SIZE_T* fileNameLength) noexcept
        ;

    NTSTATUS AppendFileToOwnedBody(
        _Inout_ Request& request,
        _In_reads_bytes_(filePathLength) const char* filePath,
        SIZE_T filePathLength) noexcept
        ;

    void ReleaseRequestStorage(_Inout_ Request& request) noexcept
        ;

    NTSTATUS CloneRequestForAsync(_In_ const Request& source, _Out_ RequestHandle* clonedRequest) noexcept
        ;

    bool IsPassiveLevel() noexcept
        ;

    NTSTATUS CheckPassiveLevel() noexcept
        ;

    SIZE_T NormalizeMaxResponseBytes(SIZE_T value) noexcept
        ;

    bool IsValidMaxResponseBytes(SIZE_T value) noexcept
        ;

    bool IsValidMaxResponseHeaders(SIZE_T value) noexcept
        ;

    bool IsValidHttp2MaxHeaderBlockBytes(SIZE_T value) noexcept
        ;

    bool IsValidMaxMessageBytes(SIZE_T value) noexcept
        ;

    bool IsWebSocketSubprotocolSeparator(char value) noexcept
        ;

    bool IsValidWebSocketSubprotocolToken(const char* token, SIZE_T length) noexcept
        ;

    bool IsValidWebSocketSubprotocolList(const char* value, SIZE_T length) noexcept
        ;

    SIZE_T EffectiveMaxResponseBytes(const HttpSendOptions* options, SIZE_T sessionValue) noexcept
        ;

    bool IsValidTlsOptions(const TlsOptions& options) noexcept
        ;

    bool IsValidProxyAuthorityText(const char* text, SIZE_T textLength) noexcept
        ;

    bool IsValidProxyHeaderValueText(const char* text, SIZE_T textLength) noexcept
        ;

    bool IsValidProxyOptions(const ProxyOptions& options) noexcept
        ;

    bool IsValidHttp11PipelineOptions(const SessionOptions& options) noexcept
        ;

    Http2KeepAliveOptions NormalizeHttp2KeepAliveOptions(
        const Http2KeepAliveOptions& options) noexcept
        ;

    bool IsValidHttp2KeepAliveOptions(const Http2KeepAliveOptions& options) noexcept
        ;

    bool IsValidSessionOptions(const SessionOptions& options) noexcept
        ;

    bool IsValidAddressFamily(AddressFamily addressFamily) noexcept
        ;

    bool IsValidHttp2CleartextMode(Http2CleartextMode mode) noexcept
        ;

    bool IsValidWebSocketTransportMode(WebSocketTransportMode mode) noexcept
        ;

    net::WskAddressFamily ToWskAddressFamily(AddressFamily addressFamily) noexcept
        ;

    bool IsValidWebSocketConnectOptions(const WebSocketConnectOptions& options) noexcept
        ;

    bool IsValidReceiveOptions(const WebSocketReceiveOptions& options) noexcept
        ;

    void* AllocateApiMemory(SIZE_T length) noexcept
        ;

    void FreeApiMemory(_In_opt_ void* data) noexcept
        ;

    char* AllocateTextCopy(const char* text, SIZE_T length) noexcept
        ;

    UCHAR* AllocateBytesCopy(const UCHAR* data, SIZE_T length) noexcept
        ;

    char ToLowerAscii(char value) noexcept
        ;

    bool TextEqualsIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right,
        SIZE_T rightLength) noexcept
        ;

    bool TextEqualsLiteralIgnoreCase(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept
        ;

    bool TextEqualsLiteral(
        const char* left,
        SIZE_T leftLength,
        const char* right) noexcept
        ;

    bool TextContainsChar(const char* text, SIZE_T textLength, char needle) noexcept
        ;

    bool IsConnectionCloseStatus(NTSTATUS status) noexcept
        ;

    bool IsOrderlyConnectionCloseStatus(NTSTATUS status) noexcept
        ;

    bool IsDefaultPort(const char* scheme, SIZE_T schemeLength, USHORT port) noexcept
        ;

    NTSTATUS CopyExactText(
        const char* source,
        SIZE_T sourceLength,
        _Out_writes_bytes_(destinationCapacity) char* destination,
        SIZE_T destinationCapacity,
        _Out_ SIZE_T* destinationLength) noexcept
        ;

    bool IsValidSendOptions(const HttpSendOptions& options, const Session& session) noexcept
        ;

}
}
