#if !defined(WKNET_USER_MODE_TEST)
#include <ntifs.h>
#endif
#include "quic/QuicConnectionPrivate.hpp"

namespace wknet::quic
{
    NTSTATUS QuicConnectionCreate(const QuicConnectionCreateOptions& o, QuicConnection** out) noexcept
    {
        if (out != nullptr)
        {
            *out = nullptr;
        }
        if (out == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }

        QuicConnection* c =
            AllocateProtocolNonPagedObject<QuicConnection>(rtl::ProtocolAllocationSite::QuicConnectionObject);
        if (c == nullptr)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NTSTATUS s = c->Initialize(o);
        if (!NT_SUCCESS(s))
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicConnectionObject, c);
            return s;
        }
        *out = c;
        return STATUS_SUCCESS;
    }
    NTSTATUS QuicConnectionConnect(QuicConnection* c, QuicOperation* o) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::Connect, o) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionWaitEstablishedAsync(QuicConnection* c, QuicOperation* o) noexcept
    {
        return c != nullptr ? c->WaitEstablished(o) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionOpenStream(QuicConnection* c, QuicOperation* o) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::OpenBidirectionalStream, o) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionOpenUnidirectionalStream(QuicConnection* c, QuicOperation* o) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::OpenUnidirectionalStream, o) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionWriteStream(QuicConnection* c, ULONGLONG streamId, const UCHAR* data, SIZE_T dataLength,
                                       bool fin, QuicOperation* o) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::WriteStream, o, streamId, data, dataLength, nullptr, fin)
                            : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionConsumeStream(QuicConnection* c, ULONGLONG streamId, UCHAR* output, SIZE_T capacity,
                                         QuicOperation* o) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::ConsumeStream, o, streamId, nullptr, capacity, output, false)
                            : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionResetStream(QuicConnection* c, ULONGLONG streamId, ULONGLONG errorCode,
                                       QuicOperation* o) noexcept
    {
        return c != nullptr
                   ? c->Enqueue(QuicCommandType::ResetStream, o, streamId, nullptr, 0, nullptr, false, errorCode)
                   : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionStopSending(QuicConnection* c, ULONGLONG streamId, ULONGLONG errorCode,
                                       QuicOperation* o) noexcept
    {
        return c != nullptr
                   ? c->Enqueue(QuicCommandType::StopSending, o, streamId, nullptr, 0, nullptr, false, errorCode)
                   : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionCloseAsync(QuicConnection* c, QuicOperation* o) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::Close, o) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionCloseApplicationAsync(QuicConnection* c, ULONGLONG applicationError,
                                                 QuicOperation* o) noexcept
    {
        return c != nullptr
                   ? c->Enqueue(QuicCommandType::CloseApplication, o, 0, nullptr, 0, nullptr, false, applicationError)
                   : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionExecuteApplication(QuicConnection* c, QuicApplicationCommandCallback callback, void* context,
                                              QuicOperation* operation) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::Application, operation, 0, nullptr, 0, nullptr, false, 0,
                                         callback, context)
                            : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionApplicationWriteStream(QuicConnection* c, ULONGLONG streamId, const UCHAR* data,
                                                  SIZE_T dataLength, bool fin, SIZE_T* bytesWritten) noexcept
    {
        return c != nullptr ? c->ApplicationWriteStream(streamId, data, dataLength, fin, bytesWritten)
                            : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionApplicationConsumeStream(QuicConnection* c, ULONGLONG streamId, UCHAR* output,
                                                    SIZE_T capacity, SIZE_T* bytesConsumed, bool* fin) noexcept
    {
        return c != nullptr ? c->ApplicationConsumeStream(streamId, output, capacity, bytesConsumed, fin)
                            : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionApplicationResetStream(QuicConnection* c, ULONGLONG streamId,
                                                  ULONGLONG applicationError) noexcept
    {
        return c != nullptr ? c->ApplicationResetStream(streamId, applicationError) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionApplicationStopSending(QuicConnection* c, ULONGLONG streamId,
                                                  ULONGLONG applicationError) noexcept
    {
        return c != nullptr ? c->ApplicationStopSending(streamId, applicationError) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionApplicationClose(QuicConnection* c, ULONGLONG applicationError) noexcept
    {
        return c != nullptr ? c->ApplicationClose(applicationError) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionWorkerOpenUnidirectionalStream(QuicConnection* c, QuicStream** stream) noexcept
    {
        return c != nullptr ? c->ApplicationOpenUnidirectionalStream(stream) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionWorkerOpenBidirectionalStream(QuicConnection* c, QuicStream** stream) noexcept
    {
        return c != nullptr ? c->ApplicationOpenBidirectionalStream(stream) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionWorkerConsumeStream(QuicConnection* c, QuicStream* stream, UCHAR* output, SIZE_T capacity,
                                               SIZE_T* bytesConsumed, bool* fin) noexcept
    {
        if (c == nullptr || stream == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        return c->ApplicationConsumeStream(stream->Id(), output, capacity, bytesConsumed, fin);
    }
    NTSTATUS QuicConnectionWorkerWriteStream(QuicConnection* c, QuicStream* stream, const UCHAR* data, SIZE_T length,
                                             bool fin, SIZE_T* bytesWritten) noexcept
    {
        if (c == nullptr || stream == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        SIZE_T localBytesWritten = 0;
        SIZE_T* result = bytesWritten != nullptr ? bytesWritten : &localBytesWritten;
        return c->ApplicationWriteStream(stream->Id(), data, length, fin, result);
    }
    NTSTATUS QuicConnectionWorkerResetStream(QuicConnection* c, QuicStream* stream, ULONGLONG applicationError) noexcept
    {
        return c != nullptr && stream != nullptr ? c->ApplicationResetStream(stream->Id(), applicationError)
                                                 : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionWorkerStopSending(QuicConnection* c, QuicStream* stream, ULONGLONG applicationError) noexcept
    {
        return c != nullptr && stream != nullptr ? c->ApplicationStopSending(stream->Id(), applicationError)
                                                 : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionWorkerCloseApplication(QuicConnection* c, ULONGLONG applicationError) noexcept
    {
        return c != nullptr ? c->ApplicationClose(applicationError) : STATUS_INVALID_PARAMETER;
    }
    QuicConnectionState QuicConnectionStateGet(const QuicConnection* c) noexcept
    {
        return c != nullptr ? c->State() : QuicConnectionState::Closed;
    }
    void QuicConnectionDestroy(QuicConnection* c) noexcept
    {
        if (c != nullptr)
        {
            FreeProtocolNonPagedObject(rtl::ProtocolAllocationSite::QuicConnectionObject, c);
        }
    }
#if defined(WKNET_USER_MODE_TEST)
    void QuicConnectionTestSetWorkerStartFailure(bool fail) noexcept { g_failWorkerStart = fail; }
    NTSTATUS QuicConnectionTestEnqueueNoop(QuicConnection* c, QuicOperation* o) noexcept
    {
        return c != nullptr ? c->Enqueue(QuicCommandType::Noop, o) : STATUS_INVALID_PARAMETER;
    }
    void QuicConnectionTestResumeWorker(QuicConnection* c) noexcept
    {
        if (c != nullptr)
            c->Resume();
    }
    NTSTATUS QuicConnectionTestConfirmHandshake(QuicConnection* c) noexcept
    {
        if (c == nullptr)
            return STATUS_INVALID_PARAMETER;
        QuicOperation o;
        QuicOperationInitialize(&o);
        NTSTATUS s = c->Enqueue(QuicCommandType::ConfirmHandshake, &o);
        return NT_SUCCESS(s) ? QuicOperationWait(&o, 1000) : s;
    }
    NTSTATUS QuicConnectionTestCloseFromWorker(QuicConnection* c) noexcept
    {
        if (c == nullptr)
            return STATUS_INVALID_PARAMETER;
        QuicOperation o;
        QuicOperationInitialize(&o);
        NTSTATUS s = c->Enqueue(QuicCommandType::SelfClose, &o);
        return NT_SUCCESS(s) ? QuicOperationWait(&o, 1000) : s;
    }
    void QuicConnectionTestWakeTimer(QuicConnection* c) noexcept
    {
        if (c == nullptr)
        {
            return;
        }
        c->WakeTimerForTest();
    }
    NTSTATUS QuicConnectionTestProcessTimer(QuicConnection* c) noexcept
    {
        if (c == nullptr)
        {
            return STATUS_INVALID_PARAMETER;
        }
        QuicOperation operation;
        QuicOperationInitialize(&operation);
        const NTSTATUS status = c->Enqueue(QuicCommandType::ProcessTimer, &operation);
        return NT_SUCCESS(status) ? QuicOperationWait(&operation, 1000) : status;
    }
    NTSTATUS QuicConnectionTestConfigureApplicationKeys(QuicConnection* c, const QuicPacketKeySet& writeKey,
                                                        const QuicPacketKeySet& readKey) noexcept
    {
        return c != nullptr ? c->ConfigureApplicationKeysForTest(writeKey, readKey) : STATUS_INVALID_PARAMETER;
    }
    NTSTATUS QuicConnectionTestForceKeyUpdate(QuicConnection* c) noexcept
    {
        return c != nullptr ? c->ForceKeyUpdateForTest() : STATUS_INVALID_PARAMETER;
    }
    void QuicConnectionTestConfirmKeyUpdate(QuicConnection* c, ULONGLONG packetNumber) noexcept
    {
        if (c != nullptr)
        {
            c->ConfirmKeyUpdateForTest(packetNumber);
        }
    }
    bool QuicConnectionTestSendKeyPhase(const QuicConnection* c) noexcept
    {
        return c != nullptr && c->SendKeyPhaseForTest();
    }
    bool QuicConnectionTestSendKeyUpdatePending(const QuicConnection* c) noexcept
    {
        return c != nullptr && c->SendKeyUpdatePendingForTest();
    }
    NTSTATUS QuicConnectionTestInjectFrame(QuicConnection* c, QuicEncryptionLevel level, QuicPacketNumberSpace space,
                                           const QuicFrame& frame) noexcept
    {
        return c != nullptr ? c->InjectFrameForTest(level, space, frame) : STATUS_INVALID_PARAMETER;
    }
#endif

} // namespace wknet::quic
