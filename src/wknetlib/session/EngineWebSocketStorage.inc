    NTSTATUS CopyWebSocketHeaders(
        const WebSocketHeader* headers,
        SIZE_T headerCount,
        WebSocket& websocket) noexcept
    {
        websocket.ExtraHeaderCount = 0;

        if (headerCount == 0) {
            return STATUS_SUCCESS;
        }

        if (headers == nullptr || headerCount > MaxHeadersPerRequest) {
            return STATUS_INVALID_PARAMETER;
        }

        static const char* const controlledHeaders[] = {
            "Host",
            "Connection",
            "Upgrade",
            "Content-Length",
            "Transfer-Encoding",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Sec-WebSocket-Protocol",
            "Sec-WebSocket-Extensions"
        };

        for (SIZE_T index = 0; index < headerCount; ++index) {
            const WebSocketHeader& header = headers[index];
            if (header.Name == nullptr || header.NameLength == 0) {
                return STATUS_INVALID_PARAMETER;
            }
            if (header.NameLength > MaxHeaderNameLength ||
                header.ValueLength > MaxHeaderValueLength) {
                return STATUS_BUFFER_TOO_SMALL;
            }
            if (!IsValidHeaderText(header.Name, header.NameLength, true) ||
                !IsValidHeaderText(header.Value, header.ValueLength, false)) {
                return STATUS_INVALID_PARAMETER;
            }

            for (SIZE_T controlled = 0;
                 controlled < sizeof(controlledHeaders) / sizeof(controlledHeaders[0]);
                 ++controlled) {
                if (TextEqualsLiteralIgnoreCase(header.Name, header.NameLength, controlledHeaders[controlled])) {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            char* nameCopy = AllocateTextCopy(header.Name, header.NameLength);
            if (nameCopy == nullptr) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            char* valueCopy = nullptr;
            if (header.ValueLength != 0) {
                valueCopy = AllocateTextCopy(header.Value, header.ValueLength);
                if (valueCopy == nullptr) {
                    FreeApiMemory(nameCopy);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }

            StoredHeader& stored = websocket.ExtraHeaders[websocket.ExtraHeaderCount++];
            stored.Name = nameCopy;
            stored.NameLength = header.NameLength;
            stored.Value = valueCopy;
            stored.ValueLength = header.ValueLength;
        }

        return STATUS_SUCCESS;
    }

    void ReleaseWebSocketStorage(_Inout_ WebSocket& websocket) noexcept
    {
        WorkspaceReleaseToLookaside(
            websocket.Workspace,
            websocket.Session != nullptr ? &websocket.Session->WorkspaceLookaside : nullptr);
        websocket.Workspace = nullptr;
#if !defined(WKNET_USER_MODE_TEST)
        if (websocket.Client != nullptr) {
            FreeNonPagedObject(websocket.Client);
            websocket.Client = nullptr;
        }
#endif
        FreeApiMemory(websocket.Url);
        FreeApiMemory(websocket.Subprotocol);
        FreeApiMemory(websocket.LastMessage);
        for (SIZE_T index = 0; index < websocket.ExtraHeaderCount && index < MaxHeadersPerRequest; ++index) {
            ReleaseStoredHeader(websocket.ExtraHeaders[index]);
        }
        websocket.ExtraHeaderCount = 0;
        websocket.Url = nullptr;
        websocket.UrlLength = 0;
        websocket.Subprotocol = nullptr;
        websocket.SubprotocolLength = 0;
        websocket.LastMessage = nullptr;
        websocket.LastMessageLength = 0;
        websocket.SchemeLength = 0;
        websocket.HostLength = 0;
        websocket.PathLength = 0;
        websocket.Port = 0;
        websocket.Connected = false;
        websocket.TransportClosed = true;
        websocket.SendFragmentOpen = false;
        websocket.SendFragmentType = WebSocketMessageType::Binary;
        websocket.SendFragmentLength = 0;
        websocket.SendTextUtf8CodePoint = 0;
        websocket.SendTextUtf8Remaining = 0;
        websocket.SendTextUtf8Expected = 0;
    }

