    NTSTATUS ResponseGetView(ResponseHandle response, ResponseView* view) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (!IsResponseHandle(response) || view == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        view->StatusCode = response->StatusCode;
        view->Body = response->Body;
        view->BodyLength = response->BodyLength;
        return STATUS_SUCCESS;
    }

    NTSTATUS ResponseGetHeader(
        ResponseHandle response,
        const char* name,
        SIZE_T nameLength,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }

        if (!IsResponseHandle(response) ||
            name == nullptr ||
            nameLength == 0 ||
            value == nullptr ||
            valueLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < response->HeaderCount; ++index) {
            const http1::HttpHeader& header = response->Headers[index];
            if (TextEqualsIgnoreCase(header.Name.Data, header.Name.Length, name, nameLength)) {
                *value = header.Value.Data;
                *valueLength = header.Value.Length;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    SIZE_T ResponseHeaderCount(ResponseHandle response) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || !IsResponseHandle(response)) {
            return 0;
        }

        return response->HeaderCount;
    }

    NTSTATUS ResponseGetHeaderAt(
        ResponseHandle response,
        SIZE_T index,
        const char** name,
        SIZE_T* nameLength,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (name != nullptr) {
            *name = nullptr;
        }
        if (nameLength != nullptr) {
            *nameLength = 0;
        }
        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }

        if (!IsResponseHandle(response) ||
            name == nullptr ||
            nameLength == nullptr ||
            value == nullptr ||
            valueLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (index >= response->HeaderCount) {
            return STATUS_NOT_FOUND;
        }

        const http1::HttpHeader& header = response->Headers[index];
        *name = header.Name.Data;
        *nameLength = header.Name.Length;
        *value = header.Value.Data;
        *valueLength = header.Value.Length;
        return STATUS_SUCCESS;
    }

    SIZE_T ResponseTrailerCount(ResponseHandle response) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || !IsResponseHandle(response)) {
            return 0;
        }

        return response->TrailerCount;
    }

    NTSTATUS ResponseGetTrailer(
        ResponseHandle response,
        const char* name,
        SIZE_T nameLength,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }

        if (!IsResponseHandle(response) ||
            name == nullptr ||
            nameLength == 0 ||
            value == nullptr ||
            valueLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        for (SIZE_T index = 0; index < response->TrailerCount; ++index) {
            const http1::HttpHeader& trailer = response->Trailers[index];
            if (TextEqualsIgnoreCase(trailer.Name.Data, trailer.Name.Length, name, nameLength)) {
                *value = trailer.Value.Data;
                *valueLength = trailer.Value.Length;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    NTSTATUS ResponseGetTrailerAt(
        ResponseHandle response,
        SIZE_T index,
        const char** name,
        SIZE_T* nameLength,
        const char** value,
        SIZE_T* valueLength) noexcept
    {
        NTSTATUS status = CheckPassiveLevel();
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (name != nullptr) {
            *name = nullptr;
        }
        if (nameLength != nullptr) {
            *nameLength = 0;
        }
        if (value != nullptr) {
            *value = nullptr;
        }
        if (valueLength != nullptr) {
            *valueLength = 0;
        }

        if (!IsResponseHandle(response) ||
            name == nullptr ||
            nameLength == nullptr ||
            value == nullptr ||
            valueLength == nullptr) {
            return STATUS_INVALID_PARAMETER;
        }

        if (index >= response->TrailerCount) {
            return STATUS_NOT_FOUND;
        }

        const http1::HttpHeader& trailer = response->Trailers[index];
        *name = trailer.Name.Data;
        *nameLength = trailer.Name.Length;
        *value = trailer.Value.Data;
        *valueLength = trailer.Value.Length;
        return STATUS_SUCCESS;
    }

    void ResponseRelease(ResponseHandle response) noexcept
    {
        if (!NT_SUCCESS(CheckPassiveLevel()) || response == nullptr) {
            return;
        }

        if (!TryCloseActiveResponseHandle(response)) {
            return;
        }

        WaitForResponseDrain(response);
        ReleaseResponseStorage(*response);
        FreeHandle(response);
    }

