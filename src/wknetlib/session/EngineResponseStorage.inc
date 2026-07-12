    void ReleaseResponseStorage(Response& response) noexcept
    {
        FreeApiMemory(response.RawResponse);
        FreeApiMemory(response.Body);
        FreeApiMemory(response.Headers);
        FreeApiMemory(response.Trailers);
        FreeApiMemory(response.HeaderNameStorage);
        FreeApiMemory(response.HeaderValueStorage);
        FreeApiMemory(response.TrailerNameStorage);
        FreeApiMemory(response.TrailerValueStorage);
        response.RawResponse = nullptr;
        response.RawResponseLength = 0;
        response.Body = nullptr;
        response.BodyLength = 0;
        response.Headers = nullptr;
        response.HeaderCount = 0;
        response.Trailers = nullptr;
        response.TrailerCount = 0;
        response.HeaderNameStorage = nullptr;
        response.HeaderNameStorageLength = 0;
        response.HeaderValueStorage = nullptr;
        response.HeaderValueStorageLength = 0;
        response.TrailerNameStorage = nullptr;
        response.TrailerNameStorageLength = 0;
        response.TrailerValueStorage = nullptr;
        response.TrailerValueStorageLength = 0;
        response.StatusCode = 0;
    }

