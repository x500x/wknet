#include <KernelHttp/http/HttpResponse.h>

namespace KernelHttp
{
namespace http
{
    bool HttpResponse::FindHeader(HttpText name, const HttpHeader** header) const noexcept
    {
        if (header != nullptr) {
            *header = nullptr;
        }

        if (name.Data == nullptr || name.Length == 0 || Headers == nullptr) {
            return false;
        }

        for (SIZE_T index = 0; index < HeaderCount; ++index) {
            if (TextEqualsIgnoreCase(Headers[index].Name, name)) {
                if (header != nullptr) {
                    *header = &Headers[index];
                }

                return true;
            }
        }

        return false;
    }

    bool HttpResponse::HasHeaderValueToken(HttpText name, HttpText token) const noexcept
    {
        if (Headers == nullptr || token.Data == nullptr || token.Length == 0) {
            return false;
        }

        for (SIZE_T index = 0; index < HeaderCount; ++index) {
            if (TextEqualsIgnoreCase(Headers[index].Name, name) &&
                HeaderValueHasToken(Headers[index].Value, token)) {
                return true;
            }
        }

        return false;
    }

    bool HttpResponse::HasConnectionClose() const noexcept
    {
        return HasHeaderValueToken(MakeText("Connection"), MakeText("close"));
    }

    bool HttpResponse::HasConnectionKeepAlive() const noexcept
    {
        return HasHeaderValueToken(MakeText("Connection"), MakeText("keep-alive"));
    }

    bool HttpResponse::HasChunkedTransferEncoding() const noexcept
    {
        return HasHeaderValueToken(MakeText("Transfer-Encoding"), MakeText("chunked"));
    }
}
}
