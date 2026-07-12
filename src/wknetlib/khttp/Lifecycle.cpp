#include <wknet/http/Lifecycle.h>
#include <wknet/engine/Engine.h>

namespace wknet::http {
    void Destroy() noexcept
    {
        (void)::wknet::session::KhEngineDrainAsync();
    }
}
