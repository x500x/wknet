#include <wknet/http/Lifecycle.h>
#include "session/Engine.h"

namespace wknet::http {
    void Destroy() noexcept
    {
        (void)::wknet::session::KhEngineDrainAsync();
    }
}
