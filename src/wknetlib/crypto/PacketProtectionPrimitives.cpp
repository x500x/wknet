#include "crypto/PacketProtectionPrimitives.h"

// The algorithm implementations are uniquely owned by Aead.cpp. This
// translation unit anchors the src-local packet-protection service in the
// project while Aead.cpp exposes the two block-level entry points above.
