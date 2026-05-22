#pragma once

#include "http/HttpTypes.h"

namespace KernelHttp
{
namespace http2
{
    struct HpackStaticEntry final
    {
        const char* Name;
        SIZE_T NameLength;
        const char* Value;
        SIZE_T ValueLength;
    };

    // RFC 7541 Appendix A - Static Table (61 entries, 1-indexed)
    // Index 0 is unused; entries[0] corresponds to index 1.
    constexpr HpackStaticEntry HpackStaticTable[] = {
        { ":authority", 10, "", 0 },                          // 1
        { ":method", 7, "GET", 3 },                           // 2
        { ":method", 7, "POST", 4 },                          // 3
        { ":path", 5, "/", 1 },                               // 4
        { ":path", 5, "/index.html", 11 },                    // 5
        { ":scheme", 7, "http", 4 },                          // 6
        { ":scheme", 7, "https", 5 },                         // 7
        { ":status", 7, "200", 3 },                           // 8
        { ":status", 7, "204", 3 },                           // 9
        { ":status", 7, "206", 3 },                           // 10
        { ":status", 7, "304", 3 },                           // 11
        { ":status", 7, "400", 3 },                           // 12
        { ":status", 7, "404", 3 },                           // 13
        { ":status", 7, "500", 3 },                           // 14
        { "accept-charset", 14, "", 0 },                      // 15
        { "accept-encoding", 15, "gzip, deflate", 13 },       // 16
        { "accept-language", 15, "", 0 },                     // 17
        { "accept-ranges", 13, "", 0 },                       // 18
        { "accept", 6, "", 0 },                               // 19
        { "access-control-allow-origin", 27, "", 0 },         // 20
        { "age", 3, "", 0 },                                  // 21
        { "allow", 5, "", 0 },                                // 22
        { "authorization", 13, "", 0 },                       // 23
        { "cache-control", 13, "", 0 },                       // 24
        { "content-disposition", 19, "", 0 },                 // 25
        { "content-encoding", 16, "", 0 },                    // 26
        { "content-language", 16, "", 0 },                    // 27
        { "content-length", 14, "", 0 },                      // 28
        { "content-location", 16, "", 0 },                    // 29
        { "content-range", 13, "", 0 },                       // 30
        { "content-type", 12, "", 0 },                        // 31
        { "cookie", 6, "", 0 },                               // 32
        { "date", 4, "", 0 },                                 // 33
        { "etag", 4, "", 0 },                                 // 34
        { "expect", 6, "", 0 },                               // 35
        { "expires", 7, "", 0 },                              // 36
        { "from", 4, "", 0 },                                 // 37
        { "host", 4, "", 0 },                                 // 38
        { "if-match", 8, "", 0 },                             // 39
        { "if-modified-since", 17, "", 0 },                   // 40
        { "if-none-match", 13, "", 0 },                       // 41
        { "if-range", 8, "", 0 },                             // 42
        { "if-unmodified-since", 19, "", 0 },                 // 43
        { "last-modified", 13, "", 0 },                       // 44
        { "link", 4, "", 0 },                                 // 45
        { "location", 8, "", 0 },                             // 46
        { "max-forwards", 12, "", 0 },                        // 47
        { "proxy-authenticate", 18, "", 0 },                  // 48
        { "proxy-authorization", 19, "", 0 },                 // 49
        { "range", 5, "", 0 },                                // 50
        { "referer", 7, "", 0 },                              // 51
        { "refresh", 7, "", 0 },                              // 52
        { "retry-after", 11, "", 0 },                         // 53
        { "server", 6, "", 0 },                               // 54
        { "set-cookie", 10, "", 0 },                          // 55
        { "strict-transport-security", 25, "", 0 },           // 56
        { "transfer-encoding", 17, "", 0 },                   // 57
        { "user-agent", 10, "", 0 },                          // 58
        { "vary", 4, "", 0 },                                 // 59
        { "via", 3, "", 0 },                                  // 60
        { "www-authenticate", 16, "", 0 },                    // 61
    };

    constexpr SIZE_T HpackStaticTableSize = sizeof(HpackStaticTable) / sizeof(HpackStaticTable[0]);

    // Overhead per entry: 32 bytes (RFC 7541 Section 4.1)
    constexpr SIZE_T HpackEntryOverhead = 32;
}
}
