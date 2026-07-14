#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "session/AltSvcCache.h"
#include "session/AltSvcClock.h"
#include "session/HandleTypes.h"
#include "rtl/ProtocolFailureInjection.h"
#include <wknet/Trace.h>

#include <stdio.h>
#include <string.h>

#ifndef STATUS_NETWORK_UNREACHABLE
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xC000023CL)
#endif

namespace
{
    bool g_failed = false;
    bool g_sensitiveTraceLeaked = false;

    void Expect(bool condition, const char *message) noexcept
    {
        if (!condition)
        {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void CaptureAltSvcTrace(
        _In_opt_ void *context,
        wknet::TraceLevel level,
        ULONG component,
        _In_z_ const char *message) noexcept
    {
        UNREFERENCED_PARAMETER(context);
        UNREFERENCED_PARAMETER(level);
        UNREFERENCED_PARAMETER(component);
        if (strstr(message, "secret-alt.example") != nullptr ||
            strstr(message, "secret-origin.example") != nullptr ||
            strstr(message, "Bearer-secret") != nullptr)
        {
            g_sensitiveTraceLeaked = true;
        }
    }

    wknet::session::Request MakeRequest(const char *host, wknet::session::AddressFamily family =
                                                              wknet::session::AddressFamily::Any) noexcept
    {
        wknet::session::Request request = {};
        memcpy(request.Scheme, "https", 5);
        request.SchemeLength = 5;
        request.HostLength = strlen(host);
        memcpy(request.Host, host, request.HostLength);
        request.Port = 443;
        request.AddressFamily = family;
        request.Tls.ServerName = request.Host;
        request.Tls.ServerNameLength = request.HostLength;
        return request;
    }

    wknet::http1::HttpHeader Header(const char *value) noexcept
    {
        return {
            {"Alt-Svc", sizeof("Alt-Svc") - 1},
            {value, strlen(value)}
        };
    }

    void TestParserAndIdentity() noexcept
    {
        wknet::session::AltSvcTestClockSet(1000);
        wknet::session::AltSvcCache *cache = nullptr;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheCreate(4, 120, &cache)),
               "Alt-Svc cache creates");

        wknet::session::Request request = MakeRequest("origin.example");
        wknet::session::AltSvcCacheKey key = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(request, &key)),
               "Alt-Svc identity key builds");

        const auto first = Header("h3=\":8443\"; ma=60; persist=1, h3-29=\"ignored.example:443\"");
        bool updated = false;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &first, 1, &updated)) && updated,
               "Alt-Svc parser stores exact h3 and ignores h3-xx");
        wknet::session::AltSvcCandidateSnapshot snapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "stored Alt-Svc candidate is found");
        Expect(snapshot.HostLength == strlen("origin.example") &&
                   memcmp(snapshot.Host, "origin.example", snapshot.HostLength) == 0 &&
                   snapshot.Port == 8443 && snapshot.Persist,
               "empty alternative host inherits origin and persist is parsed");

        const auto replacement = Header("h3=\"alt.example:9443\"; ma=30");
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &replacement, 1, &updated)),
               "new Alt-Svc field atomically replaces the old set");
        snapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)) &&
                   snapshot.HostLength == strlen("alt.example") &&
                   memcmp(snapshot.Host, "alt.example", snapshot.HostLength) == 0 &&
                   snapshot.Port == 9443,
               "replacement candidate preserves wire endpoint");

        wknet::session::Request differentIdentity = request;
        static const char OtherServerName[] = "other.example";
        differentIdentity.Tls.ServerName = OtherServerName;
        differentIdentity.Tls.ServerNameLength = sizeof(OtherServerName) - 1;
        wknet::session::AltSvcCacheKey otherKey = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(differentIdentity, &otherKey)),
               "different TLS identity key builds");
        Expect(wknet::session::AltSvcCacheLookup(cache, otherKey, &snapshot) == STATUS_NOT_FOUND,
               "Alt-Svc candidate is isolated by effective TLS identity");

        const auto ipv6 = Header("h3=\"[::1]:443\"; ma=30");
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &ipv6, 1, &updated)),
               "IPv6 literal authority parses");
        snapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)) &&
                   snapshot.HostLength == 3 && memcmp(snapshot.Host, "::1", 3) == 0,
               "IPv6 literal is stored without brackets for DNS resolution");

        wknet::session::AltSvcCacheDestroy(cache);
    }

    void TestAtomicClearMalformedAndExpiry() noexcept
    {
        wknet::session::AltSvcTestClockSet(5000);
        wknet::session::AltSvcCache *cache = nullptr;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheCreate(2, 10, &cache)),
               "expiry cache creates");
        wknet::session::Request request = MakeRequest("expiry.example");
        wknet::session::AltSvcCacheKey key = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(request, &key)),
               "expiry identity key builds");

        const auto valid = Header("h3=\"alt.example:443\"; ma=8");
        bool updated = false;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &valid, 1, &updated)),
               "expiry fixture stores");

        const auto malformed = Header("h3=\"missing-port\"; ma=8");
        Expect(!NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &malformed, 1, &updated)),
               "malformed Alt-Svc is rejected");
        wknet::session::AltSvcCandidateSnapshot snapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "malformed replacement preserves the previous complete set");

        wknet::session::AltSvcTestClockAdvance(8001);
        Expect(wknet::session::AltSvcCacheLookup(cache, key, &snapshot) == STATUS_NOT_FOUND &&
                   wknet::session::AltSvcCacheEntryCount(cache) == 0,
               "expired Alt-Svc entry is actively removed");

        wknet::session::AltSvcTestClockSet(20000);
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &valid, 1, &updated)),
               "clear fixture stores");
        const auto clear = Header("clear");
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &clear, 1, &updated)) &&
                   wknet::session::AltSvcCacheEntryCount(cache) == 0,
               "clear atomically removes all alternatives for the key");

        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &valid, 1, &updated)),
               "ma=0 fixture stores");
        const auto zeroAge = Header("h3=\"alt.example:443\"; ma=0");
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &zeroAge, 1, &updated)) &&
                   wknet::session::AltSvcCacheEntryCount(cache) == 0,
               "ma=0 removes the previous alternative set");

        wknet::session::AltSvcCacheDestroy(cache);
    }

    void TestBrokenClassificationAndNetworkChange() noexcept
    {
        wknet::session::AltSvcTestClockSet(30000);
        wknet::session::AltSvcCache *cache = nullptr;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheCreate(2, 120, &cache)),
               "broken-state cache creates");
        wknet::session::Request request = MakeRequest(
            "broken.example",
            wknet::session::AddressFamily::Ipv4);
        wknet::session::AltSvcCacheKey key = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(request, &key)),
               "broken-state identity key builds");
        const auto value = Header("h3=\"alt.example:443\"; ma=120");
        bool updated = false;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &value, 1, &updated)),
               "broken-state candidate stores");

        wknet::session::AltSvcCandidateSnapshot snapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "broken-state candidate initially eligible");
        wknet::session::AltSvcCacheMarkFailure(cache, key, snapshot, STATUS_NETWORK_UNREACHABLE);
        Expect(wknet::session::AltSvcCacheLookup(cache, key, &snapshot) == STATUS_NOT_FOUND,
               "network failure starts candidate backoff");
        wknet::session::AltSvcTestClockAdvance(1001);
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "candidate becomes eligible after initial backoff");

        wknet::session::AltSvcCacheMarkFailure(cache, key, snapshot, STATUS_INVALID_NETWORK_RESPONSE);
        Expect(wknet::session::AltSvcCacheLookup(cache, key, &snapshot) == STATUS_NOT_FOUND,
               "protocol failure disables the candidate for the entry lifetime");
        wknet::session::AltSvcCacheNetworkChanged(cache);
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "network generation change clears endpoint broken state");

        wknet::session::AltSvcCacheMarkFailure(cache, key, snapshot, STATUS_CANCELLED);
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "local cancellation does not poison Alt-Svc state");
        wknet::session::AltSvcCacheMarkFailure(cache, key, snapshot, STATUS_INSUFFICIENT_RESOURCES);
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "local resource failure does not poison Alt-Svc state");

        wknet::session::AltSvcCacheDestroy(cache);
    }

    void TestGenerationFamilyAndCandidateOrdering() noexcept
    {
        wknet::session::AltSvcTestClockSet(40000);
        wknet::session::AltSvcCache *cache = nullptr;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheCreate(4, 120, &cache)),
               "generation cache creates");

        wknet::session::Request ipv4Request = MakeRequest(
            "generation.example",
            wknet::session::AddressFamily::Ipv4);
        wknet::session::AltSvcCacheKey ipv4Key = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(ipv4Request, &ipv4Key)),
               "IPv4 Alt-Svc key builds");
        const auto ordered = Header(
            "h3=\"first.example:443\"; ma=120, h3=\"second.example:443\"; ma=120");
        bool updated = false;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, ipv4Key, &ordered, 1, &updated)),
               "ordered candidates store");

        wknet::session::AltSvcCandidateSnapshot first = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, ipv4Key, &first)) &&
                   first.CandidateIndex == 0 &&
                   first.HostLength == strlen("first.example") &&
                   memcmp(first.Host, "first.example", first.HostLength) == 0,
               "lookup selects the first eligible wire-order candidate");
        wknet::session::AltSvcCacheMarkFailure(cache, ipv4Key, first, STATUS_NETWORK_UNREACHABLE);

        wknet::session::AltSvcCandidateSnapshot second = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, ipv4Key, &second)) &&
                   second.CandidateIndex == 1 &&
                   second.HostLength == strlen("second.example") &&
                   memcmp(second.Host, "second.example", second.HostLength) == 0,
               "candidate backoff advances the next request to the next wire-order candidate");

        wknet::session::Request ipv6Request = MakeRequest(
            "generation.example",
            wknet::session::AddressFamily::Ipv6);
        wknet::session::AltSvcCacheKey ipv6Key = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(ipv6Request, &ipv6Key)),
               "IPv6 Alt-Svc key builds");
        wknet::session::AltSvcCandidateSnapshot ipv6Snapshot = {};
        Expect(wknet::session::AltSvcCacheLookup(cache, ipv6Key, &ipv6Snapshot) == STATUS_NOT_FOUND,
               "address-family policy isolates Alt-Svc entries");

        const auto replacement = Header("h3=\"replacement.example:8443\"; ma=120");
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, ipv4Key, &replacement, 1, &updated)),
               "replacement advances the entry generation");
        wknet::session::AltSvcCacheMarkFailure(cache, ipv4Key, second, STATUS_INVALID_NETWORK_RESPONSE);
        wknet::session::AltSvcCandidateSnapshot replacementSnapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, ipv4Key, &replacementSnapshot)) &&
                   replacementSnapshot.HostLength == strlen("replacement.example") &&
                   memcmp(replacementSnapshot.Host, "replacement.example",
                          replacementSnapshot.HostLength) == 0,
               "stale generation failure cannot poison a concurrently replaced candidate set");

        const auto clear = Header("clear");
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, ipv4Key, &clear, 1, &updated)),
               "generation fixture clears");
        wknet::session::AltSvcCacheMarkSuccess(cache, ipv4Key, replacementSnapshot);
        wknet::session::AltSvcCacheMarkFailure(cache, ipv4Key, replacementSnapshot,
                                               STATUS_INVALID_NETWORK_RESPONSE);
        Expect(wknet::session::AltSvcCacheLookup(cache, ipv4Key, &replacementSnapshot) == STATUS_NOT_FOUND,
               "stale generation writeback after clear is ignored");

        wknet::session::AltSvcCacheDestroy(cache);
    }

    void TestCapacityAndAtomicLimitFailures() noexcept
    {
        wknet::session::AltSvcTestClockSet(50000);
        wknet::session::AltSvcCache *cache = nullptr;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheCreate(1, 120, &cache)),
               "capacity-one cache creates");

        wknet::session::Request firstRequest = MakeRequest("first-origin.example");
        wknet::session::AltSvcCacheKey firstKey = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(firstRequest, &firstKey)),
               "first capacity key builds");
        const auto original = Header("h3=\"original.example:443\"; ma=120");
        bool updated = false;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, firstKey, &original, 1, &updated)),
               "capacity fixture stores first entry");

        const auto tooMany = Header(
            "h3=\"one.example:443\", h3=\"two.example:443\", h3=\"three.example:443\", "
            "h3=\"four.example:443\", h3=\"five.example:443\"");
        updated = true;
        Expect(wknet::session::AltSvcCacheStoreResponse(cache, firstKey, &tooMany, 1, &updated) ==
                   STATUS_BUFFER_TOO_SMALL && !updated,
               "candidate capacity overflow is rejected atomically");
        wknet::session::AltSvcCandidateSnapshot snapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, firstKey, &snapshot)) &&
                   snapshot.HostLength == strlen("original.example") &&
                   memcmp(snapshot.Host, "original.example", snapshot.HostLength) == 0,
               "candidate capacity failure preserves the previous complete set");

        wknet::session::AltSvcTestClockAdvance(1);
        wknet::session::Request secondRequest = MakeRequest("second-origin.example");
        wknet::session::AltSvcCacheKey secondKey = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(secondRequest, &secondKey)),
               "second capacity key builds");
        const auto secondValue = Header("h3=\"second-alt.example:443\"; ma=120");
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, secondKey, &secondValue, 1, &updated)) &&
                   wknet::session::AltSvcCacheEntryCount(cache) == 1,
               "entry capacity remains bounded while replacing the oldest entry");
        Expect(wknet::session::AltSvcCacheLookup(cache, firstKey, &snapshot) == STATUS_NOT_FOUND &&
                   NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, secondKey, &snapshot)),
               "entry capacity replacement removes only the selected old key");

        wknet::session::AltSvcCacheDestroy(cache);
    }

    void TestLogSafety() noexcept
    {
        wknet::session::AltSvcTestClockSet(60000);
        wknet::session::AltSvcCache *cache = nullptr;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheCreate(2, 120, &cache)),
               "log-safety cache creates");
        wknet::session::Request request = MakeRequest("secret-origin.example");
        wknet::session::AltSvcCacheKey key = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(request, &key)),
               "log-safety key builds");

        g_sensitiveTraceLeaked = false;
        wknet::TraceSetSink(CaptureAltSvcTrace, nullptr);
        wknet::TraceSetComponents(wknet::ComponentSession);
        wknet::TraceSetLevel(wknet::TraceLevel::Max);
        const auto value = Header(
            "h3=\"secret-alt.example:8443\"; ma=120; opaque=\"Bearer-secret\"");
        bool updated = false;
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheStoreResponse(cache, key, &value, 1, &updated)),
               "log-safety candidate stores");
        wknet::session::AltSvcCandidateSnapshot snapshot = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheLookup(cache, key, &snapshot)),
               "log-safety candidate is found");
        wknet::session::AltSvcCacheMarkFailure(cache, key, snapshot, STATUS_NETWORK_UNREACHABLE);
        wknet::TraceSetSink(nullptr, nullptr);
        wknet::TraceSetLevel(wknet::TraceLevel::Off);
        Expect(!g_sensitiveTraceLeaked,
               "Alt-Svc events do not expose origin, alternative authority, or raw parameter values");

        wknet::session::AltSvcCacheDestroy(cache);
    }

    void TestFailureInjection() noexcept
    {
        using wknet::rtl::ProtocolAllocationSite;
        wknet::rtl::ProtocolFailureInjectionReset();

        wknet::rtl::ProtocolFailureInjectionSetFailOnNth(ProtocolAllocationSite::AltSvcCacheObject, 1);
        wknet::session::AltSvcCache *cache = nullptr;
        Expect(wknet::session::AltSvcCacheCreate(2, 60, &cache) == STATUS_INSUFFICIENT_RESOURCES &&
                   cache == nullptr,
               "Alt-Svc cache object failpoint is propagated");
        Expect(wknet::rtl::ProtocolFailureInjectionLiveCount(ProtocolAllocationSite::AltSvcCacheObject) == 0,
               "failed Alt-Svc cache object allocation has no live owner");

        wknet::rtl::ProtocolFailureInjectionReset();
        wknet::rtl::ProtocolFailureInjectionSetFailOnNth(ProtocolAllocationSite::AltSvcCacheEntries, 1);
        Expect(wknet::session::AltSvcCacheCreate(2, 60, &cache) == STATUS_INSUFFICIENT_RESOURCES &&
                   cache == nullptr,
               "Alt-Svc entry table failpoint is propagated");
        Expect(wknet::rtl::ProtocolFailureInjectionTotalLiveCount() == 0,
               "failed Alt-Svc entry table releases the cache owner");

        wknet::rtl::ProtocolFailureInjectionReset();
        Expect(NT_SUCCESS(wknet::session::AltSvcCacheCreate(2, 60, &cache)),
               "Alt-Svc failpoint fixture creates");
        wknet::session::Request request = MakeRequest("failure.example");
        wknet::session::AltSvcCacheKey key = {};
        Expect(NT_SUCCESS(wknet::session::AltSvcBuildKey(request, &key)),
               "Alt-Svc failpoint key builds");
        const auto value = Header("h3=\"alt.example:443\"; ma=60");

        constexpr ProtocolAllocationSite parseSites[] = {
            ProtocolAllocationSite::AltSvcParsedSet,
            ProtocolAllocationSite::AltSvcParseScratch
        };
        for (const auto site : parseSites)
        {
            wknet::rtl::ProtocolFailureInjectionSetFailOnNth(site, 1);
            bool updated = true;
            Expect(wknet::session::AltSvcCacheStoreResponse(cache, key, &value, 1, &updated) ==
                       STATUS_INSUFFICIENT_RESOURCES && !updated,
                   "Alt-Svc parse allocation failpoint is propagated atomically");
            Expect(wknet::rtl::ProtocolFailureInjectionLiveCount(site) == 0 &&
                       wknet::session::AltSvcCacheEntryCount(cache) == 0,
                   "Alt-Svc parse allocation failure leaves no partial entry or live scratch");
            wknet::rtl::ProtocolFailureInjectionSetFailOnNth(site, 0);
        }
        wknet::session::AltSvcCacheDestroy(cache);
        Expect(wknet::rtl::ProtocolFailureInjectionTotalLiveCount() == 0,
               "Alt-Svc failure-injection fixture releases all tracked resources");
    }
}

int main() noexcept
{
    TestParserAndIdentity();
    TestAtomicClearMalformedAndExpiry();
    TestBrokenClassificationAndNetworkChange();
    TestGenerationFamilyAndCandidateOrdering();
    TestCapacityAndAtomicLimitFailures();
    TestLogSafety();
    TestFailureInjection();

    if (g_failed)
    {
        printf("ALT-SVC TESTS FAILED\n");
        return 1;
    }
    printf("ALT-SVC TESTS PASSED\n");
    return 0;
}
