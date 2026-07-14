#ifndef WKNET_USER_MODE_TEST
#define WKNET_USER_MODE_TEST 1
#endif

#include "rtl/ProtocolFailureInjection.h"

#include <stdio.h>
#include <string.h>

namespace
{
    bool g_failed = false;

    void Expect(bool condition, const char* message) noexcept
    {
        if (!condition)
        {
            g_failed = true;
            printf("FAIL: %s\n", message);
        }
    }

    void TestStableEnumeration() noexcept
    {
        using wknet::rtl::ProtocolAllocationSite;
        using namespace wknet::rtl;

        const ULONG maximum = ProtocolFailureInjectionMaximumSite();
        Expect(maximum + 1 == static_cast<ULONG>(ProtocolAllocationSite::Count), "maximum site matches Count");
        Expect(!ProtocolFailureInjectionIsValidSite(ProtocolAllocationSite::Invalid), "invalid site is rejected");
        Expect(!ProtocolFailureInjectionIsValidSite(ProtocolAllocationSite::Count), "Count sentinel is rejected");

        for (ULONG value = 1; value <= maximum; ++value)
        {
            const auto site = static_cast<ProtocolAllocationSite>(value);
            Expect(ProtocolFailureInjectionIsValidSite(site), "every numeric site is defined");
            Expect(strcmp(ProtocolFailureInjectionSiteName(site), "invalid") != 0, "every site has a stable name");
        }
    }

    void TestFailOnNthSemantics() noexcept
    {
        using wknet::rtl::ProtocolAllocationSite;
        using namespace wknet::rtl;

        const ULONG maximum = ProtocolFailureInjectionMaximumSite();
        for (ULONG value = 1; value <= maximum; ++value)
        {
            const auto site = static_cast<ProtocolAllocationSite>(value);
            ProtocolFailureInjectionReset();
            ProtocolFailureInjectionSetFailOnNth(site, 2);
            Expect(!ProtocolFailureInjectionShouldFail(site), "first configured occurrence succeeds");
            Expect(ProtocolFailureInjectionShouldFail(site), "configured failpoint occurrence fails");
            Expect(!ProtocolFailureInjectionShouldFail(site), "later configured occurrence succeeds");
            Expect(ProtocolFailureInjectionHitCount(site) == 3, "hit count is exact");
        }
    }

    void TestLiveCounters() noexcept
    {
        using wknet::rtl::ProtocolAllocationSite;
        using namespace wknet::rtl;

        ProtocolFailureInjectionReset();
        constexpr ProtocolAllocationSite first = ProtocolAllocationSite::QuicConnectionObject;
        constexpr ProtocolAllocationSite second = ProtocolAllocationSite::Http3ConnectionObject;

        ProtocolFailureInjectionRecordAcquire(first);
        ProtocolFailureInjectionRecordAcquire(first);
        ProtocolFailureInjectionRecordAcquire(second);
        Expect(ProtocolFailureInjectionLiveCount(first) == 2, "per-site live count tracks acquisitions");
        Expect(ProtocolFailureInjectionLiveCount(second) == 1, "independent site count is tracked");
        Expect(ProtocolFailureInjectionTotalLiveCount() == 3, "total live count is exact");
        Expect(ProtocolFailureInjectionRecordRelease(first), "first release succeeds");
        Expect(ProtocolFailureInjectionRecordRelease(first), "second release succeeds");
        Expect(!ProtocolFailureInjectionRecordRelease(first), "release underflow is rejected");
        Expect(ProtocolFailureInjectionRecordRelease(second), "other site release succeeds");
        Expect(ProtocolFailureInjectionTotalLiveCount() == 0, "all counters return to zero");
    }

    void TestFailAlways() noexcept
    {
        using namespace wknet::rtl;
        constexpr ProtocolAllocationSite site = ProtocolAllocationSite::SessionHttp3PeerLease;

        ProtocolFailureInjectionReset();
        ProtocolFailureInjectionSetFailAlways(site, true);
        Expect(ProtocolFailureInjectionShouldFail(site), "fail-always rejects the first occurrence");
        Expect(ProtocolFailureInjectionShouldFail(site), "fail-always rejects later occurrences");
        Expect(ProtocolFailureInjectionHitCount(site) == 2, "fail-always still records exact hits");
        ProtocolFailureInjectionSetFailAlways(site, false);
        Expect(!ProtocolFailureInjectionShouldFail(site), "disabling fail-always restores success");
    }
} // namespace

int main()
{
    TestStableEnumeration();
    TestFailOnNthSemantics();
    TestLiveCounters();
    TestFailAlways();

    if (g_failed)
    {
        printf("PROTOCOL FAILURE INJECTION TESTS FAILED\n");
        return 1;
    }

    printf("PROTOCOL FAILURE INJECTION TESTS PASSED\n");
    return 0;
}
