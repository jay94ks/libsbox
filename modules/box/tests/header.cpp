// sandbox.hpp alone is enough to write the README example: CSandbox needs a CEventLoop to run
// on, so the header brings the loop in (regression: the README example did not compile).
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/box/sandbox.hpp>

using namespace sbox;

TEST_CASE("sandbox.hpp provides CEventLoop, TTask and the policy types") {
    CEventLoop loop;
    int32_t value = loop.run([]() -> TTask<int32_t> {
        co_await CEventLoop::current()->yield();
        co_return int32_t(EBEXIT_NORMAL);
    }());
    CHECK(value == int32_t(EBEXIT_NORMAL));

    SBoxPolicy p = SBoxPolicy::strict();
    CHECK(p.network == EBNET_NONE);
}
