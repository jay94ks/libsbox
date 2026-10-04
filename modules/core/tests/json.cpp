#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <sbox/core/json.hpp>
#include <cerrno>

using namespace sbox;

TEST_CASE("json parses and writes back a nested document") {
    CJson v;
    REQUIRE(CJson::parse(R"({"a":1,"b":[true,false,null],"c":{"d":"x\ny","e":-2.5},"big":18446744073709551615})", v) == SBOX_OK);

    CHECK(v.isObject());
    CHECK(v.get("a").asInt() == 1);
    CHECK(v.get("b").size() == 3);
    CHECK(v.get("b").at(0).asBool() == true);
    CHECK(v.get("b").at(2).isNull());
    CHECK(v.get("c").get("d").asString() == "x\ny");
    CHECK(v.get("c").get("e").asDouble() == doctest::Approx(-2.5));
    CHECK(v.get("big").type() == EJSON_DOUBLE);
    CHECK(v.get("missing").isNull());

    CJson again;
    REQUIRE(CJson::parse(v.dump(true), again) == SBOX_OK);
    CHECK(again.dump() == v.dump());
    CHECK(v.keyAt(0) == "a");
}

TEST_CASE("json keeps member order and replaces on set") {
    CJson o = CJson::object();
    o.set("z", 1);
    o.set("a", "two");
    o["m"] = CJson::fromStrings({ "x", "y" });
    o.set("z", 3);

    CHECK(o.dump() == R"({"z":3,"a":"two","m":["x","y"]})");
    CHECK(o.remove("a"));
    CHECK_FALSE(o.remove("a"));
    CHECK(o.get("m").asStrings().size() == 2);
}

TEST_CASE("json decodes escapes and surrogate pairs") {
    CJson v;
    REQUIRE(CJson::parse(R"("\u00e9\ud83d\ude00\t\"")", v) == SBOX_OK);
    CHECK(v.asString() == "\xc3\xa9\xf0\x9f\x98\x80\t\"");
    CHECK(CJson(std::string("\x01")).dump() == "\"\\u0001\"");
}

TEST_CASE("json rejects malformed input") {
    CJson v;
    size_t at = 0;
    CHECK(CJson::parse("{\"a\":}", v, &at) == -EINVAL);
    CHECK(at == 5);
    CHECK(CJson::parse("[1,]", v) == -EINVAL);
    CHECK(CJson::parse("01", v) == -EINVAL);
    CHECK(CJson::parse("\"\\ud800\"", v) == -EINVAL);
    CHECK(CJson::parse("1 2", v) == -EINVAL);
    CHECK(CJson::parse(std::string(600, '['), v) == -EINVAL);
}
