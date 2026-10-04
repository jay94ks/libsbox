#ifndef __INCLUDE_SBOX_CORE_JSON_HPP__
#define __INCLUDE_SBOX_CORE_JSON_HPP__

#include <sbox/common.hpp>

namespace sbox {

    /**
     * Kind of value a CJson holds.
     */
    enum EJsonType : uint8_t {
        EJSON_NULL = 0,
        EJSON_BOOL,
        EJSON_INT,          // --> Integer that fits int64_t.
        EJSON_DOUBLE,       // --> Any other number.
        EJSON_STRING,
        EJSON_ARRAY,
        EJSON_OBJECT,
    };

    /**
     * JSON value (RFC 8259) with a parser and a writer.
     *
     * Objects keep their members in insertion order (OCI config.json and Docker plugin payloads
     * round-trip in the order they were written) and lookups are linear, which is the right
     * trade for the small documents libsbox handles. Integers are kept exactly as int64_t.
     */
    class SBOX_API CJson {
    private:
        EJsonType _type;
        bool _bool;
        int64_t _int;
        float64_t _double;
        std::string _string;
        std::vector<CJson> _items;          // --> Array elements, or object member values.
        std::vector<std::string> _keys;     // --> Object member names, parallel to _items.

    public:
        /** Constructs null. */
        CJson() noexcept;

        /** Constructs a boolean. */
        CJson(bool value) noexcept;

        /** Constructs an integer. */
        CJson(int32_t value) noexcept;

        /** Constructs an integer. */
        CJson(int64_t value) noexcept;

        /** Constructs an integer; values above INT64_MAX become doubles. */
        CJson(uint32_t value) noexcept;

        /** Constructs an integer; values above INT64_MAX become doubles. */
        CJson(uint64_t value) noexcept;

        /** Constructs an integer (`long long` is distinct from int64_t on LP64). */
        CJson(long long value) noexcept : CJson(int64_t(value)) {}

        /** Constructs an integer (`unsigned long long` is distinct from uint64_t on LP64). */
        CJson(unsigned long long value) noexcept : CJson(uint64_t(value)) {}

        /** Constructs a number. */
        CJson(float64_t value) noexcept;

        /** Constructs a string. */
        CJson(const char* value);

        /** Constructs a string. */
        CJson(std::string value) noexcept;

        /** Constructs a string. */
        CJson(std::string_view value);

        /** Returns an empty array. */
        static CJson array();

        /** Returns an empty object. */
        static CJson object();

        /** Returns an array of strings. */
        static CJson fromStrings(const std::vector<std::string>& values);

        /** Returns the value kind. */
        inline EJsonType type() const noexcept { return _type; }

        /** Returns true for null. */
        inline bool isNull() const noexcept { return _type == EJSON_NULL; }

        /** Returns true for a boolean. */
        inline bool isBool() const noexcept { return _type == EJSON_BOOL; }

        /** Returns true for an integer or a double. */
        inline bool isNumber() const noexcept { return _type == EJSON_INT || _type == EJSON_DOUBLE; }

        /** Returns true for a string. */
        inline bool isString() const noexcept { return _type == EJSON_STRING; }

        /** Returns true for an array. */
        inline bool isArray() const noexcept { return _type == EJSON_ARRAY; }

        /** Returns true for an object. */
        inline bool isObject() const noexcept { return _type == EJSON_OBJECT; }

        /** Returns the boolean, or `fallback` for other kinds. */
        bool asBool(bool fallback = false) const noexcept;

        /** Returns the number as int64 (doubles truncated), or `fallback`. */
        int64_t asInt(int64_t fallback = 0) const noexcept;

        /** Returns the number as double, or `fallback`. */
        float64_t asDouble(float64_t fallback = 0) const noexcept;

        /** Returns the string, or an empty string for other kinds. */
        const std::string& asString() const noexcept;

        /** Returns the string array as a vector (non-strings skipped). */
        std::vector<std::string> asStrings() const;

        /** Returns the element / member count (0 for scalars). */
        inline size_t size() const noexcept { return _items.size(); }

        /** Returns an array element or member value by position (no bounds check). */
        inline const CJson& at(size_t index) const noexcept { return _items[index]; }

        /** Returns an array element or member value by position (no bounds check). */
        inline CJson& at(size_t index) noexcept { return _items[index]; }

        /** Returns a member name by position (objects only, no bounds check). */
        inline const std::string& keyAt(size_t index) const noexcept { return _keys[index]; }

        /** Appends to an array (null turns into an array first). */
        CJson& push(CJson value);

        /** Returns a member, or nullptr when absent or not an object. */
        const CJson* find(std::string_view key) const noexcept;

        /** Returns a member, or nullptr when absent or not an object. */
        CJson* find(std::string_view key) noexcept;

        /** Returns a member, or a shared null value when absent. */
        const CJson& get(std::string_view key) const noexcept;

        /** Returns a member, inserting null when absent (null turns into an object first). */
        CJson& operator[](std::string_view key);

        /** Sets a member, replacing an existing one (null turns into an object first). */
        CJson& set(std::string_view key, CJson value);

        /** Removes a member; returns true when it existed. */
        bool remove(std::string_view key) noexcept;

        /**
         * Parses a JSON document (nesting is limited to 512 levels).
         * @param errorOffset Receives the byte offset of the first error when not null.
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, CJson& out, size_t* errorOffset = nullptr);

        /**
         * Serializes the value.
         * @param pretty Indent with two spaces and newlines when true.
         */
        std::string dump(bool pretty = false) const;

    private:
        /**
         * Appends the serialized form to `out`.
         */
        void dumpTo(std::string& out, bool pretty, int32_t depth) const;
    };

} // namespace sbox

#endif
