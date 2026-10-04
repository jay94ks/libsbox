#ifndef __INCLUDE_SBOX_HTTP_HEADERS_HPP__
#define __INCLUDE_SBOX_HTTP_HEADERS_HPP__

#include <sbox/common.hpp>

namespace sbox {
namespace http {

    /**
     * Returns true when two ASCII strings are equal ignoring case.
     */
    SBOX_API bool EqualsNoCase(std::string_view a, std::string_view b) noexcept;

    /**
     * Returns true when `name` is a valid header field name (an RFC 9110 token).
     */
    SBOX_API bool IsToken(std::string_view name) noexcept;

    /**
     * Header fields of a message: case-insensitive names, order and duplicates preserved.
     *
     * Lookups are linear, which is the right trade for the few dozen fields a message carries.
     * Names keep the spelling they were added with; values are stored without surrounding
     * whitespace.
     */
    class SBOX_API CHeaders {
    public:
        /**
         * One header field.
         */
        struct SField {
            std::string name;
            std::string value;
        };

    private:
        std::vector<SField> _fields;

    public:
        /** Returns the number of fields (duplicates counted). */
        inline size_t size() const noexcept { return _fields.size(); }

        /** Returns true when there is no field. */
        inline bool empty() const noexcept { return _fields.empty(); }

        /** Returns a field by position (no bounds check). */
        inline const SField& at(size_t index) const noexcept { return _fields[index]; }

        /** Returns the fields in order. */
        inline const std::vector<SField>& fields() const noexcept { return _fields; }

        /** Iterates the fields in order. */
        inline std::vector<SField>::const_iterator begin() const noexcept { return _fields.begin(); }

        /** Iterates the fields in order. */
        inline std::vector<SField>::const_iterator end() const noexcept { return _fields.end(); }

        /**
         * Appends a field, keeping existing fields of the same name.
         */
        void add(std::string_view name, std::string_view value);

        /**
         * Replaces every field named `name` with one field (appended at the first one's place).
         */
        void set(std::string_view name, std::string_view value);

        /**
         * Removes every field named `name`.
         * @return The number of fields removed.
         */
        size_t remove(std::string_view name) noexcept;

        /** Removes every field. */
        inline void clear() noexcept { _fields.clear(); }

        /** Returns true when a field named `name` exists. */
        bool has(std::string_view name) const noexcept;

        /**
         * Returns the first value of `name`, or nullptr.
         */
        const std::string* find(std::string_view name) const noexcept;

        /**
         * Returns the first value of `name`, or `fallback` when absent.
         */
        std::string get(std::string_view name, std::string_view fallback = {}) const;

        /**
         * Returns every value of `name`, in order.
         */
        std::vector<std::string> getAll(std::string_view name) const;

        /**
         * Returns every value of `name` joined with ", " (the list form of RFC 9110 5.3).
         */
        std::string combined(std::string_view name) const;

        /**
         * Returns true when the comma separated list in the fields named `name` contains
         * `token` (case-insensitive), as for "Connection: keep-alive, Upgrade".
         */
        bool hasToken(std::string_view name, std::string_view token) const;

        /**
         * Appends "Name: value\r\n" lines for every field.
         */
        void serializeTo(std::string& out) const;
    };

    /**
     * Splits a comma separated header list into trimmed, non-empty elements. Quoted strings
     * are kept intact (commas inside them do not split).
     */
    SBOX_API std::vector<std::string> SplitHeaderList(std::string_view value);

    /**
     * Media type such as "application/vnd.oci.image.manifest.v1+json; charset=utf-8".
     */
    struct SBOX_API SMediaType {
        std::string type;       // --> Lower case.
        std::string subtype;    // --> Lower case.
        std::vector<std::pair<std::string, std::string>> params;   // --> Names lower case, values unquoted.

        /**
         * Parses a Content-Type / Accept element.
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SMediaType& out);

        /**
         * Returns "type/subtype" without parameters.
         */
        std::string essence() const;

        /**
         * Returns a parameter value (name compared case-insensitively), or an empty string.
         */
        std::string param(std::string_view name) const;

        /**
         * Formats the media type with its parameters (values quoted when needed).
         */
        std::string toString() const;
    };

    /**
     * One element of a Link header (RFC 8288), as registries use for pagination:
     * `</v2/_catalog?last=b&n=2>; rel="next"`.
     */
    struct SBOX_API SLink {
        std::string target;     // --> The URI reference between '<' and '>', unresolved.
        std::vector<std::pair<std::string, std::string>> params;   // --> Names lower case, values unquoted.

        /**
         * Returns a parameter value (name compared case-insensitively), or an empty string.
         */
        std::string param(std::string_view name) const;

        /**
         * Returns true when the space separated "rel" parameter contains `rel`.
         */
        bool hasRel(std::string_view rel) const;
    };

    /**
     * Parses a Link header value (several comma separated links allowed).
     * @return SBOX_OK or -EINVAL.
     */
    SBOX_API int32_t ParseLinkHeader(std::string_view value, std::vector<SLink>& out);

    /**
     * Content-Range of a 206 or 416 response (byte ranges only).
     */
    struct SBOX_API SContentRange {
        uint64_t first = 0;
        uint64_t last = 0;              // --> Inclusive.
        int64_t completeLength = -1;    // --> Total size, or -1 when the server wrote '*'.
        bool unsatisfied = false;       // --> "bytes */N" (416): first/last are meaningless.

        /**
         * Parses "bytes 0-499/1234", "bytes 0-499/(star)" or "bytes (star)/1234" where (star) is an asterisk.
         * @return SBOX_OK or -EINVAL.
         */
        static int32_t parse(std::string_view text, SContentRange& out);

        /**
         * Formats the value.
         */
        std::string toString() const;

        /** Returns the number of bytes the range covers (0 when unsatisfied). */
        inline uint64_t length() const noexcept { return unsatisfied ? 0 : last - first + 1; }
    };

    /**
     * Formats a Range header value: "bytes=first-" (open ended, `last` < 0) or "bytes=first-last".
     */
    SBOX_API std::string FormatRange(uint64_t first, int64_t last = -1);

    /**
     * Parses a single byte Range header value ("bytes=a-b", "bytes=a-", "bytes=-n") against a
     * resource of `size` bytes into an inclusive [first, last].
     * @return SBOX_OK; -EINVAL when malformed or a multi-range; -ERANGE when unsatisfiable.
     */
    SBOX_API int32_t ParseRange(std::string_view value, uint64_t size, uint64_t& first, uint64_t& last);

    /**
     * Formats the current time (or `unixSeconds` when >= 0) as an IMF-fixdate for Date headers.
     */
    SBOX_API std::string FormatHttpDate(int64_t unixSeconds = -1);

}
}

#endif
