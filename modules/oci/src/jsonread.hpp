#ifndef __SRC_OCI_JSONREAD_HPP__
#define __SRC_OCI_JSONREAD_HPP__

#include <sbox/core/json.hpp>
#include <cmath>
#include <initializer_list>
#include <optional>

namespace sbox {
namespace oci {

    /**
     * Typed field reader over CJson objects with precise error messages ("process.user.uid:
     * expected an unsigned 32-bit integer"). Absent and null members leave the output alone.
     */
    class JsonReader {
    private:
        std::string& _error;
        std::vector<std::string>* _warnings;

    public:
        JsonReader(std::string& error, std::vector<std::string>* warnings) noexcept : _error(error), _warnings(warnings) {}

        /**
         * Records the first error and returns false.
         */
        bool fail(const std::string& path, std::string_view what) {
            if (_error.empty()) {
                _error = (path.empty() ? std::string("config") : path) + ": " + std::string(what);
            }

            return false;
        }

        /**
         * Joins a parent path and a key.
         */
        static std::string at(const std::string& path, std::string_view key) {
            return path.empty() ? std::string(key) : path + "." + std::string(key);
        }

        bool expectObject(const CJson& v, const std::string& path) {
            return v.isObject() ? true : fail(path, "expected an object");
        }

        bool expectArray(const CJson& v, const std::string& path) {
            return v.isArray() ? true : fail(path, "expected an array");
        }

        /**
         * Warns about members that are not in `known`.
         */
        void unknown(const CJson& obj, const std::string& path, std::initializer_list<const char*> known) {
            if (!_warnings || !obj.isObject()) {
                return;
            }

            for (size_t i = 0; i < obj.size(); ++i) {
                bool found = false;
                for (const char* k : known) {
                    found = found || obj.keyAt(i) == k;
                }

                if (!found) {
                    _warnings->push_back(at(path, obj.keyAt(i)) + ": unknown field ignored");
                }
            }
        }

        bool str(const CJson& obj, std::string_view key, std::string& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            if (!v->isString()) {
                return fail(at(path, key), "expected a string");
            }

            out = v->asString();
            return true;
        }

        bool boolean(const CJson& obj, std::string_view key, bool& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            if (!v->isBool()) {
                return fail(at(path, key), "expected a boolean");
            }

            out = v->asBool();
            return true;
        }

        bool optBool(const CJson& obj, std::string_view key, std::optional<bool>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            bool b = false;
            if (!boolean(obj, key, b, path)) {
                return false;
            }

            out = b;
            return true;
        }

        /**
         * Reads a signed integer (doubles must be integral and in range).
         */
        static bool toI64(const CJson& v, int64_t& out) {
            if (v.type() == EJSON_INT) {
                out = v.asInt();
                return true;
            }

            if (v.type() == EJSON_DOUBLE) {
                float64_t d = v.asDouble();
                if (std::isfinite(d) && std::floor(d) == d && d >= -9223372036854775808.0 && d < 9223372036854775808.0) {
                    out = int64_t(d);
                    return true;
                }
            }

            return false;
        }

        /**
         * Reads an unsigned integer (values above INT64_MAX arrive as doubles).
         */
        static bool toU64(const CJson& v, uint64_t& out) {
            if (v.type() == EJSON_INT) {
                if (v.asInt() < 0) {
                    return false;
                }

                out = uint64_t(v.asInt());
                return true;
            }

            if (v.type() == EJSON_DOUBLE) {
                float64_t d = v.asDouble();
                if (std::isfinite(d) && std::floor(d) == d && d >= 0 && d < 18446744073709551616.0) {
                    out = uint64_t(d);
                    return true;
                }
            }

            return false;
        }

        bool i64(const CJson& obj, std::string_view key, int64_t& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            return toI64(*v, out) ? true : fail(at(path, key), "expected a 64-bit integer");
        }

        bool u64(const CJson& obj, std::string_view key, uint64_t& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            return toU64(*v, out) ? true : fail(at(path, key), "expected an unsigned 64-bit integer");
        }

        bool u32(const CJson& obj, std::string_view key, uint32_t& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            uint64_t x = 0;
            if (!toU64(*v, x) || x > 0xffffffffull) {
                return fail(at(path, key), "expected an unsigned 32-bit integer");
            }

            out = uint32_t(x);
            return true;
        }

        bool optI64(const CJson& obj, std::string_view key, std::optional<int64_t>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            int64_t x = 0;
            if (!i64(obj, key, x, path)) {
                return false;
            }

            out = x;
            return true;
        }

        bool optU64(const CJson& obj, std::string_view key, std::optional<uint64_t>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            uint64_t x = 0;
            if (!u64(obj, key, x, path)) {
                return false;
            }

            out = x;
            return true;
        }

        bool optU32(const CJson& obj, std::string_view key, std::optional<uint32_t>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            uint32_t x = 0;
            if (!u32(obj, key, x, path)) {
                return false;
            }

            out = x;
            return true;
        }

        bool optU16(const CJson& obj, std::string_view key, std::optional<uint16_t>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            uint64_t x = 0;
            if (!toU64(*v, x) || x > 0xffff) {
                return fail(at(path, key), "expected an unsigned 16-bit integer");
            }

            out = uint16_t(x);
            return true;
        }

        bool optI32(const CJson& obj, std::string_view key, std::optional<int32_t>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            int64_t x = 0;
            if (!toI64(*v, x) || x < INT32_MIN || x > INT32_MAX) {
                return fail(at(path, key), "expected a 32-bit integer");
            }

            out = int32_t(x);
            return true;
        }

        bool strings(const CJson& obj, std::string_view key, std::vector<std::string>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            if (!v->isArray()) {
                return fail(at(path, key), "expected an array of strings");
            }

            out.clear();
            for (size_t i = 0; i < v->size(); ++i) {
                if (!v->at(i).isString()) {
                    return fail(at(path, key) + "[" + std::to_string(i) + "]", "expected a string");
                }

                out.push_back(v->at(i).asString());
            }

            return true;
        }

        bool u32s(const CJson& obj, std::string_view key, std::vector<uint32_t>& out, const std::string& path) {
            const CJson* v = obj.find(key);
            if (!v || v->isNull()) {
                return true;
            }

            if (!v->isArray()) {
                return fail(at(path, key), "expected an array of integers");
            }

            out.clear();
            for (size_t i = 0; i < v->size(); ++i) {
                uint64_t x = 0;
                if (!toU64(v->at(i), x) || x > 0xffffffffull) {
                    return fail(at(path, key) + "[" + std::to_string(i) + "]", "expected an unsigned 32-bit integer");
                }

                out.push_back(uint32_t(x));
            }

            return true;
        }
    };

}
}

#endif
