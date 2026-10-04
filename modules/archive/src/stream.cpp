#include <sbox/archive/stream.hpp>
#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace sbox {
namespace archive {

    /* One read(2). */
    SIoResult CFdSource::read(const SByteSpan& buffer) {
        for (;;) {
            ssize_t n = ::read(_fd, buffer.data, buffer.size);
            if (n >= 0) {
                return SIoResult{ SBOX_OK, size_t(n) };
            }

            if (errno != EINTR) {
                return SIoResult{ -errno, 0 };
            }
        }
    }

    /* Writes everything. */
    int32_t CFdSink::write(const SReadOnlyByteSpan& data) {
        const uint8_t* p = data.data;
        size_t left = data.size;
        while (left > 0) {
            ssize_t n = ::write(_fd, p, left);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }

                return -errno;
            }

            p += n;
            left -= size_t(n);
        }

        return SBOX_OK;
    }

    /* Copies the next bytes of the buffer. */
    SIoResult CMemorySource::read(const SByteSpan& buffer) {
        size_t n = _data.size - _pos;
        if (n > buffer.size) {
            n = buffer.size;
        }

        if (n) {
            std::memcpy(buffer.data, _data.data + _pos, n);
        }

        _pos += n;
        return SIoResult{ SBOX_OK, n };
    }

    /* Appends to the vector. */
    int32_t CVectorSink::write(const SReadOnlyByteSpan& data) {
        if (data.size) {
            _out.insert(_out.end(), data.data, data.data + data.size);
        }

        return SBOX_OK;
    }

    /* Reads and reports. */
    SIoResult CTapSource::read(const SByteSpan& buffer) {
        SIoResult r = _upstream.read(buffer);
        if (r.ok() && r.bytes && _hook) {
            _hook(SReadOnlyByteSpan(buffer.data, r.bytes));
        }

        return r;
    }

    /* Reports and forwards. */
    int32_t CTapSink::write(const SReadOnlyByteSpan& data) {
        if (data.size && _hook) {
            _hook(data);
        }

        return _downstream.write(data);
    }

    /* Forwards finish(). */
    int32_t CTapSink::finish() {
        return _downstream.finish();
    }

    /* Wraps a codec around a source. */
    CCodecSource::CCodecSource(ICodecPtr codec, IByteSource& upstream, size_t bufferSize)
        : _codec(std::move(codec)), _upstream(upstream), _in(bufferSize ? bufferSize : 65536) {}

    /* Pulls, transforms and returns bytes. */
    SIoResult CCodecSource::read(const SByteSpan& buffer) {
        if (_error) {
            return SIoResult{ _error, 0 };
        }

        if (!_codec) {
            return SIoResult{ -EINVAL, 0 };
        }

        for (;;) {
            if (_ended) {
                return SIoResult{ SBOX_OK, 0 };
            }

            if (_inPos == _inLen && !_eof) {
                SIoResult r = _upstream.read(SByteSpan(_in.data(), _in.size()));
                if (!r.ok()) {
                    _error = r.error;
                    return r;
                }

                _inPos = 0;
                _inLen = r.bytes;
                _eof = r.bytes == 0;
            }

            size_t consumed = 0;
            size_t produced = 0;
            int32_t rc = _codec->process(SReadOnlyByteSpan(_in.data() + _inPos, _inLen - _inPos), consumed, buffer,
                                         produced, _eof);
            _inPos += consumed;
            if (rc < 0) {
                _error = rc;
                return SIoResult{ rc, 0 };
            }

            if (rc == CODEC_END) {
                _ended = true;
                if (_inPos < _inLen) {
                    _error = -EBADMSG;
                    return SIoResult{ produced ? SBOX_OK : _error, produced };
                }
            }

            if (produced) {
                return SIoResult{ SBOX_OK, produced };
            }

            if (consumed == 0 && _inPos < _inLen) {
                // --> The codec wants more than what is buffered: keep the rest and read behind it.
                std::memmove(_in.data(), _in.data() + _inPos, _inLen - _inPos);
                _inLen -= _inPos;
                _inPos = 0;
                SIoResult r = _upstream.read(SByteSpan(_in.data() + _inLen, _in.size() - _inLen));
                if (!r.ok()) {
                    _error = r.error;
                    return r;
                }

                _inLen += r.bytes;
                _eof = r.bytes == 0;
            }
        }
    }

    /* Wraps a codec around a sink. */
    CCodecSink::CCodecSink(ICodecPtr codec, IByteSink& downstream, size_t bufferSize)
        : _codec(std::move(codec)), _downstream(downstream), _out(bufferSize ? bufferSize : 65536) {}

    /* Transforms and forwards. */
    int32_t CCodecSink::write(const SReadOnlyByteSpan& data) {
        if (_error) {
            return _error;
        }

        if (!_codec) {
            return -EINVAL;
        }

        SReadOnlyByteSpan in = data;
        for (;;) {
            if (_ended) {
                if (in.size) {
                    _error = -EBADMSG;
                }

                return _error;
            }

            size_t consumed = 0;
            size_t produced = 0;
            int32_t rc = _codec->process(in, consumed, SByteSpan(_out.data(), _out.size()), produced, false);
            in = in.slice(consumed);
            if (rc < 0) {
                _error = rc;
                return rc;
            }

            if (produced) {
                int32_t wrc = _downstream.write(SReadOnlyByteSpan(_out.data(), produced));
                if (wrc < 0) {
                    _error = wrc;
                    return wrc;
                }
            }

            if (rc == CODEC_END) {
                _ended = true;
                continue;
            }

            if (in.size == 0 && produced < _out.size()) {
                return SBOX_OK;
            }
        }
    }

    /* Drains the codec and finishes downstream. */
    int32_t CCodecSink::finish() {
        if (_error) {
            return _error;
        }

        if (!_codec) {
            return -EINVAL;
        }

        while (!_ended) {
            size_t consumed = 0;
            size_t produced = 0;
            int32_t rc = _codec->process(SReadOnlyByteSpan(), consumed, SByteSpan(_out.data(), _out.size()), produced, true);
            if (rc < 0) {
                _error = rc;
                return rc;
            }

            if (produced) {
                int32_t wrc = _downstream.write(SReadOnlyByteSpan(_out.data(), produced));
                if (wrc < 0) {
                    _error = wrc;
                    return wrc;
                }
            }

            if (rc == CODEC_END) {
                _ended = true;
            } else if (produced == 0) {
                _error = -ENODATA;
                return _error;
            }
        }

        return _downstream.finish();
    }

    /* Wraps a decoder around a stream. */
    CDecodeStream::CDecodeStream(IStream& inner, ICodecPtr codec, FByteHook rawHook, size_t bufferSize)
        : _inner(inner), _codec(std::move(codec)), _rawHook(std::move(rawHook)), _in(bufferSize ? bufferSize : 65536) {}

    /* Reads decoded bytes. */
    TTask<SIoResult> CDecodeStream::recv(const SByteSpan& buffer, int64_t timeoutMs) {
        if (_error) {
            co_return SIoResult{ _error, 0 };
        }

        if (!_codec) {
            co_return SIoResult{ -EINVAL, 0 };
        }

        for (;;) {
            if (_ended) {
                co_return SIoResult{ SBOX_OK, 0 };
            }

            if (_inPos == _inLen && !_eof) {
                SIoResult r = co_await _inner.recv(SByteSpan(_in.data(), _in.size()), timeoutMs);
                if (!r.ok()) {
                    _error = r.error;
                    co_return r;
                }

                if (r.bytes && _rawHook) {
                    _rawHook(SReadOnlyByteSpan(_in.data(), r.bytes));
                }

                _inPos = 0;
                _inLen = r.bytes;
                _eof = r.bytes == 0;
            }

            size_t consumed = 0;
            size_t produced = 0;
            int32_t rc = _codec->process(SReadOnlyByteSpan(_in.data() + _inPos, _inLen - _inPos), consumed, buffer,
                                         produced, _eof);
            _inPos += consumed;
            if (rc < 0) {
                _error = rc;
                co_return SIoResult{ rc, 0 };
            }

            if (rc == CODEC_END) {
                _ended = true;
                if (_inPos < _inLen) {
                    _error = -EBADMSG;
                    co_return SIoResult{ produced ? SBOX_OK : _error, produced };
                }
            }

            if (produced) {
                co_return SIoResult{ SBOX_OK, produced };
            }

            if (consumed == 0 && _inPos < _inLen) {
                std::memmove(_in.data(), _in.data() + _inPos, _inLen - _inPos);
                _inLen -= _inPos;
                _inPos = 0;
                SIoResult r = co_await _inner.recv(SByteSpan(_in.data() + _inLen, _in.size() - _inLen), timeoutMs);
                if (!r.ok()) {
                    _error = r.error;
                    co_return r;
                }

                if (r.bytes && _rawHook) {
                    _rawHook(SReadOnlyByteSpan(_in.data() + _inLen, r.bytes));
                }

                _inLen += r.bytes;
                _eof = r.bytes == 0;
            }
        }
    }

    /* Decode streams are read-only. */
    TTask<SIoResult> CDecodeStream::send(const SReadOnlyByteSpan&, int64_t) {
        co_return SIoResult{ -ENOTSUP, 0 };
    }

    /* Closes the inner stream. */
    void CDecodeStream::close() noexcept {
        _inner.close();
    }

    /* Wraps an encoder around a stream. */
    CEncodeStream::CEncodeStream(IStream& inner, ICodecPtr codec, size_t bufferSize)
        : _inner(inner), _codec(std::move(codec)), _out(bufferSize ? bufferSize : 65536) {}

    /* Encode streams are write-only. */
    TTask<SIoResult> CEncodeStream::recv(const SByteSpan&, int64_t) {
        co_return SIoResult{ -ENOTSUP, 0 };
    }

    /* Encodes and forwards. */
    TTask<SIoResult> CEncodeStream::send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs) {
        if (_error) {
            co_return SIoResult{ _error, 0 };
        }

        if (_finished || !_codec) {
            co_return SIoResult{ -EINVAL, 0 };
        }

        SReadOnlyByteSpan in = buffer;
        for (;;) {
            size_t consumed = 0;
            size_t produced = 0;
            int32_t rc = _codec->process(in, consumed, SByteSpan(_out.data(), _out.size()), produced, false);
            in = in.slice(consumed);
            if (rc < 0) {
                _error = rc;
                co_return SIoResult{ rc, buffer.size - in.size };
            }

            if (produced) {
                SIoResult r = co_await _inner.send(SReadOnlyByteSpan(_out.data(), produced), timeoutMs);
                if (!r.ok()) {
                    _error = r.error;
                    co_return SIoResult{ r.error, buffer.size - in.size };
                }
            }

            if (in.size == 0 && produced < _out.size()) {
                co_return SIoResult{ SBOX_OK, buffer.size };
            }
        }
    }

    /* Writes the remaining output and trailer. */
    TTask<int32_t> CEncodeStream::finish(int64_t timeoutMs) {
        if (_error) {
            co_return _error;
        }

        if (!_codec) {
            co_return -EINVAL;
        }

        while (!_finished) {
            size_t consumed = 0;
            size_t produced = 0;
            int32_t rc = _codec->process(SReadOnlyByteSpan(), consumed, SByteSpan(_out.data(), _out.size()), produced, true);
            if (rc < 0) {
                _error = rc;
                co_return rc;
            }

            if (produced) {
                SIoResult r = co_await _inner.send(SReadOnlyByteSpan(_out.data(), produced), timeoutMs);
                if (!r.ok()) {
                    _error = r.error;
                    co_return r.error;
                }
            }

            if (rc == CODEC_END) {
                _finished = true;
            } else if (produced == 0) {
                _error = -EIO;
                co_return _error;
            }
        }

        co_return SBOX_OK;
    }

    /* Closes the inner stream. */
    void CEncodeStream::close() noexcept {
        _inner.close();
    }

    /* Copies a source into a sink. */
    int32_t Pump(IByteSource& from, IByteSink& to, size_t chunk) {
        std::vector<uint8_t> buf(chunk ? chunk : 65536);
        for (;;) {
            SIoResult r = from.read(SByteSpan(buf.data(), buf.size()));
            if (!r.ok()) {
                return r.error;
            }

            if (r.bytes == 0) {
                return to.finish();
            }

            int32_t rc = to.write(SReadOnlyByteSpan(buf.data(), r.bytes));
            if (rc < 0) {
                return rc;
            }
        }
    }

    /* Copies a coroutine stream into a sink. */
    TTask<int32_t> PumpStreamToSink(IStream& from, IByteSink& to, int64_t timeoutMs, size_t chunk) {
        std::vector<uint8_t> buf(chunk ? chunk : 65536);
        for (;;) {
            SIoResult r = co_await from.recv(SByteSpan(buf.data(), buf.size()), timeoutMs);
            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                co_return to.finish();
            }

            int32_t rc = to.write(SReadOnlyByteSpan(buf.data(), r.bytes));
            if (rc < 0) {
                co_return rc;
            }
        }
    }

    /* Copies a source into a coroutine stream. */
    TTask<int32_t> PumpSourceToStream(IByteSource& from, IStream& to, int64_t timeoutMs, size_t chunk) {
        std::vector<uint8_t> buf(chunk ? chunk : 65536);
        for (;;) {
            SIoResult r = from.read(SByteSpan(buf.data(), buf.size()));
            if (!r.ok()) {
                co_return r.error;
            }

            if (r.bytes == 0) {
                co_return SBOX_OK;
            }

            SIoResult w = co_await to.send(SReadOnlyByteSpan(buf.data(), r.bytes), timeoutMs);
            if (!w.ok()) {
                co_return w.error;
            }
        }
    }

}
}
