#ifndef __INCLUDE_SBOX_ARCHIVE_STREAM_HPP__
#define __INCLUDE_SBOX_ARCHIVE_STREAM_HPP__

#include <sbox/archive/codec.hpp>
#include <sbox/core/stream.hpp>
#include <sbox/core/task.hpp>
#include <functional>

namespace sbox {
namespace archive {

    /**
     * Synchronous pull side of a pipeline: something bytes are read from (a file, a decoder,
     * a tar producer).
     */
    class SBOX_API IByteSource {
    public:
        virtual ~IByteSource() = default;

        /**
         * Reads up to `buffer.size` bytes.
         * @return bytes > 0 with SBOX_OK; bytes == 0 with SBOX_OK at the end of the data; or an error.
         */
        virtual SIoResult read(const SByteSpan& buffer) = 0;
    };

    /**
     * Synchronous push side of a pipeline: something bytes are written to (a file, an encoder,
     * a tar parser feeding an extractor).
     */
    class SBOX_API IByteSink {
    public:
        virtual ~IByteSink() = default;

        /**
         * Consumes all of `data`.
         * @return SBOX_OK or a negated errno.
         */
        virtual int32_t write(const SReadOnlyByteSpan& data) = 0;

        /**
         * Signals the end of the data: flushes trailers and verifies completeness. Default: no-op.
         */
        virtual int32_t finish() { return SBOX_OK; }
    };

    /**
     * Observer of the bytes flowing through a tap (e.g. a SHA-256 update for layer digests).
     */
    using FByteHook = std::function<void(const SReadOnlyByteSpan&)>;

    /**
     * Reads from a descriptor with read(2) (blocking descriptors: regular files, blocking pipes).
     * Does not own the descriptor.
     */
    class SBOX_API CFdSource : public IByteSource {
    private:
        int _fd;

    public:
        /** Reads from `fd` (not owned). */
        explicit CFdSource(int fd) noexcept : _fd(fd) {}

        /**
         * Reads once, retrying on EINTR. A non-blocking descriptor with nothing to read gives -EAGAIN.
         */
        SIoResult read(const SByteSpan& buffer) override;
    };

    /**
     * Writes to a descriptor with write(2), looping over short writes. Does not own the descriptor.
     */
    class SBOX_API CFdSink : public IByteSink {
    private:
        int _fd;

    public:
        /** Writes to `fd` (not owned). */
        explicit CFdSink(int fd) noexcept : _fd(fd) {}

        /**
         * Writes everything, retrying on EINTR and short writes.
         */
        int32_t write(const SReadOnlyByteSpan& data) override;
    };

    /**
     * Source over a memory buffer (not copied: the buffer must outlive the source).
     */
    class SBOX_API CMemorySource : public IByteSource {
    private:
        SReadOnlyByteSpan _data;
        size_t _pos = 0;

    public:
        /** Reads from `data` (not copied). */
        explicit CMemorySource(const SReadOnlyByteSpan& data) noexcept : _data(data) {}

        /**
         * Copies the next bytes out.
         */
        SIoResult read(const SByteSpan& buffer) override;
    };

    /**
     * Sink that appends to a byte vector.
     */
    class SBOX_API CVectorSink : public IByteSink {
    private:
        std::vector<uint8_t>& _out;

    public:
        /** Appends to `out` (must outlive the sink). */
        explicit CVectorSink(std::vector<uint8_t>& out) noexcept : _out(out) {}

        /**
         * Appends the bytes.
         */
        int32_t write(const SReadOnlyByteSpan& data) override;
    };

    /**
     * Source that calls a hook with every chunk read through it.
     */
    class SBOX_API CTapSource : public IByteSource {
    private:
        IByteSource& _upstream;
        FByteHook _hook;

    public:
        /** Taps `upstream` (must outlive the tap). */
        CTapSource(IByteSource& upstream, FByteHook hook) : _upstream(upstream), _hook(std::move(hook)) {}

        /**
         * Reads from upstream and shows the bytes to the hook.
         */
        SIoResult read(const SByteSpan& buffer) override;
    };

    /**
     * Sink that calls a hook with every chunk written through it.
     */
    class SBOX_API CTapSink : public IByteSink {
    private:
        IByteSink& _downstream;
        FByteHook _hook;

    public:
        /** Taps the way into `downstream` (must outlive the tap). */
        CTapSink(IByteSink& downstream, FByteHook hook) : _downstream(downstream), _hook(std::move(hook)) {}

        /**
         * Shows the bytes to the hook and forwards them.
         */
        int32_t write(const SReadOnlyByteSpan& data) override;

        /**
         * Forwards finish().
         */
        int32_t finish() override;
    };

    /**
     * Pull-side codec: reading from it reads from `upstream` and runs the bytes through a codec
     * (decompress a file, or compress a tar producer's output).
     */
    class SBOX_API CCodecSource : public IByteSource {
    private:
        ICodecPtr _codec;
        IByteSource& _upstream;
        std::vector<uint8_t> _in;
        size_t _inPos = 0;
        size_t _inLen = 0;
        bool _eof = false;
        bool _ended = false;
        int32_t _error = SBOX_OK;

    public:
        /**
         * @param codec The codec to run (owned).
         * @param upstream Where the input comes from (must outlive this source).
         * @param bufferSize Size of the input buffer.
         */
        CCodecSource(ICodecPtr codec, IByteSource& upstream, size_t bufferSize = 65536);

        /**
         * Returns the next transformed bytes; EOF once the codec reported its end. Input left
         * over after the codec's end is an error (-EBADMSG).
         */
        SIoResult read(const SByteSpan& buffer) override;
    };

    /**
     * Push-side codec: bytes written to it are transformed and written to `downstream`.
     */
    class SBOX_API CCodecSink : public IByteSink {
    private:
        ICodecPtr _codec;
        IByteSink& _downstream;
        std::vector<uint8_t> _out;
        bool _ended = false;
        int32_t _error = SBOX_OK;

    public:
        /**
         * @param codec The codec to run (owned).
         * @param downstream Where the output goes (must outlive this sink).
         * @param bufferSize Size of the output buffer.
         */
        CCodecSink(ICodecPtr codec, IByteSink& downstream, size_t bufferSize = 65536);

        /**
         * Transforms and forwards. Data after the codec's end is -EBADMSG.
         */
        int32_t write(const SReadOnlyByteSpan& data) override;

        /**
         * Finishes the codec (trailers, completeness check) and then `downstream`.
         */
        int32_t finish() override;
    };

    /**
     * IStream that decodes another stream: recv() yields the decoded bytes of `inner`.
     * send() is not supported.
     */
    class SBOX_API CDecodeStream : public IStream {
    private:
        IStream& _inner;
        ICodecPtr _codec;
        FByteHook _rawHook;
        std::vector<uint8_t> _in;
        size_t _inPos = 0;
        size_t _inLen = 0;
        bool _eof = false;
        bool _ended = false;
        int32_t _error = SBOX_OK;

    public:
        /**
         * @param inner The encoded stream (must outlive this one).
         * @param codec The decoder (owned).
         * @param rawHook Optional observer of the encoded bytes as they are read.
         */
        CDecodeStream(IStream& inner, ICodecPtr codec, FByteHook rawHook = nullptr, size_t bufferSize = 65536);

        /**
         * Reads decoded bytes; 0 bytes with SBOX_OK at the end of the decoded data.
         */
        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Not supported (-ENOTSUP).
         */
        TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Closes the inner stream.
         */
        void close() noexcept override;
    };

    /**
     * IStream that encodes into another stream: send() compresses into `inner`. Call finish()
     * once at the end to write the trailer. recv() is not supported.
     */
    class SBOX_API CEncodeStream : public IStream {
    private:
        IStream& _inner;
        ICodecPtr _codec;
        std::vector<uint8_t> _out;
        bool _finished = false;
        int32_t _error = SBOX_OK;

    public:
        /**
         * @param inner The destination stream (must outlive this one).
         * @param codec The encoder (owned).
         */
        CEncodeStream(IStream& inner, ICodecPtr codec, size_t bufferSize = 65536);

        /**
         * Not supported (-ENOTSUP).
         */
        TTask<SIoResult> recv(const SByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Encodes and forwards everything in `buffer`.
         */
        TTask<SIoResult> send(const SReadOnlyByteSpan& buffer, int64_t timeoutMs = -1) override;

        /**
         * Flushes the encoder's remaining output and trailer to the inner stream (once).
         */
        TTask<int32_t> finish(int64_t timeoutMs = -1);

        /**
         * Closes the inner stream (without finishing).
         */
        void close() noexcept override;
    };

    /**
     * Synchronously copies a source into a sink until EOF, then calls `to.finish()`.
     * @return SBOX_OK or the first error.
     */
    SBOX_API int32_t Pump(IByteSource& from, IByteSink& to, size_t chunk = 65536);

    /**
     * Reads a coroutine stream until EOF into a sink, then calls `to.finish()`.
     * @param timeoutMs Maximum wait per recv (negative for none).
     */
    SBOX_API TTask<int32_t> PumpStreamToSink(IStream& from, IByteSink& to, int64_t timeoutMs = -1, size_t chunk = 65536);

    /**
     * Reads a source until EOF and sends everything to a coroutine stream (which is left open).
     * @param timeoutMs Maximum wait per send (negative for none).
     */
    SBOX_API TTask<int32_t> PumpSourceToStream(IByteSource& from, IStream& to, int64_t timeoutMs = -1, size_t chunk = 65536);

}
}

#endif
