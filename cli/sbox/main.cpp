// sbox / sboxrun: runc-compatible OCI runtime command line.
//
// Both binaries are built from these sources; `sboxrun` is the name to register with dockerd
// ("runtimes") and containerd (runc shim BinaryName). Global flags, logging and command
// dispatch live here; the commands are in commands.cpp and console.cpp.
#include "cli.hpp"
#include <sbox/core/eventloop.hpp>
#include <sbox/core/file.hpp>
#include <sbox/oci/spec.hpp>
#include <sbox/version.hpp>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>

namespace sboxcli {

    namespace {

        Globals gGlobals;
        int gLogFd = -1;

        /**
         * Returns the level name logrus uses.
         */
        const char* levelName(oci::ELogLevel level) {
            switch (level) {
            case oci::ELOG_DEBUG:
                return "debug";
            case oci::ELOG_INFO:
                return "info";
            case oci::ELOG_WARNING:
                return "warning";
            default:
                return "error";
            }
        }

        /**
         * Returns the current time as RFC 3339 with seconds (logrus' default).
         */
        std::string nowSeconds() {
            time_t t = ::time(nullptr);
            struct tm tm;
            ::gmtime_r(&t, &tm);
            char buf[32];
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
            return buf;
        }

        /**
         * Quotes a value for logrus' text format.
         */
        std::string quote(const std::string& s) {
            std::string out = "\"";
            for (char c : s) {
                if (c == '"' || c == '\\') {
                    out += '\\';
                    out += c;
                } else if (c == '\n') {
                    out += "\\n";
                } else {
                    out += c;
                }
            }

            return out + "\"";
        }

        /**
         * Writes all bytes to a descriptor.
         */
        void writeAll(int fd, const std::string& text) {
            size_t off = 0;
            while (off < text.size()) {
                ssize_t n = ::write(fd, text.data() + off, text.size() - off);
                if (n < 0 && errno == EINTR) {
                    continue;
                }

                if (n <= 0) {
                    return;
                }

                off += size_t(n);
            }
        }

        void usage(FILE* out) {
            const std::string& p = gGlobals.program;
            std::fprintf(out,
                "NAME:\n   %s - runc-compatible OCI container runtime (libsbox)\n\n"
                "USAGE:\n   %s [global options] command [command options] [arguments...]\n\n"
                "COMMANDS:\n"
                "   create    create a container\n"
                "   start     executes the user defined process in a created container\n"
                "   run       create and run a container\n"
                "   state     output the state of a container\n"
                "   kill      kill sends the specified signal (default: SIGTERM) to the container's init process\n"
                "   delete    delete any resources held by the container\n"
                "   exec      execute new process inside the container\n"
                "   ps        ps displays the processes running inside a container\n"
                "   pause     pause suspends all processes inside the container\n"
                "   resume    resumes all processes that have been previously paused\n"
                "   update    update container resource constraints\n"
                "   list      lists containers started by %s with the given root\n"
                "   events    display container events such as OOM notifications and cpu, memory, and IO usage statistics\n"
                "   features  show the enabled features\n"
                "   spec      create a new specification file\n\n"
                "GLOBAL OPTIONS:\n"
                "   --debug              enable debug logging\n"
                "   --log value          set the log file to write logs to (default: stderr)\n"
                "   --log-format value   set the log format ('text' (default), or 'json')\n"
                "   --root value         root directory for storage of container state\n"
                "   --systemd-cgroup     interpret cgroupsPath as slice:prefix:name (mapped to cgroupfs)\n"
                "   --rootless value     ignore cgroup permission errors ('true', 'false', or 'auto')\n"
                "   --criu value         accepted for compatibility (checkpoint/restore is not supported)\n"
                "   --help, -h           show help\n"
                "   --version, -v        print the version\n",
                p.c_str(), p.c_str(), p.c_str());
        }

        void version() {
            std::printf("%s version %u.%u.%u\ncommit: libsbox\nspec: %s\n", gGlobals.program.c_str(),
                        unsigned(HEADER_VERSION.major), unsigned(HEADER_VERSION.minor), unsigned(HEADER_VERSION.patch),
                        oci::OCI_VERSION);
        }

        /**
         * Runs a command by name.
         */
        TTask<int> dispatch(std::vector<std::string> args, size_t at) {
            const std::string& cmd = args[at];
            size_t start = at + 1;

            if (cmd == "create") {
                co_return co_await CmdCreate(args, start);
            }

            if (cmd == "run") {
                co_return co_await CmdRun(args, start);
            }

            if (cmd == "start") {
                co_return co_await CmdStart(args, start);
            }

            if (cmd == "state") {
                co_return co_await CmdState(args, start);
            }

            if (cmd == "kill") {
                co_return co_await CmdKill(args, start);
            }

            if (cmd == "delete" || cmd == "rm") {
                co_return co_await CmdDelete(args, start);
            }

            if (cmd == "exec") {
                co_return co_await CmdExec(args, start);
            }

            if (cmd == "ps") {
                co_return co_await CmdPs(args, start);
            }

            if (cmd == "pause") {
                co_return co_await CmdPause(args, start);
            }

            if (cmd == "resume") {
                co_return co_await CmdResume(args, start);
            }

            if (cmd == "update") {
                co_return co_await CmdUpdate(args, start);
            }

            if (cmd == "list" || cmd == "ls") {
                co_return co_await CmdList(args, start);
            }

            if (cmd == "events") {
                co_return co_await CmdEvents(args, start);
            }

            if (cmd == "features") {
                co_return co_await CmdFeatures(args, start);
            }

            if (cmd == "spec") {
                co_return co_await CmdSpec(args, start);
            }

            if (cmd == "checkpoint" || cmd == "restore") {
                co_return Fail(cmd + " is not supported by this runtime (no CRIU integration)");
            }

            if (cmd == "help" || cmd == "h") {
                usage(stdout);
                co_return 0;
            }

            co_return Fail("No help topic for '" + cmd + "'");
        }

    }

    /* Returns true when the flag was given. */
    bool Flags::has(const std::string& name) const {
        return values.count(name) != 0;
    }

    /* Returns the last value of a flag. */
    std::string Flags::get(const std::string& name, const std::string& fallback) const {
        auto it = values.find(name);
        return it == values.end() || it->second.empty() ? fallback : it->second.back();
    }

    /* Returns every value of a flag. */
    std::vector<std::string> Flags::all(const std::string& name) const {
        auto it = values.find(name);
        return it == values.end() ? std::vector<std::string>() : it->second;
    }

    /* Returns a boolean flag. */
    bool Flags::flag(const std::string& name) const {
        if (!has(name)) {
            return false;
        }

        std::string v = get(name, "true");
        return v != "false" && v != "0";
    }

    /* Parses flags up to the first positional argument. */
    std::string ParseFlags(const std::vector<std::string>& args, size_t start, const std::vector<FlagSpec>& specs, Flags& out) {
        size_t i = start;
        for (; i < args.size(); ++i) {
            const std::string& a = args[i];
            if (a == "--") {
                ++i;
                break;
            }

            if (a.size() < 2 || a[0] != '-') {
                break;
            }

            std::string body = a.substr(a[1] == '-' ? 2 : 1);
            std::string value;
            bool hasValue = false;
            size_t eq = body.find('=');
            if (eq != std::string::npos) {
                value = body.substr(eq + 1);
                body = body.substr(0, eq);
                hasValue = true;
            }

            const FlagSpec* spec = nullptr;
            for (const FlagSpec& s : specs) {
                if (body == s.name || (body.size() == 1 && s.shortName == body[0])) {
                    spec = &s;
                    break;
                }
            }

            if (!spec) {
                return "flag provided but not defined: -" + body;
            }

            if (spec->takesValue && !hasValue) {
                if (i + 1 >= args.size()) {
                    return "flag needs an argument: -" + body;
                }

                value = args[++i];
            } else if (!spec->takesValue && !hasValue) {
                value = "true";
            }

            out.values[spec->name].push_back(value);
        }

        for (; i < args.size(); ++i) {
            out.positional.push_back(args[i]);
        }

        return std::string();
    }

    /* Writes a log line. */
    void Log(oci::ELogLevel level, const std::string& message) {
        if (level == oci::ELOG_DEBUG && !gGlobals.debug) {
            return;
        }

        std::string line;
        if (gGlobals.logFormat == "json") {
            CJson o = CJson::object();
            o.set("level", levelName(level));
            o.set("msg", message);
            o.set("time", nowSeconds());
            line = o.dump() + "\n";
        } else {
            line = "time=\"" + nowSeconds() + "\" level=" + levelName(level) + " msg=" + quote(message) + "\n";
        }

        writeAll(gLogFd >= 0 ? gLogFd : STDERR_FILENO, line);
    }

    /* Reports a failure. */
    int Fail(const std::string& message) {
        Log(oci::ELOG_ERROR, message);
        if (gLogFd >= 0) {
            writeAll(STDERR_FILENO, message + "\n");
        }

        return 1;
    }

    /* Returns the global options. */
    Globals& GlobalOptions() {
        return gGlobals;
    }

    /* Builds runtime options. */
    oci::SRuntimeOptions RuntimeOptions() {
        oci::SRuntimeOptions o;
        o.root = gGlobals.root;
        o.rootless = gGlobals.rootless;
        o.systemdCgroup = gGlobals.systemdCgroup;
        o.log = [](oci::ELogLevel level, const std::string& msg) { Log(level, msg); };
        return o;
    }

    /* Reads a file or stdin. */
    int32_t ReadInput(const std::string& path, std::string& out) {
        if (path != "-") {
            return CFile::readAll(path, out);
        }

        char buf[8192];
        while (true) {
            ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
            if (n < 0 && errno == EINTR) {
                continue;
            }

            if (n < 0) {
                return -errno;
            }

            if (n == 0) {
                return SBOX_OK;
            }

            out.append(buf, size_t(n));
        }
    }

    /**
     * Parses the global flags and runs the command.
     */
    int Main(int argc, char** argv) {
        std::vector<std::string> args(argv, argv + argc);
        std::string prog = args.empty() ? "sbox" : args[0];
        size_t slash = prog.find_last_of('/');
        gGlobals.program = slash == std::string::npos ? prog : prog.substr(slash + 1);

        // --> A write to a closed pipe (a shim that went away) must be an error, not death.
        ::signal(SIGPIPE, SIG_IGN);

        Flags g;
        std::string err = ParseFlags(args, 1, {
            { "debug", 0, false }, { "log", 0, true }, { "log-format", 0, true }, { "root", 0, true },
            { "criu", 0, true }, { "systemd-cgroup", 0, false }, { "rootless", 0, true },
            { "help", 'h', false }, { "version", 'v', false },
        }, g);

        if (!err.empty()) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }

        gGlobals.debug = g.flag("debug");
        gGlobals.logPath = g.get("log");
        gGlobals.logFormat = g.get("log-format", "text");
        gGlobals.systemdCgroup = g.flag("systemd-cgroup");

        if (gGlobals.logFormat != "text" && gGlobals.logFormat != "json") {
            std::fprintf(stderr, "invalid log-format: %s\n", gGlobals.logFormat.c_str());
            return 1;
        }

        if (!gGlobals.logPath.empty()) {
            gLogFd = ::open(gGlobals.logPath.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
            if (gLogFd < 0) {
                std::fprintf(stderr, "cannot open log file %s: %s\n", gGlobals.logPath.c_str(), std::strerror(errno));
                return 1;
            }
        }

        std::string rootless = g.get("rootless", "auto");
        if (rootless == "auto") {
            gGlobals.rootless = ::geteuid() != 0;
        } else if (rootless == "true" || rootless == "false") {
            gGlobals.rootless = rootless == "true";
        } else {
            return Fail("invalid --rootless value: " + rootless);
        }

        gGlobals.root = g.get("root", oci::CRuntime::DefaultRoot(gGlobals.rootless));

        if (gGlobals.systemdCgroup) {
            Log(oci::ELOG_DEBUG, "--systemd-cgroup: cgroupsPath is mapped to a cgroupfs path (no systemd unit is created)");
        }

        if (g.flag("version")) {
            version();
            return 0;
        }

        if (g.flag("help") || g.positional.empty()) {
            usage(g.positional.empty() && !g.flag("help") ? stderr : stdout);
            return g.flag("help") ? 0 : 1;
        }

        size_t at = args.size() - g.positional.size();
        CEventLoop loop;
        int code = loop.run(dispatch(args, at));
        std::fflush(stdout);
        return code;
    }

}

int main(int argc, char** argv) {
    return sboxcli::Main(argc, argv);
}
