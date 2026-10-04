#ifndef __CLI_SBOX_CLI_HPP__
#define __CLI_SBOX_CLI_HPP__

// sbox / sboxrun: runc-compatible command line over sbox::oci::CRuntime.

#include <sbox/core/task.hpp>
#include <sbox/oci/runtime.hpp>
#include <map>
#include <string>
#include <vector>

namespace sboxcli {

    using namespace sbox;

    /**
     * Description of one flag of a command.
     */
    struct FlagSpec {
        const char* name;           // --> Long name without dashes.
        char shortName;             // --> 0 when none.
        bool takesValue;
    };

    /**
     * Parsed flags and positional arguments of a command.
     */
    struct Flags {
        std::map<std::string, std::vector<std::string>> values;
        std::vector<std::string> positional;

        /** Returns true when the flag was given. */
        bool has(const std::string& name) const;

        /** Returns the last value of a flag, or `fallback`. */
        std::string get(const std::string& name, const std::string& fallback = std::string()) const;

        /** Returns every value of a repeatable flag. */
        std::vector<std::string> all(const std::string& name) const;

        /** Returns a boolean flag ("--x", "--x=true", "--x=false"). */
        bool flag(const std::string& name) const;
    };

    /**
     * Parses flags (long names with one or two dashes, "--name=value" or "--name value", short
     * names) up to the first positional argument or "--"; everything after is positional.
     * @return An empty string, or the error message.
     */
    std::string ParseFlags(const std::vector<std::string>& args, size_t start, const std::vector<FlagSpec>& specs, Flags& out);

    /**
     * Global options (runc's global flags).
     */
    struct Globals {
        std::string program;        // --> "sbox" or "sboxrun".
        std::string root;
        std::string logPath;
        std::string logFormat = "text";
        bool debug = false;
        bool systemdCgroup = false;
        bool rootless = false;
    };

    /**
     * Writes a log line in runc's formats: logrus text (time="..." level=... msg="...") or
     * JSON lines ({"level":...,"msg":...,"time":...}), to --log or standard error.
     */
    void Log(oci::ELogLevel level, const std::string& message);

    /**
     * Reports a command failure: logged at error level, and printed plainly on standard error
     * when a log file is in use (as runc does).
     * @return 1.
     */
    int Fail(const std::string& message);

    /**
     * Returns the global options.
     */
    Globals& GlobalOptions();

    /**
     * Builds a runtime from the global options.
     */
    oci::SRuntimeOptions RuntimeOptions();

    /**
     * Command entry points. Each returns the process exit status.
     */
    TTask<int> CmdCreate(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdRun(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdStart(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdState(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdKill(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdDelete(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdExec(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdPs(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdPause(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdResume(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdUpdate(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdList(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdEvents(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdFeatures(const std::vector<std::string>& args, size_t start);
    TTask<int> CmdSpec(const std::vector<std::string>& args, size_t start);

    /**
     * Supervises a foreground container process: forwards signals (signalfd), proxies a pty
     * between the terminal and the container (raw mode, window size), waits for the exit.
     * @return The exit status to report (code, or 128 + signal).
     */
    TTask<int> Supervise(oci::CContainerProcess& process, bool terminal);

    /**
     * Runs `ps` with `options` and keeps the header and the lines of `pids` (runc's table form).
     */
    TTask<int> PrintPsTable(const std::vector<pid_t>& pids, const std::vector<std::string>& options);

    /**
     * Reads a file, or standard input for "-".
     */
    int32_t ReadInput(const std::string& path, std::string& out);

}

#endif
