// log_analyzer.cpp
// -----------------
// See log_analyzer.hpp for the "why dependency-free JSON parsing" note.
#include "log_analyzer.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <cctype>

namespace sentinel {

namespace {

// Extracts the value of "key":<value> from a single JSON-lines record.
// Handles both quoted-string values ("foo") and bare numeric values
// (123). Returns true and fills `out` if the key was found.
bool extract_field(const std::string &line, const std::string &key, std::string &out) {
    std::string needle = "\"" + key + "\":";
    auto pos = line.find(needle);
    if (pos == std::string::npos) return false;
    pos += needle.size();

    if (pos < line.size() && line[pos] == '"') {
        // quoted string value
        ++pos;
        std::string value;
        while (pos < line.size() && line[pos] != '"') {
            if (line[pos] == '\\' && pos + 1 < line.size()) {
                value += line[pos + 1];
                pos += 2;
            } else {
                value += line[pos];
                ++pos;
            }
        }
        out = value;
        return true;
    }

    // bare numeric value: read until ',' or '}'
    std::string value;
    while (pos < line.size() && line[pos] != ',' && line[pos] != '}') {
        value += line[pos];
        ++pos;
    }
    out = value;
    return true;
}

long long to_ll(const std::string &s) {
    if (s.empty()) return 0;
    try {
        return std::stoll(s);
    } catch (...) {
        return 0;
    }
}

// Syscalls that, if a program NOT expected to need them attempts them,
// are strong signals of exploitation / post-compromise behaviour rather
// than an overly-strict policy. This list is intentionally short and
// commentated rather than exhaustive -- see README for how to extend it
// for your own threat model.
const std::map<std::string, Severity> &severity_table() {
    static const std::map<std::string, Severity> table = {
        // Process/debugger control -- classic privilege-escalation and
        // anti-debugging / injection primitives.
        {"ptrace", Severity::High},
        {"process_vm_writev", Severity::High},
        {"process_vm_readv", Severity::High},

        // Spawning shells or other binaries from a process that was not
        // expected to do so is the signature of command injection / RCE.
        {"execve", Severity::High},
        {"execveat", Severity::High},

        // Kernel module / namespace manipulation -- container escape and
        // rootkit territory.
        {"init_module", Severity::High},
        {"finit_module", Severity::High},
        {"delete_module", Severity::High},
        {"kexec_load", Severity::High},
        {"reboot", Severity::High},
        {"unshare", Severity::High},
        {"setns", Severity::High},
        {"mount", Severity::High},
        {"pivot_root", Severity::High},

        // Networking -- relevant for anything that was supposed to be
        // network-isolated (e.g. an "untrusted-script" profile).
        {"socket", Severity::Medium},
        {"connect", Severity::Medium},
        {"sendto", Severity::Medium},
        {"recvfrom", Severity::Medium},
        {"bind", Severity::Medium},

        // Credential / capability manipulation.
        {"setuid", Severity::High},
        {"setgid", Severity::High},
        {"capset", Severity::High},
        {"keyctl", Severity::Medium},
    };
    return table;
}

Severity classify(const std::string &syscall_name) {
    auto &table = severity_table();
    auto it = table.find(syscall_name);
    if (it != table.end()) return it->second;
    return Severity::Low;
}

const char *severity_label(Severity s) {
    switch (s) {
        case Severity::High: return "HIGH";
        case Severity::Medium: return "MEDIUM";
        default: return "low";
    }
}

} // namespace

std::vector<Violation> load_violations(const std::string &path) {
    std::vector<Violation> out;
    std::ifstream in(path);
    if (!in.is_open()) return out;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;

        std::string ts_s, pid_s, nr_s, name_s, policy_s;
        bool ok = extract_field(line, "ts", ts_s) &&
                  extract_field(line, "pid", pid_s) &&
                  extract_field(line, "syscall_nr", nr_s) &&
                  extract_field(line, "syscall_name", name_s);
        if (!ok) continue; // skip malformed/partial lines

        Violation v;
        v.ts = to_ll(ts_s);
        v.pid = to_ll(pid_s);
        v.syscall_nr = static_cast<int>(to_ll(nr_s));
        v.syscall_name = name_s;
        extract_field(line, "policy", policy_s);
        v.policy = policy_s;
        out.push_back(std::move(v));
    }
    return out;
}

Report analyze(const std::vector<Violation> &violations) {
    Report report;
    report.total_violations = static_cast<int>(violations.size());

    std::map<std::string, int> counts;
    std::map<long long, bool> pids;
    for (const auto &v : violations) {
        counts[v.syscall_name]++;
        pids[v.pid] = true;
    }
    report.distinct_syscalls = static_cast<int>(counts.size());
    report.distinct_pids = static_cast<int>(pids.size());

    for (const auto &kv : counts) {
        SyscallStat stat;
        stat.name = kv.first;
        stat.count = kv.second;
        stat.severity = classify(kv.first);
        report.top_syscalls.push_back(stat);
    }
    std::sort(report.top_syscalls.begin(), report.top_syscalls.end(),
              [](const SyscallStat &a, const SyscallStat &b) {
                  if (a.severity != b.severity) return a.severity > b.severity;
                  return a.count > b.count;
              });

    for (const auto &stat : report.top_syscalls) {
        if (stat.severity == Severity::High) {
            std::ostringstream note;
            note << "\"" << stat.name << "\" was attempted " << stat.count
                 << " time(s). This syscall is commonly associated with "
                    "privilege escalation, sandbox escape, or post-exploitation "
                    "activity -- investigate what triggered it even though the "
                    "sandbox already blocked it.";
            report.high_severity_findings.push_back(note.str());
        }
    }

    return report;
}

std::string render_markdown(const Report &report) {
    std::ostringstream md;
    md << "# Sentinel Violation Report\n\n";
    md << "- **Total blocked syscalls:** " << report.total_violations << "\n";
    md << "- **Distinct syscalls attempted:** " << report.distinct_syscalls << "\n";
    md << "- **Distinct processes involved:** " << report.distinct_pids << "\n\n";

    if (report.total_violations == 0) {
        md << "No violations recorded. Either the sandboxed program behaved "
              "exactly within policy, or it never ran long enough to be "
              "exercised -- try the `sentinel demo` attack suite to generate "
              "sample data.\n";
        return md.str();
    }

    md << "## Blocked syscalls by frequency\n\n";
    md << "| Syscall | Count | Severity |\n";
    md << "|---|---|---|\n";
    for (const auto &stat : report.top_syscalls) {
        md << "| `" << stat.name << "` | " << stat.count << " | "
           << severity_label(stat.severity) << " |\n";
    }
    md << "\n";

    if (!report.high_severity_findings.empty()) {
        md << "## High-severity findings\n\n";
        for (const auto &finding : report.high_severity_findings) {
            md << "- " << finding << "\n";
        }
        md << "\n";
    } else {
        md << "No high-severity syscalls (ptrace, execve, mount, ...) were "
              "attempted. The blocked calls were most likely just the "
              "target program legitimately needing a broader policy, not "
              "an attack.\n";
    }

    return md.str();
}

} // namespace sentinel

#ifndef SENTINEL_LOG_ANALYZER_NO_MAIN
int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <violations.jsonl> [output.md]\n";
        return 2;
    }

    auto violations = sentinel::load_violations(argv[1]);
    auto report = sentinel::analyze(violations);
    std::string markdown = sentinel::render_markdown(report);

    if (argc >= 3) {
        std::ofstream out(argv[2]);
        if (!out.is_open()) {
            std::cerr << "Could not open output file: " << argv[2] << "\n";
            return 1;
        }
        out << markdown;
        std::cerr << "Report written to " << argv[2] << "\n";
    } else {
        std::cout << markdown;
    }
    return 0;
}
#endif
