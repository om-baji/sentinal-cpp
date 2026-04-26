#include "syscall_graph.hpp"
#include <sstream>
#include <algorithm>

static const std::unordered_map<uint32_t, std::string> kTypeNames = {
    {1,  "clone"},
    {2,  "execve"},
    {3,  "exit"},
    {4,  "setuid"},
    {5,  "setgid"},
    {6,  "setns"},
    {7,  "unshare"},
    {8,  "ptrace"},
    {9,  "kill"},
    {10, "mount"},
    {11, "umount"},
    {12, "chroot"},
    {13, "prctl"},
    {14, "cap_capable"},
};

SyscallGraph::SyscallGraph() : seq_(0) {}

std::string SyscallGraph::proc_id(uint32_t pid) {
    return "proc_" + std::to_string(pid);
}

std::string SyscallGraph::event_id(uint32_t seq) {
    return "ev_" + std::to_string(seq);
}

std::string SyscallGraph::escape_json(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

void SyscallGraph::add_event(const Event& e) {
    if (processes_.find(e.pid) == processes_.end()) {
        ProcessNode pn;
        pn.pid  = e.pid;
        pn.ppid = e.ppid;
        pn.uid  = e.uid;
        pn.gid  = e.gid;
        pn.comm = std::string(e.comm, strnlen(e.comm, 16));
        processes_[e.pid] = pn;

        if (e.ppid != 0 && processes_.find(e.ppid) != processes_.end()) {
            edges_.push_back({proc_id(e.ppid), proc_id(e.pid), "spawns"});
        }
    }

    std::string name = "unknown";
    auto it = kTypeNames.find(e.type);
    if (it != kTypeNames.end()) name = it->second;

    uint32_t s = seq_++;
    EventNode en;
    en.seq  = s;
    en.type = e.type;
    en.arg1 = e.arg1;
    en.arg2 = e.arg2;
    en.pid  = e.pid;
    en.name = name;
    events_.push_back(en);

    edges_.push_back({proc_id(e.pid), event_id(s), "invokes"});

    auto prev = last_event_by_pid_.find(e.pid);
    if (prev != last_event_by_pid_.end()) {
        edges_.push_back({event_id(prev->second), event_id(s), "sequences"});
    } 
    last_event_by_pid_[e.pid] = s;
}

std::string SyscallGraph::to_json(const std::string& image,
                                   const std::string& verdict,
                                   const std::string& runtime,
                                   int exit_code) const {
    std::ostringstream ss;

    ss << "{\n";
    ss << "  \"graph\": {\n";
    ss << "    \"image\": \"" << escape_json(image) << "\",\n";
    ss << "    \"verdict\": \"" << escape_json(verdict) << "\",\n";
    ss << "    \"runtime\": \"" << escape_json(runtime) << "\",\n";
    ss << "    \"container_exit_code\": " << exit_code << ",\n";
    ss << "    \"total_events\": " << events_.size() << ",\n";
    ss << "    \"total_processes\": " << processes_.size() << ",\n";
    ss << "    \"total_edges\": " << edges_.size() << "\n";
    ss << "  },\n";

    ss << "  \"nodes\": [\n";
    bool first = true;
    for (auto& [pid, p] : processes_) {
        if (!first) ss << ",\n";
        first = false;
        ss << "    {\"id\": \"" << proc_id(pid) << "\", "
           << "\"node_type\": \"process\", "
           << "\"comm\": \"" << escape_json(p.comm) << "\", "
           << "\"pid\": " << p.pid << ", "
           << "\"ppid\": " << p.ppid << ", "
           << "\"uid\": " << p.uid << ", "
           << "\"gid\": " << p.gid << "}";
    }
    for (auto& ev : events_) {
        if (!first) ss << ",\n";
        first = false;
        ss << "    {\"id\": \"" << event_id(ev.seq) << "\", "
           << "\"node_type\": \"syscall\", "
           << "\"name\": \"" << escape_json(ev.name) << "\", "
           << "\"type\": " << ev.type << ", "
           << "\"arg1\": " << ev.arg1 << ", "
           << "\"arg2\": " << ev.arg2 << ", "
           << "\"pid\": " << ev.pid << "}";
    }
    ss << "\n  ],\n";

    ss << "  \"links\": [\n";
    first = true;
    for (auto& edge : edges_) {
        if (!first) ss << ",\n";
        first = false;
        ss << "    {\"source\": \"" << edge.src << "\", "
           << "\"target\": \"" << edge.dst << "\", "
           << "\"relation\": \"" << edge.relation << "\"}";
    }
    ss << "\n  ]\n";

    ss << "}\n";
    return ss.str();
}

std::map<std::string, std::string> SyscallGraph::summary() const {
    std::map<std::string, uint32_t> counts;
    for (auto& ev : events_) {
        counts[ev.name]++;
    }

    std::vector<std::pair<uint32_t, std::string>> sorted;
    for (auto& [name, count] : counts) {
        sorted.push_back({count, name});
    }
    std::sort(sorted.rbegin(), sorted.rend());

    std::ostringstream top;
    for (size_t i = 0; i < sorted.size() && i < 5; i++) {
        if (i) top << " ";
        top << sorted[i].second << "=" << sorted[i].first;
    }

    return {
        {"total_events",    std::to_string(events_.size())},
        {"total_processes", std::to_string(processes_.size())},
        {"total_edges",     std::to_string(edges_.size())},
        {"top_syscalls",    top.str()},
    };
}
