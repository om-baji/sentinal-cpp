#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include "bpf_runner.hpp"

struct GnnInputs {
    std::vector<float>   x;
    std::vector<int64_t> edge_index;
    std::vector<int64_t> batch;
    int64_t              num_nodes;
    int64_t              num_edges;
};

struct ProcessNode {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    std::string comm;
};

struct EventNode {
    uint32_t seq;
    uint32_t type;
    uint32_t arg1;
    uint32_t arg2;
    uint32_t pid;
    std::string name;
};

struct GraphEdge {
    std::string src;
    std::string dst;
    std::string relation;
};

class SyscallGraph {
public:
    SyscallGraph();

    void add_event(const Event& e);

    std::string to_json(const std::string& image,
                        const std::string& verdict,
                        const std::string& runtime,
                        int exit_code) const;

    std::map<std::string, std::string> summary() const;

    GnnInputs to_gnn_inputs() const;

private:
    std::unordered_map<uint32_t, ProcessNode> processes_;
    std::vector<EventNode> events_;
    std::vector<GraphEdge> edges_;
    std::unordered_map<uint32_t, uint32_t> last_event_by_pid_;
    uint32_t seq_;

    static std::string proc_id(uint32_t pid);
    static std::string event_id(uint32_t seq);
    static std::string escape_json(const std::string& s);
};
