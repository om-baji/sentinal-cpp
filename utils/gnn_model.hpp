#pragma once
#include <onnxruntime_cxx_api.h>
#include <cstdint>
#include <string>
#include <vector>

struct GnnInputs {
    std::vector<float>   x;
    std::vector<int64_t> edge_index;
    std::vector<int64_t> batch;
    int64_t              num_nodes;
    int64_t              num_edges;
};

class GnnModel {
public:
    explicit GnnModel(const std::string& path);

    std::vector<float> forward(const GnnInputs& inputs);

private:
    Ort::Env     env_;
    Ort::Session session_;
};
