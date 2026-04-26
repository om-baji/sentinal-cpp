#pragma once
#include <torch/script.h>
#include <vector>
#include <string>

class TorchModel {
public:
    explicit TorchModel(const std::string& path);
    at::Tensor forward(const std::vector<int64_t>& shape);

private:
    torch::jit::script::Module model;
};
