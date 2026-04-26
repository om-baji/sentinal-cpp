#include "torch_model.hpp"

TorchModel::TorchModel(const std::string& path) {
    model = torch::jit::load(path);
}

at::Tensor TorchModel::forward(const std::vector<int64_t>& shape) {
    std::vector<torch::jit::IValue> inputs;
    inputs.push_back(torch::rand(shape));
    return model.forward(inputs).toTensor();
}
