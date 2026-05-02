#include "gnn_model.hpp"
#include <stdexcept>

GnnModel::GnnModel(const std::string& path)
    : env_(ORT_LOGGING_LEVEL_WARNING, "gnn"),
      session_(env_, path.c_str(), Ort::SessionOptions{}) {}

std::vector<float> GnnModel::forward(const GnnInputs& inputs) {
    if (inputs.num_nodes == 0)
        return {0.0f, 0.0f};

    Ort::MemoryInfo mem = Ort::MemoryInfo::CreateCpu(
        OrtArenaAllocator, OrtMemTypeDefault
    );

    std::vector<int64_t> x_shape         = {inputs.num_nodes, 20};
    std::vector<int64_t> edge_index_shape = {2, inputs.num_edges};
    std::vector<int64_t> batch_shape      = {inputs.num_nodes};

    Ort::Value x_tensor = Ort::Value::CreateTensor<float>(
        mem,
        const_cast<float*>(inputs.x.data()),
        inputs.x.size(),
        x_shape.data(), x_shape.size()
    );

    Ort::Value edge_tensor = Ort::Value::CreateTensor<int64_t>(
        mem,
        const_cast<int64_t*>(inputs.edge_index.data()),
        inputs.edge_index.size(),
        edge_index_shape.data(), edge_index_shape.size()
    );

    Ort::Value batch_tensor = Ort::Value::CreateTensor<int64_t>(
        mem,
        const_cast<int64_t*>(inputs.batch.data()),
        inputs.batch.size(),
        batch_shape.data(), batch_shape.size()
    );

    const char* input_names[]  = {"x", "edge_index", "batch"};
    const char* output_names[] = {"linear_7"};

    Ort::Value input_tensors[] = {
        std::move(x_tensor),
        std::move(edge_tensor),
        std::move(batch_tensor)
    };

    auto outputs = session_.Run(
        Ort::RunOptions{nullptr},
        input_names,   input_tensors, 3,
        output_names,  1
    );

    float* out     = outputs[0].GetTensorMutableData<float>();
    size_t out_len = outputs[0].GetTensorTypeAndShapeInfo().GetElementCount();

    return std::vector<float>(out, out + out_len);
}
