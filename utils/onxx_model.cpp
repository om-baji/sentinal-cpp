#include "onxx_model.hpp"

OnnxModel::OnnxModel(const std::string& path)
    : env(ORT_LOGGING_LEVEL_WARNING, "onnx"),
      session(env, path.c_str(), Ort::SessionOptions{}) {}

std::vector<float> OnnxModel::forward(const std::vector<int64_t>& shape) {
    size_t total = 1;
    for (auto s : shape) total *= s;

    std::vector<float> input(total);

    Ort::MemoryInfo memory_info = Ort::MemoryInfo::CreateCpu(
        OrtArenaAllocator, OrtMemTypeDefault
    );

    Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
        memory_info,
        input.data(),
        input.size(),
        shape.data(),
        shape.size()
    );

    const char* input_names[] = {"input"};
    const char* output_names[] = {"output"};

    auto outputs = session.Run(
        Ort::RunOptions{nullptr},
        input_names,
        &input_tensor,
        1,
        output_names,
        1
    );

    float* out = outputs[0].GetTensorMutableData<float>();
    size_t out_size = outputs[0].GetTensorTypeAndShapeInfo().GetElementCount();

    return std::vector<float>(out, out + out_size);
}
