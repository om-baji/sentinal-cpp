#pragma once
#include <onnxruntime_cxx_api.h>
#include <vector>
#include <string>

class OnnxModel {
public:
    explicit OnnxModel(const std::string& path);
    std::vector<float> forward(const std::vector<int64_t>& shape);

private:
    Ort::Env env;
    Ort::Session session;
};
