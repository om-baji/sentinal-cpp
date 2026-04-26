#pragma once
#include <string>
#include <vector>
#include <cstdint>

class LinearEncoder {
public:
    LinearEncoder();
    void build_image(const std::string& tar_path, const std::string& output_dir = ".");

private:
    std::vector<uint8_t> extract(const std::string& path, const std::string& name);
    std::vector<std::string> list_files(const std::string& path);
};
