#pragma once
#include <string>
#include <vector>
#include <cstdint>

class SpaceFillingEncoder {
public:
    SpaceFillingEncoder();
    void build_image(const std::string& tar_path, const std::string& output_dir = ".");

private:
    std::vector<uint8_t> extract(const std::string& path, const std::string& name);
    std::vector<std::string> list_files(const std::string& path);
    std::pair<int, int> hilbert_d2xy(int n, int d);
};
