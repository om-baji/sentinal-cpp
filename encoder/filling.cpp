#include "filling.hpp"
#include <archive.h>
#include <archive_entry.h>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstdint>

SpaceFillingEncoder::SpaceFillingEncoder() = default;

std::pair<int, int> SpaceFillingEncoder::hilbert_d2xy(int n, int d) {
    int x = 0, y = 0;
    for (int s = 1; s < n; s <<= 1) {
        int rx = (d >> 1) & 1;
        int ry = (d ^ rx) & 1;
        if (!ry) {
            if (rx) {
                x = s - 1 - x;
                y = s - 1 - y;
            }
            std::swap(x, y);
        }
        x += s * rx;
        y += s * ry;
        d >>= 2;
    }
    return {x, y};
}

std::vector<std::string> SpaceFillingEncoder::list_files(const std::string& path) {
    std::vector<std::string> files;

    archive* a = archive_read_new();
    archive_read_support_format_tar(a);
    archive_read_support_filter_all(a);
    archive_read_open_filename(a, path.c_str(), 10240);

    archive_entry* entry;

    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        std::string name = archive_entry_pathname(entry);
        if (archive_entry_filetype(entry) == AE_IFREG) {
            std::string lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            if (lower.find("json") == std::string::npos &&
                lower.find("manifest") == std::string::npos &&
                lower.find("repositories") == std::string::npos &&
                lower.find("version") == std::string::npos) {
                files.push_back(name);
            }
        }
        archive_read_data_skip(a);
    }

    archive_read_free(a);
    return files;
}

std::vector<uint8_t> SpaceFillingEncoder::extract(const std::string& path, const std::string& target) {
    archive* a = archive_read_new();
    archive_read_support_format_tar(a);
    archive_read_support_filter_all(a);
    archive_read_open_filename(a, path.c_str(), 10240);

    archive_entry* entry;

    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        std::string name = archive_entry_pathname(entry);

        if (name == target) {
            size_t size = archive_entry_size(entry);
            std::vector<uint8_t> buffer(size);
            archive_read_data(a, buffer.data(), size);
            archive_read_free(a);
            return buffer;
        }

        archive_read_data_skip(a);
    }

    archive_read_free(a);
    return {};
}

void SpaceFillingEncoder::build_image(const std::string& tar_path, const std::string& output_dir) {
    auto files = list_files(tar_path);

    int order = 10;
    int n = 1 << order;
    int width = n;
    int height = n;
    size_t total = static_cast<size_t>(width) * height;

    std::vector<std::pair<int, int>> curve(total);
    for (size_t d = 0; d < total; d++) {
        curve[d] = hilbert_d2xy(n, static_cast<int>(d));
    }

    for (size_t i = 0; i < files.size(); i++) {
        std::vector<uint8_t> bytes = extract(tar_path, files[i]);
        if (bytes.empty()) continue;

        if (bytes.size() < total) {
            bytes.resize(total, 0);
        } else {
            bytes.resize(total);
        }

        std::vector<uint8_t> canvas(total * 3, 0);

        for (size_t d = 0; d < total; d++) {
            auto [x, y] = curve[d];
            size_t pixel = static_cast<size_t>(y) * width + x;
            uint8_t v = bytes[d];
            canvas[pixel * 3 + 0] = v;
            canvas[pixel * 3 + 1] = v;
            canvas[pixel * 3 + 2] = v;
        }

        std::string filename = output_dir + "/hilbert_" + std::to_string(i) + ".ppm";
        std::ofstream out(filename, std::ios::binary);

        out << "P6\n" << width << " " << height << "\n255\n";
        out.write(reinterpret_cast<char*>(canvas.data()), canvas.size());

        out.close();
    }
}
