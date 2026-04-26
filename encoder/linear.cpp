#include "linear.hpp"
#include <archive.h>
#include <archive_entry.h>
#include <vector>
#include <string>
#include <fstream>
#include <algorithm>

LinearEncoder::LinearEncoder() = default;

std::vector<std::string> LinearEncoder::list_files(const std::string& path) {
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

std::vector<uint8_t> LinearEncoder::extract(const std::string& path, const std::string& target) {
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

void LinearEncoder::build_image(const std::string& tar_path, const std::string& output_dir) {
    auto files = list_files(tar_path);

    int width = 1024;
    int height = 512;
    size_t total = width * height;

    for (size_t i = 0; i < files.size(); i++) {
        std::vector<uint8_t> bytes = extract(tar_path, files[i]);
        if (bytes.empty()) continue;

        if (bytes.size() < total) {
            bytes.resize(total, 0);
        } else {
            bytes.resize(total);
        }

        std::string filename = output_dir + "/linear_" + std::to_string(i) + ".ppm";
        std::ofstream out(filename, std::ios::binary);

        out << "P6\n" << width << " " << height << "\n255\n";

        for (size_t j = 0; j < total; j++) {
            uint8_t v = bytes[j];
            out.write(reinterpret_cast<char*>(&v), 1);
            out.write(reinterpret_cast<char*>(&v), 1);
            out.write(reinterpret_cast<char*>(&v), 1);
        }

        out.close();
    }
}
