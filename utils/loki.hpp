#pragma once
#include <string>
#include <vector>
#include <map>
#include <ctime>

struct LokiLabel {
    std::string key;
    std::string value;
};

struct LokiEntry {
    long long ts;
    std::string line;
};

class LokiClient {
public:
    LokiClient(const std::string& url);

    void push(const std::vector<LokiLabel>& labels,
              const std::vector<LokiEntry>& entries);

    void pushLog(const std::map<std::string,std::string>& labels,
                 const std::string& line);

private:
    std::string endpoint;

    std::string buildPayload(const std::vector<LokiLabel>& labels,
                             const std::vector<LokiEntry>& entries);
};
