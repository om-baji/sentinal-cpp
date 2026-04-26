#include "loki.hpp"
#include "http.hpp"
#include <sstream>

LokiClient::LokiClient(const std::string& url) {
    endpoint = url;
}

std::string LokiClient::buildPayload(const std::vector<LokiLabel>& labels,
                                     const std::vector<LokiEntry>& entries) {
    std::ostringstream ss;
    ss << "{\"streams\":[{\"stream\":{";

    for (size_t i = 0; i < labels.size(); ++i) {
        ss << "\"" << labels[i].key << "\":\"" << labels[i].value << "\"";
        if (i != labels.size() - 1) ss << ",";
    }

    ss << "},\"values\":[";

    for (size_t i = 0; i < entries.size(); ++i) {
        ss << "[\"" << entries[i].ts << "\",\"" << entries[i].line << "\"]";
        if (i != entries.size() - 1) ss << ",";
    }

    ss << "]}]}";
    return ss.str();
}

void LokiClient::push(const std::vector<LokiLabel>& labels,
                      const std::vector<LokiEntry>& entries) {
    std::string payload = buildPayload(labels, entries);

    std::map<std::string,std::string> headers = {
        {"Content-Type", "application/json"}
    };

    HttpClient client;
    client.post(endpoint + "/loki/api/v1/push", payload, headers);
}

void LokiClient::pushLog(const std::map<std::string,std::string>& labels,
                         const std::string& line) {
    std::vector<LokiLabel> lbls;
    for (auto& [k,v] : labels) {
        lbls.push_back({k,v});
    }

    long long ts = std::time(nullptr) * 1000000000LL;

    std::vector<LokiEntry> entries = {
        {ts, line}
    };

    push(lbls, entries);
}
