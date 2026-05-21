#include <cstring>
#include <exception>
#include <iostream>
#include <sstream>
#include <string>
#include <array>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <vector>
#include <map>
#include <fstream>
#include <mutex>
#include <ctime>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <thread>
#include "encoder/filling.hpp"
#include "encoder/linear.hpp"
#include "utils/helpers.hpp"
#include "utils/loki.hpp"
#include "utils/http.hpp"
#include "utils/bpf_runner.hpp"
#include "utils/syscall_graph.hpp"

using namespace std;

static string readFileBytes(const string& path, vector<uint8_t>& out) {
    ifstream f(path, ios::binary);
    if (!f) return "";
    out.assign(istreambuf_iterator<char>(f), {});
    return path;
}

static const vector<string> kMalwareClasses = {
    "Adialer.C", "Agent.FYI", "Allaple.A", "Allaple.L", "Alueron.gen!J",
    "Autorun.K", "Benign", "C2LOP.P", "C2LOP.gen!g", "Dialplatform.B",
    "Dontovo.A", "Fakerean", "Instantaccess", "Lolyda.AA1", "Lolyda.AA2",
    "Lolyda.AA3", "Lolyda.AT", "Malex.gen!J", "Obfuscator.AD", "Rbot!gen",
    "Skintrim.N", "Swizzor.gen!E", "Swizzor.gen!I", "VB.AT", "Wintrim.BX",
    "Yuner.A"
};

static string classFromNumber(int cls) {
    if (cls >= 0 && cls < (int)kMalwareClasses.size()) return kMalwareClasses[cls];
    return "class_" + to_string(cls);
}



static string trimCopy(const string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

static bool parseFirstIntAfterKey(const string& body, const string& key, int& value) {
    string needle = string("\"") + key + "\"";
    size_t keyPos = body.find(needle);
    if (keyPos == string::npos) return false;

    size_t openPos = body.find('[', keyPos);
    if (openPos == string::npos) return false;

    size_t firstDigit = body.find_first_of("-0123456789", openPos);
    if (firstDigit == string::npos) return false;

    size_t endPos = body.find_first_not_of("-0123456789", firstDigit);
    string number = body.substr(firstDigit, endPos - firstDigit);
    if (number.empty()) return false;

    value = stoi(number);
    return true;
}

static bool parseFirstFloatListAfterKey(const string& body, const string& key, vector<float>& values) {
    string needle = string("\"") + key + "\"";
    size_t keyPos = body.find(needle);
    if (keyPos == string::npos) return false;

    size_t firstOpen = body.find('[', keyPos);
    if (firstOpen == string::npos) return false;
    size_t secondOpen = body.find('[', firstOpen + 1);
    if (secondOpen == string::npos) return false;
    size_t closePos = body.find(']', secondOpen + 1);
    if (closePos == string::npos) return false;

    string payload = body.substr(secondOpen + 1, closePos - secondOpen - 1);
    stringstream ss(payload);
    string token;
    values.clear();
    while (getline(ss, token, ',')) {
        token = trimCopy(token);
        if (token.empty()) continue;
        values.push_back(stof(token));
    }

    return !values.empty();
}

static string buildCnnMultipartBody(const vector<uint8_t>& imageBytes,
                                    const string& filename,
                                    string& boundary) {
    boundary = "----sentinal-model-boundary";
    string body;
    body.reserve(imageBytes.size() + 256);
    body += "--" + boundary + "\r\n";
    body += "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n";
    body += "Content-Type: application/octet-stream\r\n\r\n";
    body.append(reinterpret_cast<const char*>(imageBytes.data()), imageBytes.size());
    body += "\r\n--" + boundary + "--\r\n";
    return body;
}

static string buildGnnRequestBody(const GnnInputs& inputs) {
    constexpr int kFeatDim = 20;
    size_t numNodes = inputs.num_nodes > 0 ? static_cast<size_t>(inputs.num_nodes) : 0;
    size_t numEdges = inputs.edge_index.size() / 2;

    ostringstream ss;
    ss << "{\"x\":[";
    for (size_t node = 0; node < numNodes; node++) {
        if (node) ss << ',';
        ss << '[';
        for (int feat = 0; feat < kFeatDim; feat++) {
            if (feat) ss << ',';
            ss << inputs.x[node * kFeatDim + feat];
        }
        ss << ']';
    }
    ss << "],\"edge_index\":[[";
    for (size_t edge = 0; edge < numEdges; edge++) {
        if (edge) ss << ',';
        ss << inputs.edge_index[edge];
    }
    ss << "],[";
    for (size_t edge = 0; edge < numEdges; edge++) {
        if (edge) ss << ',';
        ss << inputs.edge_index[numEdges + edge];
    }
    ss << "]],\"batch\":[";
    for (size_t node = 0; node < inputs.batch.size(); node++) {
        if (node) ss << ',';
        ss << inputs.batch[node];
    }
    ss << "]}";
    return ss.str();
}

static bool tryRemotePredict(const string& imageDir,
                             const string& apiBaseUrl,
                             string& verdict,
                             string& scoreStr) {
    string ppmPath;
    for (int i = 0; ; i++) {
        string candidate = imageDir + "/hilbert_" + to_string(i) + ".ppm";
        struct stat st;
        if (stat(candidate.c_str(), &st) == 0) {
            ppmPath = candidate;
            break;
        }
        if (i > 100) break;
    }

    if (ppmPath.empty()) {
        for (int i = 0; ; i++) {
            string candidate = imageDir + "/linear_" + to_string(i) + ".ppm";
            struct stat st;
            if (stat(candidate.c_str(), &st) == 0) {
                ppmPath = candidate;
                break;
            }
            if (i > 100) break;
        }
    }

    if (ppmPath.empty()) return false;

    vector<uint8_t> imgBytes;
    readFileBytes(ppmPath, imgBytes);
    if (imgBytes.empty()) return false;

    float confidenceThreshold = 0.70f;
    const char* threshEnv = getenv("SENTINAL_CONFIDENCE_THRESHOLD");
    if (threshEnv) {
        try { confidenceThreshold = stof(threshEnv); } catch (...) {}
    }

    try {
        HttpClient http;
        string boundary;
        string body = buildCnnMultipartBody(imgBytes, "image.ppm", boundary);
        map<string, string> headers = {{"Content-Type", "multipart/form-data; boundary=" + boundary}};
        HttpResponse resp = http.post(apiBaseUrl + "/predict/cnn", body, headers);

        if (resp.status != 200) return false;

        int cls = -1;
        if (!parseFirstIntAfterKey(resp.body, "preds", cls)) {
            return false;
        }

        vector<float> probs;
        float confidence = 0.0f;
        if (parseFirstFloatListAfterKey(resp.body, "probs", probs)) {
            if (cls >= 0 && cls < (int)probs.size()) {
                confidence = probs[cls];
            }
        }

        ostringstream ss;
        ss.precision(4);
        ss << fixed;

        if (cls == 6) {
            verdict = "clean";
            ss << "Benign (conf=" << confidence << ")";
        } else if (confidence < confidenceThreshold) {
            verdict = "clean";
            ss << classFromNumber(cls) << " (conf=" << confidence << ", below threshold " << confidenceThreshold << ")";
            cerr << "[sentinal] low confidence " << confidence
                 << " < " << confidenceThreshold
                 << " for class " << classFromNumber(cls)
                 << " — treating as clean\n";
        } else {
            verdict = "malicious";
            ss << classFromNumber(cls) << " (conf=" << confidence << ")";
        }

        scoreStr = ss.str();
        return true;
    } catch (...) {
        return false;
    }
}

static bool tryRemoteGnnPredict(const GnnInputs& inputs,
                                const string& apiBaseUrl,
                                string& verdict,
                                string& scoreStr) {
    float gnnThreshold = 0.60f;
    const char* gnnThreshEnv = getenv("SENTINAL_GNN_CONFIDENCE_THRESHOLD");
    if (gnnThreshEnv) {
        try { gnnThreshold = stof(gnnThreshEnv); } catch (...) {}
    }

    try {
        HttpClient http;
        map<string, string> headers = {{"Content-Type", "application/json"}};
        string body = buildGnnRequestBody(inputs);
        HttpResponse resp = http.post(apiBaseUrl + "/predict/gat", body, headers);

        if (resp.status != 200) {
            cerr << "[sentinal] gnn api returned status=" << resp.status << " body=" << resp.body << "\n";
            return false;
        }

        int cls = -1;
        if (!parseFirstIntAfterKey(resp.body, "preds", cls)) {
            cerr << "[sentinal] gnn api missing preds in body=" << resp.body << "\n";
            return false;
        }

        vector<float> probs;
        float malProb = 0.0f;
        float normProb = 0.0f;
        if (parseFirstFloatListAfterKey(resp.body, "probs", probs) && probs.size() >= 2) {
            malProb = probs[0];
            normProb = probs[1];
        }

        ostringstream ss;
        ss.precision(4);
        ss << fixed;
        ss << "malicious=" << malProb << " normal=" << normProb;

        if (cls == 0 && malProb >= gnnThreshold) {
            verdict = "malicious";
        } else if (cls == 0 && malProb < gnnThreshold) {
            verdict = "clean";
            cerr << "[sentinal] gnn low confidence " << malProb
                 << " < " << gnnThreshold
                 << " — treating as clean\n";
        } else {
            verdict = "clean";
        }

        scoreStr = ss.str();
        return true;
    } catch (...) {
        cerr << "[sentinal] gnn api request failed\n";
        return false;
    }
}

static const map<uint32_t, string> kEventNames = {
    {1,  "clone"},    {2,  "execve"},   {3,  "exit"},
    {4,  "setuid"},   {5,  "setgid"},   {6,  "setns"},
    {7,  "unshare"},  {8,  "ptrace"},   {9,  "kill"},
    {10, "mount"},    {11, "umount"},   {12, "chroot"},
    {13, "prctl"},    {14, "cap_capable"},
};

static string execCommand(const string& cmd) {
    array<char, 256> buffer;
    string result;
    using PipeCloser = int(*)(FILE*);
    unique_ptr<FILE, PipeCloser> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) throw runtime_error("popen failed");
    while (fgets(buffer.data(), buffer.size(), pipe.get())) result += buffer.data();
    return result;
}

static void showHelp() {
    cout << "[sentinal] Pre-Hook v0.1\n";
    cout << "Usage: sentinal <runtime-args...>\n";
    cout << "Wraps docker/podman with image analysis, eBPF monitoring, and graph export.\n";
}

static string buildArgv0Cmd(const string& runtime, int argc, char* argv[]) {
    ostringstream cmd;
    cmd << runtime;
    for (int i = 1; i < argc; i++) cmd << " " << argv[i];
    return cmd.str();
}

static bool flagTakesValue(const char* flag) {
    static const char* kFlags[] = {
        "--name", "-p", "--publish", "--volume", "-v", "--env", "-e",
        "--network", "--net", "--hostname", "-h", "--user", "-u",
        "--workdir", "-w", "--entrypoint", "--label", "-l",
        "--mount", "--cpus", "--memory", "-m", "--restart",
        "--log-driver", "--log-opt", "--pid", "--ipc",
        "--expose", "--add-host", "--dns", "--dns-search",
        "--device", "--cap-add", "--cap-drop", "--security-opt",
        "--ulimit", "--cgroupns", "--userns", "--pull",
        "--platform", "--shm-size", "--stop-signal", "--stop-timeout",
        "--tmpfs", "--sysctl", "-f", "--file", "--tag", "-t",
        "--build-arg", "--target", "--output", "-o",
        nullptr
    };
    for (const char** p = kFlags; *p; ++p) {
        if (!strcmp(flag, *p)) return true;
    }
    return false;
}

static string findImageArg(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "run") || !strcmp(argv[i], "build") || !strcmp(argv[i], "pull")) {
            for (int j = i + 1; j < argc; j++) {
                string arg = argv[j];
                if (arg[0] == '-') {
                    if (arg.find('=') != string::npos) continue;
                    if (flagTakesValue(argv[j]) && j + 1 < argc) {
                        j++;
                    }
                    continue;
                }
                return arg;
            }
        }
    }
    return "";
}

static string saveImageAsTarball(const string& runtime, const string& image) {
    string tarPath = "/tmp/sentinal_" + image;
    for (char& c : tarPath) {
        if (c == '/' || c == ':') c = '_';
    }
    tarPath += ".tar";
    unlink(tarPath.c_str());
    string cmd = runtime + " save " + image + " -o " + tarPath + " 2>&1";
    string out = execCommand(cmd);
    if (!out.empty()) cerr << out;
    return tarPath;
}

static string loadBpfProgram(const string& path) {
    ifstream f(path);
    if (!f) throw runtime_error("cannot open bpf program: " + path);
    return string(istreambuf_iterator<char>(f), {});
}

static string sanitize(const string& s) {
    string out = s;
    for (char& c : out) {
        if (c == '/' || c == ':' || c == ' ') c = '_';
    }
    return out;
}

static void saveGraph(const string& graphDir,
                      const string& image,
                      const string& json) {
    mkdir(graphDir.c_str(), 0755);
    string filename = graphDir + "/" + sanitize(image) + "_"
                      + to_string(time(nullptr)) + ".json";
    ofstream f(filename);
    if (!f) {
        cerr << "[sentinal] failed to write graph: " << filename << "\n";
        return;
    }
    f << json;
    f.close();
    cout << "[sentinal] graph saved: " << filename << "\n";
}

static void runBpfMonitor(pid_t container_pid,
                          const string& bpf_src,
                          const string& loki_url,
                          const string& runtime,
                          const string& image,
                          const string& verdict,
                          const string& graphDir,
                          const string& apiBaseUrl) {
    BpfRunner runner(bpf_src);
    SyscallGraph graph;

    mutex batch_mu;
    vector<LokiEntry> batch;
    time_t last_flush = time(nullptr);
    time_t last_gnn = time(nullptr);

    const char* flushIntervalEnv = getenv("SENTINAL_FLUSH_INTERVAL");
    int flush_interval = 30;
    if (flushIntervalEnv) {
        try { flush_interval = stoi(flushIntervalEnv); } catch (...) { flush_interval = 30; }
    }

    const char* gnnIntervalEnv = getenv("SENTINAL_GNN_INTERVAL");
    int gnn_interval = 30;
    if (gnnIntervalEnv) {
        try { gnn_interval = stoi(gnnIntervalEnv); } catch (...) { gnn_interval = 30; }
    }

    auto flush_logs = [&]() {
        vector<LokiEntry> batch_copy;
        {
            lock_guard<mutex> lk(batch_mu);
            if (batch.empty()) return;
            batch_copy = batch;
            batch.clear();
        }

        LokiClient loki(loki_url);
        vector<LokiLabel> labels = {
            {"app",     "sentinal"},
            {"runtime", runtime},
            {"image",   image},
            {"phase",   "runtime"},
        };
        loki.push(labels, batch_copy);
        last_flush = (long long)time(nullptr);
    };

    auto run_gnn = [&]() {
        GnnInputs inputs;
        long long ts = (long long)time(nullptr);
        {
            lock_guard<mutex> lk(batch_mu);
            inputs = graph.to_gnn_inputs();
        }
        if (inputs.num_nodes == 0) return;

        cout << "[sentinal] gnn check ts=" << ts << " nodes=" << inputs.num_nodes << "\n";

        thread([inputs, apiBaseUrl, loki_url, runtime, image, ts]() mutable {
            string v,s;
            if (tryRemoteGnnPredict(inputs, apiBaseUrl, v, s)) {
                cout << "[sentinal] gnn verdict=" << v << " score=[" << s << "]\n";
                LokiClient loki2(loki_url);
                map<string,string> gnn_labels = {
                    {"app", "sentinal"},
                    {"runtime", runtime},
                    {"image", image},
                    {"phase", "runtime-gnn"},
                    {"ts", to_string(ts)},
                };
                ostringstream gnn_line;
                gnn_line << "runtime_gnn_verdict=" << v
                         << " runtime_gnn_score=[" << s << "]";
                loki2.pushLog(gnn_labels, gnn_line.str());
            }
        }).detach();

        last_gnn = ts;
    };

    runner.set_callback([&](const Event& e) {
        string name = "unknown";
        auto it = kEventNames.find(e.type);
        if (it != kEventNames.end()) name = it->second;

        long long ts = (long long)time(nullptr) * 1000000000LL;

        ostringstream line;
        line << "syscall=" << name
             << " pid=" << e.pid
             << " ppid=" << e.ppid
             << " uid=" << e.uid
             << " gid=" << e.gid
             << " comm=" << e.comm
             << " arg1=" << e.arg1
             << " arg2=" << e.arg2;

        bool should_flush = false;
        {
            lock_guard<mutex> lk(batch_mu);
            graph.add_event(e);
            batch.push_back({ts, line.str()});
            should_flush = (batch.size() >= 50);
        }

        if (should_flush) {
            flush_logs();
        }
    });

    runner.start();

    int status = 0;
    while (waitpid(container_pid, &status, WNOHANG) == 0) {
        runner.poll();
        time_t now = time(nullptr);
        if (difftime(now, last_flush) >= flush_interval) {
            flush_logs();
        }
        if (difftime(now, last_gnn) >= gnn_interval) {
            run_gnn();
        }
        this_thread::sleep_for(chrono::milliseconds(100));
    }

    flush_logs();
    run_gnn();

    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    string graphJson = graph.to_json(image, verdict, runtime, exit_code);
    saveGraph(graphDir, image, graphJson);

    string gnn_verdict = "unavailable";
    string gnn_score   = "n/a";

    [&]() noexcept {
        GnnInputs inputs = graph.to_gnn_inputs();
        if (inputs.num_nodes == 0) {
            cerr << "[sentinal] gnn skipped: empty graph\n";
            return;
        }
        if (!tryRemoteGnnPredict(inputs, apiBaseUrl, gnn_verdict, gnn_score)) {
            cerr << "[sentinal] gnn inference failed: remote api unavailable"
                 << " — continuing without gnn verdict\n";
            return;
        }
        cout << "[sentinal] gnn runtime verdict: " << gnn_verdict
             << " | " << gnn_score << "\n";
    }();

    auto graphSummary = graph.summary();
    LokiClient loki(loki_url);
    map<string, string> exit_labels = {
        {"app",             "sentinal"},
        {"runtime",         runtime},
        {"image",           image},
        {"phase",           "exit"},
        {"total_events",    graphSummary["total_events"]},
        {"total_processes", graphSummary["total_processes"]},
        {"gnn_verdict",     gnn_verdict},
    };
    ostringstream exitLog;
    exitLog << "container_exited"
            << " image="    << image
            << " exit_code="<< exit_code
            << " nodes="    << graphSummary["total_events"]
            << " processes="<< graphSummary["total_processes"]
            << " edges="    << graphSummary["total_edges"]
            << " top=["     << graphSummary["top_syscalls"] << "]"
            << " gnn_verdict=" << gnn_verdict
            << " gnn_score=["  << gnn_score << "]";
    loki.pushLog(exit_labels, exitLog.str());
}

int main(int argc, char* argv[]) {
    try {
        if (argc == 1) {
            showHelp();
            return 0;
        }

        Helpers helpers;
        string runtime = helpers.get_runtime();
        if (runtime.empty()) throw runtime_error("Docker/Podman environment not found!");

        const char* lokiUrl   = getenv("SENTINAL_LOKI_URL");
        if (!lokiUrl)   lokiUrl   = "http://localhost:3100";

        const char* modelApiUrl = getenv("SENTINAL_MODEL_API_URL");
        if (!modelApiUrl) modelApiUrl = "http://localhost:8000";

        const char* bpfPath   = getenv("SENTINAL_BPF_PATH");
        if (!bpfPath)   bpfPath   = "./bpf/sys_call.c";

        const char* graphDir  = getenv("SENTINAL_GRAPH_DIR");
        if (!graphDir)  graphDir  = "./out/graphs";

        string subcommand;
        for (int i = 1; i < argc; i++) {
            if (!strcmp(argv[i], "run") || !strcmp(argv[i], "build") || !strcmp(argv[i], "pull")) {
                subcommand = argv[i];
                break;
            }
        }

        if (subcommand == "run" || subcommand == "pull") {
            string image = findImageArg(argc, argv);

            if (!image.empty()) {
                cout << "[sentinal] image: " << image << "\n";

                string inspectOut = execCommand(runtime + " image inspect " + image + " > /dev/null 2>&1 && echo exists");
                if (trimCopy(inspectOut) != "exists") {
                    cout << "[sentinal] pulling image...\n";
                    execCommand(runtime + " pull " + image + " 2>&1");
                }

                cout << "[sentinal] saving tarball...\n";
                string tarPath = saveImageAsTarball(runtime, image);

                string imageDir = "./out/images";
                mkdir(imageDir.c_str(), 0755);

                cout << "[sentinal] encoding (linear)...\n";
                LinearEncoder le;
                le.build_image(tarPath, imageDir);

                cout << "[sentinal] encoding (hilbert)...\n";
                SpaceFillingEncoder sfe;
                sfe.build_image(tarPath, imageDir);

                string verdict;
                string scoreStr_s;

                cout << "[sentinal] running model...\n";
                if (tryRemotePredict(imageDir, modelApiUrl, verdict, scoreStr_s)) {
                    cout << "[sentinal] remote prediction succeeded\n";
                } else {
                    cerr << "[sentinal] inference api unavailable at " << modelApiUrl
                         << " — skipping inference (defaulting to clean)\n";
                    verdict = "clean";
                    scoreStr_s = "n/a";
                }

                cout << "[sentinal] verdict: " << verdict
                     << " | detected class: " << scoreStr_s << "\n";

                LokiClient loki(lokiUrl);
                map<string, string> preLabels = {
                    {"app",     "sentinal"},
                    {"runtime", runtime},
                    {"image",   image},
                    {"phase",   "pre-run"},
                    {"verdict", verdict},
                };
                ostringstream preLog;
                preLog << "image=" << image
                       << " verdict=" << verdict
                       << " class=" << scoreStr_s;
                loki.pushLog(preLabels, preLog.str());
                cout << "[sentinal] pre-run log pushed\n";

                if (verdict == "malicious") {
                    cerr << "[sentinal] WARNING: image classified as malicious ("
                         << scoreStr_s << ")\n";
                    cerr << "[sentinal] proceed anyway? [y/N]: ";
                    string answer;
                    getline(cin, answer);
                    if (answer.empty() || (answer[0] != 'y' && answer[0] != 'Y')) {
                        cerr << "[sentinal] ABORTED by user\n";
                        return 2;
                    }
                    cerr << "[sentinal] continuing at user request\n";
                }

                if (subcommand == "run") {
                    string fullCmd = buildArgv0Cmd(runtime, argc, argv);

                    pid_t pid = fork();
                    if (pid < 0) throw runtime_error("fork failed");

                    if (pid == 0) {
                        execl("/bin/sh", "sh", "-c", fullCmd.c_str(), nullptr);
                        _exit(127);
                    }

                    cout << "[sentinal] container pid=" << pid << " — eBPF monitor active\n";

                    string bpfSrc = loadBpfProgram(bpfPath);
                    runBpfMonitor(pid, bpfSrc, lokiUrl, runtime, image, verdict, graphDir, modelApiUrl);
                    return 0;
                }
            }
        }

        string fullCmd = buildArgv0Cmd(runtime, argc, argv);
        cout << "[sentinal] forwarding: " << fullCmd << "\n";
        return system(fullCmd.c_str());

    } catch (const exception& e) {
        cerr << "[sentinal] error: " << e.what() << "\n";
        return 1;
    }
}
