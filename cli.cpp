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
#include "encoder/filling.hpp"
#include "encoder/linear.hpp"
#include "utils/helpers.hpp"
#include "utils/loki.hpp"
#include "utils/http.hpp"
#include "utils/onxx_model.hpp"
#include "utils/gnn_model.hpp"
#include "utils/bpf_runner.hpp"
#include "utils/syscall_graph.hpp"

using namespace std;

static const string kBase64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static string base64Encode(const vector<uint8_t>& data) {
    string encoded;
    int val = 0;
    int bits = -6;
    const unsigned int mask = 0x3F;

    for (uint8_t c : data) {
        val = (val << 8) + c;
        bits += 8;
        while (bits >= 0) {
            encoded.push_back(kBase64Chars[(val >> bits) & mask]);
            bits -= 6;
        }
    }

    if (bits > -6) {
        encoded.push_back(kBase64Chars[((val << 8) >> (bits + 8)) & mask]);
    }
    while (encoded.size() % 4) encoded.push_back('=');
    return encoded;
}

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

static string verdictFromClass(int cls) {
    if (cls == 6) return "clean";
    return "malicious";
}

static bool tryRemotePredict(const string& imageDir, string& verdict, string& scoreStr) {
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

    string b64 = base64Encode(imgBytes);
    string jsonBody = "{\"image\":\"" + b64 + "\"}";

    try {
        HttpClient http;
        map<string, string> headers = {{"Content-Type", "application/json"}};
        HttpResponse resp = http.post("http://localhost:8000/predict", jsonBody, headers);

        if (resp.status != 200) return false;

        string body = resp.body;
        string numStr;
        for (char c : body) {
            if (c >= '0' && c <= '9') numStr += c;
        }

        if (numStr.empty()) return false;

        int cls = stoi(numStr);
        verdict = verdictFromClass(cls);
        scoreStr = classFromNumber(cls);
        return true;
    } catch (...) {
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

static string findImageArg(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "run") || !strcmp(argv[i], "build") || !strcmp(argv[i], "pull")) {
            for (int j = i + 1; j < argc; j++) {
                if (argv[j][0] != '-') return string(argv[j]);
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
    string cmd = runtime + " save " + image + " -o " + tarPath + " 2>&1";
    string out = execCommand(cmd);
    if (!out.empty()) cerr << out;
    return tarPath;
}

static string classifyResult(const vector<float>& scores) {
    if (scores.empty()) return "unknown";
    size_t best = 0;
    for (size_t i = 1; i < scores.size(); i++) {
        if (scores[i] > scores[best]) best = i;
    }
    return verdictFromClass(static_cast<int>(best));
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
                          const string& gnnModelPath) {
    BpfRunner runner(bpf_src);
    SyscallGraph graph;

    mutex batch_mu;
    vector<LokiEntry> batch;

    runner.set_callback([&](const Event& e) {
        graph.add_event(e);

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

        lock_guard<mutex> lk(batch_mu);
        batch.push_back({ts, line.str()});

        if (batch.size() >= 50) {
            LokiClient loki(loki_url);
            vector<LokiLabel> labels = {
                {"app",     "sentinal"},
                {"runtime", runtime},
                {"image",   image},
                {"phase",   "runtime"},
            };
            loki.push(labels, batch);
            batch.clear();
        }
    });

    runner.start();

    int status = 0;
    while (waitpid(container_pid, &status, WNOHANG) == 0) {
        runner.poll();
    }

    {
        lock_guard<mutex> lk(batch_mu);
        if (!batch.empty()) {
            LokiClient loki(loki_url);
            vector<LokiLabel> labels = {
                {"app",     "sentinal"},
                {"runtime", runtime},
                {"image",   image},
                {"phase",   "runtime"},
            };
            loki.push(labels, batch);
            batch.clear();
        }
    }

    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    string graphJson = graph.to_json(image, verdict, runtime, exit_code);
    saveGraph(graphDir, image, graphJson);

    string gnn_verdict = "unavailable";
    string gnn_score   = "n/a";

    [&]() noexcept {
        struct stat gnn_stat;
        if (gnnModelPath.empty() || stat(gnnModelPath.c_str(), &gnn_stat) != 0) {
            cerr << "[sentinal] gnn model not found at " << gnnModelPath << " — skipping\n";
            return;
        }
        try {
            GnnModel gnn(gnnModelPath);
            GnnInputs inputs = graph.to_gnn_inputs();
            vector<float> logits = gnn.forward(inputs);

            if (logits.size() >= 2) {
                gnn_verdict = (logits[1] > logits[0]) ? "malicious" : "clean";
                ostringstream ss;
                ss << "normal=" << logits[0] << " malicious=" << logits[1];
                gnn_score = ss.str();
            }
            cout << "[sentinal] gnn runtime verdict: " << gnn_verdict
                 << " | " << gnn_score << "\n";
        } catch (const exception& ex) {
            cerr << "[sentinal] gnn inference failed: " << ex.what()
                 << " — continuing without gnn verdict\n";
        } catch (...) {
            cerr << "[sentinal] gnn inference failed: unknown error"
                 << " — continuing without gnn verdict\n";
        }
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

        const char* modelPath = getenv("SENTINAL_MODEL_PATH");
        if (!modelPath) modelPath = "/etc/sentinal/model.onnx";

        const char* bpfPath   = getenv("SENTINAL_BPF_PATH");
        if (!bpfPath)   bpfPath   = "./bpf/sys_call.c";

        const char* graphDir  = getenv("SENTINAL_GRAPH_DIR");
        if (!graphDir)  graphDir  = "./out/graphs";

        const char* gnnModelPathEnv = getenv("SENTINAL_GNN_MODEL_PATH");
        string gnnModelPath = gnnModelPathEnv ? gnnModelPathEnv : "./models/syscall_gnn.onnx";

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

                execCommand(runtime + " pull " + image + " 2>&1");

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

                struct stat model_stat;
                if (stat(modelPath, &model_stat) == 0) {
                    cout << "[sentinal] running model...\n";
                    OnnxModel model(modelPath);
                    vector<int64_t> shape = {1, 1, 1024, 1024};
                    vector<float> scores = model.forward(shape);
                    verdict = classifyResult(scores);

                    ostringstream scoreStr;
                    for (size_t i = 0; i < scores.size(); i++) {
                        if (i) scoreStr << ",";
                        scoreStr << scores[i];
                    }
                    scoreStr_s = scoreStr.str();
                } else if (tryRemotePredict(imageDir, verdict, scoreStr_s)) {
                    cout << "[sentinal] remote prediction succeeded\n";
                } else {
                    cerr << "[sentinal] model not found at " << modelPath
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
                    runBpfMonitor(pid, bpfSrc, lokiUrl, runtime, image, verdict, graphDir, gnnModelPath);
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
