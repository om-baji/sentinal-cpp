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
#include "utils/onxx_model.hpp"
#include "utils/bpf_runner.hpp"
#include "utils/syscall_graph.hpp"

using namespace std;

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
    const vector<string> labels = {"clean", "suspicious", "malicious"};
    if (best < labels.size()) return labels[best];
    return "class_" + to_string(best);
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
                          const string& graphDir) {
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

    auto graphSummary = graph.summary();
    LokiClient loki(loki_url);
    map<string, string> exit_labels = {
        {"app",             "sentinal"},
        {"runtime",         runtime},
        {"image",           image},
        {"phase",           "exit"},
        {"total_events",    graphSummary["total_events"]},
        {"total_processes", graphSummary["total_processes"]},
    };
    ostringstream exitLog;
    exitLog << "container_exited"
            << " image=" << image
            << " exit_code=" << exit_code
            << " nodes=" << graphSummary["total_events"]
            << " processes=" << graphSummary["total_processes"]
            << " edges=" << graphSummary["total_edges"]
            << " top=[" << graphSummary["top_syscalls"] << "]";
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
                } else {
                    cerr << "[sentinal] model not found at " << modelPath
                         << " — skipping inference (defaulting to clean)\n";
                    verdict = "clean";
                    scoreStr_s = "n/a";
                }

                cout << "[sentinal] verdict: " << verdict << "\n";

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
                       << " scores=[" << scoreStr_s << "]";
                loki.pushLog(preLabels, preLog.str());
                cout << "[sentinal] pre-run log pushed\n";

                if (verdict == "malicious") {
                    cerr << "[sentinal] BLOCKED: image flagged as malicious\n";
                    return 2;
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
                    runBpfMonitor(pid, bpfSrc, lokiUrl, runtime, image, verdict, graphDir);
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
