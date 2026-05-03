CXX       := g++
CXXFLAGS  := -std=c++17 -Wall -O2

# Sources
CLI_SRC   := cli.cpp \
             encoder/filling.cpp \
             encoder/image.cpp \
             encoder/linear.cpp \
             utils/helpers.cpp \
             utils/http.cpp \
             utils/loki.cpp \
             utils/bpf_runner.cpp \
             utils/syscall_graph.cpp

LIBS      := -lcurl -lbcc -larchive

# Targets
all: cli.out

cli.out: $(CLI_SRC)
	$(CXX) $(CXXFLAGS) -I. $(CLI_SRC) $(LIBS) -o $@

http: utils/http.cpp
	$(CXX) $(CXXFLAGS) utils/http.cpp -lcurl -o http.out

clean:
	rm -f cli.out http.out

.PHONY: all http clean

test:
	sudo SENTINAL_BPF_PATH=./bpf/sys_call.c ./cli.out run --rm alpine sh -c "echo hello; sleep 2; ls /; whoami" 2>&1 | grep -v "prog tag mismatch\|WARNING: cannot get prog tag" && echo "=== GRAPH OUTPUT ===" && cat out/graphs/$$(ls -t out/graphs/ | head -1) | python3 -m json.tool

test-nginx:
	sudo SENTINAL_BPF_PATH=./bpf/sys_call.c ./cli.out run --rm --name myapp -p 8080:80 nginx:alpine

.PHONY: test test-nginx


build-suspicious:
	podman build -t sentinal/suspicious:latest ./malwares/suspicious/

test-suspicious: build-suspicious
	sudo SENTINAL_BPF_PATH=./bpf/sys_call.c ./cli.out run --rm sentinal/suspicious:latest 2>&1 \
	| grep -v "prog tag mismatch\|WARNING: cannot get prog tag" \
	&& echo "=== GRAPH OUTPUT ===" \
	&& cat out/graphs/$$(ls -t out/graphs/ | head -1) | python3 -m json.tool

.PHONY: build-suspicious test-suspicious
