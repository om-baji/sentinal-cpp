#pragma once

#include <bcc/BPF.h>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct Event {
  uint32_t pid;
  uint32_t ppid;
  uint32_t uid;
  uint32_t gid;
  uint32_t type;
  uint32_t arg1;
  uint32_t arg2;
  char comm[16];
};

class BpfRunner {
public:
  using Callback = std::function<void(const Event&)>;

  explicit BpfRunner(const std::string& program);
  void set_callback(Callback cb);
  void start();
  void poll();

private:
  ebpf::BPF bpf_;
  Callback callback_;

  static void handle_event(void* cb_cookie, void* data, int data_size);
};
