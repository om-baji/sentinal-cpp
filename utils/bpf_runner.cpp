#include "bpf_runner.hpp"
#include <stdexcept>

BpfRunner::BpfRunner(const std::string& program) {
  auto res = bpf_.init(program);
  if (res.code() != 0) {
    throw std::runtime_error(res.msg());
  }
}

void BpfRunner::set_callback(Callback cb) {
  callback_ = std::move(cb);
}

void BpfRunner::start() {
  struct Probe { std::string kernel_fn; std::string bpf_fn; };

  std::vector<Probe> probes = {
    {"__x64_sys_clone",   "trace_clone"},
    {"__x64_sys_execve",  "trace_execve"},
    {"do_exit",           "trace_exit"},
    {"__x64_sys_setuid",  "trace_setuid"},
    {"__x64_sys_setgid",  "trace_setgid"},
    {"__x64_sys_setns",   "trace_setns"},
    {"__x64_sys_unshare", "trace_unshare"},
    {"__x64_sys_ptrace",  "trace_ptrace"},
    {"__x64_sys_kill",    "trace_kill"},
    {"__x64_sys_mount",   "trace_mount"},
    {"__x64_sys_umount",  "trace_umount"},
    {"__x64_sys_chroot",  "trace_chroot"},
    {"__x64_sys_prctl",   "trace_prctl"},
    {"cap_capable",       "trace_cap_capable"},
  };

  for (const auto& p : probes) {
    auto res = bpf_.attach_kprobe(p.kernel_fn, p.bpf_fn);
    if (res.code() != 0) {
      throw std::runtime_error(res.msg());
    }
  }

  auto res = bpf_.open_perf_buffer("events", handle_event, nullptr, this);
  if (res.code() != 0) {
    throw std::runtime_error(res.msg());
  }
}

void BpfRunner::poll() {
  bpf_.poll_perf_buffer("events");
}

void BpfRunner::handle_event(void* cb_cookie, void* data, int) {
  auto* self = static_cast<BpfRunner*>(cb_cookie);
  if (!self->callback_) return;

  Event e{};
  __builtin_memcpy(&e, data, sizeof(Event));
  self->callback_(e);
}
