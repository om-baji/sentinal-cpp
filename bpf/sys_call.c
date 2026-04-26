#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <bcc/proto.h>

struct data_t {
  u32 pid;
  u32 ppid;
  u32 uid;
  u32 gid;
  u32 type;
  u32 arg1;
  u32 arg2;
  char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

static __always_inline void fill_data(struct data_t *data) {
  struct task_struct *task;
  u64 id, ugid;

  task = (struct task_struct*)bpf_get_current_task();

  id = bpf_get_current_pid_tgid();
  data->pid = id >> 32;

  ugid = bpf_get_current_uid_gid();
  data->uid = ugid & 0xFFFFFFFF;
  data->gid = ugid >> 32;

  bpf_probe_read_kernel(&data->ppid, sizeof(data->ppid), &task->real_parent->tgid);
  bpf_get_current_comm(&data->comm, sizeof(data->comm));
}

int trace_clone(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 1;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_execve(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 2;
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_exit(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 3;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_setuid(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 4;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_setgid(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 5;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_setns(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 6;
  data.arg1 = (u32)PT_REGS_PARM2(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_unshare(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 7;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_ptrace(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 8;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  data.arg2 = (u32)PT_REGS_PARM2(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_kill(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 9;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  data.arg2 = (u32)PT_REGS_PARM2(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_mount(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 10;
  data.arg1 = (u32)PT_REGS_PARM4(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_umount(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 11;
  data.arg1 = (u32)PT_REGS_PARM2(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_chroot(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 12;
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_prctl(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 13;
  data.arg1 = (u32)PT_REGS_PARM1(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_cap_capable(struct pt_regs *ctx) {
  struct data_t data = {};
  fill_data(&data);
  data.type = 14;
  data.arg1 = (u32)PT_REGS_PARM3(ctx);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
