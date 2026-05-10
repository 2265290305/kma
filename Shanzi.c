#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/hw_breakpoint.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/mutex.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/elf.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/input.h>
#include <linux/ptrace.h>
#include <linux/uio.h>
#include <linux/vmalloc.h>
#include <linux/smp.h>
#include <asm/cputype.h>
#include <asm/hw_breakpoint.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>

#define HELLO_DEVICE_NAME "Shanzi"
#define SHANZI_READ_STACK_BUF_SIZE 256
#define SHANZI_READ_MAX_SIZE 0x10000
#define SHANZI_PTE_POOL_SLOTS 32

#ifdef SHANZI_RELEASE_BUILD
#define SHZ_INFO(fmt, ...) do { } while (0)
#else
#define SHZ_INFO(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#endif

struct paradise_get_pid_cmd {
	pid_t pid;
	char name[256];
};

struct paradise_get_module_base_cmd {
	pid_t pid;
	char name[256];
	uintptr_t base;
	uintptr_t end;
	int vm_flag;
};

struct paradise_memory_fast_cmd {
	pid_t pid;
	uintptr_t src_va;
	uintptr_t dst_va;
	size_t size;
	uintptr_t phy_addr;
	int prot;
};

struct paradise_hide_process_cmd {
	uint32_t pid;
	uint32_t hide;
};

struct shanzi_hide_module_cmd {
	uint32_t hide;
};

struct shanzi_hwbp_open_process_cmd {
	uint64_t pid;
	uint64_t handle;
};

struct shanzi_hwbp_u64_cmd {
	uint64_t value;
};

struct shanzi_hwbp_install_cmd {
	uint64_t process_handle;
	uint64_t address;
	uint32_t bp_len;
	uint32_t bp_type;
	uint64_t hwbp_handle;
};

struct shanzi_hwbp_count_cmd {
	uint64_t hwbp_handle;
	uint64_t hit_total_count;
	uint64_t hit_item_count;
};

struct shanzi_user_pt_regs {
	uint64_t regs[31];
	uint64_t sp;
	uint64_t pc;
	uint64_t pstate;
	uint64_t orig_x0;
	uint64_t syscallno;
};

struct shanzi_hwbp_hit_item {
	uint64_t task_id;
	uint64_t hit_addr;
	uint64_t hit_time;
	struct shanzi_user_pt_regs regs_info;
};

struct shanzi_hwbp_read_cmd {
	uint64_t hwbp_handle;
	uint64_t user_buffer;
	uint64_t capacity;
	uint64_t copied;
};

struct paradise_touch_down_cmd {
	int32_t slot;
	int32_t x;
	int32_t y;
};

struct paradise_touch_move_cmd {
	int32_t slot;
	int32_t x;
	int32_t y;
};

struct paradise_touch_up_cmd {
	int32_t slot;
};

struct paradise_touch_mode_cmd {
	int32_t mode;
};

struct shanzi_ring_event {
	uint64_t ts_ns;
	uint32_t type;
	int32_t slot;
	int32_t x;
	int32_t y;
};

#define PARADISE_IOCTL_GET_PID _IOWR('W', 11, struct paradise_get_pid_cmd)
#define PARADISE_IOCTL_GET_MODULE_BASE \
	_IOWR('W', 10, struct paradise_get_module_base_cmd)
#define PARADISE_IOCTL_READ_MEMORY_FAST \
	_IOWR('W', 16, struct paradise_memory_fast_cmd)
#define PARADISE_IOCTL_HIDE_PROCESS \
	_IOWR('W', 14, struct paradise_hide_process_cmd)
#define SHANZI_IOCTL_HIDE_MODULE \
	_IOWR('W', 15, struct shanzi_hide_module_cmd)
#define PARADISE_IOCTL_TOUCH_DOWN \
	_IOWR('W', 22, struct paradise_touch_down_cmd)
#define PARADISE_IOCTL_TOUCH_MOVE \
	_IOWR('W', 23, struct paradise_touch_move_cmd)
#define PARADISE_IOCTL_TOUCH_UP \
	_IOWR('W', 24, struct paradise_touch_up_cmd)
#define PARADISE_IOCTL_TOUCH_SET_MODE \
	_IOWR('W', 25, struct paradise_touch_mode_cmd)
#define SHANZI_IOCTL_HWBP_OPEN_PROCESS \
	_IOWR('W', 30, struct shanzi_hwbp_open_process_cmd)
#define SHANZI_IOCTL_HWBP_CLOSE_HANDLE \
	_IOWR('W', 31, struct shanzi_hwbp_u64_cmd)
#define SHANZI_IOCTL_HWBP_GET_NUM_BRPS \
	_IOR('W', 32, struct shanzi_hwbp_u64_cmd)
#define SHANZI_IOCTL_HWBP_GET_NUM_WRPS \
	_IOR('W', 33, struct shanzi_hwbp_u64_cmd)
#define SHANZI_IOCTL_HWBP_ADD_PROCESS_BP \
	_IOWR('W', 34, struct shanzi_hwbp_install_cmd)
#define SHANZI_IOCTL_HWBP_DEL_PROCESS_BP \
	_IOWR('W', 35, struct shanzi_hwbp_u64_cmd)
#define SHANZI_IOCTL_HWBP_SUSPEND_PROCESS_BP \
	_IOWR('W', 36, struct shanzi_hwbp_u64_cmd)
#define SHANZI_IOCTL_HWBP_RESUME_PROCESS_BP \
	_IOWR('W', 37, struct shanzi_hwbp_u64_cmd)
#define SHANZI_IOCTL_HWBP_GET_HIT_COUNT \
	_IOWR('W', 38, struct shanzi_hwbp_count_cmd)
#define SHANZI_IOCTL_HWBP_READ_HIT_INFO \
	_IOWR('W', 39, struct shanzi_hwbp_read_cmd)
#define SHANZI_IOCTL_HWBP_SET_HOOK_PC \
	_IOWR('W', 40, struct shanzi_hwbp_u64_cmd)

#define SHANZI_HWBP_MAX_HITS 128
#define SHANZI_HWDEBUG_MAX_SLOTS 16
#define SHANZI_RING_CAPACITY 256

struct shanzi_proc_handle {
	struct list_head link;
	struct pid *pid;
};

struct shanzi_hidden_proc {
	struct list_head link;
	uint32_t pid;
	struct task_struct *task;
	bool tasks_unlinked;
	bool proc_mounted;
	bool cgroup_mounted;
	bool kgsl_mounted;
};

struct shanzi_hw_reg_state {
	uint64_t addr;
	uint32_t ctrl;
};

struct shanzi_user_bp_stat {
	struct list_head link;
	pid_t tgid;
	pid_t tid;
	uint32_t break_info;
	uint32_t watch_info;
	uint32_t break_slot_count;
	uint32_t watch_slot_count;
	struct shanzi_hw_reg_state break_regs[SHANZI_HWDEBUG_MAX_SLOTS];
	struct shanzi_hw_reg_state watch_regs[SHANZI_HWDEBUG_MAX_SLOTS];
};

struct shanzi_virtual_target {
	struct list_head link;
	pid_t tgid;
	uint32_t refs;
};

struct shanzi_hwbp_handle_info {
	struct list_head link;
	uint64_t task_id;
	uint32_t bp_count;
	struct perf_event **bps;
	struct perf_event_attr original_attr;
	uint64_t hit_total_count;
	uint32_t hit_count;
	struct shanzi_hwbp_hit_item *hits;
	refcount_t refs;
	bool removing;
	struct completion released;
};

static struct class *hello_class;
static struct device *hello_device;
static int hello_major;
static DEFINE_MUTEX(shanzi_proc_lock);
static LIST_HEAD(shanzi_proc_handles);
static DEFINE_MUTEX(shanzi_hide_lock);
static LIST_HEAD(shanzi_hidden_procs);
static DEFINE_MUTEX(shanzi_module_hide_lock);
static DEFINE_MUTEX(shanzi_ring_lock);
static DEFINE_MUTEX(g_touch_lock);
static DECLARE_WAIT_QUEUE_HEAD(shanzi_ring_waitq);
static DEFINE_SPINLOCK(shanzi_hwbp_lock);
static DEFINE_SPINLOCK(shanzi_bp_stat_lock);
static DEFINE_SPINLOCK(shanzi_virtual_target_lock);
static LIST_HEAD(shanzi_hwbp_handles);
static LIST_HEAD(shanzi_bp_stats);
static LIST_HEAD(shanzi_virtual_targets);
static struct shanzi_ring_event shanzi_ring_q[SHANZI_RING_CAPACITY];
static uint32_t shanzi_ring_head;
static uint32_t shanzi_ring_tail;
static atomic64_t shanzi_hook_pc = ATOMIC64_INIT(0);
static int shanzi_touch_mode;
static DEFINE_MUTEX(shanzi_pte_pool_lock);
static bool shanzi_pte_pool_ready;

struct shanzi_pte_slot {
	void *va;
	pte_t *pte;
	pte_t saved_pte;
	unsigned long mapped_pfn;
};

static struct shanzi_pte_slot shanzi_pte_pool[SHANZI_PTE_POOL_SLOTS];

enum {
	SHANZI_TOUCH_MODE_FOPS = 0,
	SHANZI_TOUCH_MODE_RING = 1,
	SHANZI_TOUCH_MODE_RING_HOOK = 2,
};
static unsigned long (*shanzi_kallsyms_lookup_name)(const char *name);
static int (*shanzi_kern_path_fn)(const char *name, unsigned int flags, struct path *path);
static void (*shanzi_path_put_fn)(const struct path *path);
static int (*shanzi_path_umount_fn)(struct path *path, int flags);
static int (*shanzi_path_mount_fn)(const char *dev_name, struct path *path,
				       const char *type_page, unsigned long flags,
				       void *data_page);
static rwlock_t *shanzi_tasklist_lock_ptr;
static struct task_struct *shanzi_init_task_ptr;
static struct mutex *shanzi_module_mutex_ptr;
static struct perf_event *(*shanzi_register_user_hw_breakpoint_fn)(
	struct perf_event_attr *attr, perf_overflow_handler_t triggered,
	void *context, struct task_struct *task);
static int (*shanzi_modify_user_hw_breakpoint_fn)(
	struct perf_event *bp, struct perf_event_attr *attr);
static void (*shanzi_unregister_hw_breakpoint_fn)(struct perf_event *bp);
static bool shanzi_module_hidden;
static struct list_head *shanzi_module_prev;
static struct mm_struct *shanzi_init_mm_ptr;
static struct mutex *shanzi_input_mutex_ptr;
static struct list_head *shanzi_input_dev_list_ptr;
static void (*shanzi_input_event_fn)(struct input_dev *dev,
					 unsigned int type,
					 unsigned int code,
					 int value);
static bool g_touch_initialized;
static struct input_dev *g_touch_dev;
static struct kprobe shanzi_arch_ptrace_kp;
static bool shanzi_arch_ptrace_hooked;

struct shanzi_touch_slot_state {
	bool active;
	int tracking_id;
	int x;
	int y;
};

static struct shanzi_touch_slot_state g_active_touches[10];
static int g_touch_next_tracking_id = 1;

static long shanzi_ioctl_hwbp_remove(uint64_t handle);
static int shanzi_get_num_brps(void);
static int shanzi_get_num_wrps(void);

static uint32_t shanzi_hwdebug_slot_count(const struct shanzi_hw_reg_state *regs,
				  uint32_t max_slots)
{
	uint32_t i;
	uint32_t used = 0;

	if (!regs)
		return 0;

	for (i = 0; i < max_slots; i++) {
		if (regs[i].addr || regs[i].ctrl)
			used = i + 1;
	}

	return used;
}

static uint32_t shanzi_hwdebug_info_value(bool is_break)
{
	uint32_t debug_arch = read_cpuid(ID_AA64DFR0_EL1) & 0xfU;
	uint32_t slots = is_break ? shanzi_get_num_brps() : shanzi_get_num_wrps();

	if (slots > SHANZI_HWDEBUG_MAX_SLOTS)
		slots = SHANZI_HWDEBUG_MAX_SLOTS;

	return (debug_arch << 8) | slots;
}

static struct shanzi_user_bp_stat *
shanzi_find_bp_stat_locked(pid_t tgid, pid_t tid)
{
	struct shanzi_user_bp_stat *entry;

	list_for_each_entry(entry, &shanzi_bp_stats, link) {
		if (entry->tgid == tgid && entry->tid == tid)
			return entry;
	}

	return NULL;
}

static struct shanzi_user_bp_stat *
shanzi_find_or_create_bp_stat(pid_t tgid, pid_t tid)
{
	struct shanzi_user_bp_stat *entry;
	struct shanzi_user_bp_stat *fresh;
	unsigned long flags;

	spin_lock_irqsave(&shanzi_bp_stat_lock, flags);
	entry = shanzi_find_bp_stat_locked(tgid, tid);
	spin_unlock_irqrestore(&shanzi_bp_stat_lock, flags);
	if (entry)
		return entry;

	fresh = kzalloc(sizeof(*fresh), GFP_ATOMIC);
	if (!fresh)
		return NULL;

	fresh->tgid = tgid;
	fresh->tid = tid;
	fresh->break_info = shanzi_hwdebug_info_value(true);
	fresh->watch_info = shanzi_hwdebug_info_value(false);

	spin_lock_irqsave(&shanzi_bp_stat_lock, flags);
	entry = shanzi_find_bp_stat_locked(tgid, tid);
	if (!entry) {
		list_add_tail(&fresh->link, &shanzi_bp_stats);
		entry = fresh;
		fresh = NULL;
	}
	spin_unlock_irqrestore(&shanzi_bp_stat_lock, flags);

	kfree(fresh);
	return entry;
}

static void shanzi_cleanup_all_bp_stats(void)
{
	struct shanzi_user_bp_stat *entry;
	struct shanzi_user_bp_stat *tmp;
	LIST_HEAD(garbage);
	unsigned long flags;

	spin_lock_irqsave(&shanzi_bp_stat_lock, flags);
	list_splice_init(&shanzi_bp_stats, &garbage);
	spin_unlock_irqrestore(&shanzi_bp_stat_lock, flags);

	list_for_each_entry_safe(entry, tmp, &garbage, link) {
		list_del(&entry->link);
		kfree(entry);
	}
}

static struct shanzi_virtual_target *
shanzi_find_virtual_target_locked(pid_t tgid)
{
	struct shanzi_virtual_target *entry;

	list_for_each_entry(entry, &shanzi_virtual_targets, link) {
		if (entry->tgid == tgid)
			return entry;
	}

	return NULL;
}

static void shanzi_virtual_target_get(pid_t tgid)
{
	struct shanzi_virtual_target *entry;
	struct shanzi_virtual_target *fresh;
	unsigned long flags;

	spin_lock_irqsave(&shanzi_virtual_target_lock, flags);
	entry = shanzi_find_virtual_target_locked(tgid);
	if (entry) {
		entry->refs++;
		spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);
		return;
	}
	spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);

	fresh = kzalloc(sizeof(*fresh), GFP_KERNEL);
	if (!fresh)
		return;

	fresh->tgid = tgid;
	fresh->refs = 1;

	spin_lock_irqsave(&shanzi_virtual_target_lock, flags);
	entry = shanzi_find_virtual_target_locked(tgid);
	if (entry) {
		entry->refs++;
		spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);
		kfree(fresh);
		return;
	}
	list_add_tail(&fresh->link, &shanzi_virtual_targets);
	spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);
}

static void shanzi_virtual_target_put(pid_t tgid)
{
	struct shanzi_virtual_target *entry;
	unsigned long flags;

	spin_lock_irqsave(&shanzi_virtual_target_lock, flags);
	entry = shanzi_find_virtual_target_locked(tgid);
	if (!entry) {
		spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);
		return;
	}

	if (--entry->refs == 0) {
		list_del(&entry->link);
		spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);
		kfree(entry);
		return;
	}
	spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);
}

static bool shanzi_virtual_target_active(pid_t tgid)
{
	struct shanzi_virtual_target *entry;
	unsigned long flags;
	bool found = false;

	spin_lock_irqsave(&shanzi_virtual_target_lock, flags);
	entry = shanzi_find_virtual_target_locked(tgid);
	if (entry && entry->refs)
		found = true;
	spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);
	return found;
}

static void shanzi_cleanup_all_virtual_targets(void)
{
	struct shanzi_virtual_target *entry;
	struct shanzi_virtual_target *tmp;
	LIST_HEAD(garbage);
	unsigned long flags;

	spin_lock_irqsave(&shanzi_virtual_target_lock, flags);
	list_splice_init(&shanzi_virtual_targets, &garbage);
	spin_unlock_irqrestore(&shanzi_virtual_target_lock, flags);

	list_for_each_entry_safe(entry, tmp, &garbage, link) {
		list_del(&entry->link);
		kfree(entry);
	}
}

static int shanzi_ptrace_hwdebug_read_iov(struct iovec __user *uiov,
				  struct iovec *iov)
{
	if (!uiov || !iov)
		return -EINVAL;

	if (copy_from_user_nofault(iov, uiov, sizeof(*iov)))
		return -EFAULT;

	return 0;
}

static int shanzi_ptrace_hwdebug_write_iov(struct iovec __user *uiov,
				   const struct iovec *iov)
{
	if (!uiov || !iov)
		return -EINVAL;

	if (copy_to_user_nofault(uiov, iov, sizeof(*iov)))
		return -EFAULT;

	return 0;
}

static long shanzi_emulate_ptrace_setregset(pid_t tgid, pid_t tid,
				    unsigned long note_type,
				    struct iovec __user *uiov)
{
	struct user_hwdebug_state local;
	struct iovec iov;
	struct shanzi_user_bp_stat *stat;
	struct shanzi_hw_reg_state *regs;
	uint32_t slot_count;
	uint32_t max_slots;
	size_t copy_len;
	size_t reg_bytes = 0;
	uint32_t slots_to_copy = 0;
	unsigned long flags;
	bool is_break;
	uint32_t i;
	long ret = 0;

	ret = shanzi_ptrace_hwdebug_read_iov(uiov, &iov);
	if (ret)
		return ret;

	if (iov.iov_len % sizeof(uint32_t))
		return -EINVAL;

	copy_len = min_t(size_t, iov.iov_len, sizeof(local));
	memset(&local, 0, sizeof(local));
	if (copy_len && copy_from_user_nofault(&local, iov.iov_base, copy_len))
		return -EFAULT;

	iov.iov_len = copy_len;
	ret = shanzi_ptrace_hwdebug_write_iov(uiov, &iov);
	if (ret)
		return ret;

	if (copy_len > offsetof(struct user_hwdebug_state, dbg_regs))
		reg_bytes = copy_len - offsetof(struct user_hwdebug_state, dbg_regs);
	slots_to_copy = min_t(uint32_t, reg_bytes / sizeof(local.dbg_regs[0]),
			      SHANZI_HWDEBUG_MAX_SLOTS);

	stat = shanzi_find_or_create_bp_stat(tgid, tid);
	if (!stat)
		return -ENOMEM;

	is_break = note_type == NT_ARM_HW_BREAK;
	max_slots = is_break ? shanzi_get_num_brps() : shanzi_get_num_wrps();
	if (max_slots > SHANZI_HWDEBUG_MAX_SLOTS)
		max_slots = SHANZI_HWDEBUG_MAX_SLOTS;

	spin_lock_irqsave(&shanzi_bp_stat_lock, flags);
	regs = is_break ? stat->break_regs : stat->watch_regs;
	for (i = 0; i < slots_to_copy; i++) {
		regs[i].addr = local.dbg_regs[i].addr;
		regs[i].ctrl = local.dbg_regs[i].ctrl;
	}

	slot_count = shanzi_hwdebug_slot_count(regs, SHANZI_HWDEBUG_MAX_SLOTS);
	if (is_break) {
		stat->break_info = shanzi_hwdebug_info_value(true);
		stat->break_slot_count = slot_count;
	} else {
		stat->watch_info = shanzi_hwdebug_info_value(false);
		stat->watch_slot_count = slot_count;
	}
	spin_unlock_irqrestore(&shanzi_bp_stat_lock, flags);

	if (slot_count > max_slots)
		ret = -ENOSPC;

	return ret;
}

static long shanzi_emulate_ptrace_getregset(pid_t tgid, pid_t tid,
				    unsigned long note_type,
				    struct iovec __user *uiov)
{
	struct user_hwdebug_state local;
	struct iovec iov;
	struct shanzi_user_bp_stat *stat;
	const struct shanzi_hw_reg_state *regs;
	size_t copy_len;
	unsigned long flags;
	bool is_break;
	uint32_t i;
	long ret;

	ret = shanzi_ptrace_hwdebug_read_iov(uiov, &iov);
	if (ret)
		return ret;

	if (iov.iov_len % sizeof(uint32_t))
		return -EINVAL;

	copy_len = min_t(size_t, iov.iov_len, sizeof(local));
	memset(&local, 0, sizeof(local));

	stat = shanzi_find_or_create_bp_stat(tgid, tid);
	if (!stat)
		return -ENOMEM;

	is_break = note_type == NT_ARM_HW_BREAK;
	spin_lock_irqsave(&shanzi_bp_stat_lock, flags);
	if (is_break) {
		local.dbg_info = stat->break_info;
		regs = stat->break_regs;
	} else {
		local.dbg_info = stat->watch_info;
		regs = stat->watch_regs;
	}
	for (i = 0; i < SHANZI_HWDEBUG_MAX_SLOTS; i++) {
		local.dbg_regs[i].addr = regs[i].addr;
		local.dbg_regs[i].ctrl = regs[i].ctrl;
	}
	spin_unlock_irqrestore(&shanzi_bp_stat_lock, flags);

	if (copy_len && copy_to_user_nofault(iov.iov_base, &local, copy_len))
		return -EFAULT;

	iov.iov_len = copy_len;
	return shanzi_ptrace_hwdebug_write_iov(uiov, &iov);
}

static long shanzi_emulate_ptrace_hwdebug(struct task_struct *child,
				  long request,
				  unsigned long note_type,
				  unsigned long data)
{
	pid_t tgid;
	pid_t tid;

	if (!child)
		return -EINVAL;

	tgid = task_tgid_nr(child);
	if (!shanzi_virtual_target_active(tgid))
		return LONG_MIN;

	tid = task_pid_nr(child);
	if (request == PTRACE_SETREGSET)
		return shanzi_emulate_ptrace_setregset(tgid, tid, note_type,
					       (struct iovec __user *)data);
	if (request == PTRACE_GETREGSET)
		return shanzi_emulate_ptrace_getregset(tgid, tid, note_type,
					       (struct iovec __user *)data);

	return LONG_MIN;
}

static int shanzi_skip_kprobe_with_ret(struct pt_regs *regs, long ret)
{
	regs->regs[0] = ret;
	regs->pc = regs->regs[30];
	return 1;
}

static int shanzi_arch_ptrace_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct task_struct *child;
	long request;
	unsigned long note_type;
	unsigned long data;
	long ret;

	child = (struct task_struct *)regs->regs[0];
	request = (long)regs->regs[1];
	note_type = regs->regs[2];
	data = regs->regs[3];

	if (request != PTRACE_GETREGSET && request != PTRACE_SETREGSET)
		return 0;
	if (note_type != NT_ARM_HW_BREAK && note_type != NT_ARM_HW_WATCH)
		return 0;

	ret = shanzi_emulate_ptrace_hwdebug(child, request, note_type, data);
	if (ret == LONG_MIN)
		return 0;

	SHZ_INFO("Shanzi: ptrace virtualized req=%ld tgid=%d tid=%d type=0x%lx ret=%ld\n",
		 request, child ? task_tgid_nr(child) : -1,
		 child ? task_pid_nr(child) : -1, note_type, ret);
	return shanzi_skip_kprobe_with_ret(regs, ret);
}

static int shanzi_install_ptrace_virtualization(void)
{
	int ret;

	memset(&shanzi_arch_ptrace_kp, 0, sizeof(shanzi_arch_ptrace_kp));
	shanzi_arch_ptrace_kp.symbol_name = "arch_ptrace";
	shanzi_arch_ptrace_kp.pre_handler = shanzi_arch_ptrace_pre;

	ret = register_kprobe(&shanzi_arch_ptrace_kp);
	if (ret) {
		pr_err("Shanzi: arch_ptrace kprobe register failed: %d\n", ret);
		return ret;
	}

	shanzi_arch_ptrace_hooked = true;
	SHZ_INFO("Shanzi: ptrace hwdebug virtualization active\n");
	return 0;
}

static void shanzi_remove_ptrace_virtualization(void)
{
	if (!shanzi_arch_ptrace_hooked)
		return;

	unregister_kprobe(&shanzi_arch_ptrace_kp);
	shanzi_arch_ptrace_hooked = false;
}

static void shanzi_xor_decode(char *buf, size_t len, unsigned char key)
{
	size_t i;

	for (i = 0; i < len; i++)
		buf[i] ^= key;
}

#define SHZ_DEC(name, key, ...)                         \
	char name[] = { __VA_ARGS__ };                  \
	shanzi_xor_decode(name, sizeof(name) - 1, key)

static unsigned long shanzi_lookup_symbol(const char *name)
{
	SHZ_DEC(kallsyms_name, 0x5A,
		'k'^0x5A,'a'^0x5A,'l'^0x5A,'l'^0x5A,'s'^0x5A,'y'^0x5A,
		'm'^0x5A,'s'^0x5A,'_'^0x5A,'l'^0x5A,'o'^0x5A,'o'^0x5A,
		'k'^0x5A,'u'^0x5A,'p'^0x5A,'_'^0x5A,'n'^0x5A,'a'^0x5A,
		'm'^0x5A,'e'^0x5A, 0);
	struct kprobe kp = {
		.symbol_name = kallsyms_name,
	};
	unsigned long addr = 0;

	if (shanzi_kallsyms_lookup_name)
		return shanzi_kallsyms_lookup_name(name);

	if (register_kprobe(&kp) == 0) {
		shanzi_kallsyms_lookup_name = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
	if (shanzi_kallsyms_lookup_name)
		addr = shanzi_kallsyms_lookup_name(name);
	return addr;
}

static int shanzi_resolve_hide_helpers(void)
{
	SHZ_DEC(sym_kern_path, 0x31, 'k'^0x31,'e'^0x31,'r'^0x31,'n'^0x31,'_'^0x31,'p'^0x31,'a'^0x31,'t'^0x31,'h'^0x31,0);
	SHZ_DEC(sym_path_put, 0x31, 'p'^0x31,'a'^0x31,'t'^0x31,'h'^0x31,'_'^0x31,'p'^0x31,'u'^0x31,'t'^0x31,0);
	SHZ_DEC(sym_path_umount, 0x31, 'p'^0x31,'a'^0x31,'t'^0x31,'h'^0x31,'_'^0x31,'u'^0x31,'m'^0x31,'o'^0x31,'u'^0x31,'n'^0x31,'t'^0x31,0);
	SHZ_DEC(sym_path_mount, 0x31, 'p'^0x31,'a'^0x31,'t'^0x31,'h'^0x31,'_'^0x31,'m'^0x31,'o'^0x31,'u'^0x31,'n'^0x31,'t'^0x31,0);

	if (!shanzi_kern_path_fn)
		shanzi_kern_path_fn = (void *)shanzi_lookup_symbol(sym_kern_path);
	if (!shanzi_path_put_fn)
		shanzi_path_put_fn = (void *)shanzi_lookup_symbol(sym_path_put);
	if (!shanzi_path_umount_fn)
		shanzi_path_umount_fn = (void *)shanzi_lookup_symbol(sym_path_umount);
	if (!shanzi_path_mount_fn)
		shanzi_path_mount_fn = (void *)shanzi_lookup_symbol(sym_path_mount);

	if (!shanzi_kern_path_fn || !shanzi_path_put_fn ||
	    !shanzi_path_umount_fn || !shanzi_path_mount_fn)
		return -ENOENT;

	if (!shanzi_tasklist_lock_ptr)
		shanzi_tasklist_lock_ptr =
			(void *)shanzi_lookup_symbol("tasklist_lock");
	if (!shanzi_init_task_ptr)
		shanzi_init_task_ptr = (void *)shanzi_lookup_symbol("init_task");
	return 0;
}

static int shanzi_resolve_module_hide_helpers(void)
{
	SHZ_DEC(sym_module_mutex, 0x24, 'm'^0x24,'o'^0x24,'d'^0x24,'u'^0x24,'l'^0x24,'e'^0x24,'_'^0x24,'m'^0x24,'u'^0x24,'t'^0x24,'e'^0x24,'x'^0x24,0);
	if (!shanzi_module_mutex_ptr)
		shanzi_module_mutex_ptr =
			(void *)shanzi_lookup_symbol(sym_module_mutex);

	if (!shanzi_module_mutex_ptr)
		return -ENOENT;

	return 0;
}

static long shanzi_set_module_hidden(bool hide)
{
	long ret;

	ret = shanzi_resolve_module_hide_helpers();
	if (ret)
		return ret;

	mutex_lock(&shanzi_module_hide_lock);
	mutex_lock(shanzi_module_mutex_ptr);

	if (hide) {
		if (!shanzi_module_hidden) {
			shanzi_module_prev = THIS_MODULE->list.prev;
			list_del_init(&THIS_MODULE->list);
			shanzi_module_hidden = true;
			SHZ_INFO("Shanzi: module hidden from module list\n");
		}
		ret = 0;
	} else {
		if (shanzi_module_hidden) {
			if (shanzi_module_prev)
				list_add(&THIS_MODULE->list, shanzi_module_prev);
			shanzi_module_hidden = false;
			shanzi_module_prev = NULL;
			SHZ_INFO("Shanzi: module restored to module list\n");
		}
		ret = 0;
	}

	mutex_unlock(shanzi_module_mutex_ptr);
	mutex_unlock(&shanzi_module_hide_lock);
	return ret;
}

static long shanzi_ioctl_hide_module(unsigned long arg)
{
	struct shanzi_hide_module_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;

	return shanzi_set_module_hidden(cmd.hide != 0);
}

static void shanzi_hide_module_auto(void)
{
	if (shanzi_set_module_hidden(true) == 0)
		SHZ_INFO("Shanzi: auto hide_module completed\n");
	else
		SHZ_INFO("Shanzi: auto hide_module failed\n");
}

static struct shanzi_hidden_proc *shanzi_find_hidden_proc(uint32_t pid)
{
	struct shanzi_hidden_proc *entry;

	list_for_each_entry(entry, &shanzi_hidden_procs, link) {
		if (entry->pid == pid)
			return entry;
	}

	return NULL;
}

static int shanzi_hide_mount_tmpfs(const char *path)
{
	struct path mount_path;
	SHZ_DEC(mount_data, 0x11,
		's'^0x11,'i'^0x11,'z'^0x11,'e'^0x11,'='^0x11,'0'^0x11,','^0x11,
		'm'^0x11,'o'^0x11,'d'^0x11,'e'^0x11,'='^0x11,'0'^0x11,'5'^0x11,
		'5'^0x11,'5'^0x11,0);
	SHZ_DEC(tmpfs_name, 0x22, 't'^0x22,'m'^0x22,'p'^0x22,'f'^0x22,'s'^0x22,0);
	int ret;

	ret = shanzi_kern_path_fn(path, LOOKUP_FOLLOW, &mount_path);
	if (ret)
		return ret;

	ret = shanzi_path_mount_fn(tmpfs_name, &mount_path, tmpfs_name, 0, mount_data);
	shanzi_path_put_fn(&mount_path);
	return ret;
}

static void shanzi_hide_umount_path(const char *path)
{
	struct path mount_path;

	if (shanzi_kern_path_fn(path, LOOKUP_FOLLOW, &mount_path))
		return;

	shanzi_path_umount_fn(&mount_path, 2);
	shanzi_path_put_fn(&mount_path);
}

static void shanzi_cleanup_hidden_proc(struct shanzi_hidden_proc *hidden)
{
	char path_buf[64];

	if (!hidden)
		return;

	if (hidden->tasks_unlinked && shanzi_tasklist_lock_ptr &&
	    shanzi_init_task_ptr && list_empty(&hidden->task->tasks)) {
		write_lock_irq(shanzi_tasklist_lock_ptr);
		list_add_tail(&hidden->task->tasks, &shanzi_init_task_ptr->tasks);
		write_unlock_irq(shanzi_tasklist_lock_ptr);
	}

	if (hidden->task) {
		unsigned int flags = READ_ONCE(hidden->task->flags);

		flags &= ~BIT(28);
		WRITE_ONCE(hidden->task->flags, flags);
	}

	if (hidden->proc_mounted) {
		snprintf(path_buf, sizeof(path_buf), "/proc/%u", hidden->pid);
		shanzi_hide_umount_path(path_buf);
	}
	if (hidden->cgroup_mounted) {
		snprintf(path_buf, sizeof(path_buf),
			 "/sys/fs/cgroup/uid_0/pid_%u", hidden->pid);
		shanzi_hide_umount_path(path_buf);
	}
	if (hidden->kgsl_mounted) {
		snprintf(path_buf, sizeof(path_buf),
			 "/sys/devices/virtual/kgsl/kgsl/proc/%u", hidden->pid);
		shanzi_hide_umount_path(path_buf);
	}

	if (hidden->task)
		put_task_struct(hidden->task);
	kfree(hidden);
}

static void shanzi_cleanup_all_hidden_procs(void)
{
	struct shanzi_hidden_proc *entry;
	struct shanzi_hidden_proc *tmp;

	mutex_lock(&shanzi_hide_lock);
	list_for_each_entry_safe(entry, tmp, &shanzi_hidden_procs, link) {
		list_del(&entry->link);
		shanzi_cleanup_hidden_proc(entry);
	}
	mutex_unlock(&shanzi_hide_lock);
}

static bool shanzi_ring_empty(void)
{
	return shanzi_ring_head == shanzi_ring_tail;
}

static bool shanzi_ring_full(void)
{
	return ((shanzi_ring_head + 1) % SHANZI_RING_CAPACITY) == shanzi_ring_tail;
}

static __maybe_unused int shanzi_ring_queue_push(uint32_t type, int32_t slot,
						 int32_t x, int32_t y)
{
	struct shanzi_ring_event *evt;

	mutex_lock(&shanzi_ring_lock);
	if (shanzi_ring_full()) {
		mutex_unlock(&shanzi_ring_lock);
		SHZ_INFO("Shanzi: touch_ring: queue full\n");
		return -ENOSPC;
	}

	evt = &shanzi_ring_q[shanzi_ring_head];
	evt->ts_ns = ktime_get_ns();
	evt->type = type;
	evt->slot = slot;
	evt->x = x;
	evt->y = y;
	shanzi_ring_head = (shanzi_ring_head + 1) % SHANZI_RING_CAPACITY;
	mutex_unlock(&shanzi_ring_lock);
	wake_up_interruptible(&shanzi_ring_waitq);
	return 0;
}

static int shanzi_resolve_touch_helpers(void)
{
	SHZ_DEC(sym_input_dev_list, 0x33,
		'i'^0x33,'n'^0x33,'p'^0x33,'u'^0x33,'t'^0x33,'_'^0x33,
		'd'^0x33,'e'^0x33,'v'^0x33,'_'^0x33,'l'^0x33,'i'^0x33,
		's'^0x33,'t'^0x33,0);
	SHZ_DEC(sym_input_mutex, 0x33,
		'i'^0x33,'n'^0x33,'p'^0x33,'u'^0x33,'t'^0x33,'_'^0x33,
		'm'^0x33,'u'^0x33,'t'^0x33,'e'^0x33,'x'^0x33,0);
	SHZ_DEC(sym_input_event, 0x33,
		'i'^0x33,'n'^0x33,'p'^0x33,'u'^0x33,'t'^0x33,'_'^0x33,
		'e'^0x33,'v'^0x33,'e'^0x33,'n'^0x33,'t'^0x33,0);

	if (!shanzi_input_dev_list_ptr)
		shanzi_input_dev_list_ptr = (struct list_head *)shanzi_lookup_symbol(sym_input_dev_list);
	if (!shanzi_input_mutex_ptr)
		shanzi_input_mutex_ptr = (struct mutex *)shanzi_lookup_symbol(sym_input_mutex);
	if (!shanzi_input_event_fn)
		shanzi_input_event_fn = (void *)shanzi_lookup_symbol(sym_input_event);

	if (!shanzi_input_dev_list_ptr || !shanzi_input_mutex_ptr || !shanzi_input_event_fn)
		return -ENOENT;
	return 0;
}

static struct input_dev *shanzi_find_touch_device_locked(void)
{
	struct input_dev *dev;
	struct input_dev *best = NULL;
	int best_area = -1;

	if (!shanzi_input_dev_list_ptr)
		return NULL;

	list_for_each_entry(dev, shanzi_input_dev_list_ptr, node) {
		int max_x;
		int max_y;
		int area;

		if (!test_bit(EV_ABS, dev->evbit) || !dev->absinfo)
			continue;
		if (!test_bit(ABS_MT_POSITION_X, dev->absbit) ||
		    !test_bit(ABS_MT_POSITION_Y, dev->absbit))
			continue;

		max_x = dev->absinfo[ABS_MT_POSITION_X].maximum;
		max_y = dev->absinfo[ABS_MT_POSITION_Y].maximum;
		if (max_x <= 0 || max_y <= 0)
			continue;

		area = max_x * max_y;
		if (area > best_area) {
			best = dev;
			best_area = area;
		}
	}

	return best;
}

static int shanzi_touch_init_if_needed(void)
{
	int ret;

	if (g_touch_initialized && g_touch_dev)
		return 0;

	ret = shanzi_resolve_touch_helpers();
	if (ret)
		return ret;

	mutex_lock(&g_touch_lock);
	if (!g_touch_initialized || !g_touch_dev) {
		mutex_lock(shanzi_input_mutex_ptr);
		g_touch_dev = shanzi_find_touch_device_locked();
		mutex_unlock(shanzi_input_mutex_ptr);
		if (!g_touch_dev) {
			mutex_unlock(&g_touch_lock);
			return -ENODEV;
		}
		memset(g_active_touches, 0, sizeof(g_active_touches));
		g_touch_next_tracking_id = 1;
		g_touch_initialized = true;
	}
	mutex_unlock(&g_touch_lock);
	return 0;
}

static void shanzi_emit_touch_sync_locked(void)
{
	bool any_active = false;
	int i;

	for (i = 0; i < ARRAY_SIZE(g_active_touches); i++) {
		if (g_active_touches[i].active) {
			any_active = true;
			break;
		}
	}

	shanzi_input_event_fn(g_touch_dev, EV_KEY, BTN_TOUCH, any_active ? 1 : 0);
	shanzi_input_event_fn(g_touch_dev, EV_KEY, BTN_TOOL_FINGER, any_active ? 1 : 0);
	shanzi_input_event_fn(g_touch_dev, EV_SYN, SYN_REPORT, 0);
}

static long shanzi_touch_inject_event(uint32_t type, int32_t slot, int32_t x, int32_t y)
{
	struct shanzi_touch_slot_state *touch;
	int ret;

	if (slot < 0 || slot >= ARRAY_SIZE(g_active_touches))
		return -EINVAL;

	ret = shanzi_touch_init_if_needed();
	if (ret)
		return ret;

	mutex_lock(&g_touch_lock);
	touch = &g_active_touches[slot];
	shanzi_input_event_fn(g_touch_dev, EV_ABS, ABS_MT_SLOT, slot);

	switch (type) {
	case 0:
		if (!touch->active) {
			touch->tracking_id = g_touch_next_tracking_id++;
			touch->active = true;
		}
		touch->x = x;
		touch->y = y;
		shanzi_input_event_fn(g_touch_dev, EV_ABS, ABS_MT_TRACKING_ID, touch->tracking_id);
		shanzi_input_event_fn(g_touch_dev, EV_ABS, ABS_MT_POSITION_X, x);
		shanzi_input_event_fn(g_touch_dev, EV_ABS, ABS_MT_POSITION_Y, y);
		break;
	case 1:
		if (touch->active) {
			shanzi_input_event_fn(g_touch_dev, EV_ABS, ABS_MT_TRACKING_ID, -1);
			touch->active = false;
			touch->tracking_id = 0;
		}
		break;
	case 2:
		if (!touch->active) {
			mutex_unlock(&g_touch_lock);
			return -EINVAL;
		}
		touch->x = x;
		touch->y = y;
		shanzi_input_event_fn(g_touch_dev, EV_ABS, ABS_MT_POSITION_X, x);
		shanzi_input_event_fn(g_touch_dev, EV_ABS, ABS_MT_POSITION_Y, y);
		break;
	default:
		mutex_unlock(&g_touch_lock);
		return -EINVAL;
	}

	shanzi_emit_touch_sync_locked();
	mutex_unlock(&g_touch_lock);
	return 0;
}

static long hello_ioctl_touch_down(unsigned long arg)
{
	struct paradise_touch_down_cmd cmd = {};

	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.slot < 0 || cmd.slot > 9)
		return -EINVAL;
	if (shanzi_touch_mode == SHANZI_TOUCH_MODE_RING ||
	    shanzi_touch_mode == SHANZI_TOUCH_MODE_RING_HOOK)
		return shanzi_ring_queue_push(0, cmd.slot, cmd.x, cmd.y);
	return shanzi_touch_inject_event(0, cmd.slot, cmd.x, cmd.y);
}

static long hello_ioctl_touch_move(unsigned long arg)
{
	struct paradise_touch_move_cmd cmd = {};

	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.slot < 0 || cmd.slot > 9)
		return -EINVAL;
	if (shanzi_touch_mode == SHANZI_TOUCH_MODE_RING ||
	    shanzi_touch_mode == SHANZI_TOUCH_MODE_RING_HOOK)
		return shanzi_ring_queue_push(2, cmd.slot, cmd.x, cmd.y);
	return shanzi_touch_inject_event(2, cmd.slot, cmd.x, cmd.y);
}

static long hello_ioctl_touch_up(unsigned long arg)
{
	struct paradise_touch_up_cmd cmd = {};

	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.slot < 0 || cmd.slot > 9)
		return -EINVAL;
	if (shanzi_touch_mode == SHANZI_TOUCH_MODE_RING ||
	    shanzi_touch_mode == SHANZI_TOUCH_MODE_RING_HOOK)
		return shanzi_ring_queue_push(1, cmd.slot, 0, 0);
	return shanzi_touch_inject_event(1, cmd.slot, 0, 0);
}

static long hello_ioctl_touch_set_mode(unsigned long arg)
{
	struct paradise_touch_mode_cmd cmd = {};

	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.mode < 0 || cmd.mode > 2)
		return -EINVAL;
	shanzi_touch_mode = cmd.mode;
	SHZ_INFO("Shanzi: touch mode=%d\n", shanzi_touch_mode);
	if (shanzi_touch_mode == SHANZI_TOUCH_MODE_RING_HOOK)
		SHZ_INFO("Shanzi: touch ring hook mode requested, using ring fallback for now\n");
	return 0;
}

static int shanzi_resolve_hwbp_helpers(void)
{
	SHZ_DEC(sym_reg_hwbp, 0x4D,
		'r'^0x4D,'e'^0x4D,'g'^0x4D,'i'^0x4D,'s'^0x4D,'t'^0x4D,'e'^0x4D,'r'^0x4D,'_'^0x4D,
		'u'^0x4D,'s'^0x4D,'e'^0x4D,'r'^0x4D,'_'^0x4D,'h'^0x4D,'w'^0x4D,'_'^0x4D,
		'b'^0x4D,'r'^0x4D,'e'^0x4D,'a'^0x4D,'k'^0x4D,'p'^0x4D,'o'^0x4D,'i'^0x4D,'n'^0x4D,'t'^0x4D,0);
	SHZ_DEC(sym_mod_hwbp, 0x4D,
		'm'^0x4D,'o'^0x4D,'d'^0x4D,'i'^0x4D,'f'^0x4D,'y'^0x4D,'_'^0x4D,
		'u'^0x4D,'s'^0x4D,'e'^0x4D,'r'^0x4D,'_'^0x4D,'h'^0x4D,'w'^0x4D,'_'^0x4D,
		'b'^0x4D,'r'^0x4D,'e'^0x4D,'a'^0x4D,'k'^0x4D,'p'^0x4D,'o'^0x4D,'i'^0x4D,'n'^0x4D,'t'^0x4D,0);
	SHZ_DEC(sym_unreg_hwbp, 0x4D,
		'u'^0x4D,'n'^0x4D,'r'^0x4D,'e'^0x4D,'g'^0x4D,'i'^0x4D,'s'^0x4D,'t'^0x4D,'e'^0x4D,'r'^0x4D,'_'^0x4D,
		'h'^0x4D,'w'^0x4D,'_'^0x4D,'b'^0x4D,'r'^0x4D,'e'^0x4D,'a'^0x4D,'k'^0x4D,'p'^0x4D,'o'^0x4D,'i'^0x4D,'n'^0x4D,'t'^0x4D,0);

	if (!shanzi_register_user_hw_breakpoint_fn)
		shanzi_register_user_hw_breakpoint_fn =
			(void *)shanzi_lookup_symbol(sym_reg_hwbp);
	if (!shanzi_modify_user_hw_breakpoint_fn)
		shanzi_modify_user_hw_breakpoint_fn =
			(void *)shanzi_lookup_symbol(sym_mod_hwbp);
	if (!shanzi_unregister_hw_breakpoint_fn)
		shanzi_unregister_hw_breakpoint_fn =
			(void *)shanzi_lookup_symbol(sym_unreg_hwbp);

	if (!shanzi_register_user_hw_breakpoint_fn ||
	    !shanzi_modify_user_hw_breakpoint_fn ||
	    !shanzi_unregister_hw_breakpoint_fn) {
		pr_err("Shanzi: hwbp helper resolve failed reg=%px mod=%px unreg=%px\n",
		       shanzi_register_user_hw_breakpoint_fn,
		       shanzi_modify_user_hw_breakpoint_fn,
		       shanzi_unregister_hw_breakpoint_fn);
		return -ENOENT;
	}

	return 0;
}

static int shanzi_get_num_brps(void)
{
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 12) & 0xf) + 1;
}

static int shanzi_get_num_wrps(void)
{
	return ((read_cpuid(ID_AA64DFR0_EL1) >> 20) & 0xf) + 1;
}

#define SHANZI_READ_WB_REG_CASE(OFF, N, REG, VAL) \
	case (OFF + N): \
		AARCH64_DBG_READ(N, REG, VAL); \
		break

#define SHANZI_WRITE_WB_REG_CASE(OFF, N, REG, VAL) \
	case (OFF + N): \
		AARCH64_DBG_WRITE(N, REG, VAL); \
		break

#define SHANZI_GEN_READ_WB_REG_CASES(OFF, REG, VAL) \
	SHANZI_READ_WB_REG_CASE(OFF, 0, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 1, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 2, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 3, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 4, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 5, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 6, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 7, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 8, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 9, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 10, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 11, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 12, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 13, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 14, REG, VAL); \
	SHANZI_READ_WB_REG_CASE(OFF, 15, REG, VAL)

#define SHANZI_GEN_WRITE_WB_REG_CASES(OFF, REG, VAL) \
	SHANZI_WRITE_WB_REG_CASE(OFF, 0, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 1, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 2, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 3, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 4, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 5, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 6, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 7, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 8, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 9, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 10, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 11, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 12, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 13, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 14, REG, VAL); \
	SHANZI_WRITE_WB_REG_CASE(OFF, 15, REG, VAL)

static uint64_t shanzi_read_wb_reg(int reg, int n)
{
	uint64_t val = 0;

	switch (reg + n) {
	SHANZI_GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
	SHANZI_GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
	SHANZI_GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
	SHANZI_GEN_READ_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
	default:
		break;
	}

	return val;
}

static void shanzi_write_wb_reg(int reg, int n, uint64_t val)
{
	switch (reg + n) {
	SHANZI_GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BVR, AARCH64_DBG_REG_NAME_BVR, val);
	SHANZI_GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_BCR, AARCH64_DBG_REG_NAME_BCR, val);
	SHANZI_GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WVR, AARCH64_DBG_REG_NAME_WVR, val);
	SHANZI_GEN_WRITE_WB_REG_CASES(AARCH64_DBG_REG_WCR, AARCH64_DBG_REG_NAME_WCR, val);
	default:
		break;
	}
	isb();
}

static bool shanzi_toggle_bp_registers_directly(const struct perf_event_attr *attr,
						int enable)
{
	int i;
	int max_slots;
	int val_reg;
	int ctrl_reg;
	int cur_slot = -1;
	u32 ctrl;
	uint64_t hw_addr;

	if (!attr)
		return false;

	hw_addr = attr->bp_addr;
	if (attr->bp_type == HW_BREAKPOINT_X)
		hw_addr &= ~0x3ULL;
	else
		hw_addr &= ~0x7ULL;

	switch (attr->bp_type) {
	case HW_BREAKPOINT_R:
	case HW_BREAKPOINT_W:
	case HW_BREAKPOINT_RW:
		ctrl_reg = AARCH64_DBG_REG_WCR;
		val_reg = AARCH64_DBG_REG_WVR;
		max_slots = shanzi_get_num_wrps();
		break;
	case HW_BREAKPOINT_X:
		ctrl_reg = AARCH64_DBG_REG_BCR;
		val_reg = AARCH64_DBG_REG_BVR;
		max_slots = shanzi_get_num_brps();
		break;
	default:
		return false;
	}

	for (i = 0; i < max_slots; i++) {
		if (shanzi_read_wb_reg(val_reg, i) == hw_addr) {
			cur_slot = i;
			break;
		}
	}
	if (cur_slot < 0)
		return false;

	ctrl = shanzi_read_wb_reg(ctrl_reg, cur_slot);
	if (enable)
		ctrl |= 0x1;
	else
		ctrl &= ~0x1;
	shanzi_write_wb_reg(ctrl_reg, cur_slot, ctrl);
	return true;
}

static long convert_wmt_to_pgprot(unsigned int mode, pgprot_t *out)
{
	switch (mode) {
	case 0:
		*out = PAGE_KERNEL;
		return 0;
	case 1:
	case 2:
	case 4:
	case 5:
		*out = PAGE_KERNEL;
		return 0;
	case 3:
	case 6:
	case 7:
	default:
		return -EINVAL;
	}
}

static int read_process_cmdline(struct task_struct *task, char *buffer, size_t buflen)
{
	struct mm_struct *mm;
	unsigned long arg_start, arg_end;
	int copied = 0;

	if (!buflen)
		return 0;

	buffer[0] = '\0';
	mm = get_task_mm(task);
	if (!mm)
		return 0;
	if (!mm->arg_end)
		goto out_mm;

	spin_lock(&mm->arg_lock);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	spin_unlock(&mm->arg_lock);
	if (arg_end <= arg_start)
		goto out_mm;

	if (arg_end - arg_start > buflen - 1)
		arg_end = arg_start + buflen - 1;

	copied = access_process_vm(task, arg_start, buffer, arg_end - arg_start,
				   FOLL_FORCE);
	if (copied > 0) {
		char *space;
		char *slash;

		buffer[copied] = '\0';
		space = strchr(buffer, ' ');
		if (space)
			*space = '\0';
		slash = strrchr(buffer, '/');
		if (slash && slash[1] != '\0')
			memmove(buffer, slash + 1, strlen(slash + 1) + 1);
	}

out_mm:
	mmput(mm);
	return copied;
}

static int find_process_by_name(const char *name)
{
	struct task_struct **tasks = NULL;
	struct task_struct *task;
	size_t needle_len;
	size_t count = 0;
	size_t i = 0;
	int pid = 0;

	needle_len = strnlen(name, sizeof(((struct paradise_get_pid_cmd *)0)->name));
	if (!needle_len)
		return -EINVAL;

	read_lock(&tasklist_lock);
	for_each_process(task)
		count++;
	read_unlock(&tasklist_lock);

	if (!count)
		return 0;

	tasks = kcalloc(count, sizeof(*tasks), GFP_KERNEL);
	if (!tasks)
		return -ENOMEM;

	read_lock(&tasklist_lock);
	for_each_process(task) {
		if (i >= count)
			break;
		get_task_struct(task);
		tasks[i++] = task;
	}
	read_unlock(&tasklist_lock);

	count = i;
	for (i = 0; i < count; i++) {
		char cmdline[256];
		const char *comm;
		size_t comm_len;

		task = tasks[i];
		if (read_process_cmdline(task, cmdline, sizeof(cmdline)) > 0) {
			size_t cmd_len = strnlen(cmdline, sizeof(cmdline));

			if (cmd_len == needle_len && !strncmp(cmdline, name, needle_len)) {
				pid = task_pid_nr(task);
				put_task_struct(task);
				break;
			}
		}

		comm = task->comm;
		comm_len = strnlen(comm, TASK_COMM_LEN);
		if (comm_len == needle_len && !strncmp(comm, name, needle_len)) {
			pid = task_pid_nr(task);
			put_task_struct(task);
			break;
		}

		put_task_struct(task);
	}

	while (++i < count)
		put_task_struct(tasks[i]);

	kfree(tasks);
	return pid;
}

static bool get_module_bounds(pid_t pid, const char *name, unsigned long vm_flag,
			      uintptr_t *base_out, uintptr_t *end_out)
{
	struct pid *kpid;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	size_t needle_len;
	uintptr_t base = 0;
	uintptr_t end = 0;
	bool found = false;

	needle_len = strnlen(name, sizeof(((struct paradise_get_module_base_cmd *)0)->name));
	if (!needle_len)
		return false;

	kpid = find_get_pid(pid);
	if (!kpid)
		return false;

	task = get_pid_task(kpid, PIDTYPE_PID);
	put_pid(kpid);
	if (!task)
		return false;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return false;

	VMA_ITERATOR(vmi, mm, 0);
	mmap_read_lock(mm);
	for_each_vma(vmi, vma) {
		struct file *file;
		const char *dname;
		size_t match_len;

		file = vma->vm_file;
		if (!file)
			continue;
		if (vm_flag && !(vma->vm_flags & vm_flag))
			continue;

		dname = file->f_path.dentry->d_name.name;
		if (!dname)
			continue;

		match_len = strnlen(dname, NAME_MAX);
		if (match_len > needle_len)
			match_len = needle_len;
		if (!match_len)
			continue;

		if (!bcmp(dname, name, match_len)) {
			if (!found || (uintptr_t)vma->vm_start < base)
				base = (uintptr_t)vma->vm_start;
			if (!found || (uintptr_t)vma->vm_end > end)
				end = (uintptr_t)vma->vm_end;
			found = true;
		}
	}
	mmap_read_unlock(mm);
	mmput(mm);

	if (!found)
		return false;

	if (base_out)
		*base_out = base;
	if (end_out)
		*end_out = end;
	return true;
}

static long lockfree_va_to_pa(pid_t pid, uintptr_t vaddr, uintptr_t *phys_out)
{
	struct pid *kpid;
	struct task_struct *task;
	struct mm_struct *mm;
	struct page *page = NULL;
	unsigned long offset;
	long ret;
	int locked = 1;

	*phys_out = 0;

	kpid = find_get_pid(pid);
	if (!kpid)
		return -ESRCH;

	task = get_pid_task(kpid, PIDTYPE_PID);
	put_pid(kpid);
	if (!task)
		return -ESRCH;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return -ESRCH;

	offset = offset_in_page(vaddr);
	mmap_read_lock(mm);
	ret = get_user_pages_remote(mm, vaddr & PAGE_MASK, 1, FOLL_FORCE, &page,
				    &locked);
	if (locked)
		mmap_read_unlock(mm);
	mmput(mm);
	if (ret != 1 || !page)
		return -EFAULT;

	*phys_out = page_to_phys(page) + offset;
	put_page(page);
	return 0;
}

static void shanzi_free_pte_slot(struct shanzi_pte_slot *slot)
{
	if (!slot || !slot->va || !slot->pte)
		return;

	set_pte(slot->pte, slot->saved_pte);
	flush_tlb_kernel_range((unsigned long)slot->va,
			       (unsigned long)slot->va + PAGE_SIZE);
	vfree(slot->va);
	slot->va = NULL;
	slot->pte = NULL;
	slot->mapped_pfn = ULONG_MAX;
}

static void shanzi_pte_phys_cleanup(void)
{
	int cpu;

	mutex_lock(&shanzi_pte_pool_lock);
	shanzi_pte_pool_ready = false;
	for_each_possible_cpu(cpu) {
		if (cpu >= SHANZI_PTE_POOL_SLOTS)
			break;
		shanzi_free_pte_slot(&shanzi_pte_pool[cpu]);
	}
	mutex_unlock(&shanzi_pte_pool_lock);
}

static int shanzi_pte_pool_ensure(void)
{
	int cpu;

	mutex_lock(&shanzi_pte_pool_lock);
	if (shanzi_pte_pool_ready) {
		mutex_unlock(&shanzi_pte_pool_lock);
		return 0;
	}
	if (!shanzi_init_mm_ptr && shanzi_kallsyms_lookup_name)
		shanzi_init_mm_ptr = (struct mm_struct *)shanzi_kallsyms_lookup_name("init_mm");
	if (!shanzi_init_mm_ptr) {
		mutex_unlock(&shanzi_pte_pool_lock);
		return -ENOENT;
	}

	for_each_possible_cpu(cpu) {
		struct shanzi_pte_slot *slot;
		unsigned long addr;
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;

		if (cpu >= SHANZI_PTE_POOL_SLOTS)
			break;
		slot = &shanzi_pte_pool[cpu];
		slot->mapped_pfn = ULONG_MAX;
		slot->va = vzalloc(PAGE_SIZE);
		if (!slot->va)
			goto err;

		addr = (unsigned long)slot->va;
		pgd = pgd_offset(shanzi_init_mm_ptr, addr);
		if (pgd_none(*pgd) || pgd_bad(*pgd))
			goto err;
		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d) || p4d_bad(*p4d))
			goto err;
		pud = pud_offset(p4d, addr);
		if (pud_none(*pud) || pud_bad(*pud))
			goto err;
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd) || pmd_bad(*pmd))
			goto err;
		slot->pte = pte_offset_kernel(pmd, addr);
		if (!slot->pte)
			goto err;
		slot->saved_pte = READ_ONCE(*slot->pte);
	}

	shanzi_pte_pool_ready = true;
	mutex_unlock(&shanzi_pte_pool_lock);
	return 0;
err:
	while (--cpu >= 0)
		shanzi_free_pte_slot(&shanzi_pte_pool[cpu]);
	mutex_unlock(&shanzi_pte_pool_lock);
	return -ENOMEM;
}

static void *shanzi_map_phys_page(unsigned long phys, size_t *page_off_out)
{
	unsigned long pfn = phys >> PAGE_SHIFT;
	int cpu;
	struct shanzi_pte_slot *slot;

	if (!shanzi_pte_pool_ready || !pfn_valid(pfn))
		return NULL;

	*page_off_out = offset_in_page(phys);
	cpu = get_cpu();
	if (cpu >= SHANZI_PTE_POOL_SLOTS) {
		put_cpu();
		return NULL;
	}

	slot = &shanzi_pte_pool[cpu];
	if (!slot->va || !slot->pte) {
		put_cpu();
		return NULL;
	}

	if (slot->mapped_pfn != pfn) {
		set_pte(slot->pte, pfn_pte(pfn, PAGE_KERNEL));
		flush_tlb_kernel_range((unsigned long)slot->va,
				       (unsigned long)slot->va + PAGE_SIZE);
		slot->mapped_pfn = pfn;
	}

	return (char *)slot->va + *page_off_out;
}

static void shanzi_unmap_phys_page(void)
{
	put_cpu();
}

static struct shanzi_proc_handle *shanzi_find_proc_handle(uint64_t handle)
{
	struct shanzi_proc_handle *entry;

	list_for_each_entry(entry, &shanzi_proc_handles, link) {
		if ((uint64_t)(uintptr_t)entry->pid == handle)
			return entry;
	}
	return NULL;
}

static struct shanzi_hwbp_handle_info *shanzi_find_hwbp_handle_locked(uint64_t handle)
{
	struct shanzi_hwbp_handle_info *entry;

	list_for_each_entry(entry, &shanzi_hwbp_handles, link) {
		if ((uint64_t)(uintptr_t)entry == handle)
			return entry;
	}
	return NULL;
}

static void shanzi_hwbp_put(struct shanzi_hwbp_handle_info *info)
{
	if (!info)
		return;

	if (refcount_dec_and_test(&info->refs))
		complete(&info->released);
}

static struct shanzi_hwbp_handle_info *
shanzi_find_hwbp_handle_get_locked(uint64_t handle)
{
	struct shanzi_hwbp_handle_info *info;

	info = shanzi_find_hwbp_handle_locked(handle);
	if (!info || info->removing)
		return NULL;

	refcount_inc(&info->refs);
	return info;
}

static struct shanzi_hwbp_handle_info *
shanzi_find_hwbp_by_event_locked(struct perf_event *bp)
{
	struct shanzi_hwbp_handle_info *entry;
	uint32_t i;

	list_for_each_entry(entry, &shanzi_hwbp_handles, link) {
		for (i = 0; i < entry->bp_count; i++) {
			if (entry->bps && entry->bps[i] == bp)
				return entry;
		}
	}
	return NULL;
}

static struct shanzi_hwbp_handle_info *
shanzi_find_hwbp_by_event_get_locked(struct perf_event *bp)
{
	struct shanzi_hwbp_handle_info *info;

	info = shanzi_find_hwbp_by_event_locked(bp);
	if (!info || info->removing)
		return NULL;

	refcount_inc(&info->refs);
	return info;
}

static void shanzi_hwbp_destroy(struct shanzi_hwbp_handle_info *info)
{
	if (!info)
		return;

	while (info->bp_count > 0) {
		info->bp_count--;
		shanzi_unregister_hw_breakpoint_fn(info->bps[info->bp_count]);
	}

	kfree(info->bps);
	kfree(info->hits);
	kfree(info);
}

static void shanzi_record_hit_details(struct shanzi_hwbp_handle_info *info,
					 struct pt_regs *regs)
{
	struct shanzi_hwbp_hit_item *hit;

	if (!info || !regs)
		return;

	info->hit_total_count++;
	if (info->hit_count >= SHANZI_HWBP_MAX_HITS || !info->hits)
		return;

	hit = &info->hits[info->hit_count++];
	memset(hit, 0, sizeof(*hit));
	hit->task_id = info->task_id;
	hit->hit_addr = regs->pc;
	hit->hit_time = ktime_get_real_seconds();
	memcpy(hit->regs_info.regs, regs->regs, sizeof(hit->regs_info.regs));
	hit->regs_info.sp = regs->sp;
	hit->regs_info.pc = regs->pc;
	hit->regs_info.pstate = regs->pstate;
	hit->regs_info.orig_x0 = regs->orig_x0;
	hit->regs_info.syscallno = regs->syscallno;
}

static void shanzi_hwbp_handler(struct perf_event *bp,
				   struct perf_sample_data *data,
				   struct pt_regs *regs)
{
	struct shanzi_hwbp_handle_info *info;
	struct perf_event_attr attr;
	unsigned long flags;
	uint64_t hook_pc;
	bool disable_bp = false;

	hook_pc = atomic64_read(&shanzi_hook_pc);
	if (hook_pc)
		regs->pc = hook_pc;

	spin_lock_irqsave(&shanzi_hwbp_lock, flags);
	info = shanzi_find_hwbp_by_event_get_locked(bp);
	if (!info) {
		spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
		return;
	}

	shanzi_record_hit_details(info, regs);
	info->original_attr.disabled = 1;
	attr = info->original_attr;
	attr.disabled = 1;
	disable_bp = true;
	spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);

	if (disable_bp)
		shanzi_toggle_bp_registers_directly(&attr, 0);

	shanzi_hwbp_put(info);
}

static long shanzi_ioctl_hwbp_open_process(unsigned long arg)
{
	struct shanzi_hwbp_open_process_cmd cmd;
	struct shanzi_proc_handle *entry;
	struct pid *pid;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.pid)
		return -EINVAL;

	pid = find_get_pid((pid_t)cmd.pid);
	if (!pid)
		return -ESRCH;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		put_pid(pid);
		return -ENOMEM;
	}

	entry->pid = pid;
	mutex_lock(&shanzi_proc_lock);
	list_add_tail(&entry->link, &shanzi_proc_handles);
	mutex_unlock(&shanzi_proc_lock);

	cmd.handle = (uint64_t)(uintptr_t)pid;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static long shanzi_ioctl_hwbp_close_handle(unsigned long arg)
{
	struct shanzi_hwbp_u64_cmd cmd;
	struct shanzi_proc_handle *entry, *tmp;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.value)
		return -EINVAL;

	mutex_lock(&shanzi_proc_lock);
	list_for_each_entry_safe(entry, tmp, &shanzi_proc_handles, link) {
		if ((uint64_t)(uintptr_t)entry->pid != cmd.value)
			continue;
		list_del(&entry->link);
		mutex_unlock(&shanzi_proc_lock);
		put_pid(entry->pid);
		kfree(entry);
		return 0;
	}
	mutex_unlock(&shanzi_proc_lock);
	return -ENOENT;
}

static long shanzi_ioctl_hwbp_get_num(unsigned long arg, int type)
{
	struct shanzi_hwbp_u64_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	cmd.value = (type == TYPE_INST) ? shanzi_get_num_brps() : shanzi_get_num_wrps();
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static long shanzi_ioctl_hwbp_add_process_bp(unsigned long arg)
{
	struct shanzi_hwbp_install_cmd cmd;
	struct shanzi_proc_handle *proc_handle;
	struct shanzi_hwbp_handle_info *info;
	struct task_struct *task;
	struct task_struct **threads;
	struct task_struct *iter;
	unsigned long flags;
	uint32_t thread_count = 0;
	uint32_t i = 0;
	long ret = 0;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.process_handle || !cmd.address || !cmd.bp_len)
		return -EINVAL;
	ret = shanzi_resolve_hwbp_helpers();
	if (ret)
		return ret;

	mutex_lock(&shanzi_proc_lock);
	proc_handle = shanzi_find_proc_handle(cmd.process_handle);
	if (!proc_handle) {
		mutex_unlock(&shanzi_proc_lock);
		return -ENOENT;
	}
	task = get_pid_task(proc_handle->pid, PIDTYPE_PID);
	mutex_unlock(&shanzi_proc_lock);
	if (!task)
		return -ESRCH;

	read_lock(&tasklist_lock);
	thread_count = 1;
	for_each_thread(task, iter)
		thread_count++;
	read_unlock(&tasklist_lock);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		put_task_struct(task);
		return -ENOMEM;
	}

	refcount_set(&info->refs, 1);
	init_completion(&info->released);
	info->removing = false;

	info->hits = kcalloc(SHANZI_HWBP_MAX_HITS, sizeof(*info->hits), GFP_KERNEL);
	if (!info->hits) {
		put_task_struct(task);
		kfree(info);
		return -ENOMEM;
	}

	info->bps = kcalloc(thread_count, sizeof(*info->bps), GFP_KERNEL);
	if (!info->bps) {
		put_task_struct(task);
		kfree(info->hits);
		kfree(info);
		return -ENOMEM;
	}

	threads = kcalloc(thread_count, sizeof(*threads), GFP_KERNEL);
	if (!threads) {
		put_task_struct(task);
		kfree(info->bps);
		kfree(info->hits);
		kfree(info);
		return -ENOMEM;
	}

	read_lock(&tasklist_lock);
	get_task_struct(task);
	threads[i++] = task;
	for_each_thread(task, iter) {
		if (i >= thread_count)
			break;
		get_task_struct(iter);
		threads[i++] = iter;
	}
	read_unlock(&tasklist_lock);
	put_task_struct(task);
	thread_count = i;

	info->task_id = pid_nr(proc_handle->pid);
	SHZ_INFO("Shanzi: add hwbp pid=%llu addr=0x%llx len=%u type=%u threads=%u\n",
		(unsigned long long)info->task_id,
		(unsigned long long)cmd.address, cmd.bp_len, cmd.bp_type,
		thread_count);
	ptrace_breakpoint_init(&info->original_attr);
	info->original_attr.bp_addr = cmd.address;
	info->original_attr.bp_len = cmd.bp_len;
	info->original_attr.bp_type = cmd.bp_type;
	info->original_attr.disabled = 0;

	for (i = 0; i < thread_count; i++) {
		struct perf_event *bp;

		bp = shanzi_register_user_hw_breakpoint_fn(
			&info->original_attr, shanzi_hwbp_handler, NULL,
			threads[i]);
		put_task_struct(threads[i]);
		if (IS_ERR(bp)) {
			ret = PTR_ERR(bp);
			pr_err("Shanzi: register hwbp failed pid=%llu idx=%u/%u addr=0x%llx err=%ld\n",
			       (unsigned long long)info->task_id, i, thread_count,
			       (unsigned long long)cmd.address, ret);
			break;
		}
		info->bps[info->bp_count++] = bp;
	}
	kfree(threads);
	if (ret || !info->bp_count) {
		shanzi_hwbp_destroy(info);
		return ret ? ret : -EINVAL;
	}

	spin_lock_irqsave(&shanzi_hwbp_lock, flags);
	list_add_tail(&info->link, &shanzi_hwbp_handles);
	spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
	shanzi_virtual_target_get((pid_t)info->task_id);
	SHZ_INFO("Shanzi: add hwbp success pid=%llu addr=0x%llx installed=%u handle=0x%llx\n",
		(unsigned long long)info->task_id,
		(unsigned long long)cmd.address, info->bp_count,
		(unsigned long long)(uintptr_t)info);

	cmd.hwbp_handle = (uint64_t)(uintptr_t)info;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd))) {
		shanzi_ioctl_hwbp_remove(cmd.hwbp_handle);
		return -EFAULT;
	}
	return 0;
}

static long shanzi_ioctl_hwbp_remove(uint64_t handle)
{
	struct shanzi_hwbp_handle_info *info;
	unsigned long flags;

	if (!handle)
		return -EINVAL;

	spin_lock_irqsave(&shanzi_hwbp_lock, flags);
	info = shanzi_find_hwbp_handle_get_locked(handle);
	if (info)
		SHZ_INFO("Shanzi: del hwbp handle=0x%llx bp_count=%u hit_count=%u total=%llu\n",
			(unsigned long long)handle, info->bp_count,
			info->hit_count,
			(unsigned long long)info->hit_total_count);
	if (info) {
		info->removing = true;
		list_del(&info->link);
	}
	spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
	if (!info)
		return -ENOENT;

	shanzi_virtual_target_put((pid_t)info->task_id);
	shanzi_hwbp_put(info);
	shanzi_hwbp_put(info);
	wait_for_completion(&info->released);
	shanzi_hwbp_destroy(info);
	return 0;
}

static long shanzi_ioctl_hwbp_del_process_bp(unsigned long arg)
{
	struct shanzi_hwbp_u64_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	return shanzi_ioctl_hwbp_remove(cmd.value);
}

static long shanzi_ioctl_hwbp_toggle(unsigned long arg, bool enable)
{
	struct shanzi_hwbp_u64_cmd cmd;
	struct shanzi_hwbp_handle_info *info;
	struct perf_event_attr attr;
	unsigned long flags;
	int ret = 0;
	uint32_t i;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.value)
		return -EINVAL;

	spin_lock_irqsave(&shanzi_hwbp_lock, flags);
	info = shanzi_find_hwbp_handle_get_locked(cmd.value);
	if (!info) {
		spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
		return -ENOENT;
	}
	SHZ_INFO("Shanzi: %s hwbp handle=0x%llx bp_count=%u hit_count=%u total=%llu\n",
		enable ? "resume" : "suspend",
		(unsigned long long)cmd.value, info->bp_count, info->hit_count,
		(unsigned long long)info->hit_total_count);
	attr = info->original_attr;
	attr.disabled = enable ? 0 : 1;
	info->original_attr.disabled = attr.disabled;
	spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);

	for (i = 0; i < info->bp_count; i++) {
		ret = shanzi_modify_user_hw_breakpoint_fn(info->bps[i], &attr);
		if (ret) {
			pr_err("Shanzi: %s hwbp handle=0x%llx idx=%u/%u err=%d\n",
			       enable ? "resume" : "suspend",
			       (unsigned long long)cmd.value, i, info->bp_count,
			       ret);
			shanzi_hwbp_put(info);
			return ret;
		}
	}
	SHZ_INFO("Shanzi: %s hwbp handle=0x%llx done\n",
		enable ? "resume" : "suspend",
		(unsigned long long)cmd.value);
	shanzi_hwbp_put(info);
	return 0;
}

static long shanzi_ioctl_hwbp_get_hit_count(unsigned long arg)
{
	struct shanzi_hwbp_count_cmd cmd;
	struct shanzi_hwbp_handle_info *info;
	unsigned long flags;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.hwbp_handle)
		return -EINVAL;

	spin_lock_irqsave(&shanzi_hwbp_lock, flags);
	info = shanzi_find_hwbp_handle_get_locked(cmd.hwbp_handle);
	if (info) {
		cmd.hit_total_count = info->hit_total_count;
		cmd.hit_item_count = info->hit_count;
		SHZ_INFO("Shanzi: get_hit_count handle=0x%llx hit_count=%u total=%llu\n",
			(unsigned long long)cmd.hwbp_handle, info->hit_count,
			(unsigned long long)info->hit_total_count);
	}
	spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
	if (!info)
		return -ENOENT;
	shanzi_hwbp_put(info);

	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static long shanzi_ioctl_hwbp_read_hit_info(unsigned long arg)
{
	struct shanzi_hwbp_read_cmd cmd;
	struct shanzi_hwbp_handle_info *info;
	struct shanzi_hwbp_hit_item *tmp;
	size_t remaining;
	unsigned long flags;
	size_t count;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.hwbp_handle || !cmd.user_buffer || !cmd.capacity)
		return -EINVAL;

	spin_lock_irqsave(&shanzi_hwbp_lock, flags);
	info = shanzi_find_hwbp_handle_get_locked(cmd.hwbp_handle);
	if (!info) {
		spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
		return -ENOENT;
	}
	count = min_t(size_t, info->hit_count, cmd.capacity);
	SHZ_INFO("Shanzi: read_hit_info handle=0x%llx req=%llu copy=%zu hit_count=%u total=%llu\n",
		(unsigned long long)cmd.hwbp_handle,
		(unsigned long long)cmd.capacity, count, info->hit_count,
		(unsigned long long)info->hit_total_count);
	tmp = kmemdup(info->hits, count * sizeof(*tmp), GFP_ATOMIC);
	spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
	shanzi_hwbp_put(info);
	if (!tmp)
		return -ENOMEM;

	if (copy_to_user((void __user *)(uintptr_t)cmd.user_buffer, tmp,
			 count * sizeof(*tmp))) {
		kfree(tmp);
		return -EFAULT;
	}

	if (count > 0) {
		spin_lock_irqsave(&shanzi_hwbp_lock, flags);
		info = shanzi_find_hwbp_handle_get_locked(cmd.hwbp_handle);
		if (info) {
			if (count > info->hit_count)
				count = info->hit_count;
			remaining = info->hit_count - count;
			if (remaining > 0)
				memmove(info->hits, info->hits + count,
					remaining * sizeof(*info->hits));
			info->hit_count = remaining;
			shanzi_hwbp_put(info);
		}
		spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
	}
	kfree(tmp);

	cmd.copied = count;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;
	return 0;
}

static long shanzi_ioctl_hwbp_set_hook_pc(unsigned long arg)
{
	struct shanzi_hwbp_u64_cmd cmd;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	atomic64_set(&shanzi_hook_pc, cmd.value);
	return 0;
}

static void shanzi_cleanup_all_hwbp(void)
{
	struct shanzi_hwbp_handle_info *info, *tmp;
	unsigned long flags;

	for (;;) {
		spin_lock_irqsave(&shanzi_hwbp_lock, flags);
		if (list_empty(&shanzi_hwbp_handles)) {
			spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
			break;
		}
		info = list_first_entry(&shanzi_hwbp_handles,
				       struct shanzi_hwbp_handle_info, link);
		info->removing = true;
		list_del(&info->link);
		spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
		shanzi_virtual_target_put((pid_t)info->task_id);

		shanzi_hwbp_put(info);
		shanzi_hwbp_put(info);
		wait_for_completion(&info->released);
		shanzi_hwbp_destroy(info);
	}

	spin_lock_irqsave(&shanzi_hwbp_lock, flags);
	list_for_each_entry_safe(info, tmp, &shanzi_hwbp_handles, link)
		list_del(&info->link);
	spin_unlock_irqrestore(&shanzi_hwbp_lock, flags);
}

static void shanzi_cleanup_all_proc_handles(void)
{
	struct shanzi_proc_handle *entry, *tmp;

	mutex_lock(&shanzi_proc_lock);
	list_for_each_entry_safe(entry, tmp, &shanzi_proc_handles, link) {
		list_del(&entry->link);
		put_pid(entry->pid);
		kfree(entry);
	}
	mutex_unlock(&shanzi_proc_lock);
}

static long hello_ioctl_get_pid(unsigned long arg)
{
	struct paradise_get_pid_cmd cmd;
	int pid;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;

	cmd.name[sizeof(cmd.name) - 1] = '\0';
	pid = find_process_by_name(cmd.name);
	if (pid <= 0)
		return pid ? pid : -ENAVAIL;

	cmd.pid = pid;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return 0;
}

static long hello_ioctl_get_module_base(unsigned long arg)
{
	struct paradise_get_module_base_cmd cmd;
	uintptr_t base;
	uintptr_t end;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;

	cmd.name[sizeof(cmd.name) - 1] = '\0';
	if (!get_module_bounds(cmd.pid, cmd.name, (unsigned long)cmd.vm_flag, &base, &end))
		return -ENAVAIL;

	cmd.base = base;
	cmd.end = end;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return 0;
}

static long do_read_physical_memory(unsigned long arg)
{
	struct paradise_memory_fast_cmd cmd;
	struct pid *kpid;
	struct task_struct *task;
	struct mm_struct *mm;
	pgprot_t prot;
	uintptr_t first_phys = 0;
	void *bounce = NULL;
	size_t bounce_size;
	size_t buffered = 0;
	size_t copied = 0;
	size_t done = 0;
	long ret = 0;
	u8 stack_buf[SHANZI_READ_STACK_BUF_SIZE];

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;

	if (cmd.pid <= 0 || !cmd.src_va || !cmd.dst_va || !cmd.size)
		return -EINVAL;
	if (cmd.size > SHANZI_READ_MAX_SIZE)
		return -EINVAL;
	if (convert_wmt_to_pgprot(cmd.prot, &prot))
		return -EINVAL;

	ret = lockfree_va_to_pa(cmd.pid, cmd.src_va, &first_phys);
	if (ret)
		return ret;

	cmd.phy_addr = first_phys;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	ret = shanzi_pte_pool_ensure();
	if (ret)
		return ret;

	bounce_size = min_t(size_t, cmd.size, SHANZI_READ_MAX_SIZE);
	if (bounce_size <= sizeof(stack_buf)) {
		bounce = stack_buf;
		bounce_size = sizeof(stack_buf);
	} else {
		bounce = kmalloc(bounce_size, GFP_KERNEL);
		if (!bounce) {
			bounce_size = PAGE_SIZE;
			bounce = kmalloc(bounce_size, GFP_KERNEL);
			if (!bounce)
				return -ENOMEM;
		}
	}

	kpid = find_get_pid(cmd.pid);
	if (!kpid) {
		ret = -ESRCH;
		goto out_free_bounce;
	}
	task = get_pid_task(kpid, PIDTYPE_PID);
	put_pid(kpid);
	if (!task) {
		ret = -ESRCH;
		goto out_free_bounce;
	}
	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm) {
		ret = -ESRCH;
		goto out_free_bounce;
	}

	while (done < cmd.size) {
		uintptr_t cur = cmd.src_va + done;
		uintptr_t cur_phys = 0;
		size_t page_off = 0;
		size_t chunk;
		size_t room = bounce_size - buffered;
		void *kaddr;

		chunk = min_t(size_t, cmd.size - done, PAGE_SIZE);
		if (chunk > room) {
			if (copy_to_user((void __user *)(cmd.dst_va + copied), bounce, buffered)) {
				ret = -EFAULT;
				break;
			}
			copied += buffered;
			buffered = 0;
			room = bounce_size;
		}
		if (chunk > room)
			chunk = room;

		ret = lockfree_va_to_pa(cmd.pid, cur, &cur_phys);
		if (ret)
			break;

		page_off = offset_in_page(cur_phys);
		chunk = min_t(size_t, cmd.size - done, PAGE_SIZE - page_off);
		if (chunk > room)
			chunk = room;

		kaddr = shanzi_map_phys_page(cur_phys, &page_off);
		if (!kaddr) {
			ret = -EFAULT;
			break;
		}

		memcpy((u8 *)bounce + buffered, kaddr, chunk);
		shanzi_unmap_phys_page();
		buffered += chunk;
		ret = 0;
		if (ret)
			break;
		done += chunk;
	}

	if (!ret && buffered) {
		if (copy_to_user((void __user *)(cmd.dst_va + copied), bounce, buffered))
			ret = -EFAULT;
	}

	mmput(mm);
out_free_bounce:
	if (bounce && bounce != stack_buf)
		kfree(bounce);
	return ret;
}

static long hello_ioctl_hide_process(unsigned long arg)
{
	struct paradise_hide_process_cmd cmd;
	struct shanzi_hidden_proc *hidden;
	struct pid *kpid;
	struct task_struct *task;
	long ret;
	unsigned int flags;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (!cmd.pid)
		return -EINVAL;

	ret = shanzi_resolve_hide_helpers();
	if (ret)
		return ret;

	mutex_lock(&shanzi_hide_lock);
	hidden = shanzi_find_hidden_proc(cmd.pid);
	if (!cmd.hide) {
		if (!hidden) {
			mutex_unlock(&shanzi_hide_lock);
			return -ESRCH;
		}
		list_del(&hidden->link);
		mutex_unlock(&shanzi_hide_lock);
		shanzi_cleanup_hidden_proc(hidden);
		SHZ_INFO("Shanzi: unhid pid %u\n", cmd.pid);
		return 0;
	}

	if (hidden) {
		mutex_unlock(&shanzi_hide_lock);
		return 0;
	}

	kpid = find_get_pid((pid_t)cmd.pid);
	if (!kpid) {
		mutex_unlock(&shanzi_hide_lock);
		return -ESRCH;
	}

	task = get_pid_task(kpid, PIDTYPE_PID);
	put_pid(kpid);
	if (!task) {
		mutex_unlock(&shanzi_hide_lock);
		return -ESRCH;
	}

	hidden = kzalloc(sizeof(*hidden), GFP_KERNEL);
	if (!hidden) {
		put_task_struct(task);
		mutex_unlock(&shanzi_hide_lock);
		return -ENOMEM;
	}

	hidden->pid = cmd.pid;
	hidden->task = task;

	flags = READ_ONCE(task->flags);
	flags |= BIT(28);
	WRITE_ONCE(task->flags, flags);

	if (shanzi_tasklist_lock_ptr && shanzi_init_task_ptr) {
		write_lock_irq(shanzi_tasklist_lock_ptr);
		if (!list_empty(&task->tasks)) {
			list_del_init(&task->tasks);
			hidden->tasks_unlinked = true;
		}
		write_unlock_irq(shanzi_tasklist_lock_ptr);
	} else {
		SHZ_INFO("Shanzi: hide: tasklist_lock/init_task not found, task list unlink disabled\n");
	}

	{
		char path_buf[64];

		snprintf(path_buf, sizeof(path_buf), "/proc/%u", cmd.pid);
		if (!shanzi_hide_mount_tmpfs(path_buf))
			hidden->proc_mounted = true;
		else
			SHZ_INFO("Shanzi: hide: mount over %s failed\n", path_buf);

		snprintf(path_buf, sizeof(path_buf),
			 "/sys/fs/cgroup/uid_0/pid_%u", cmd.pid);
		if (!shanzi_hide_mount_tmpfs(path_buf))
			hidden->cgroup_mounted = true;

		snprintf(path_buf, sizeof(path_buf),
			 "/sys/devices/virtual/kgsl/kgsl/proc/%u", cmd.pid);
		if (!shanzi_hide_mount_tmpfs(path_buf))
			hidden->kgsl_mounted = true;
	}

	list_add(&hidden->link, &shanzi_hidden_procs);
	mutex_unlock(&shanzi_hide_lock);
	SHZ_INFO("Shanzi: hid pid %u (unlinked=%d proc=%d cgroup=%d kgsl=%d)\n",
		cmd.pid, hidden->tasks_unlinked, hidden->proc_mounted,
		hidden->cgroup_mounted, hidden->kgsl_mounted);
	return 0;
}

static long hello_unlocked_ioctl(struct file *file, unsigned int cmd,
				 unsigned long arg)
{
	switch (cmd) {
	case PARADISE_IOCTL_READ_MEMORY_FAST:
		return do_read_physical_memory(arg);
	case PARADISE_IOCTL_HIDE_PROCESS:
		return hello_ioctl_hide_process(arg);
	case SHANZI_IOCTL_HIDE_MODULE:
		return shanzi_ioctl_hide_module(arg);
	case PARADISE_IOCTL_TOUCH_DOWN:
		return hello_ioctl_touch_down(arg);
	case PARADISE_IOCTL_TOUCH_MOVE:
		return hello_ioctl_touch_move(arg);
	case PARADISE_IOCTL_TOUCH_UP:
		return hello_ioctl_touch_up(arg);
	case PARADISE_IOCTL_TOUCH_SET_MODE:
		return hello_ioctl_touch_set_mode(arg);
	case PARADISE_IOCTL_GET_MODULE_BASE:
		return hello_ioctl_get_module_base(arg);
	case PARADISE_IOCTL_GET_PID:
		return hello_ioctl_get_pid(arg);
	case SHANZI_IOCTL_HWBP_OPEN_PROCESS:
		return shanzi_ioctl_hwbp_open_process(arg);
	case SHANZI_IOCTL_HWBP_CLOSE_HANDLE:
		return shanzi_ioctl_hwbp_close_handle(arg);
	case SHANZI_IOCTL_HWBP_GET_NUM_BRPS:
		return shanzi_ioctl_hwbp_get_num(arg, TYPE_INST);
	case SHANZI_IOCTL_HWBP_GET_NUM_WRPS:
		return shanzi_ioctl_hwbp_get_num(arg, TYPE_DATA);
	case SHANZI_IOCTL_HWBP_ADD_PROCESS_BP:
		return shanzi_ioctl_hwbp_add_process_bp(arg);
	case SHANZI_IOCTL_HWBP_DEL_PROCESS_BP:
		return shanzi_ioctl_hwbp_del_process_bp(arg);
	case SHANZI_IOCTL_HWBP_SUSPEND_PROCESS_BP:
		return shanzi_ioctl_hwbp_toggle(arg, false);
	case SHANZI_IOCTL_HWBP_RESUME_PROCESS_BP:
		return shanzi_ioctl_hwbp_toggle(arg, true);
	case SHANZI_IOCTL_HWBP_GET_HIT_COUNT:
		return shanzi_ioctl_hwbp_get_hit_count(arg);
	case SHANZI_IOCTL_HWBP_READ_HIT_INFO:
		return shanzi_ioctl_hwbp_read_hit_info(arg);
	case SHANZI_IOCTL_HWBP_SET_HOOK_PC:
		return shanzi_ioctl_hwbp_set_hook_pc(arg);
	default:
		return -ENOTTY;
	}
}

static int hello_open(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t hello_read(struct file *file, char __user *buf, size_t count,
			  loff_t *ppos)
{
	size_t copied = 0;

	if (count < sizeof(struct shanzi_ring_event))
		return -EINVAL;

	mutex_lock(&shanzi_ring_lock);
	while (!shanzi_ring_empty() &&
	       count - copied >= sizeof(struct shanzi_ring_event)) {
		struct shanzi_ring_event evt = shanzi_ring_q[shanzi_ring_tail];

		shanzi_ring_tail = (shanzi_ring_tail + 1) % SHANZI_RING_CAPACITY;
		mutex_unlock(&shanzi_ring_lock);
		if (copy_to_user(buf + copied, &evt, sizeof(evt)))
			return copied ? (ssize_t)copied : -EFAULT;
		copied += sizeof(evt);
		mutex_lock(&shanzi_ring_lock);
	}
	mutex_unlock(&shanzi_ring_lock);

	return copied;
}

static __poll_t hello_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;

	poll_wait(file, &shanzi_ring_waitq, wait);
	mutex_lock(&shanzi_ring_lock);
	if (!shanzi_ring_empty())
		mask |= POLLIN | POLLRDNORM;
	mutex_unlock(&shanzi_ring_lock);
	return mask;
}

static int hello_release(struct inode *inode, struct file *file)
{
	shanzi_cleanup_all_hwbp();
	shanzi_cleanup_all_proc_handles();
	shanzi_cleanup_all_hidden_procs();
	shanzi_cleanup_all_virtual_targets();
	shanzi_pte_phys_cleanup();
	memset(g_active_touches, 0, sizeof(g_active_touches));
	g_touch_initialized = false;
	g_touch_dev = NULL;
	atomic64_set(&shanzi_hook_pc, 0);
	return 0;
}

static const struct file_operations hello_fops = {
	.owner = THIS_MODULE,
	.open = hello_open,
	.read = hello_read,
	.poll = hello_poll,
	.release = hello_release,
	.unlocked_ioctl = hello_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = hello_unlocked_ioctl,
#endif
};

static int __init shanzi_init(void)
{
	int ret;

	hello_major = register_chrdev(0, HELLO_DEVICE_NAME, &hello_fops);
	if (hello_major < 0)
		return hello_major;

	hello_class = class_create(HELLO_DEVICE_NAME);
	if (IS_ERR(hello_class)) {
		ret = PTR_ERR(hello_class);
		goto err_chrdev;
	}

	hello_device = device_create(hello_class, NULL, MKDEV(hello_major, 0), NULL,
				     HELLO_DEVICE_NAME);
	if (IS_ERR(hello_device)) {
		ret = PTR_ERR(hello_device);
		goto err_class;
	}

	shanzi_hide_module_auto();
	if (shanzi_install_ptrace_virtualization())
		SHZ_INFO("Shanzi: ptrace virtualization unavailable, continuing without it\n");
	SHZ_INFO("Shanzi: loaded, device /dev/%s ready\n", HELLO_DEVICE_NAME);
	return 0;

err_class:
	class_destroy(hello_class);
err_chrdev:
	unregister_chrdev(hello_major, HELLO_DEVICE_NAME);
	return ret;
}

static void __exit shanzi_exit(void)
{
	if (shanzi_module_hidden && shanzi_module_prev) {
		mutex_lock(&shanzi_module_hide_lock);
		if (shanzi_module_hidden) {
			if (shanzi_module_mutex_ptr)
				mutex_lock(shanzi_module_mutex_ptr);
			list_add(&THIS_MODULE->list, shanzi_module_prev);
			if (shanzi_module_mutex_ptr)
				mutex_unlock(shanzi_module_mutex_ptr);
			shanzi_module_hidden = false;
			shanzi_module_prev = NULL;
		}
		mutex_unlock(&shanzi_module_hide_lock);
	}

	shanzi_remove_ptrace_virtualization();
	device_destroy(hello_class, MKDEV(hello_major, 0));
	class_destroy(hello_class);
	unregister_chrdev(hello_major, HELLO_DEVICE_NAME);
	shanzi_cleanup_all_hwbp();
	shanzi_cleanup_all_proc_handles();
	shanzi_cleanup_all_hidden_procs();
	shanzi_cleanup_all_virtual_targets();
	shanzi_cleanup_all_bp_stats();
	shanzi_pte_phys_cleanup();
	memset(g_active_touches, 0, sizeof(g_active_touches));
	g_touch_initialized = false;
	g_touch_dev = NULL;
	SHZ_INFO("Shanzi: module unloaded\n");
}

module_init(shanzi_init);
module_exit(shanzi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Codex");
MODULE_DESCRIPTION("Shanzi driver with Paradise-compatible memory and HWBP ioctls");
MODULE_VERSION("1.2");
