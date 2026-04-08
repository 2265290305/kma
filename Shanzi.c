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
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <asm/cputype.h>
#include <asm/hw_breakpoint.h>

#define HELLO_DEVICE_NAME "Shanzi"

#ifdef SHANZI_RELEASE_BUILD
#define SHZ_INFO(fmt, ...) do { } while (0)
#define SHZ_ERR(fmt, ...) pr_err(fmt, ##__VA_ARGS__)
#else
#define SHZ_INFO(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#define SHZ_ERR(fmt, ...) pr_err(fmt, ##__VA_ARGS__)
#endif

struct paradise_get_pid_cmd {
	pid_t pid;
	char name[256];
};

struct paradise_get_module_base_cmd {
	pid_t pid;
	char name[256];
	uintptr_t base;
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
static DECLARE_WAIT_QUEUE_HEAD(shanzi_ring_waitq);
static DEFINE_SPINLOCK(shanzi_hwbp_lock);
static LIST_HEAD(shanzi_hwbp_handles);
static struct shanzi_ring_event shanzi_ring_q[SHANZI_RING_CAPACITY];
static uint32_t shanzi_ring_head;
static uint32_t shanzi_ring_tail;
static atomic64_t shanzi_hook_pc = ATOMIC64_INIT(0);
static int shanzi_touch_mode;

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

static long shanzi_ioctl_hwbp_remove(uint64_t handle);

static char *shz_xor_dup(const unsigned char *enc, size_t len, unsigned char key)
{
	char *out;
	size_t i;

	out = kmalloc(len + 1, GFP_KERNEL);
	if (!out)
		return NULL;

	for (i = 0; i < len; i++)
		out[i] = enc[i] ^ key;
	out[len] = '\0';
	return out;
}

static int shz_make_proc_path(char *buf, size_t size, uint32_t pid)
{
	static const unsigned char enc[] = {
		0x2b, 0x74, 0x27, 0x39, 0x34, 0x36, 0x74, 0x70, 0x28
	};
	char *fmt = shz_xor_dup(enc, sizeof(enc), 0x04);
	int ret;

	if (!fmt)
		return -ENOMEM;
	ret = snprintf(buf, size, fmt, pid);
	kfree(fmt);
	return ret;
}

static int shz_make_cgroup_path(char *buf, size_t size, uint32_t pid)
{
	static const unsigned char enc[] = {
		0x66, 0x2a, 0x2c, 0x2a, 0x66, 0x38, 0x3a, 0x66, 0x38, 0x3c,
		0x2e, 0x39, 0x34, 0x22, 0x37, 0x66, 0x2c, 0x22, 0x31, 0x74,
		0x35, 0x66, 0x35, 0x2e, 0x31, 0x74, 0x7c, 0x6a
	};
	char *fmt = shz_xor_dup(enc, sizeof(enc), 0x49);
	int ret;

	if (!fmt)
		return -ENOMEM;
	ret = snprintf(buf, size, fmt, pid);
	kfree(fmt);
	return ret;
}

static int shz_make_kgsl_path(char *buf, size_t size, uint32_t pid)
{
	static const unsigned char enc[] = {
		0x13, 0x5e, 0x04, 0x0c, 0x13, 0x13, 0x12, 0x0c, 0x1f, 0x13,
		0x13, 0x01, 0x1d, 0x06, 0x13, 0x12, 0x0c, 0x1f, 0x07, 0x14,
		0x06, 0x13, 0x1f, 0x13, 0x07, 0x16, 0x5d, 0x47
	};
	char *fmt = shz_xor_dup(enc, sizeof(enc), 0x3c);
	int ret;

	if (!fmt)
		return -ENOMEM;
	ret = snprintf(buf, size, fmt, pid);
	kfree(fmt);
	return ret;
}

static unsigned long shanzi_lookup_symbol(const char *name)
{
	static const unsigned char enc[] = {
		0x20, 0x2a, 0x27, 0x27, 0x38, 0x32, 0x26, 0x34,
		0x34, 0x3b, 0x3e, 0x0c, 0x27, 0x34, 0x34, 0x3e,
		0x22, 0x25, 0x08, 0x23, 0x34, 0x38, 0x3e
	};
	char *sym;
	struct kprobe kp = {};
	unsigned long addr = 0;

	if (shanzi_kallsyms_lookup_name)
		return shanzi_kallsyms_lookup_name(name);

	sym = shz_xor_dup(enc, sizeof(enc), 0x4b);
	if (!sym)
		return 0;
	kp.symbol_name = sym;
	if (register_kprobe(&kp) == 0) {
		shanzi_kallsyms_lookup_name = (void *)kp.addr;
		unregister_kprobe(&kp);
	}
	kfree(sym);
	if (shanzi_kallsyms_lookup_name)
		addr = shanzi_kallsyms_lookup_name(name);
	return addr;
}

static int shanzi_resolve_hide_helpers(void)
{
	static const unsigned char enc_kern_path[] = {
		0x5f, 0x51, 0x46, 0x5a, 0x0b, 0x44, 0x5a, 0x4f
	};
	static const unsigned char enc_path_put[] = {
		0x44, 0x55, 0x40, 0x5c, 0x0b, 0x44, 0x40, 0x41
	};
	static const unsigned char enc_path_umount[] = {
		0x69, 0x78, 0x6d, 0x71, 0x22, 0x6d, 0x71, 0x79,
		0x5f, 0x79, 0x63, 0x62
	};
	static const unsigned char enc_path_mount[] = {
		0x69, 0x78, 0x6d, 0x71, 0x22, 0x7f, 0x63, 0x71,
		0x6c, 0x70
	};
	static const unsigned char enc_tasklist_lock[] = {
		0x31, 0x24, 0x36, 0x2e, 0x29, 0x2c, 0x36, 0x31,
		0x3a, 0x2a, 0x27, 0x2d, 0x3f
	};
	static const unsigned char enc_init_task[] = {
		0x22, 0x25, 0x22, 0x3f, 0x34, 0x29, 0x3f, 0x2a,
		0x38
	};
	char *sym;

	if (!shanzi_kern_path_fn)
	{
		sym = shz_xor_dup(enc_kern_path, sizeof(enc_kern_path), 0x34);
		if (!sym)
			return -ENOMEM;
		shanzi_kern_path_fn = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	if (!shanzi_path_put_fn)
	{
		sym = shz_xor_dup(enc_path_put, sizeof(enc_path_put), 0x34);
		if (!sym)
			return -ENOMEM;
		shanzi_path_put_fn = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	if (!shanzi_path_umount_fn)
	{
		sym = shz_xor_dup(enc_path_umount, sizeof(enc_path_umount), 0x19);
		if (!sym)
			return -ENOMEM;
		shanzi_path_umount_fn = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	if (!shanzi_path_mount_fn)
	{
		sym = shz_xor_dup(enc_path_mount, sizeof(enc_path_mount), 0x19);
		if (!sym)
			return -ENOMEM;
		shanzi_path_mount_fn = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}

	if (!shanzi_kern_path_fn || !shanzi_path_put_fn ||
	    !shanzi_path_umount_fn || !shanzi_path_mount_fn)
		return -ENOENT;

	if (!shanzi_tasklist_lock_ptr)
	{
		sym = shz_xor_dup(enc_tasklist_lock, sizeof(enc_tasklist_lock), 0x45);
		if (!sym)
			return -ENOMEM;
		shanzi_tasklist_lock_ptr = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	if (!shanzi_init_task_ptr)
	{
		sym = shz_xor_dup(enc_init_task, sizeof(enc_init_task), 0x4b);
		if (!sym)
			return -ENOMEM;
		shanzi_init_task_ptr = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	return 0;
}

static int shanzi_resolve_module_hide_helpers(void)
{
	static const unsigned char enc_module_mutex[] = {
		0x3b, 0x35, 0x32, 0x23, 0x3a, 0x35, 0x2f, 0x3d,
		0x3d, 0x23, 0x32, 0x29
	};
	char *sym;

	if (!shanzi_module_mutex_ptr)
	{
		sym = shz_xor_dup(enc_module_mutex, sizeof(enc_module_mutex), 0x56);
		if (!sym)
			return -ENOMEM;
		shanzi_module_mutex_ptr = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}

	if (!shanzi_module_mutex_ptr)
		return -ENOENT;

	return 0;
}

static int shanzi_resolve_task_helpers(void)
{
	static const unsigned char enc_tasklist_lock[] = {
		0x31, 0x24, 0x36, 0x2e, 0x29, 0x2c, 0x36, 0x31,
		0x3a, 0x2a, 0x27, 0x2d, 0x3f
	};
	static const unsigned char enc_init_task[] = {
		0x22, 0x25, 0x22, 0x3f, 0x34, 0x29, 0x3f, 0x2a,
		0x38
	};
	char *sym;

	if (!shanzi_tasklist_lock_ptr) {
		sym = shz_xor_dup(enc_tasklist_lock, sizeof(enc_tasklist_lock), 0x45);
		if (!sym)
			return -ENOMEM;
		shanzi_tasklist_lock_ptr = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	if (!shanzi_init_task_ptr) {
		sym = shz_xor_dup(enc_init_task, sizeof(enc_init_task), 0x4b);
		if (!sym)
			return -ENOMEM;
		shanzi_init_task_ptr = (void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	return shanzi_tasklist_lock_ptr ? 0 : -ENOENT;
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
	static const unsigned char enc_data[] = {
		0x12, 0x0a, 0x01, 0x16, 0x4f, 0x5d, 0x42, 0x5a,
		0x55, 0x56, 0x5c, 0x4f, 0x52, 0x5c
	};
	static const unsigned char enc_tmpfs[] = {
		0x2d, 0x34, 0x28, 0x3f, 0x2d
	};
	struct path mount_path;
	char *mount_data;
	char *tmpfs;
	int ret;

	ret = shanzi_kern_path_fn(path, LOOKUP_FOLLOW, &mount_path);
	if (ret)
		return ret;

	mount_data = shz_xor_dup(enc_data, sizeof(enc_data), 0x61);
	tmpfs = shz_xor_dup(enc_tmpfs, sizeof(enc_tmpfs), 0x59);
	if (!mount_data || !tmpfs) {
		kfree(mount_data);
		kfree(tmpfs);
		shanzi_path_put_fn(&mount_path);
		return -ENOMEM;
	}
	ret = shanzi_path_mount_fn(tmpfs, &mount_path, tmpfs, 0, mount_data);
	kfree(mount_data);
	kfree(tmpfs);
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
		shz_make_proc_path(path_buf, sizeof(path_buf), hidden->pid);
		shanzi_hide_umount_path(path_buf);
	}
	if (hidden->cgroup_mounted) {
		shz_make_cgroup_path(path_buf, sizeof(path_buf), hidden->pid);
		shanzi_hide_umount_path(path_buf);
	}
	if (hidden->kgsl_mounted) {
		shz_make_kgsl_path(path_buf, sizeof(path_buf), hidden->pid);
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

static long hello_ioctl_touch_down(unsigned long arg)
{
	struct paradise_touch_down_cmd cmd = {};

	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.slot < 0 || cmd.slot > 9)
		return -EINVAL;
	if (shanzi_touch_mode != 1)
		return 0;
	return shanzi_ring_queue_push(0, cmd.slot, cmd.x, cmd.y);
}

static long hello_ioctl_touch_move(unsigned long arg)
{
	struct paradise_touch_move_cmd cmd = {};

	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.slot < 0 || cmd.slot > 9)
		return -EINVAL;
	if (shanzi_touch_mode != 1)
		return 0;
	return shanzi_ring_queue_push(2, cmd.slot, cmd.x, cmd.y);
}

static long hello_ioctl_touch_up(unsigned long arg)
{
	struct paradise_touch_up_cmd cmd = {};

	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;
	if (cmd.slot < 0 || cmd.slot > 9)
		return -EINVAL;
	if (shanzi_touch_mode != 1)
		return 0;
	return shanzi_ring_queue_push(1, cmd.slot, 0, 0);
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
	static const unsigned char enc_reg[] = {
		0x27, 0x30, 0x32, 0x3c, 0x26, 0x21, 0x30, 0x27,
		0x0a, 0x20, 0x26, 0x30, 0x27, 0x0a, 0x3d, 0x22,
		0x17, 0x27, 0x30, 0x34, 0x3e, 0x25, 0x3a, 0x3c,
		0x3b, 0x21
	};
	static const unsigned char enc_mod[] = {
		0x72, 0x78, 0x79, 0x76, 0x7b, 0x65, 0x6c, 0x76,
		0x6b, 0x6a, 0x65, 0x70, 0x6c, 0x76, 0x6b, 0x6a,
		0x70, 0x63, 0x7a, 0x75, 0x76, 0x78, 0x72, 0x69,
		0x76, 0x7a, 0x75
	};
	static const unsigned char enc_unreg[] = {
		0x42, 0x41, 0x55, 0x52, 0x58, 0x5e, 0x44, 0x43,
		0x52, 0x41, 0x68, 0x42, 0x44, 0x52, 0x41, 0x68,
		0x5f, 0x40, 0x75, 0x41, 0x52, 0x56, 0x5c, 0x43,
		0x5d, 0x58, 0x5e, 0x43
	};
	char *sym;

	if (!shanzi_register_user_hw_breakpoint_fn)
	{
		sym = shz_xor_dup(enc_reg, sizeof(enc_reg), 0x55);
		if (!sym)
			return -ENOMEM;
		shanzi_register_user_hw_breakpoint_fn =
			(void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	if (!shanzi_modify_user_hw_breakpoint_fn)
	{
		sym = shz_xor_dup(enc_mod, sizeof(enc_mod), 0x1f);
		if (!sym)
			return -ENOMEM;
		shanzi_modify_user_hw_breakpoint_fn =
			(void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}
	if (!shanzi_unregister_hw_breakpoint_fn)
	{
		sym = shz_xor_dup(enc_unreg, sizeof(enc_unreg), 0x37);
		if (!sym)
			return -ENOMEM;
		shanzi_unregister_hw_breakpoint_fn =
			(void *)shanzi_lookup_symbol(sym);
		kfree(sym);
	}

	if (!shanzi_register_user_hw_breakpoint_fn ||
	    !shanzi_modify_user_hw_breakpoint_fn ||
	    !shanzi_unregister_hw_breakpoint_fn) {
		SHZ_ERR("hwbp resolve failed reg=%px mod=%px unreg=%px\n",
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
	int ret;

	needle_len = strnlen(name, sizeof(((struct paradise_get_pid_cmd *)0)->name));
	if (!needle_len)
		return -EINVAL;

	ret = shanzi_resolve_task_helpers();
	if (ret)
		return ret;

	read_lock(shanzi_tasklist_lock_ptr);
	for_each_process(task)
		count++;
	read_unlock(shanzi_tasklist_lock_ptr);

	if (!count)
		return 0;

	tasks = kcalloc(count, sizeof(*tasks), GFP_KERNEL);
	if (!tasks)
		return -ENOMEM;

	read_lock(shanzi_tasklist_lock_ptr);
	for_each_process(task) {
		if (i >= count)
			break;
		get_task_struct(task);
		tasks[i++] = task;
	}
	read_unlock(shanzi_tasklist_lock_ptr);

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

static uintptr_t get_module_base(pid_t pid, const char *name, unsigned long vm_flag)
{
	struct pid *kpid;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	size_t needle_len;
	uintptr_t base = 0;

	needle_len = strnlen(name, sizeof(((struct paradise_get_module_base_cmd *)0)->name));
	if (!needle_len)
		return 0;

	kpid = find_get_pid(pid);
	if (!kpid)
		return 0;

	task = get_pid_task(kpid, PIDTYPE_PID);
	put_pid(kpid);
	if (!task)
		return 0;

	mm = get_task_mm(task);
	put_task_struct(task);
	if (!mm)
		return 0;

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
			base = (uintptr_t)vma->vm_start;
			break;
		}
	}
	mmap_read_unlock(mm);
	mmput(mm);

	return base;
}

static long translate_process_vaddr(pid_t pid, uintptr_t vaddr, uintptr_t *phys_out)
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

	ret = shanzi_resolve_task_helpers();
	if (ret) {
		put_task_struct(task);
		return ret;
	}

	read_lock(shanzi_tasklist_lock_ptr);
	thread_count = 1;
	for_each_thread(task, iter)
		thread_count++;
	read_unlock(shanzi_tasklist_lock_ptr);

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

	read_lock(shanzi_tasklist_lock_ptr);
	get_task_struct(task);
	threads[i++] = task;
	for_each_thread(task, iter) {
		if (i >= thread_count)
			break;
		get_task_struct(iter);
		threads[i++] = iter;
	}
	read_unlock(shanzi_tasklist_lock_ptr);
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
			SHZ_ERR("register hwbp failed pid=%llu idx=%u/%u addr=0x%llx err=%ld\n",
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
			SHZ_ERR("Shanzi: %s hwbp handle=0x%llx idx=%u/%u err=%d\n",
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

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;

	cmd.name[sizeof(cmd.name) - 1] = '\0';
	base = get_module_base(cmd.pid, cmd.name, (unsigned long)cmd.vm_flag);
	if (!base)
		return -ENAVAIL;

	cmd.base = base;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	return 0;
}

static long hello_ioctl_read_memory_fast(unsigned long arg)
{
	struct paradise_memory_fast_cmd cmd;
	struct pid *kpid;
	struct task_struct *task;
	struct mm_struct *mm;
	pgprot_t prot;
	uintptr_t first_phys = 0;
	size_t done = 0;
	long ret = 0;

	memset(&cmd, 0, sizeof(cmd));
	if (copy_from_user(&cmd, (void __user *)arg, sizeof(cmd)))
		return -EFAULT;

	if (cmd.pid <= 0 || !cmd.src_va || !cmd.dst_va || !cmd.size)
		return -EINVAL;
	if (cmd.size > PAGE_SIZE)
		return -EINVAL;
	if (convert_wmt_to_pgprot(cmd.prot, &prot))
		return -EINVAL;

	ret = translate_process_vaddr(cmd.pid, cmd.src_va, &first_phys);
	if (ret)
		return ret;

	cmd.phy_addr = first_phys;
	if (copy_to_user((void __user *)arg, &cmd, sizeof(cmd)))
		return -EFAULT;

	kpid = find_get_pid(cmd.pid);
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

	while (done < cmd.size) {
		struct page *page = NULL;
		uintptr_t cur = cmd.src_va + done;
		size_t page_off = offset_in_page(cur);
		size_t chunk = min_t(size_t, cmd.size - done, PAGE_SIZE - page_off);
		int locked = 1;
		void *kaddr;

		mmap_read_lock(mm);
		ret = get_user_pages_remote(mm, cur & PAGE_MASK, 1, FOLL_FORCE,
					    &page, &locked);
		if (locked)
			mmap_read_unlock(mm);
		if (ret != 1 || !page) {
			ret = -EFAULT;
			break;
		}
		if (!pfn_valid(page_to_pfn(page))) {
			put_page(page);
			ret = -EFAULT;
			break;
		}

		kaddr = kmap_local_page(page);
		if (copy_to_user((void __user *)(cmd.dst_va + done),
				 (char *)kaddr + page_off, chunk))
			ret = -EFAULT;
		else
			ret = 0;
		kunmap_local(kaddr);
		put_page(page);
		if (ret)
			break;
		done += chunk;
	}

	mmput(mm);
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

		shz_make_proc_path(path_buf, sizeof(path_buf), cmd.pid);
		if (!shanzi_hide_mount_tmpfs(path_buf))
			hidden->proc_mounted = true;
		else
			SHZ_INFO("Shanzi: hide: mount over %s failed\n", path_buf);

		shz_make_cgroup_path(path_buf, sizeof(path_buf), cmd.pid);
		if (!shanzi_hide_mount_tmpfs(path_buf))
			hidden->cgroup_mounted = true;

		shz_make_kgsl_path(path_buf, sizeof(path_buf), cmd.pid);
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
		return hello_ioctl_read_memory_fast(arg);
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

	device_destroy(hello_class, MKDEV(hello_major, 0));
	class_destroy(hello_class);
	unregister_chrdev(hello_major, HELLO_DEVICE_NAME);
	shanzi_cleanup_all_hwbp();
	shanzi_cleanup_all_proc_handles();
	shanzi_cleanup_all_hidden_procs();
	SHZ_INFO("Shanzi: module unloaded\n");
}

module_init(shanzi_init);
module_exit(shanzi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Shanzi");
MODULE_DESCRIPTION("Shanzi kernel module");
MODULE_VERSION("1.2");
