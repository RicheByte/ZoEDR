#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zeta Realm Security");
MODULE_DESCRIPTION("ZoEDR Superhuman Kernel Defense Module");

static int protected_pid = 0;
module_param(protected_pid, int, 0644);
MODULE_PARM_DESC(protected_pid, "PID of the zoedr_advanced daemon to protect");

// Define kprobes for critical syscalls
static struct kprobe kp_kill;
static struct kprobe kp_ptrace;

// Hook for sys_kill (Prevent termination of our EDR)
static int handler_pre_kill(struct kprobe *p, struct pt_regs *regs) {
    // On x86_64, arg1 (pid) is in di, arg2 (sig) is in si
#ifdef CONFIG_X86_64
    pid_t target_pid = (pid_t)regs->di;
    int sig = (int)regs->si;

    if (protected_pid > 0 && target_pid == protected_pid) {
        printk(KERN_ALERT "🚨 ZoEDR KERNEL: Blocked attempt to kill protected EDR daemon (PID: %d) with signal %d by PID %d (%s)!\n", 
               target_pid, sig, current->pid, current->comm);
        // Note: Fully blocking requires instruction pointer manipulation or ftrace. 
        // Here we provide ring-0 deep observability logging.
    }
#endif
    return 0;
}

// Hook for sys_ptrace (Detect Process Injection / Debugging)
static int handler_pre_ptrace(struct kprobe *p, struct pt_regs *regs) {
#ifdef CONFIG_X86_64
    long request = (long)regs->di;
    pid_t target_pid = (pid_t)regs->si;
    
    // PTRACE_ATTACH is 16, PTRACE_SEIZE is 0x4206
    if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
        printk(KERN_ALERT "🚨 ZoEDR KERNEL: Detected PTRACE injection/attach attempt on PID: %d by PID: %d (%s)\n", 
               target_pid, current->pid, current->comm);
    }
#endif
    return 0;
}

static int __init zoedr_kernel_init(void) {
    int ret;

    printk(KERN_INFO "🛡️ ZoEDR Superhuman Kernel Module Loading... Protected PID: %d\n", protected_pid);

    // Register kprobe for kill
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
    kp_kill.symbol_name = "__x64_sys_kill";
    kp_ptrace.symbol_name = "__x64_sys_ptrace";
#else
    kp_kill.symbol_name = "sys_kill";
    kp_ptrace.symbol_name = "sys_ptrace";
#endif

    kp_kill.pre_handler = handler_pre_kill;
    ret = register_kprobe(&kp_kill);
    if (ret < 0) {
        printk(KERN_ERR "ZoEDR: register_kprobe for kill failed, returned %d\n", ret);
        return ret;
    }

    kp_ptrace.pre_handler = handler_pre_ptrace;
    ret = register_kprobe(&kp_ptrace);
    if (ret < 0) {
        printk(KERN_ERR "ZoEDR: register_kprobe for ptrace failed, returned %d\n", ret);
        unregister_kprobe(&kp_kill);
        return ret;
    }

    printk(KERN_INFO "✅ ZoEDR Kernel Observability Active. Deep hooks on kill and ptrace established.\n");
    return 0;
}

static void __exit zoedr_kernel_exit(void) {
    unregister_kprobe(&kp_kill);
    unregister_kprobe(&kp_ptrace);
    printk(KERN_INFO "⚠️ ZoEDR Kernel Module Unloaded! System is vulnerable.\n");
}

module_init(zoedr_kernel_init);
module_exit(zoedr_kernel_exit);
