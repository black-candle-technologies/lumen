/* Experimental Linux x86-64 Pi runtime guard. See ADR-0008 before changing.
 * Required through the pinned Node bootstrap before any Pi code is loaded.
 * No syscall is permitted by default; JS/worker code cannot weaken the filter.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <node_api.h>
#include <sched.h>
#include <stdatomic.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <termios.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || defined(__ILP32__)
#error "The reviewed prototype supports Linux x86-64 only"
#endif

#define ALLOW(n) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##n, 0, 1), \
                 BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
#define DENY BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
#define ARG(i) (offsetof(struct seccomp_data, args) + 8 * (i))

static void fail(void) {
    static const char message[] = "Lumen: native confinement failed\n";
    if (write(STDERR_FILENO, message, sizeof(message) - 1) < 0) _exit(126);
    _exit(126);
}

static void seal(void) {
    const unsigned int threads = CLONE_THREAD | CLONE_VM | CLONE_SIGHAND;
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* Reject the x32 ABI, whose arch identifier also says x86-64. */
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* clone3 hides flags behind a pointer. Never dereference or guess. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 9),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG(0) + 4),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0),
        DENY,
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG(0)),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
                 (unsigned int)~(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                 CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
                 CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID | CLONE_DETACHED), 3, 0),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, threads),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, threads, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        DENY,
        /* Node asks tty/pipe metadata; no TIOCSTI or arbitrary device ioctl. */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG(1)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TCGETS, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, TIOCGWINSZ, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONBIO, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, FIONREAD, 1, 0),
        DENY,
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        ALLOW(read), ALLOW(write), ALLOW(close), ALLOW(close_range),
        ALLOW(fstat), ALLOW(newfstatat), ALLOW(stat), ALLOW(lstat), ALLOW(statx),
        ALLOW(lseek), ALLOW(pread64), ALLOW(pwrite64), ALLOW(readv), ALLOW(writev),
        ALLOW(preadv), ALLOW(pwritev), ALLOW(preadv2), ALLOW(pwritev2),
        ALLOW(open), ALLOW(openat), ALLOW(access), ALLOW(faccessat), ALLOW(faccessat2),
        ALLOW(readlink), ALLOW(readlinkat), ALLOW(getdents), ALLOW(getdents64),
        ALLOW(getcwd), ALLOW(chdir), ALLOW(fchdir),
        /* The only writable filesystem is the disposable private state mount. */
        ALLOW(mkdir), ALLOW(mkdirat), ALLOW(rmdir), ALLOW(unlink), ALLOW(unlinkat),
        ALLOW(rename), ALLOW(renameat), ALLOW(renameat2),
        ALLOW(ftruncate), ALLOW(truncate), ALLOW(fsync), ALLOW(fdatasync),
        ALLOW(chmod), ALLOW(fchmod), ALLOW(fchmodat), ALLOW(umask),
        ALLOW(utimensat), ALLOW(futimesat), ALLOW(utimes),
        ALLOW(dup), ALLOW(dup2), ALLOW(dup3), ALLOW(fcntl), ALLOW(flock),
        ALLOW(pipe), ALLOW(pipe2), ALLOW(poll), ALLOW(ppoll), ALLOW(select), ALLOW(pselect6),
        ALLOW(epoll_create), ALLOW(epoll_create1), ALLOW(epoll_ctl),
        ALLOW(epoll_wait), ALLOW(epoll_pwait), ALLOW(epoll_pwait2),
        ALLOW(eventfd), ALLOW(eventfd2),
        ALLOW(mmap), ALLOW(mprotect), ALLOW(munmap), ALLOW(brk),
        ALLOW(mremap), ALLOW(madvise), ALLOW(mincore), ALLOW(msync),
        ALLOW(rt_sigaction), ALLOW(rt_sigprocmask), ALLOW(rt_sigreturn),
        ALLOW(sigaltstack), ALLOW(tgkill),
        ALLOW(futex), ALLOW(set_robust_list), ALLOW(get_robust_list),
        ALLOW(rseq), ALLOW(set_tid_address), ALLOW(sched_yield), ALLOW(sched_getaffinity),
        ALLOW(nanosleep), ALLOW(clock_nanosleep), ALLOW(clock_gettime), ALLOW(clock_getres),
        ALLOW(gettimeofday), ALLOW(time), ALLOW(times),
        ALLOW(getpid), ALLOW(gettid), ALLOW(getppid),
        ALLOW(getuid), ALLOW(geteuid), ALLOW(getgid), ALLOW(getegid), ALLOW(getgroups),
        ALLOW(getrlimit), ALLOW(prlimit64), ALLOW(getrusage), ALLOW(sysinfo), ALLOW(uname),
        ALLOW(getrandom), ALLOW(statfs), ALLOW(fstatfs),
        ALLOW(exit), ALLOW(exit_group),
        DENY,
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(code) / sizeof(code[0])), .filter = code,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, &program) != 0) fail();
}

NAPI_MODULE_INIT() {
    /* All workers share this module's mapping. The first load is from the
     * trusted main-thread bootstrap; TSYNC also seals pre-existing threads.
     * Requiring the addon in a later worker must not attempt to weaken or
     * replace its inherited filter (seccomp itself is deliberately denied).
     */
    static atomic_bool installed = 0;
    if (!atomic_load_explicit(&installed, memory_order_acquire)) {
        seal();
        atomic_store_explicit(&installed, 1, memory_order_release);
    }
    napi_value value;
    if (napi_get_boolean(env, true, &value) != napi_ok ||
        napi_set_named_property(env, exports, "sealed", value) != napi_ok) fail();
    return exports;
}
