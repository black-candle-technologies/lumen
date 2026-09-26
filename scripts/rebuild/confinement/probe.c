/* Deliberately hostile native test code, never part of an admitted Pi image. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <node_api.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static napi_value probe(napi_env env, napi_callback_info info) {
    napi_value arg, result;
    size_t count = 1, length = 0;
    char name[32] = {0};
    napi_get_cb_info(env, info, &count, &arg, NULL, NULL);
    napi_get_value_string_utf8(env, arg, name, sizeof(name), &length);
    const char *argv[] = {"node", "-e", "console.log('EXEC_ESCAPED')", NULL};
    const char *envp[] = {NULL};
    long rc = -1;
    errno = 0;
    if (!strcmp(name, "socket_inet")) rc = syscall(SYS_socket, AF_INET, SOCK_STREAM, 0);
    else if (!strcmp(name, "socket_inet6")) rc = syscall(SYS_socket, AF_INET6, SOCK_STREAM, 0);
    else if (!strcmp(name, "socket_unix")) rc = syscall(SYS_socket, AF_UNIX, SOCK_STREAM, 0);
    else if (!strcmp(name, "fork")) rc = syscall(SYS_fork);
    else if (!strcmp(name, "clone_process")) rc = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    else if (!strcmp(name, "execve")) rc = syscall(SYS_execve, "/usr/bin/node", argv, envp);
    else if (!strcmp(name, "execveat")) rc = syscall(SYS_execveat, AT_FDCWD, "/usr/bin/node", argv, envp, 0);
    else if (!strcmp(name, "unshare")) rc = syscall(SYS_unshare, CLONE_NEWUSER);
    else if (!strcmp(name, "ptrace")) rc = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
    else if (!strcmp(name, "io_uring")) rc = syscall(SYS_io_uring_setup, 0, NULL);
    else if (!strcmp(name, "bpf")) rc = syscall(SYS_bpf, 0, NULL, 0);
    else if (!strcmp(name, "ioctl_inject")) rc = syscall(SYS_ioctl, 0, 0x5412, "x");
    else if (!strcmp(name, "x32")) rc = syscall(0x40000000 | SYS_getpid);
    else if (!strcmp(name, "i386")) {
        /* i386 getpid through int80 has a different seccomp arch value. */
        __asm__ volatile("int $0x80" : "=a"(rc) : "a"(20) : "memory");
    } else errno = EINVAL;
    int error = rc < 0 ? errno : 0;
    if (rc == 0 && (!strcmp(name, "fork") || !strcmp(name, "clone_process"))) _exit(250);
    if (rc >= 0 && !strncmp(name, "socket_", 7)) close((int)rc);
    napi_create_int32(env, error, &result);
    return result;
}

NAPI_MODULE_INIT() {
    napi_value function;
    napi_create_function(env, "probe", 5, probe, NULL, &function);
    napi_set_named_property(env, exports, "probe", function);
    return exports;
}
