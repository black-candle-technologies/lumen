/* Trusted unprivileged service main process. See ADR-0009 before changing.
 * Its private FIFO is never mounted into Pi; no descriptor reaches the guest.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int reap(pid_t child) {
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return 126;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 126;
}

int main(int argc, char **argv) {
    if (geteuid() == 0 || argc < 4 || strcmp(argv[2], "--") ||
        strcmp(argv[3], "/usr/bin/bwrap")) return 126;
    struct sigaction action = { .sa_handler = SIG_DFL };
    if (sigemptyset(&action.sa_mask) || sigaction(SIGCHLD, &action, NULL)) return 126;
    int live = open(argv[1], O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
    struct stat info;
    char marker;
    if (live < 0 || fstat(live, &info) || !S_ISFIFO(info.st_mode) ||
        info.st_uid != geteuid() || (info.st_mode & 0777) != 0600 ||
        read(live, &marker, 1) != 1 || marker != 'L') return 126;
    pid_t parent = getpid();
    pid_t child = fork();
    if (child < 0) return 126;
    if (!child) {
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent) _exit(126);
        close(live);
        execv(argv[3], &argv[3]);
        _exit(127);
    }
    int pidfd = syscall(SYS_pidfd_open, child, 0);
    if (pidfd < 0) {
        kill(child, SIGKILL);
        reap(child);
        return 126;
    }
    struct pollfd watched[] = {
        { .fd = live, .events = POLLIN },
        { .fd = pidfd, .events = POLLIN },
    };
    for (;;) {
        int ready = poll(watched, 2, -1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0 || watched[0].revents) {
            /* Only the startup marker is permitted. EOF, extra data, errors,
             * or hangup all end this generation; no reconnect or restart. */
            kill(child, SIGKILL);
            reap(child);
            return 125;
        }
        if (watched[1].revents) return reap(child);
    }
}
