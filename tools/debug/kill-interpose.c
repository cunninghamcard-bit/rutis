// TEMPORARY (#287 debug): log every kill(pid, SIGKILL) with the caller's
// backtrace to /tmp/rutis-kill-interpose.log. Loaded with DYLD_INSERT_LIBRARIES.
#include <execinfo.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static int my_kill(pid_t pid, int sig) {
    if (sig == SIGKILL) {
        int fd = open("/tmp/rutis-kill-interpose.log", O_WRONLY | O_APPEND | O_CREAT, 0644);
        if (fd >= 0) {
            void *frames[48];
            int n = backtrace(frames, 48);
            char **names = backtrace_symbols(frames, n);
            char buf[16384];
            struct timeval tv; gettimeofday(&tv, NULL);
            int len = snprintf(buf, sizeof buf, "==== t=%ld.%03d sender=%d target=%d\n",
                               (long)tv.tv_sec, (int)(tv.tv_usec / 1000), getpid(), pid);
            for (int i = 1; names && i < n && len < (int)sizeof buf - 300; i++)
                len += snprintf(buf + len, sizeof buf - len, "  %s\n", names[i]);
            write(fd, buf, len);  // one write per record: no interleaving
            close(fd);
        }
    }
    return kill(pid, sig);
}

__attribute__((used)) static struct { const void *replacement; const void *original; }
    interposers[] __attribute__((section("__DATA,__interpose"))) = {
        {(const void *)(unsigned long)&my_kill, (const void *)(unsigned long)&kill},
};
