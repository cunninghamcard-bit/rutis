// #287 repro: one thread reads the keychain trust settings (as
// rustls-native-certs does) while other threads fork, in a fresh process
// per round. argv[1]: "race", or "pre" (notify_is_valid_token(0) first).
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <notify.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define THREADS 8
static volatile int go;

static void *trust(void *arg) {
    (void)arg;
    while (!go) {}
    CFArrayRef certs = NULL;
    if (SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainUser, &certs) == 0 && certs) CFRelease(certs);
    return NULL;
}

static void *forker(void *arg) {
    while (!go) {}
    int *sig = arg;
    for (int i = 0; i < 4; i++) {
        pid_t pid = fork();
        if (pid == 0) _exit(0);
        int st = 0;
        waitpid(pid, &st, 0);
        if (WIFSIGNALED(st)) *sig = WTERMSIG(st);
    }
    return NULL;
}

static int round_once(const char *mode) {
    if (strcmp(mode, "pre") == 0) notify_is_valid_token(0);
    pthread_t t[THREADS + 1];
    int sig[THREADS] = {0};
    pthread_create(&t[THREADS], NULL, trust, NULL);
    for (int i = 0; i < THREADS; i++) pthread_create(&t[i], NULL, forker, &sig[i]);
    go = 1;
    int killed = 0;
    for (int i = 0; i < THREADS; i++) {
        pthread_join(t[i], NULL);
        if (sig[i]) killed++;
    }
    pthread_join(t[THREADS], NULL);
    return killed;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "race";
    int rounds = argc > 2 ? atoi(argv[2]) : 100;
    int bad = 0;
    for (int r = 0; r < rounds; r++) {
        pid_t p = fork();
        if (p == 0) {
            execl(argv[0], argv[0], "--round", mode, (char *)NULL);
            _exit(127);
        }
        int st;
        waitpid(p, &st, 0);
        if (WIFEXITED(st) && WEXITSTATUS(st)) bad++;
    }
    printf("%s: %d/%d rounds had a forked child killed\n", mode, bad, rounds);
    return 0;
}

__attribute__((constructor)) static void maybe_round(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--round") == 0) _exit(round_once(argv[2]));
}
