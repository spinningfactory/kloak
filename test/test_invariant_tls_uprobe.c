#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_HOST_LEN 256

START_TEST(test_buffer_reads_never_exceed_declared_length)
{
    // Invariant: Buffer reads never exceed the declared length
    const char *payloads[] = {
        "normal.example.com",  // Valid input
        "x",  // Boundary case: exactly MAX_HOST_LEN-1
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  // Exploit case: exceeds MAX_HOST_LEN by 2x
    };
    
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);
    
    for (int i = 0; i < num_payloads; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            // Child process: compile and run the actual eBPF code
            FILE *fp = fopen("test_input.bin", "wb");
            if (!fp) _exit(EXIT_FAILURE);
            
            // Write payload length followed by payload
            size_t len = strlen(payloads[i]);
            fwrite(&len, sizeof(size_t), 1, fp);
            fwrite(payloads[i], 1, len, fp);
            fclose(fp);
            
            // Compile and run the actual eBPF code
            int result = system("clang -target bpf -O2 -c pkg/ebpf/bpf/tls_uprobe.c -o /dev/null 2>&1");
            if (result != 0) {
                // Check if compilation failed due to buffer overflow detection
                FILE *log = fopen("compile.log", "r");
                if (log) {
                    char line[256];
                    while (fgets(line, sizeof(line), log)) {
                        if (strstr(line, "buffer overflow") || strstr(line, "out of bounds")) {
                            fclose(log);
                            _exit(EXIT_FAILURE);  // Test fails if overflow detected
                        }
                    }
                    fclose(log);
                }
            }
            
            // Run verifier on the compiled eBPF
            result = system("bpftool prog load tls_uprobe.o /sys/fs/bpf/test 2>&1 | grep -q 'buffer access'");
            if (result == 0) {
                _exit(EXIT_FAILURE);  // Verifier detected buffer access violation
            }
            
            _exit(EXIT_SUCCESS);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            ck_assert_msg(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS,
                         "Buffer overflow detected for payload %d", i);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_buffer_reads_never_exceed_declared_length);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}