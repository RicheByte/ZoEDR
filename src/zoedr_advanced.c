// zoedr_advanced.c - FIXED VERSION
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>  // ADD THIS LINE - fixes errno and EINTR errors

#include "zoedr_common.h" // Include shared header

// Global tracking structures
proc_node_t *process_list = NULL;
pthread_mutex_t proc_mutex = PTHREAD_MUTEX_INITIALIZER;

// Baseline hash for self-integrity checking
unsigned char zoedr_self_hash_baseline[SHA256_DIGEST_LENGTH] = {0};

// Flag to indicate if main loop should exit gracefully
volatile sig_atomic_t terminate_flag = 0;

// === COMMON UTILITY FUNCTIONS (from zoedr_common.h) ===

char* get_hostname(void) {
    static char hostname[MAX_COMM_LEN];
    gethostname(hostname, sizeof(hostname));
    return hostname;
}

time_t get_current_timestamp(void) {
    return time(NULL);
}

// Placeholder for system process check
int is_known_system_process(pid_t ppid) {
    // Basic check: init/systemd, kthreadd etc.
    return (ppid == 1 || ppid == 2);
}

// Placeholder for script interpreter check
int is_script_interpreter(const char *comm) {
    return (strstr(comm, "bash") || strstr(comm, "sh") || strstr(comm, "python"));
}

void sanitize_string(char *str, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (str[i] == '\n' || str[i] == '\r' || str[i] == '\"' || str[i] == '\\') {
            str[i] = '_'; // Replace problematic characters
        }
    }
}

const char* alert_type_to_string(alert_type_t type) {
    switch(type) {
        case ALERT_CRYPTOMINER: return "CRYPTOMINER_DETECTED";
        case ALERT_REVERSE_SHELL: return "REVERSE_SHELL_DETECTED";
        case ALERT_PRIVILEGE_ESC: return "PRIVILEGE_ESCALATION";
        case ALERT_FILELESS_EXEC: return "FILELESS_EXECUTION";
        case ALERT_INTEGRITY_FAIL: return "INTEGRITY_COMPROMISED";
        case ALERT_KERNEL_MODULE_UNLOADED: return "KERNEL_MODULE_UNLOADED";
        case ALERT_PROCESS_QUARANTINE: return "PROCESS_QUARANTINED";
        case ALERT_SUSPICIOUS_BEHAVIOR: return "SUSPICIOUS_BEHAVIOR";
        case ALERT_FILE_EVENT: return "FILE_SYSTEM_EVENT";
        default: return "UNKNOWN_ALERT_TYPE";
    }
}

const char* score_to_severity(int score) {
    if (score >= 90) return "critical";
    if (score >= 70) return "high";
    if (score >= 40) return "medium";
    if (score >= 10) return "low";
    return "info";
}

void send_json_alert(threat_score_t score, proc_node_t *proc, alert_type_t type, const char *details) {
    char json_payload[1024];
    time_t now = get_current_timestamp();
    char timestamp_str[64];
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    char process_name_safe[MAX_COMM_LEN];
    if (proc && proc->comm[0] != '\0') {
        strncpy(process_name_safe, proc->comm, sizeof(process_name_safe) - 1);
        process_name_safe[sizeof(process_name_safe) - 1] = '\0';
        sanitize_string(process_name_safe, strlen(process_name_safe));
    } else {
        strncpy(process_name_safe, "N/A", sizeof(process_name_safe) - 1);
    }
    
    char details_safe[512];
    if (details) {
        strncpy(details_safe, details, sizeof(details_safe) - 1);
        details_safe[sizeof(details_safe) - 1] = '\0';
        sanitize_string(details_safe, strlen(details_safe));
    } else {
        strncpy(details_safe, "No additional details.", sizeof(details_safe) - 1);
    }


    if (proc) {
        snprintf(json_payload, sizeof(json_payload),
            "{\"timestamp\": \"%s\", \"host\": \"%s\", \"alert_type\": \"%s\", "
            "\"pid\": %d, \"process_name\": \"%s\", \"threat_score_total\": %d, "
            "\"severity\": \"%s\", \"details\": \"%s\"}",
            timestamp_str, get_hostname(), alert_type_to_string(type),
            proc->pid, process_name_safe, score.total, score_to_severity(score.total), details_safe);
    } else {
        snprintf(json_payload, sizeof(json_payload),
            "{\"timestamp\": \"%s\", \"host\": \"%s\", \"alert_type\": \"%s\", "
            "\"threat_score_total\": %d, \"severity\": \"%s\", \"details\": \"%s\"}",
            timestamp_str, get_hostname(), alert_type_to_string(type),
            score.total, score_to_severity(score.total), details_safe);
    }
    
    FILE *log = fopen(ALERT_LOG_PATH, "a");
    if (log) {
        fprintf(log, "%s\n", json_payload);
        fclose(log);
    } else {
        fprintf(stderr, "ERROR: Could not open alert log file: %s\n", ALERT_LOG_PATH);
    }
}


// === CORE MONITORING FUNCTIONS ===

void scan_process_tree() {
    DIR *proc_dir;
    struct dirent *entry;
    
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        return;
    }

    pthread_mutex_lock(&proc_mutex);
    
    // Clear existing list
    proc_node_t *current = process_list;
    while (current) {
        proc_node_t *next = current->next;
        free(current);
        current = next;
    }
    process_list = NULL;

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type == DT_DIR && atoi(entry->d_name) > 0) {
            pid_t pid = atoi(entry->d_name);
            char path[MAX_PATH_LEN], line[MAX_PATH_LEN];
            FILE *fp;
            
            snprintf(path, sizeof(path), "/proc/%d/stat", pid);
            fp = fopen(path, "r");
            if (fp) {
                if (fgets(line, sizeof(line), fp) != NULL) {
                    char comm_raw[MAX_COMM_LEN];
                    pid_t ppid;
                    // Example stat format: PID (comm) S PPID ...
                    // %*d to skip pid, %s for comm, %c for state, %d for ppid
                    sscanf(line, "%*d (%255[^)]) %*c %d", comm_raw, &ppid); // Capture comm including spaces
                    
                    proc_node_t *new_node = malloc(sizeof(proc_node_t));
                    if (!new_node) {
                        perror("malloc proc_node");
                        fclose(fp);
                        continue;
                    }
                    new_node->pid = pid;
                    new_node->ppid = ppid;
                    strncpy(new_node->comm, comm_raw, sizeof(new_node->comm)-1);
                    new_node->comm[sizeof(new_node->comm)-1] = '\0';
                    sanitize_string(new_node->comm, strlen(new_node->comm));
                    
                    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
                    ssize_t len = readlink(path, new_node->exe_path, sizeof(new_node->exe_path)-1);
                    if (len != -1) {
                        new_node->exe_path[len] = '\0';
                    } else {
                        strcpy(new_node->exe_path, "unknown");
                    }
                    
                    new_node->start_time = 0; // Not extracted from /proc/stat in this simplified version
                    new_node->next = process_list;
                    process_list = new_node;
                }
                fclose(fp);
            }
        }
    }
    
    pthread_mutex_unlock(&proc_mutex);
    closedir(proc_dir);
}

void* start_file_watcher(void *arg) {
    int fd, wd;
    char buffer[BUF_LEN];
    
    fd = inotify_init();
    if (fd < 0) {
        perror("inotify_init");
        return NULL;
    }

    char *watch_paths[] = {"/bin", "/usr/bin", "/etc", "/root", "/home", ZOEDR_BINARY_PATH, NULL};
    
    for (int i = 0; watch_paths[i]; i++) {
        // Check if path exists before adding watch
        struct stat st;
        if (stat(watch_paths[i], &st) == 0) {
            wd = inotify_add_watch(fd, watch_paths[i], 
                                IN_MODIFY | IN_CREATE | IN_DELETE | IN_ATTRIB | IN_CLOSE_WRITE);
            if (wd == -1) {
                fprintf(stderr, "ZoEDR: Cannot watch '%s' (%s)\n", watch_paths[i], strerror(errno));
            } else {
                printf("ZoEDR: Watching '%s'\n", watch_paths[i]);
            }
        } else {
            fprintf(stderr, "ZoEDR: Path '%s' does not exist, skipping watch.\n", watch_paths[i]);
        }
    }

    while (!terminate_flag) {
        int length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            if (errno == EINTR) continue; // Interrupted by signal, just retry
            perror("read inotify");
            break;
        }

        int i = 0;
        while (i < length) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];
            if (event->len) {
                char details[512];
                snprintf(details, sizeof(details), "File: %s, Event: %s%s%s%s", 
                        event->name,
                        (event->mask & IN_CREATE) ? "CREATE " : "",
                        (event->mask & IN_MODIFY) ? "MODIFY " : "",
                        (event->mask & IN_DELETE) ? "DELETE " : "",
                        (event->mask & IN_ATTRIB) ? "ATTRIB " : "");
                
                threat_score_t file_score = {.total = 30}; // Base score for file event
                if (event->mask & (IN_CREATE | IN_DELETE)) file_score.total += 20; // Higher for creation/deletion
                if (strstr(event->name, "sudoers") || strstr(event->name, "shadow")) file_score.total = 80; // Critical files
                
                send_json_alert(file_score, NULL, ALERT_FILE_EVENT, details);
            }
            i += EVENT_SIZE + event->len;
        }
    }
    
    close(fd);
    printf("ZoEDR: File watcher terminated.\n");
    return NULL;
}

// === ADVANCED DETECTION ===

int check_cpu_pattern(pid_t pid) {
    char stat_path[MAX_PATH_LEN];
    FILE *fp;
    unsigned long utime, stime;
    static unsigned long last_utime[65536] = {0}; // Max PID on Linux is usually 32768 or 4194304
    static unsigned long last_stime[65536] = {0};
    
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    fp = fopen(stat_path, "r");
    if (!fp) return 0;
    
    if (fscanf(fp, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
           &utime, &stime) != 2) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    
    if (last_utime[pid] > 0) {
        unsigned long delta = (utime - last_utime[pid]) + (stime - last_stime[pid]);
        // A delta > 1000 Jiffies (10s on a 100HZ system) in a short interval is high CPU usage
        if (delta > 500) return 1; // Arbitrary high CPU usage threshold
    }
    
    last_utime[pid] = utime;
    last_stime[pid] = stime;
    return 0;
}

int check_network_activity(pid_t pid) {
    char net_path[MAX_PATH_LEN];
    DIR *dir;
    struct dirent *entry;
    
    snprintf(net_path, sizeof(net_path), "/proc/%d/fd", pid);
    dir = opendir(net_path);
    if (!dir) return 0;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_LNK) {
            char fd_path[MAX_PATH_LEN], link_path[MAX_PATH_LEN];
            snprintf(fd_path, sizeof(fd_path), "%s/%s", net_path, entry->d_name);
            
            ssize_t len = readlink(fd_path, link_path, sizeof(link_path)-1);
            if (len != -1) {
                link_path[len] = '\0';
                if (strstr(link_path, "socket:")) { // Found an open socket
                    closedir(dir);
                    return 1;
                }
            }
        }
    }
    
    closedir(dir);
    return 0;
}

threat_score_t analyze_process_behavior(proc_node_t *proc) {
    threat_score_t score = {0};
    score.detection_time = get_current_timestamp();
    
    // Crypto miner detection
    if (strstr(proc->comm, "minerd") || strstr(proc->comm, "xmrig") ||
        strstr(proc->comm, "cpuminer") || check_cpu_pattern(proc->pid)) {
        score.crypto_miner = 85;
    }
    
    // Reverse shell detection
    // Check for common shell/network tools used for reverse shells combined with network activity
    if ((strstr(proc->comm, "nc") || strstr(proc->comm, "netcat") || 
         strstr(proc->comm, "bash") || strstr(proc->comm, "sh")) &&
        check_network_activity(proc->pid)) {
        score.reverse_shell = 90;
    }
    
    // Privilege escalation (simplified: root process not spawned by init, but could be legitimate)
    if (proc->pid > 1 && getuid() == 0 && proc->ppid != 1 && !is_known_system_process(proc->ppid)) {
        score.privilege_esc = 75;
    }
    
    // Fileless execution (simplified: checking /proc/<pid>/exe link target)
    if (strstr(proc->exe_path, "memfd:") || strstr(proc->exe_path, "/dev/shm")) {
        score.fileless_exec = 80;
    }
    
    score.total = score.crypto_miner + score.reverse_shell + 
                  score.privilege_esc + score.fileless_exec;
    
    return score;
}

// === INTEGRITY & PERSISTENCE ===

void compute_file_sha256(const char *filepath, unsigned char *output_hash) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        memset(output_hash, 0, SHA256_DIGEST_LENGTH);
        return;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer = malloc(bufSize);
    int bytesRead = 0;
    
    if (!buffer) {
        perror("malloc buffer for SHA256");
        fclose(file);
        memset(output_hash, 0, SHA256_DIGEST_LENGTH);
        return;
    }
    
    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(output_hash, &sha256);
    
    free(buffer);
    fclose(file);
}

void load_baseline_hash() {
    FILE *hash_file = fopen(BASELINE_HASH_PATH, "r");
    if (!hash_file) {
        fprintf(stderr, "❌ ZoEDR: No baseline hash found at %s. Run install.sh first!\n", BASELINE_HASH_PATH);
        exit(1);
    }
    
    char hex_hash[65];
    if (fread(hex_hash, 1, 64, hash_file) == 64) {
        hex_hash[64] = '\0';
        // Convert hex to binary
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sscanf(hex_hash + 2*i, "%2hhx", &zoedr_self_hash_baseline[i]);
        }
    } else {
        fprintf(stderr, "❌ ZoEDR: Failed to read 64 characters from baseline hash file: %s\n", BASELINE_HASH_PATH);
        exit(1);
    }
    fclose(hash_file);
}

void check_self_integrity() {
    unsigned char current_hash[SHA256_DIGEST_LENGTH];
    compute_file_sha256(ZOEDR_BINARY_PATH, current_hash);

    if (memcmp(current_hash, zoedr_self_hash_baseline, SHA256_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "🚨 ZOEDR INTEGRITY COMPROMISED! Binary modified!\n");
        send_json_alert((threat_score_t){.total=100}, NULL, ALERT_INTEGRITY_FAIL, "ZoEDR binary has been tampered with!");
        
        // Critical alert - attempt recovery
        fprintf(stderr, "ZoEDR: Attempting automatic recovery...\n");
        system("sudo systemctl stop zoedr_advanced.service 2>/dev/null");
        // Keep a copy of the corrupted binary for forensic analysis
        system("sudo cp " ZOEDR_BINARY_PATH " " ZOEDR_BINARY_PATH ".corrupted 2>/dev/null"); 
        system("sudo " ZOEDR_INSTALL_DIR "/recover.sh 2>/dev/null");
        
        exit(1); // Self-terminate after recovery attempt
    }
}

void quarantine_process(pid_t pid) {
    printf("🔒 QUARANTINING PID %d\n", pid);
    
    char cmd[256];
    // Suspend process
    snprintf(cmd, sizeof(cmd), "kill -STOP %d 2>/dev/null", pid);
    system(cmd);
    
    // Isolate network for the process owner (this affects all processes run by the same user)
    // A more granular approach would be to use cgroups or process-specific iptables rules which are more complex.
    // For now, dropping all output from the PID owner for simplicity.
    snprintf(cmd, sizeof(cmd), "iptables -I OUTPUT -p all -m owner --uid-owner %d -j DROP 2>/dev/null", geteuid()); // Assuming the malicious process is running as current user
    system(cmd);
    
    // Log quarantine
    proc_node_t fake_proc = {.pid = pid};
    strncpy(fake_proc.comm, "quarantined", sizeof(fake_proc.comm) - 1);
    fake_proc.comm[sizeof(fake_proc.comm) - 1] = '\0';
    send_json_alert((threat_score_t){.total=100}, &fake_proc, ALERT_PROCESS_QUARANTINE, "Process quarantined due to critical threat score.");
}

// === WATCHDOG & SELF-HEALING ===

void* watchdog_thread(void* arg) {
    printf("🐕 ZoEDR Watchdog Started - Immortal Defense Activated\n");
    
    while (!terminate_flag) {
        sleep(15); // Check every 15 seconds

        // Check self integrity
        check_self_integrity();

        // Check if kernel module is loaded
        if (access("/sys/module/zoedr_kernel", F_OK) == -1) {
            fprintf(stderr, "🚨 KERNEL MODULE UNLOADED! Reloading...\n");
            send_json_alert((threat_score_t){.total=70}, NULL, ALERT_KERNEL_MODULE_UNLOADED, "ZoEDR kernel module was unloaded, attempting reload.");
            system("sudo modprobe zoedr_kernel 2>/dev/null");
            // Also check if modprobe succeeded
            if (access("/sys/module/zoedr_kernel", F_OK) == -1) {
                fprintf(stderr, "❌ KERNEL MODULE RELOAD FAILED!\n");
            }
        }

        // Check if our service is running
        if (system("systemctl is-active --quiet zoedr_advanced.service") != 0) {
            fprintf(stderr, "🚨 SERVICE STOPPED! Restarting...\n");
            system("sudo systemctl start zoedr_advanced.service 2>/dev/null");
            if (system("systemctl is-active --quiet zoedr_advanced.service") != 0) {
                 fprintf(stderr, "❌ SERVICE RESTART FAILED!\n");
            }
        }
    }
    printf("ZoEDR: Watchdog terminated.\n");
    return NULL;
}

// === MAIN MONITORING LOOP ===

void* advanced_monitoring_loop(void *arg) {
    printf("🎯 Advanced ZoEDR Started - Deep System Analysis\n");
    
    while (!terminate_flag) {
        scan_process_tree();
        
        pthread_mutex_lock(&proc_mutex);
        proc_node_t *current = process_list;
        
        while (current) {
            threat_score_t score = analyze_process_behavior(current);
            
            if (score.total > 50) { // Threshold for significant alert
                printf("🚨 THREAT DETECTED: PID=%d (%s), Score=%d/100\n", 
                       current->pid, current->comm, score.total);
                
                send_json_alert(score, current, ALERT_SUSPICIOUS_BEHAVIOR, "Detected suspicious process behavior.");
                
                if (score.total >= 80) { // Threshold for quarantine
                    quarantine_process(current->pid);
                }
            }
            
            current = current->next;
        }
        pthread_mutex_unlock(&proc_mutex);
        
        sleep(3); // Scan every 3 seconds
    }
    printf("ZoEDR: Main monitoring loop terminated.\n");
    return NULL;
}

// Signal handler for graceful termination
void sigterm_handler(int signum) {
    fprintf(stderr, "ZoEDR: Received signal %d, initiating graceful shutdown...\n", signum);
    terminate_flag = 1;
}

// === MAIN FUNCTION ===

int main() {
    printf("🐧 ZoEDR-Linux v4.0 - Alpha's Immortal Watchdog\n");
    printf("Initializing core systems with persistence...\n");

    // Register signal handler for graceful shutdown
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT, sigterm_handler); // Also handle Ctrl+C

    // Load baseline hash for integrity checking
    load_baseline_hash();
    
    // Initial integrity check
    check_self_integrity();

    pthread_t monitor_thread, file_thread, watchdog_t;

    // Start all monitoring threads
    pthread_create(&monitor_thread, NULL, advanced_monitoring_loop, NULL);
    pthread_create(&file_thread, NULL, start_file_watcher, NULL);
    pthread_create(&watchdog_t, NULL, watchdog_thread, NULL);

    printf("✅ All systems operational. Watchdog active.\n");
    
    // Wait for all threads to finish (they should respect terminate_flag)
    pthread_join(monitor_thread, NULL);
    pthread_join(file_thread, NULL);
    pthread_join(watchdog_t, NULL);

    // Clean up process list
    pthread_mutex_lock(&proc_mutex);
    proc_node_t *current = process_list;
    while (current) {
        proc_node_t *next = current->next;
        free(current);
        current = next;
    }
    process_list = NULL;
    pthread_mutex_unlock(&proc_mutex);

    printf("ZoEDR: Shutdown complete. Zeta Realm remains secured.\n");

    return 0;
}
