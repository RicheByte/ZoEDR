#ifndef ZOEDR_COMMON_H
#define ZOEDR_COMMON_H

#include <time.h>
#include <unistd.h> // For pid_t

// Common constants
#define MAX_PATH_LEN 1024
#define MAX_COMM_LEN 256
#define MAX_EVENTS 1024
#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (MAX_EVENTS * (EVENT_SIZE + 16))

// Installation paths
#define ZOEDR_BINARY_PATH "/usr/sbin/zoedr_advanced"
#define ZOEDR_INSTALL_DIR "/opt/zoedr"
#define ZOEDR_LOG_DIR "/var/log/zoedr"
#define ZOEDR_CONFIG_DIR "/etc/zoedr"
#define BASELINE_HASH_PATH ZOEDR_CONFIG_DIR "/zoedr_advanced.sha256"
#define ALERT_LOG_PATH ZOEDR_LOG_DIR "/alerts.json" // Updated path

// Alert types
typedef enum {
    ALERT_CRYPTOMINER = 1,
    ALERT_REVERSE_SHELL,
    ALERT_PRIVILEGE_ESC,
    ALERT_FILELESS_EXEC,
    ALERT_INTEGRITY_FAIL,
    ALERT_KERNEL_MODULE_UNLOADED,
    ALERT_PROCESS_QUARANTINE,
    ALERT_SUSPICIOUS_BEHAVIOR, // Generic suspicious behavior
    ALERT_FILE_EVENT
} alert_type_t;

// Process node for tracking
typedef struct proc_node {
    pid_t pid;
    pid_t ppid;
    char comm[MAX_COMM_LEN];
    char exe_path[MAX_PATH_LEN];
    time_t start_time;
    struct proc_node *next;
} proc_node_t;

// Threat scoring system
typedef struct threat_score {
    int crypto_miner;
    int reverse_shell;
    int privilege_esc;
    int fileless_exec;
    int total;
    time_t detection_time;
} threat_score_t;

// Alert structure for JSON serialization
typedef struct {
    time_t timestamp;
    char host[MAX_COMM_LEN]; // hostname fits here
    alert_type_t alert_type;
    int pid;
    char process_name[MAX_COMM_LEN];
    threat_score_t threat_score;
    char details[512];
    char severity_str[16]; // "low", "medium", "high", "critical"
    char type_str[32];     // "Process Alert", "File Event", etc.
} zoedr_alert_t;

// Function prototypes for common utilities
char* get_hostname(void);
time_t get_current_timestamp(void);
int is_known_system_process(pid_t ppid);
int is_script_interpreter(const char *comm);
void sanitize_string(char *str, size_t len);
const char* alert_type_to_string(alert_type_t type);
const char* score_to_severity(int score);
void send_json_alert(threat_score_t score, proc_node_t *proc, alert_type_t type, const char *details);


#endif // ZOEDR_COMMON_H
