#define COMM_LEN 17            /* Maximum length of command line */
#define NUM_STAT_FEILDS 30     /* Number of fields read from /proc/pid/stat */

/* Status of the dump */
extern int status;

/* Structure for Status of process */
struct pid_stat {
	int ps_pid;
	char ps_comm[COMM_LEN];
	char ps_state;
	unsigned long long ps_num[NUM_STAT_FEILDS];
};
