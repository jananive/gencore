#define COMM_LEN 17            /* Maximum length of command line */
#define NUM_STAT_FEILDS 30     /* Number of fields read from /proc/pid/stat */

#define PPID 0			/* Index for parent process ID */
#define PGRP 1			/* Index for process group ID */
#define SID 2			/* Index for session ID */
#define FLAG 5			/* Index for flags */
#define NICE 15		/* Index for nice value */
#define THREAD_COUNT_IDX 16	/* Index for number of threads */

#define __ps_thread_count ps_num[THREAD_COUNT_IDX]	/* Process Information */
#define __ps_ppid ps_num[PPID]				/* Process PID */	
#define __ps_pgrp ps_num[PGRP]				/* Process Group ID */ 
#define __ps_sid ps_num[SID]				/* Process Session ID */
#define __ps_flag ps_num[FLAG]				/* Process Flags */
#define __ps_nice ps_num[NICE]				/* Process Nice Value */

/* Status of the dump */
extern int status;

/* Structure for Status of process */
struct pid_stat {
	int ps_pid;
	char ps_comm[COMM_LEN];
	char ps_state;
	unsigned long long ps_num[NUM_STAT_FEILDS];
};

/* Structure for maps */
struct maps {
	unsigned long long src, dst, offset;
	char r, w, x;
	long inode;
	struct maps *next;
	char fname[0];
};

/*
 * Structure for Notes
 * We follow this linked list data-type as we dont know the number of notes
 * as that depends on the architecture. Also the notebuf contains the final
 * in-file format for the note data.
 */
struct mem_note {
	unsigned char *notebuf;		/* Notes - type, name_sz, datasz, name and data */
	unsigned int size;		/* Size of Note */
	struct mem_note *next;
};

/* Structure for the Core of the Process */
struct core_proc {
	int thread_count;		/* Number of threads */
	int *t_id;			/* Threads_ids of all the threads */
	struct maps *vmas;		/* VMAs */
	int phdrs_count;		/* Number of Program headers */
	int elf_class;			/* Elf class of the process */
	void *elf_hdr;			/* Stores the ELF_header */
	struct mem_note *notes;		/* Head of Notes */
};
