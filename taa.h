#ifndef _TAA_H_
#define _TAA_H_

#ifdef DEBUG_PRINTS
  #define DEBUG printk
#else
  #define DEBUG(...)
#endif

/*
 * Functions prototype
 */
static int  thread_scheduler(void *unused);
static void detection (char *mem_ptr, long *abort_l1_set, long *abort_l1_total,
					   long *no_abort_total, long *abort_total);
static void mitigation (struct task_struct *task_list, int detected_cpu);
static inline void mfence(void);
static inline void maccess(void *p);
static inline void maccess_set_whole(void *mem_ptr, int set);
static inline unsigned int xbegin(void);
static inline void xend(void);

/*
 * MACROS Definition
 */
#define DEBUG_ERR(...)	debug_sprintf_event(debug_info, 3, ##__VA_ARGS__)
#define _XBEGIN_STARTED		(~0u)
#define _XABORT_EXPLICIT	(1 << 0)
#define _XABORT_RETRY		(1 << 1)
#define _XABORT_CONFLICT	(1 << 2)
#define _XABORT_CAPACITY	(1 << 3)
#define _XABORT_DEBUG		(1 << 4)
#define _XABORT_NESTED		(1 << 5)
#define _XABORT_CODE(x)		(((x) >> 24) & 0xFF)

// Enable this to accuracy, 3 features.
// otherwise select only one feature
#define ACCURACY_REQUIRED
#ifdef ACCURACY_REQUIRED
#define INTERVAL_FLUSH_ONLY  	150000
#else
#define INTERVAL_FLUSH_ONLY  	10000
#endif

// Number of CPUS in the machine
#define NUM_CPUS 			8
#define NUM_SETS  		 	64
#define LINE_SIZE 		    64
#define SET_DIFF            (NUM_SETS*LINE_SIZE)
#define NUM_WAYS  		 	8

// OPCODES
#define XBEGIN_1            0xc7
#define XBEGIN_2            0xf8
#define NOP					0x90

// Features Thresholds
#define FET1_THRESHOLD      120
#define FET2_THRESHOLD      500
#define FET3_THRESHOLD      200
#define FET4_THRESHOLD      360 // Not documented in paper, just average threshold like FET1

/*
 * feature thresholds structure
 */
typedef struct {
	int max;
	int avrg;
	int min;
	int max2;
	int idx;
	int idx2;
	int idx_min;
	unsigned long long abrt_per;
	int diff;
} feature_stats;


/*
 * Global Variables
 */
// Mapping array for each of the CPU
// Perfectly fit for L1 Cache
char mapping_cache_line_set [NUM_CPUS][NUM_WAYS * (NUM_SETS*LINE_SIZE)] \
							__attribute__((aligned(NUM_SETS*LINE_SIZE)));
static struct task_struct *thread_worker[NUM_CPUS];
volatile int first[NUM_CPUS] = {0};
volatile int wait_flag[4] = {0};
int happen[NUM_CPUS] = {0};
int false_negative = 0;
int false_detect = 0;
int last_detect = -1;
int new_detect = -1;
volatile int false_negative_helper = 0;

#endif /* _TAA_H_ */
