/*
 * Include libraries
 */
#include <linux/module.h> // Required for kernel module
#include <linux/kthread.h> // Required for kernel threads
#include <linux/delay.h> // Required for sleep
#include <linux/buffer_head.h> // Required for user pages
#include <linux/sched/signal.h> // Required for process iteration
#include <linux/slab.h> // Required for memory allocation
#include "taa.h" // Header definitions

/*
 * Module description
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ameer Hamza");
MODULE_DESCRIPTION("TAA Mitigation Module");
MODULE_VERSION("1.0");

/*
 * Scheduler thread
 * Each thread will be affined with a separate core
 * get_cpu() is able to distinguish between CPU cores
 */
static int thread_scheduler(void *unused) {
	// Local variables
	int i;
	const int this_cpu = (const int) get_cpu();
	int this_cpu_lower = 0;
	struct task_struct *task_list;
	unsigned int detection_cnter_single=0;
	unsigned int detection_cnter_pid[3]={0};
	long detection_interval = 0;
	long no_abort_total = 0;
	long abort_total = 0;
	long abort_l1_total = 0;
	long abort_l1_set[NUM_SETS] = {0};
	volatile int detected_cpu = (get_cpu() < 4) ? (get_cpu() + 4) : get_cpu() - 4;
	char *mem_ptr = mapping_cache_line_set[this_cpu];
	feature_stats *f_stat = (feature_stats*) kmalloc(sizeof(feature_stats),GFP_ATOMIC);

	// clear mapping array
	for (i=0; i<NUM_WAYS; i++) {
		memset(mapping_cache_line_set[this_cpu] + (i*4096), 0, 4096);
	}

	/* Run until module is loaded */
	while (!kthread_should_stop()) {
		this_cpu_lower = (this_cpu < 4) ? this_cpu : (this_cpu-4);

		// Synchronization between thread groups
		if (first[this_cpu] == 0) {
			first[this_cpu] = 1;
			while (wait_flag[this_cpu_lower] == 1) {
				msleep(10);
			}
			wait_flag[this_cpu_lower] = 1;
		}

		// TAA detection routine
		detection(mem_ptr, &abort_l1_set[0], &abort_l1_total, &no_abort_total, &abort_total);

		// Load sharing
#ifdef ACCURACY_REQUIRED
			schedule_timeout (2000);
#else
			usleep_range(25, 50);
			usleep_range(25, 50);
#endif

		// Check if detection count exhausted
		if (++detection_interval > INTERVAL_FLUSH_ONLY) {
			mfence();
			detection_interval = 0;
			memset(f_stat, 0, sizeof(feature_stats));
			f_stat->min = 0x0FFFFFFF;

			// Feature calculation
			for (i=0; i<NUM_SETS; i++) {
				f_stat->avrg += abort_l1_set[i];
				if (abort_l1_set[i] > f_stat->max) {
					f_stat->max2 = f_stat->max;
					f_stat->max = abort_l1_set[i];
					f_stat->idx = i;
				}
				if (abort_l1_set[i] < f_stat->min) {
					f_stat->min = abort_l1_set[i];
					f_stat->idx_min = i;
				}
				else if (abort_l1_set[i] > f_stat->max2) {
					f_stat->max2 = abort_l1_set[i];
					f_stat->idx2 = i;
				}
				abort_l1_set[i] = 0;
			}
			f_stat->avrg /= NUM_SETS;
			f_stat->abrt_per = ((abort_l1_total * 50000) / ((no_abort_total > 0) ? no_abort_total : 1));
			f_stat->diff = f_stat->max - f_stat->max2;

			// Just debug
			if (detected_cpu == 0) {
				DEBUG(KERN_INFO "[CPU:%d], PER:%lld, Max:%d, Min:%d\n", detected_cpu, f_stat->abrt_per, f_stat->max, f_stat->min);
			}

			// If TAA Detected
#ifdef ACCURACY_REQUIRED
			if ((f_stat->abrt_per > FET1_THRESHOLD) &&
				(f_stat->max > FET2_THRESHOLD) &&
				(f_stat->min > FET3_THRESHOLD) &&
				(f_stat->avrg > FET4_THRESHOLD))
#else
				if (f_stat->abrt_per > FET1_THRESHOLD)
#endif
			{
				detection_cnter_single = (detection_cnter_single + 1) % 3;
				last_detect = new_detect;
				new_detect = detected_cpu;
				happen[detected_cpu] = 1;

				if (detection_cnter_single == 1)
					DEBUG(KERN_INFO "DETECTED ONCE\n");
				if (detection_cnter_single == 2)
					DEBUG(KERN_INFO "DETECTED TWICE\n");
				if (detection_cnter_single == 0)
					DEBUG(KERN_INFO "DETECTED THRICE\n");

				DEBUG(KERN_INFO "TAA Attack Detected on CPU:[%d], CNTER:[%d]\n", detected_cpu, detection_cnter_single);
				DEBUG(KERN_INFO "PER=%lld\t\tMax=%d\tMin=%d\tAvrg=%d\n", f_stat->abrt_per, f_stat->max, f_stat->min, f_stat->avrg);

				false_negative_helper = 0;

				// Parse process list
				for_each_process(task_list)
				{
					if (task_list->state == TASK_RUNNING && (task_list->cpu == detected_cpu) /*&& ((task_list->mm->end_code - task_list->mm->start_code) < 8192)*/) {
						detection_cnter_pid[detection_cnter_single] = task_list->pid;

						// Detect three times in a row
						if ((detection_cnter_pid[0] !=detection_cnter_pid[1]) ||
							(detection_cnter_pid[0] !=detection_cnter_pid[2])) {
							break;
						}
						printk(KERN_INFO "TAA Detection on Core:%d\n", detected_cpu);
						mitigation(task_list, detected_cpu);
					}
				}

				if (last_detect == (NUM_CPUS - 1)) {
					last_detect = -1;
				}

				if (new_detect != last_detect + 1) {
					false_detect++;
				}
				if (false_negative_helper > 1) {
					false_negative += (false_negative_helper -1);
				}

				// stats
				DEBUG(KERN_INFO "False Negative Mitigate: %d False Negative Detect: %d\n", false_negative, false_detect);
			} else {
				detection_cnter_single = 0;
				detection_cnter_pid[0] = 0;
				detection_cnter_pid[1] = 0;
				detection_cnter_pid[2] = 0;
			}

			abort_total = 0;
			abort_l1_total = 0;
			no_abort_total = 0;
			first[this_cpu] = 0;
			// Synchronization
			if (happen[this_cpu] == 1) {
				happen[this_cpu] = 0;
				msleep(1);
				printk(KERN_ALERT "\n");
				msleep(1);
			}
			wait_flag[this_cpu_lower] = 0;
			msleep(15);
		}
	}
	wait_flag[0] = 0;
	wait_flag[1] = 0;
	wait_flag[2] = 0;
	wait_flag[3] = 0;

	// Module unloaded
	printk(KERN_CONT "TAA Mitigation Kernel Thread Exits (CPU=%d)!!!\n", this_cpu);

	return 0;
}

/*
 * Mitigation Code
 */
static void mitigation (struct task_struct *task_list, int detected_cpu) {
	int i;
	unsigned char *myaddr;
	int res;
	unsigned int code_size = 0;
	struct  page *page;

	// Apply mitigation-2 to cores 0 to 3
	if (detected_cpu < 4) {
		// Get user space mappings
		task_lock(task_list);
		down_read(&task_list->mm->mmap_sem);
		code_size = task_list->mm->end_code - task_list->mm->start_code;
		res = get_user_pages_remote(task_list, task_list->mm,
				  (unsigned long)task_list->mm->start_code,
				  1, FOLL_WRITE | FOLL_FORCE | FOLL_REMOTE | FOLL_TOUCH,
				  &page, NULL, NULL);
		if (res) {
			// Map to kernel
			myaddr = kmap(page);

			// Parse text section of detected process
			for (i=0; i<code_size && (i<PAGE_SIZE); i++) {
				// Replace to XBEGIN to NOP
				if ((i < (code_size-5)) && (*(myaddr+i) == XBEGIN_1) && \
					(*(myaddr+i+1) == XBEGIN_2)) {
					// 2 bytes for XBEGIN & 4 bytes for operand
					memset(myaddr+i, NOP, sizeof(*myaddr) * 6);
				}

				// Replace to XEND to NOP
				if ((i<(code_size-2))   && (*(myaddr+i)==0xf) && \
					(*(myaddr+i+1)==0x1) && (*(myaddr+i+2)==0xD5)) {
					// 3 bytes for XEND
					memset(myaddr+i, NOP, sizeof(*myaddr) * 3);
				}
			}

			// Unmap and release user mapping
			kunmap(page);
			put_page(page);
		}
		up_read(&task_list->mm->mmap_sem);
		task_unlock(task_list);

		printk(KERN_ALERT "MITIGATION-1: Vulnerable Instruction Replaced, PID: %d\n", task_list->pid);
	}

	// Apply mitigation-1 to cores 4 to 7
	else {
		// Send SIGKILL signal to detected process
		false_negative_helper++;
		task_lock(task_list);
		send_sig(SIGKILL, task_list, 0);
		task_unlock(task_list);
		printk(KERN_ALERT "MIGITATION-2: Vulnerable Process Killed, PID: %d\n", task_list->pid);
	}
}

/*
 * TAA Detection Code
 */
static void detection (char *mem_ptr, long *abort_l1_set, long *abort_l1_total,
					   long *no_abort_total, long *abort_total) {
	int set;
	volatile int status = 0;

	// Access all cache sets
	for (set=0; set<NUM_SETS; set++) {

		// Initiate TSX Transaction
		if((status=xbegin()) == _XBEGIN_STARTED) {

			// Access all 8 WAYS of this set
			maccess_set_whole(mem_ptr, set);

			// End TSX Transaction
			xend();

			// If comes here, no abort && Increment counter
			++(*no_abort_total);
		} else {

			// Transaction is aborted. Increment counter
			++(*abort_total);
		}

		// Aborted and Cache conflict
		if ((status != (_XBEGIN_STARTED)) && (status & _XABORT_CONFLICT)) {
			status = 0;

			// Increment total conflict counter
			++(*abort_l1_total);

			// Increment per set conflict counter
			abort_l1_set[set]++;
		}
	}
}

/*
 * Access all ways of a particular set
 * Do not use loop to prevent extra registers
 */
static inline void maccess_set_whole(void *mem_ptr, int set) {
	maccess(mem_ptr + (SET_DIFF * 0) + (set * LINE_SIZE)); // Way-1
	maccess(mem_ptr + (SET_DIFF * 1) + (set * LINE_SIZE)); // Way-2
	maccess(mem_ptr + (SET_DIFF * 2) + (set * LINE_SIZE)); // Way-3
	maccess(mem_ptr + (SET_DIFF * 3) + (set * LINE_SIZE)); // Way-4
	maccess(mem_ptr + (SET_DIFF * 4) + (set * LINE_SIZE)); // Way-5
	maccess(mem_ptr + (SET_DIFF * 5) + (set * LINE_SIZE)); // Way-6
	maccess(mem_ptr + (SET_DIFF * 6) + (set * LINE_SIZE)); // Way-7
	maccess(mem_ptr + (SET_DIFF * 7) + (set * LINE_SIZE)); // Way-8
}

/*
 * Access an address
 */
static inline void maccess(void *p) {
	asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax");
}

/*
 * Protection against CPU speculation
 */
static inline void mfence() {
	asm volatile("mfence");
}

/*
 * XBEGIN to mount TAA Transaction
 */
static inline unsigned int xbegin(void) {
	unsigned status;
	asm volatile(".byte 0xc7,0xf8,0x00,0x00,0x00,0x00" : "=a"(status) : "a"(-1UL) : "memory");
	return status;
}

/*
 * XEND to unmount TAA Transaction
 */
static inline void xend(void) {
	asm volatile(".byte 0x0f; .byte 0x01; .byte 0xd5" ::: "memory");
}

/*
 * init module
 */
static int __init mod_init(void) {
	int i=0;
	char thread_name[64] = "";
	for (i=0; i<NUM_CPUS; i++) {
		printk(KERN_CONT "TAA Detection is active on CPU: %d, bind to %d\n", i, (i<4) ? (i + 4) : (i-4));
		snprintf(thread_name, sizeof(thread_name), "taa_thread_%d", i);
		thread_worker[i] = kthread_create(thread_scheduler, "a", thread_name);
		kthread_bind(thread_worker[i], (i<4) ? (i + 4) : (i-4));
		wake_up_process(thread_worker[i]);
	}
	printk ("TAA Mitigation Module Init...\n");
	return 0;
}

/*
 * exit module
 */
static void __exit mod_exit(void){
	/* Stop main C-Module thread */
	int i=0;
	for (i=0; i<NUM_CPUS; i++) {
		kthread_stop(thread_worker[i]);
	}
	printk (KERN_CONT "TAA Mitigation Module Exits...\n");
}

module_init(mod_init);
module_exit(mod_exit);
