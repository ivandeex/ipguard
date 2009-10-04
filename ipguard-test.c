/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>

#include "ipguard.h"

#define NUM_TEST	20000
#define NUM_THREAD	300
#define TEST_ADDR	"2.208.125.100"

pthread_mutex_t fail_mutex = PTHREAD_MUTEX_INITIALIZER;
int failed, done;


void * one_request(void *_cfg)
{
	ipguard_cfg_t *cfg = _cfg;
	char *addr = TEST_ADDR;
	char buf[80];
	int ret;

	ret = ipguard_check_ipaddr(cfg, addr, buf, sizeof(buf));
	pthread_mutex_lock(&fail_mutex);
	if (0 == strcmp(buf, "FAIL"))
		failed++;
	done++;
	pthread_mutex_unlock(&fail_mutex);

	return NULL;
}


int
run_stress_test(ipguard_cfg_t *cfg)
{
	int i, ret;
	char *addr = TEST_ADDR;
	char buf[80];
	struct timeval tv1, tv2;
	double usec;

	/* non-thread test */
	if (1) {
		failed = 0;
		gettimeofday(&tv1, NULL);
		for (i = 0; i < NUM_TEST; i++) {
			ret = ipguard_check_ipaddr(cfg, addr, buf, sizeof(buf));
			if (0 == strcmp(buf, "FAIL"))
				failed++;
		}
		gettimeofday(&tv2, NULL);
		usec = (tv2.tv_sec - tv1.tv_sec) * 1e6 + (tv2.tv_usec - tv1.tv_usec);

		printf("test1: request count: %d\n", NUM_TEST);
		printf("test1: fail count: %d\n", failed);
		printf("test1: usec per call: %d\n", (int)(usec / NUM_TEST));
	}

#if IPGUARD_PTHREADS
	/* thread test */
	if (1) {
		pthread_t threads[NUM_THREAD];
		int num;
		void *val;

		failed = num = done = 0;
		printf("creating %d threads...\n", NUM_THREAD);
		for (i = 0; i < NUM_THREAD; i++) {
			ret = pthread_create(&threads[num], NULL, one_request, cfg);
			if (ret == 0)
				num++;
		}

		printf("joining %d threads...\n", num);
		for (i = 0; i < num; i++)
			pthread_join(threads[i], &val);

		printf("test2: created threads: %d\n", num);
		printf("test2: return count: %d\n", done);
		printf("test2: fail count: %d\n", failed);
	}
#endif /* IPGUARD_THREADS */

	ipguard_shutdown(cfg);
	return 0;
}


int
main(int argc, char **argv)
{
	int ret;
	char buf[80], addr[80];
	int stress_test = 0;
	ipguard_cfg_t cfg_buf;
	ipguard_cfg_t *cfg = &cfg_buf;

	ipguard_init(cfg);

	while (1) {
		ret = getopt(argc, argv, "vprs:S");
		if (ret == -1)
			break;
		switch (ret) {
			case 'v':
				ipguard_set_debug(cfg, 1);
				break;
			case 'p':
				ipguard_set_restrictive(cfg, 0);
				break;
			case 'r':
				ipguard_set_restrictive(cfg, 1);
				break;
			case 's':
				ipguard_set_socket_path(cfg, optarg);
				break;
			case 'S':
				stress_test = 1;
				break;
			default:
				printf("usage: %s [-v] [-p] [-r] [-s <socketpath>]\n", argv[0]);
				printf("\t-d\tbe verbose\n");
				printf("\t-p\tbe permissive (don't ban if server is down)\n");
				printf("\t-r\tbe restrictive (the default)\n");
				printf("\t-s\tset socket path (by default /var/run/ipguard.sock)\n");
				printf("\t-S\tperform stress test\n");
				exit(1);
				break;
		}
	}

	ipguard_set_enable(cfg, 1);

	if (stress_test) {
		return run_stress_test(cfg);
	}

	while (1) {
		fputs("ip> ", stdout);
		fflush(stdout);
		fgets(buf, sizeof(buf), stdin);
		*addr = '\0';
		sscanf(buf, " %s", addr);
		if (*addr == 'q' || *addr == 'e')
			break;
		ret = ipguard_check_ipaddr(cfg, addr, buf, sizeof(buf));
		printf("%s (%s)\n", ret == 0 ? "OK" : "BAN", buf);
	}

	ipguard_shutdown(cfg);
	return 0;
}

