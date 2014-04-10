#ifndef MONITOR_H_
#define MONITOR_H_

#include <stdint.h>

#define SUCCESS "[\x1b[32m+\x1b[37m] "
#define FAILURE "[\x1b[31m-\x1b[37m] "
#define ALERT   "[\x1b[33m!\x1b[37m] "

typedef struct {
	char 		*target_output;
	char 		*fuzzer_host;
	uint32_t	fuzzer_port;
	char 		*crashlog;
	uint8_t 	continuous;
	char 		**argv;
} opts_t;

void
print_help(char *prog);
	
opts_t * 
parse_opts(int argc, char **argv);

#endif
