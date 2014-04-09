#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "monitor.h"

int option_index = 0;

static struct option long_options[] = {
	{ "help", no_argument, NULL, '?'},
	{ "fuzzer-host", required_argument, NULL, 'h'},
	{ "fuzzer-port", required_argument, NULL, 'p'},
	{ "crashlog", required_argument, NULL, 'l'},
	{ "continuous", no_argument, NULL, 'c'},
	{ 0, 0, 0, 0}
};

void 
print_help(char *prog)
{
	fprintf(stderr,
	"usage: %s [options] <target>\n"
	"\n"
	"\t-?, --help		print this help message\n"
	"\t-h, --fuzzer-host	hostname or ip address of the fuzzer\n"	
	"\t-p, --fuzzer-port	port the fuzzer is listening on\n"
	"\t-l, --crashlog	name of the file to log crash reports to\n"
	"\t-c, --continuos	run in continuous mode, resurrecting the\n"
	"\t			target if a fatal signal is sent\n",
	prog);
}

opts_t *
parse_opts(int argc, char **argv)
{
	opts_t *opts;
	char *tmp;
	int result;
	int c;

	opts = (opts_t *) malloc(sizeof(opts_t));	
	if (opts==NULL)
	{
		perror("malloc");
		return NULL;		
	}

	memset(opts, 0, sizeof(opts_t));
	while ((c = getopt_long(argc, argv, "h:p:l:c", long_options,
	      		       &option_index)) != 1)
	{
		switch(c)
		{
			case 'h':
				tmp = (char *) malloc(strlen(optarg));
				if (tmp==NULL)
					return NULL;
				strcpy(tmp, optarg);
				opts->fuzzer_host = tmp;
				break;
			case 'p':
				result = atoi(optarg);
				if (result==0)
					return NULL;
				opts->fuzzer_port = result;
				break;
			case 'l':
				tmp = (char *) malloc(strlen(optarg));	
				if (tmp==NULL)
					return NULL;
				strcpy(tmp, optarg);
				opts->crashlog = tmp;
				break;
			case 'c':
				opts->continuous++;	
				break;
		}
	}
	
	fprintf(stderr, "opton_index: %d\n", option_index);
}