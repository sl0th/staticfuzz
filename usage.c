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
	"usage: %s [options] \"<target>\"\n"
	"\n"
	"\t-?, --help		print this help message\n"
	"\t-h, --fuzzer-host	hostname or ip address of the fuzzer\n"	
	"\t-p, --fuzzer-port	port the fuzzer is listening on\n"
	"\t-l, --crashlog	name of the file to log crash reports to\n"
	"\t-c, --continuous	run in continuous mode, resurrecting the\n"
	"\t			target if a fatal signal is sent\n"
	"\n"
	"<target> argument must be encapsultaed it in double qoutes and\n"
	"a full path to the target executable is required\n",
	prog);
}

opts_t *
parse_opts(int argc, char **argv)
{
	opts_t *opts;
	char *tmp;
	char **newargv;
	int result;
	int i;
	int c;

	opts = (opts_t *) malloc(sizeof(opts_t));	
	if (opts==NULL)
	{
		perror("malloc");
		return NULL;		
	}

	i = 0;
	memset(opts, 0, sizeof(opts_t));
	while ((c = getopt_long(argc, argv, "?h:p:l:c", long_options,
	      		       &option_index)) != -1)
	{
		switch(c)
		{
			case '?':
				return NULL;
			case 'h':
				tmp = (char *) malloc(strlen(optarg));
				if (tmp==NULL)
					return NULL;
				strcpy(tmp, optarg);
				opts->fuzzer_host = tmp;
				i++;
				break;
			case 'p':
				result = atoi(optarg);
				if (result==0)
					return NULL;
				opts->fuzzer_port = result;
				i++;
				break;
			case 'l':
				tmp = (char *) malloc(strlen(optarg));	
				if (tmp==NULL)
					return NULL;
				strcpy(tmp, optarg);
				opts->crashlog = tmp;
				i++;
				break;
			case 'c':
				opts->continuous++;	
				break;
			default:
				return NULL;
		}
		i++;
	}
	
	/* our target should now be in the argument vector at 
         * index i + 1 */
	if ((i+1) <= (argc-1))
	{
		result = makeargv(argv[i+1], " ", &newargv);
		if (result<0)
			return NULL;
		opts->argv = newargv;
	} 
	else 
	{
		return NULL;	
	}

	return opts;
}
