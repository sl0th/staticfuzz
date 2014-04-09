#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "monitor.h"

/* MPD Monitor - monitors the MPD process for signals, certain signals are
 * consider noteworthy and are forwarded to a corresponding fuzzer. The
 * host and port this fuzzer is listening on can be configured through the
 * command line arguments */

void printregs(struct user_regs_struct *regs, char *crashreport)
{
	FILE *fp = stdout;

	if (crashreport != NULL)
	{
		if ((fp = fopen(crashreport, "a")) == NULL)
		{
			fp = stdout;
			printf(FAILURE "failed to open crashreport file... printing to stdout\n");	
		}
	}
	fprintf(fp, "EIP:
}

void
monitor(pid_t target, char *crashreport)
{
	struct user_regs_struct regs;
	pid_t error;	
	int status;

	while(1)
	{
		error = waitpid(target, &status, 0);
		if (error != target)
		{
			printf(FAILURE "wait returned with error %d\n", error);
			return; 
		}
		if (WIFEXITED(status))
		{
			printf(ALERT "(status: %d, signal: %s) child exited \n",
				status, strsignal(WEXITSTATUS(status)));
			return;
		}
		if (WIFSIGNALED(status))
		{
			printf(ALERT "(status: %d, signal: %s) child received fatal signal\n",	
				status, strsignal(WTERMSIG(status)));
		}
		if (WIFSTOPPED(status))
		{
			printf(ALERT "(status: %d, signal: %s) child stopped\n",
				status, strsignal(WSTOPSIG(status)));
			switch(WSTOPSIG(status))
			{
				case SIGTRAP:	
					printf(SUCCESS "continuing via ptrace\n");
					ptrace(PTRACE_CONT, target, 0, 0);
					break;
				case SIGSEGV:
					printf(SUCCESS "target attempted to access invalid memory!");
					ptrace(PTRACE_GETREGS, target, &regs, (void *) NULL);
					printregs(&regs, crashreport);
				default:
					printf(FAILURE "no handling mechanism in place for recieved signal\n");
			}
		}
	}
}

int
main(int argc, char **argv)
{
	pid_t childpid;
	pid_t forked;
	int status;
	int result;

	setsid();

	forked = fork();

	/* replace with spinup() */
	if (forked==0)
	{
		/* wait until we receive a PTRACE_ATTACH */
		childpid = getpid();
		ptrace(PTRACE_TRACEME, (pid_t) 0, (void *) NULL, (void *) NULL);
		printf(SUCCESS "(child) tracer attached...\n");
		printf(SUCCESS "(child) execing into /usr/local/bin/mpd...\n");
		//execl("/usr/local/bin/mpd", "mpd", "--help", NULL);
		execl("/usr/local/bin/mpd", "mpd", "--no-config", "--no-daemon", NULL);
	}

	/* parse args here */

	/* register child killing signal handler */

	//ptrace(PTRACE_CONT, forked, 0, 0);

	printf(ALERT "starting monitor over process %d...\n", forked);
	/* if mode == continuous */
	/* while (1) { */
	monitor(forked, NULL);
}
