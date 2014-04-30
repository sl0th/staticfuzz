#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "monitor.h"

/* MPD Monitor - monitors the MPD process for signals, certain signals are
 * consider noteworthy and are forwarded to a corresponding fuzzer. The
 * host and port this fuzzer is listening on can be configured through the
 * command line arguments */

void cprintf(pid_t original, pid_t signaled, char *format)
{
	if (original != signaled)
		printf("[Child Thread %d] ", signaled);
	else
		printf("[Parent Thread %d] ", signaled);
	
	printf(format);
}

void 
printstats(pid_t target, char *crashreport)
{
	struct user_regs_struct regs;	
	time_t crashtime;	
	FILE *fp = stdout;
	int result;

	/* only fails if pointer is invalid */
	time(&crashtime);

	result = ptrace(PTRACE_GETREGS, target, NULL, &regs);
	if (result)
	{
		printf(FAILURE "unable to peek at target's registers\n");
		perror("ptrace");
	}

	if (crashreport != NULL)
	{
		if ((fp = fopen(crashreport, "a")) == NULL)
		{
			fp = stdout;
			printf(FAILURE "failed to open crashreport file..."
				" printing to stdout\n");	
			perror("fopen");
		}
	}
	fprintf(stderr, ALERT "attempting to print crash stats\n");
	fprintf(fp, "--[ BEGIN REGISTER DUMP\n");
	fprintf(fp, "--[ %s", ctime(&crashtime));
	fprintf(fp, "EBX: %08x | ECX: %08x | EDX: %08x |\n"
		    "ESI: %08x | EDI: %08x | EBP: %08x |\n"
		    "EAX: %08x | EIP: %08x | ESP: %08x |\n"
		    "EFLAGS: %08x\n",
		    regs.ebx, regs.ecx, regs.edx, 
		    regs.esi, regs.edi, regs.ebp, 
		    regs.eax, regs.eip, regs.esp, 
		    regs.eflags);

	if (fp != stdout)
		fclose(fp);
}

void
setptraceopt(pid_t target)
{
	long ret;	

	ret = ptrace(PTRACE_SETOPTIONS, target, NULL, PTRACE_O_TRACECLONE);

	fprintf(stderr, "returned: %ld\n", ret);

}

pid_t
spinup(char **argv, char *redirect)
{
	pid_t child;	
	int fd;

	child = fork();
	if (child==0)
	{
		if (redirect!=NULL)
		{
			if ((fd = open(redirect, O_CREAT | O_TRUNC | 
				O_WRONLY, 0644)) < 0)
			{
				perror(FAILURE "(child) open");
			}
			else	
			{
				dup2(fd, 1); /* stdout */
				dup2(fd, 2); /* stderr */
			}
		}

		ptrace(PTRACE_TRACEME, (pid_t) 0, (void *) NULL, 
			(void *) NULL);

		printf(SUCCESS "(child) tracer attached...\n");
		printf(SUCCESS "(child) execing into %s...\n",  argv[0]);

		execv(argv[0], argv);
		printf(FAILURE "execv failed to execute given target!\n");
		printf(ALERT "did you provide a full path?\n");
		exit(1);
	}

	return child;
}

void
monitor(pid_t target, char *crashreport, int verbose)
{
	struct user_regs_struct regs;
	int status;
	pid_t signaled;
	int setopt;
	int error;
	int ret;
	pid_t original;
	pid_t newpid;
	memset(&regs, 0, sizeof(struct user_regs_struct));

	original = target;
	setopt = 0;
	while(1)
	{
		signaled = waitpid(-1, &status, __WALL);
		if (signaled == -1)
		{
			printf(FAILURE "wait returned with " 
				"error %d\n", signaled);
			return; 
		}
		if (verbose)
			fprintf(stderr, ALERT "process %d recieved signal!\n", signaled);
		if (WIFEXITED(status))
		{
			printf(ALERT "(status: %d, signal: %s) "
				"child exited \n",
				status, strsignal(WEXITSTATUS(status)));
			return;
		}
		if (WIFSIGNALED(status))
		{
			printf(ALERT "(status: %d, signal: %s) "
				"child received fatal signal\n",	
				status, strsignal(WTERMSIG(status)));
			return;
		}
		if (WIFSTOPPED(status))
		{
			if (verbose)
				printf(ALERT "(status: %d, signal: %s) "
				"child stopped\n",
				status, strsignal(WSTOPSIG(status)));

			switch(WSTOPSIG(status))
			{
				case SIGTRAP:
					/* set up child tracing */
					if (!setopt)
					{
						setptraceopt(signaled);
						setopt = 1;
					}
					else
					{
						ptrace(PTRACE_GETEVENTMSG, signaled, NULL, (void *)&newpid);
						printf(SUCCESS "new LWP %d\n", newpid);
					}
					if (verbose)
						printf(SUCCESS "continuing via "
						"ptrace\n");
			break;
				case SIGSTOP:
					if (verbose)
						cprintf(original, signaled, SUCCESS "received SIGSTOP!\n");
					break;
				case SIGSEGV:
				case SIGILL:
				case SIGABRT:
				case SIGFPE:
				case SIGBUS:
				case SIGSYS:
					cprintf(original, signaled, SUCCESS "target received "
					"an interesting signal!\n");
					printstats(signaled, crashreport);
					break;
				default:
					printf(FAILURE "no handling "
					"mechanism in place for recieved "
					"signal\n");
			}

			ret = ptrace(PTRACE_CONT, signaled, 0, 
			WSTOPSIG(status) == SIGTRAP ? 0 : 
			WSTOPSIG(status));
		}
	}
}

int
main(int argc, char **argv)
{
	pid_t childpid;
	int status;
	int result;
	opts_t *opts;

	setsid();

	opts = parse_opts(argc, argv);
	if (opts==NULL)
	{
		print_help(argv[0]);
		return 1;
	}

	do
	{
		childpid = spinup(opts->argv, opts->target_output);
		if (childpid < 0)
		{
			printf(FAILURE "failed to spin up target process\n");
			printf(ALERT "exiting...\n");
			exit(1);
		}

		printf(ALERT "starting monitor over " 
			     "process %d...\n", childpid);

		printf("---monitor session begin ---\n");
		monitor(childpid, opts->crashlog, opts->verbose);
		printf("---end of monitor session---\n");

	} while (opts->continuous);
}
