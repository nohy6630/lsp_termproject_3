#include"ssu_monitor.h"

FILE *log_fp;
char *ID = "20192492";
char *monitor_list = "monitor_list.txt";
volatile sig_atomic_t signal_received = 0;
Node *head = NULL;

int main(int argc, char *argv[])
{
    ssu_monitor(argc,argv);
    return 0;
}


void ssu_monitor(int argc, char *argv[]) {
    ssu_prompt();
    return;
}

void ssu_prompt(void)
{
	char command[BUFLEN];
	char* argv[100];
	int argc;

    while (1)
    {
		printf("%s> ", ID);
		fgets(command, BUFLEN, stdin);
		argc = 0;
		char *token = strtok(command," ");
		while(token != NULL)
		{
			argv[argc++] = token;
			token = strtok(NULL," ");
		}
		if(execute_command(argc, argv) == 1)
			return;
    }
}

int execute_command(int argc, char *argv[]) 
{
	if (!strcmp(argv[0], "add")) 
	{
		execute_add(argc, argv);
	} 
	else if (!strcmp(argv[0], "delete")) 
	{
		execute_delete(argc, argv);	
	} 
	else if (!strcmp(argv[0], "tree")) 
	{
		execute_tree(argc, argv);
	} 
	else if (!strcmp(argv[0], "help")) 
	{
		execute_help(argc, argv);	
	} 
	else if (!strcmp(argv[0], "exit")) 
	{
		execute_exit(argc, argv);
		return 1;
	} 
	else 
	{
		fprintf(stderr, "wrong command in prompt\n");
		execute_help(argc, argv);
	}
	return 0;
}

void execute_add(int argc, char *argv[])
{
	char real_path[BUFLEN];
	realpath(argv[1],real_path);
	init_daemon(real_path, mn_time);
	printf("monitoring started (%s)\n", real_path);
	return;
}

void execute_delete(int argc, char *argv[]) {

}	

void execute_tree(int argc, char *argv[]) {

}

void execute_help(int argc, char *argv[]) {

}

void execute_exit(int argc, char *argv[]) {

}

void init_daemon(char *dirpath, time_t mn_time)
{
	char buf[BUFLEN];

	if ((pid = fork()) < 0)
	{
		fprintf(stderr, "fork error\n");
	}
	else if (pid == 0)
	{
		if ((dpid = (make_daemon())) < 0) 
		{
			fprintf(stderr, "getpid error\n");
			exit(1);
		}
		signal(SIGUSR1, signal_handler);
		sprintf(buf, "%s/log.txt", dirpath)
		log_fp = fopen(buf, "a");
		while (!signal_received)
		{
			monitoring(dirpath);
			sleep(mn_time);
		}
		fclose(log_fp);
		printf("monitoring ended (%s)\n", dirpath);
		exit(0);
	}
	else
		return;
}

pid_t make_daemon(void) 
{
	pid_t pid;
	int fd, maxfd;

	if ((pid = fork()) < 0) {
		fprintf(stderr, "fork error\n");
		exit(1);
	}
	else if (pid != 0)
		exit(0);

	setsid();
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);

	maxfd = getdtablesize();
	for (fd = 0; fd < maxfd; fd++) //for debug , fd=3
		close(fd);
	
	umask(0);
	//	chdir("/");
	fd = open("/dev/null", O_RDWR);//stdin무시
	dup(0);//stdout무시
	dup(0);//stderr무시
	
	return getpid();
}


tree *create_node(char *path, mode_t mode, time_t mtime) 
{
	tree *new;

	new = (tree *)malloc(sizeof(tree));
	strcpy(new->path, path);
	new->isEnd = false;
	new->mode = mode;
	new->mtime = mtime;
	new->next = NULL;
	new->prev = NULL;
	new->child = NULL;
	new->parent = NULL;

	return new;
}

void make_tree(tree *dir, char *path) {
	if ((count = scandir(path, &filelist, scandir_filter, alphasort)) < 0) {
		fprintf(stderr, "in function make_tree: scandir error for %s\n", path);
		return;
	}
	
	for (i = 0; i < count; i++) {

	}
}

void compare_tree(tree *old, tree *new) {

}

void print_tree(tree *node) {
	if (node == NULL) return;

	printf("%s\n", node->path);
	print_tree(node->child);
	print_tree(node->next);
}

void free_tree(tree *cur) {

}

void signal_handler(int signum) {
	signal_received = 1;
}

int scandir_filter(const struct dirent *file) {
	if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, "..")
			|| !strcmp(file->d_name, "log.txt")
			|| !strcmp(file->d_name, monitor_list)) {
		return 0;
	}
	else
		return 1;
}

void monitoring(char *dirpath)
{
	char dirent **filelist;
	int cnt=scandir(dirpath, &filelist, scandir_filter, alphasort);
	char buf[BUFLEN];
	char curtime[50];
	char modifytime[50];
	struct stat statbuf;
	struct tm *tm_p;
	time_t now;

	if(cnt < 0)
	{
		fprintf(stderr, "scandir error\n");
		exit(1);
	}
	for(int i = 0; i < cnt; i++)
	{
		sprintf(buf,"%s/%s",dirpath,filelist[cnt]->d_name);
		stat(buf, statbuf);
		time(&now);
		tm_p = localtime(&now);
		sprintf(curtime, "%02d-%02d-%02d %02d:%02d:%02d",
							tm_p->tm_year + 1900,
							tm_p->tm_mon + 1,
							tm_p->tm_mday,
							tm_p->tm_hour,
							tm_p->tm_min,
							tm_p->tm_sec);		
		Node *node = find_node(buf);
		if(buf == NULL)
		{
			push_node(buf, statbuf.st_mtime);
			fprintf(log_fp, "[%s][create][%s]\n", curtime, buf);
		}
		else
		{
			if(node->mtime != statbuf.st_mtime)
			{
				node->mtime = statbuf.st_mtime;
				tm_p = localtime(&node->mtime);
				sprintf(modifytime, "%02d-%02d-%02d %02d:%02d:%02d",
                            tm_p->tm_year + 1900,
                            tm_p->tm_mon + 1,
                            tm_p->tm_mday,
                            tm_p->tm_hour,
                            tm_p->tm_min,
                            tm_p->tm_sec);
				fprintf(log_fp, "[%s][modify][%s]\n", modifytime, buf);
			}
		}
	}
	Node *cur = head;
	while(cur != NULL)
	{
		if(access(cur->path, F_OK) != 0)
		{
			fprintf(log_fp, "[%s][remove][%s]\n", curtime, cur->path);
		}
		cur = cur->next;
	}
}

Node *find_node(char *path)
{
	Node *cur = head;
	while(cur != NULL)
	{
		if(!strcmp(path,cur->path))
			return cur;
		cur = cur->next;
	}
	return NULL;
}

void push_node(char *path, time_t mtime)
{
	Node *node = (Node *)malloc(sizeof(Node));
	strcpy(node->path, path);
	node->mtime = mtime;
	node->next = NULL;
	if(head == NULL)
	{
		head = node;
		return;
	}
	Node *cur = head;
	while(cur->next != NULL)
		cur = cur->next;
	cur->next = node;
}

void remove_node(char *path)
{
	Node *prev = NULL;
	Node *cur = head;
    while(cur != NULL)
    {
        if(!strcmp(path,cur->path))
        {
			if(prev == NULL)
				head = cur->next;
			else
				prev->next = cur->next;
			free(prev);
			return;
		}
		prev = cur;
        cur = cur->next;
    }
}
