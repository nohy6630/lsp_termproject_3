#include"ssu_monitor.h"

FILE *log_fp = NULL;
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

void ssu_prompt()
{
	char command[BUFLEN];
	char* argv[100];
	int argc;

    while (1)
    {
		printf("%s> ", ID);
		fgets(command, BUFLEN - 1, stdin);
		command[strlen(command) - 1] = 0;
		argc = 0;
		char *token = strtok(command," ");
		while(token != NULL)
		{
			argv[argc++] = token;
			token = strtok(NULL," ");
		}
		execute_command(argc, argv);
    }
}

void execute_command(int argc, char *argv[]) 
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
		exit(1);
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
	int c;
	char real_path[BUFLEN];
	time_t mn_time;

	while((c = getopt(argc, argv, "t:")) != -1)
	{
		switch(c)
		{
			case 't':
				mn_time = atoi(optarg);
				if(mn_time == 0)
				{
					fprintf(stderr, "mntime is 0 OR atoi error\n");
					return;
				}
				break;
			case '?':
				fprintf(stderr, "argv option error\n");
				return;
		}
	}
	realpath(argv[1],real_path);
	init_daemon(real_path, mn_time);
	printf("monitoring started (%s)\n", real_path);
	return;
}

void execute_delete(int argc, char *argv[]) {
	char *tmp_file=".delete_tmp";
	FILE* fp = fopen(monitor_list, "r");
	FILE* wfp = fopen(tmp_file, "w");
	char buf[BUFLEN];
	pid_t input_pid= atoi(argv[1]);

	while(fgets(buf, BUFLEN, fp) != NULL)
	{

		strtok(buf, " ");
		pid_t pid = atoi(strtok(NULL, " "));
		if(pid == input_pid)
			kill(pid, SIGUSR1);
		else
			fprintf(wfp, "%s", buf);
	}
	close(fp);
	close(wfp);
	rename(tmp_file, monitor_list);
}	

void execute_tree(int argc, char *argv[])
{
	char real_path[BUFLEN];

	realpath(argv[1], real_path);
	printf("%s\n", strrchr(real_path, '/')+1);
	//log_fp=stdout;
	monitoring(real_path);
	print_tree(NULL, 0);
	while(head)
		remove_node(head);
}

void execute_help(int argc, char *argv[])
{
	printf("Usage:\n");
	printf(" > add <DIRPATH> [OPTION]\n");
	printf("   -t <TIME> : set monitoring time\n");
    printf(" > delete <DAEMON_PID>n");
    printf(" > tree <DIRPATH>\n");
    printf(" > help\n");
    printf(" > exit\n");
}

void init_daemon(char *dirpath, time_t mn_time)
{
	char buf[BUFLEN];
	FILE *monitor_fp;
	pid_t pid, dpid;

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
		monitor_fp = fopen(monitor_list, "a");
		fprintf(monitor_fp, "%s %d\n", dirpath, dpid);
		fclose(monitor_fp);
		sprintf(buf, "%s/log.txt", dirpath);
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

void signal_handler(int signum)
{
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
	struct dirent **filelist;
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
		sprintf(buf,"%s/%s",dirpath,filelist[i]->d_name);
		//printf("%s\n",buf);
		stat(buf, &statbuf);
		time(&now);
		tm_p = localtime(&now);
		sprintf(curtime, "%02d-%02d-%02d %02d:%02d:%02d",
							tm_p->tm_year + 1900,
							tm_p->tm_mon + 1,
							tm_p->tm_mday,
							tm_p->tm_hour,
							tm_p->tm_min,
							tm_p->tm_sec);
		Node *node = find_node(buf, NULL);
		if(node == NULL)
		{
			push_node(create_node(buf, statbuf.st_mtime), NULL);
			if(log_fp)
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
				if(log_fp)
					fprintf(log_fp, "[%s][modify][%s]\n", modifytime, buf);
			}
		}
		if(filelist[i]->d_type == DT_DIR)
        {
            monitoring(buf);
        }
	}
	Node *node;
	while((node=get_removable_node()) != NULL)
	{
		if(log_fp)
			fprintf(log_fp, "[%s][remove][%s]\n", curtime, node->path);
		remove_node(node);
	}
}

Node *get_removable_node()
{
	Node *cur = head;
	while(cur)
	{
		if(access(cur->path, F_OK) != 0)
			return cur;
		if(cur->child)
			cur = cur->child;
		else if(cur->next)
			cur = cur->next;
		else if(cur->parent)
			cur = cur->parent->next;
		else
			cur = NULL;
	}
}

Node *find_node(char *path, Node *parent)//parent 자식 노드들 중에서 해당 노드를 찾는다.
{
	Node *cur;
	char buf[BUFLEN];

	if(parent == NULL)
		cur = head;
	else
		cur = parent->child;
	while(cur != NULL)
	{
		if(!strcmp(path,cur->path))
			return cur;
		sprintf(buf, "%s/", cur->path);
		if(strstr(path, buf) == path)
			return find_node(path, cur);
		cur = cur->next;
	}
	return NULL;
}

void push_node(Node *new,  Node *parent)
{
	char buf[BUFLEN];

	Node *cur;
	if(parent == NULL)
	{
		if(head == NULL)
		{
			head = new;
			return;
		}
        cur = head;
	}
    else
	{
		if(parent->child == NULL)
		{
			parent->child = new;
			new->parent = parent;
			return;
		}
        cur = parent->child;
	}
	while(cur->next != NULL)
	{
		sprintf(buf, "%s/", cur->path);
		//printf("strstr(%s,%s)==%s\n",new->path,buf,strstr(new->path,buf));
        if(strstr(new->path, buf) == new->path)
            return push_node(new->path, cur);
		cur = cur->next;
	}
	sprintf(buf, "%s/", cur->path);
    //printf("strstr(%s,%s)==%s\n",new->path,buf,strstr(new->path,buf));
    if(strstr(new->path, buf) == new->path)
        return push_node(new->path, cur);
	cur->next = new;
	new->prev = cur;
	new->parent = cur->parent;
}

Node *create_node(char *path, time_t time)
{
	Node *new = (Node *)malloc(sizeof(Node));
    strcpy(new->path, path);
    new->mtime = time;
    new->next = NULL;
    new->child = NULL;
	new->prev = NULL;
	new->parent = NULL;
	return new;
}

void remove_node(Node *node)
{
	//printf("remove_node(%s) start\n",node->path);
	while(node->child)
		remove_node(node->child);
	if(node->parent)
	{
		if(node->parent->child == node)
			node->parent->child = node->next;
	}
	else
	{
		if(head == node)
			head = node->next;
	}
	if(node->next)
		node->next->prev = node->prev;
	if(node->prev)
		node->prev = node->next;
	//printf("remove_node(%s) end\n",node->path);
	free(node);
}

void print_tree(Node *parent, int depth)
{
	Node *cur;

	if(parent == NULL)
		cur = head;
	else
		cur = parent->child;
	while(cur != NULL)
	{
		for(int i = 0; i < depth; i++)
			printf("|    ");
		printf("|----%s\n",strrchr(cur->path, '/') + 1);
		print_tree(cur, depth + 1);
		cur = cur->next;
	}
}
