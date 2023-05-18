
FILE *log_fp;
char *ID = "20230000";
char *monitor_list = "monitor_list.txt";
volatile sig_atomic_t signal_received = 0;

void ssu_monitor(int argc, char *argv[]) {
	ssu_prompt();
	return;
}

void ssu_prompt(void) {
	while (1) {
		printf("%s> ", ID);
		fgets(command, BUFLEN, stdin);
		if (execute_command(argc, argv) == 1)
	}
}

int execute_command(int argc, char *argv[]) {
	if (!strcmp(argv[0], "add")) {
		execute_add(argc, argv);
	} else if (!strcmp(argv[0], "delete")) {
		execute_delete(argc, argv);	
	} else if (!strcmp(argv[0], "tree")) {
		execute_tree(argc, argv);
	} else if (!strcmp(argv[0], "help")) {
		execute_help(argc, argv);	
	} else if (!strcmp(argv[0], "exit")) {
		execute_exit(argc, argv);
		return 1;
	} else {
		fprintf(stderr, "wrong command in prompt\n");
		execute_help(argc, argv);
	}
	return 0;
}

void execute_add(int argc, char *argv[]) {

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

void init_daemon(char *dirpath, time_t mn_time) {
	if ((pid = fork()) < 0) {
		
	}
	else if (pid == 0) { //child
		if ((dpid = (make_daemon())) < 0) {

		}

		while (!signal_received) {

		}

		printf("monitoring ended (%s)\n", dirpath);
		exit(0);
	}
	else
		return;
}

pid_t make_daemon(void) {
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
	fd = open("/dev/null", O_RDWR);
	dup(0);
	dup(0);
	
	return getpid();
}


tree *create_node(char *path, mode_t mode, time_t mtime) {
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
