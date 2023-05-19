#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<dirent.h>
#include<sys/stat.h>
#include<sys/types.h>
#include<time.h>
#define BUFLEN 1024

typedef struct Node
{
	char path[BUFLEN];
	time_t mtime;
	struct Node *next;
	struct Node *child;
	struct Node *prev;
	struct Node *parent;
} Node;

void ssu_monitor(int argc, char *argv[]);
void ssu_prompt(int argc, char *argv[]);
int execute_command(int argc, char *argv[]);
void execute_add(int argc, char *argv[]);
voidexecute_delete(int argc, char *argv[]);
void execute_tree(int argc, char *argv[]);
void execute_help();
void init_daemon(char *dirpath, time_t mn_time);
pid_t make_daemon();
void signal_handler(int signum);
int scandir_filter(const struct dirent *file);
void monitoring(char *dirpath);
Node *get_removable_node();
Node *find_node(char *path, Node *parent);
void push_node(Node *new, Node *parent);
Node *create_node(char *path, time_t mtime);
void remove_node(Node *node);
void print_tree(Node *parent, int depth);

