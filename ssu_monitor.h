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
} Node;

void ssu_monitor(int argc, char *argv[]);
void ssu_prompt(int argc, char *argv[]);
int execute_command(int argc, char *argv[]);
int execute_add(int argc, char *argv[]);
int execute_delete(int argc, char *argv[]);
int execute_tree(int argc, char *argv[]);
int execute_help();
int execute_exit();
void init_daemon(char *dirpath, time_t mn_time);
pid_t make_daemon();
tree *create_node(char *path, mode_t mode, time_t mtime);
void make_tree(tree *dir, char *path);
void compare_tree(tree *old, tree *new);
void print_tree(tree *node);
void free_tree(tree *cur);
void signal_handler(int signum);
int scandir_filter(const struct dirent *file);
void monitoring(char *dirpath);
Node *find_node(char *path);
void push_node(char *path, time_t mtime);
void remove_node(char *path);
