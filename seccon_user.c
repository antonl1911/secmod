/**
 * Netlink-based control program for secmod kernel module
 * Leshchenko Anton, 2014
 */

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
/* Common include for user and kernelspace */
#include "seccon.h"

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024 /* maximum payload size, path length + 1 byte for command */
#define CONFIG_NAME "seccon.conf"
#define MODNAME "secmod.ko"
#define debug(fmt, ...) (0)

typedef struct app_entry app_entry;
struct app_entry{
	char* name;
	app_entry* next;
};

/* Sends msg_str into sock */
int nl_send_msg(int sock, char* msg_str, struct nlmsghdr* nlh);
int read_applist(char* config_name, app_entry* head);
void free_applist(app_entry* curr);
void sig_handler(int signo);
/**
 * Logic is following: main function reads application list,
 * sends registration request and listens for access queries
 * in infinite loop. Signal handler is registered to send
 * unregister msg on program close.
 */
int sock_fd = 0;
int read_entries = 0;
static app_entry head;
struct msghdr msg;
struct nlmsghdr *nlh;
struct sockaddr_nl src_addr, dest_addr;
struct iovec iov;

int main()
{
	int res = 0;
	app_entry* curr;
	char cmd[2] = " ";


	read_entries = read_applist(CONFIG_NAME, &head);
	if (read_entries <= 0) {
		printf("Error reading application list from %s\n", CONFIG_NAME);
		printf("There is no point in continuing\n");
		res = -1;
		goto exit_fail;
	}
	debug("Read %d entries from %s\n", read_entries , CONFIG_NAME);

	/* open socket */
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
		printf("Cannot open Netlink socket\n");
		perror("socket");
		printf("Please check that %s is loaded,\n", MODNAME);
		printf("and kernel supports AF_NETLINK\n");
		res = -1;
		goto exit_fail;
	}

	/* bind */
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

    res = bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));
   
	if (res) {
		printf("Error binding Netlink socket\n");
		goto exit_sock;
	}

	/* Register signal handler*/
	if (signal(SIGINT, sig_handler) == SIG_ERR)
	{
		printf("\ncan't catch SIGINT\n");
		goto exit_sock;
	}

    printf("Press Ctrl+C to exit\n");
	nlh = malloc(NLMSG_SPACE(MAX_PAYLOAD));
	cmd[0] = eRegister;
    res = nl_send_msg(sock_fd, cmd, nlh);
	if (-1 == res) { 
		perror("sendmsg");
		printf("Error sending register msg, aborting\n");
		goto exit_sock;
	}
	
	/* Receive loop */
	debug("Waiting for message from kernel\n");
	while(1) {
		res = recvmsg(sock_fd, &msg, 0);
		if(res == -1)
			continue;
    	debug("Received message payload: %s\n", (char *)NLMSG_DATA(nlh));
		
		char *msg_rx = (char *)NLMSG_DATA(nlh);
		/* Only valid paths are allowed */
    	if(msg_rx[0] != '/')
			continue;
		debug("Searching for filename %s\n", msg_rx);
		curr = &head;
		cmd[0] = eAllow;
		
		do {
			debug("Checking if %s equals to %s\n", msg_rx, curr->name);
			if (0 == strcmp(msg_rx,curr->name)) {
				cmd[0] = eDeny;
				break;
			}
		} while((curr = curr->next) && curr->name);
		nl_send_msg(sock_fd, cmd, nlh);
	}
	free(nlh);
    /* unregister pid */ 
	cmd[0] = eUnregister;
    nl_send_msg(sock_fd, cmd, nlh);
exit_sock:
    close(sock_fd);
	if (read_entries)
		free_applist(&head);
exit_fail:
	return res;
}

int read_applist(char* config_name, app_entry* head)
{
	int res = 0, read_entries = 0;
	app_entry* curr = head;
	char buf[PATH_MAX + 1];
	/* open file, parse it into array */
	FILE* cfg_file = fopen(config_name,"r");
	if (!cfg_file) {
		perror("fopen");
		res = -1;
		goto exit_fail;
	}
	/* read file, allocate entries */
	while (fscanf(cfg_file,"%s", buf) > 0)
	{
		/* We don't want filenames without leading slash */
		if (buf[0] != '/')
			continue;
		debug("Read %s from config file\n", buf);
		curr->name = malloc(strlen(buf));
		strcpy(curr->name, buf);
		/* Zero-init next list element */
		curr->next = calloc(1, sizeof(app_entry));
		curr = curr->next;
		read_entries++;
	}
	fclose(cfg_file);
	res = read_entries;
exit_fail:
	return res;
}

void free_applist(app_entry* head)
{
	app_entry* curr = head;
	app_entry* next = NULL;
	if (!curr)
		return;
	do {
		next = curr->next;
		/* First release the string */
		free(curr->name);
		/* Then struct itself */
	    if (curr != head)	
			free(curr);
		curr = next;
	} while(curr);
}
void sig_handler(int signo)
{
	char cmd[2] = " ";
  	if (signo == SIGINT) {
		cmd[0] = (int)eUnregister;
	    nl_send_msg(sock_fd, cmd, nlh);
	}
	free(nlh);
	close(sock_fd);
	if (read_entries)
		free_applist(&head);
	exit(0);
}
int nl_send_msg(int socket, char* msg_str, struct nlmsghdr * nlh)
{
	
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), msg_str);

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    debug("Sending message to kernel\n");
    return sendmsg(socket,&msg,0);
}

