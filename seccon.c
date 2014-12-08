/**
 * Linux module for controlling process launch
 * Leshchenko Anton, 2014
 * based on AKARI sources
 */

#include <linux/binfmts.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <linux/semaphore.h>
#include <linux/sched.h> 
#include <linux/pid.h>

#include "probe.h"
/* Common include for user and kernelspace */
#include "seccon.h"

#define debug(fmt, ...) (0)
/*#define debug(fmt...) \
	pr_info("[" KBUILD_MODNAME "] " fmt)*/
#define mprintk(fmt...) \
	pr_info("[" KBUILD_MODNAME "] " fmt)

#define NETLINK_USER 31
/*
 * Why not to copy all operations by "original_security_ops = *ops" ?
 * Because copying byte array is not atomic. Reader checks
 * original_security_ops.op != NULL before doing original_security_ops.op().
 * Thus, modifying original_security_ops.op has to be atomic.
 */
#define swap_security_ops(op)						\
	original_security_ops.op = ops->op; smp_wmb(); ops->op = seccon_##op;

/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;
static struct security_operations *ops;
static struct sock *nl_sk = NULL;
static void seccon_nl_recv_msg(struct sk_buff *skb);
static int client_pid = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
/* This is for 3.6 kernels and above.
 */
static struct netlink_kernel_cfg cfg = {
    .input = seccon_nl_recv_msg,
};
#endif
DEFINE_SEMAPHORE(nl_mutex);
/**
 * seccon_nl_send_msg - sends plain char message to process pid
 */ 
static int seccon_nl_send_msg(const char* msg, int msg_size, int pid)
{
	int res;
	struct sk_buff *skb_out;
	struct nlmsghdr *nlh;
	skb_out = nlmsg_new(msg_size, 0);

	if(!skb_out)
	{
		mprintk( "Failed to allocate new skb\n");
		return -1;
	} 
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh), msg, msg_size);

	res = nlmsg_unicast(nl_sk, skb_out, pid);

	debug("send to pid %d returned %d\n", pid, res);
	if (res < 0)
	    debug("Error while sending packet\n");
	return res;
}
static int cond_var = 0;
/**
 * seccon_init - Initialize this module.
 *
 * Returns 0 on success, -EINVAL otherwise.
 */
static int seccon_bprm_check_security(struct linux_binprm *bprm)
{
	int res;
	/* Do nothing if client not registered */
	if (!client_pid)
		goto orig;
	
	debug("File is %s\n", bprm->filename);
	/* Critical section start */
	down(&nl_mutex);
	/* If userspace program is in registered state,
	send request to userspace program */
	cond_var = 0;
    res = seccon_nl_send_msg(bprm->filename, strlen(bprm->filename), client_pid);
	/* If send failed, forget that pid */
	if (res < 0) {
		client_pid = 0;
		cond_var = eAllow;
	}
	/*
	 * Block here until answer is received or client unregistered
	 */

	while (!cond_var)
	{
		schedule();
	}

	/* Critical section end, we got the answer */
	up(&nl_mutex);

	if(cond_var == eDeny)
		return -EACCES;
	

	/* Protect from bad pointer state */
orig:
	while (!original_security_ops.bprm_check_security);
	return original_security_ops.bprm_check_security(bprm);
}
/**
* seccon_nl_receive_msg - recieves reg/unreg requests &
* access control messages
*/
static void seccon_nl_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int pid, res;

	debug( "Entering: %s\n", __FUNCTION__);

	nlh = (struct nlmsghdr*)skb->data;
	pid = nlh->nlmsg_pid; /*pid of sending process */
	debug( "Netlink received msg payload:%s from pid %d \n",(char*)nlmsg_data(nlh), pid);
	char *msg_rx = (char *)nlmsg_data(nlh);
	/* Parse incoming command */
	switch(msg_rx[0]){
		case eRegister:
			debug("eRegister msg rx: pid %d\n", pid);
			client_pid = pid;
    		res = seccon_nl_send_msg("Ok", 3, client_pid);
			break;
		case eUnregister:
			debug("eUnregister msg rx\n");
			client_pid = 0;
			break;
		case eAllow:
			/* signal to security function somehow */
			debug("eAllow msg rx\n");
			cond_var = eAllow;
			break;
		case eDeny:
			debug("eDeny msg rx\n");
			/* signal to security function somehow */
			cond_var = eDeny;
			break;
		default:
			break;
	}
}
/**
 * seccon_init - get security ops, open Netlink socket
 */
static int __init seccon_init(void)
{
	ops = probe_security_ops();
	if (!ops)
		goto ops_err;
	
	swap_security_ops(bprm_check_security);
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,6,0)
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
#else
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, seccon_nl_recv_msg , NULL, THIS_MODULE);
#endif
	if(!nl_sk)
		goto sock_err;
	mprintk("initialized\n");
	return 0;
sock_err:
	mprintk("Error creating socket.\n");
	return -ECHILD;
ops_err:
	mprintk("Sorry, I couldn't guess dependent symbols.\n");
	mprintk("I need some changes for supporting your "
	       "environment.\n");
	mprintk("Please contact the author.\n");
	return -EINVAL;
}

/**
 * seccon_exit - Exit this module.
 *
 * Returns nothing.
 */
static void seccon_exit(void)
{
	ops->bprm_check_security = original_security_ops.bprm_check_security;
	netlink_kernel_release(nl_sk);
	mprintk("removed\n");
}

module_init(seccon_init);
module_exit(seccon_exit);
MODULE_LICENSE("GPL");
