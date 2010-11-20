/* mason.c --- 
 * 
 * Filename: mason.c
 * Author: David Bild <drbild@umich.edu>
 * Created: 11/05/2010
 * 
 * Description: Kernel module for mason protocol (L3 network layer
 * implementation.
 */

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include <linux/netdevice.h>

#include "if_mason.h"
#include "mason.h"

#define DRIVER_AUTHOR "David R. Bild <drbild@umich.edu>"
#define DRIVER_DESC   "Mason Protocol"

/* **************************************************************
 * State Machine transition functions
 * ************************************************************** */
static enum fsm_state fsm_idle_packet(struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_parlist_packet(struct sk_buff *skb){
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_txreq_packet(struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_rsstreq_packet(struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_par_packet(struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_meas_packet(struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_rsst_packet(struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_idle_timeout(long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_parlist_timeout(long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_txreq_timeout(long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_rsstreq_timeout(long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_par_timeout(long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_meas_timeout(long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_rsst_timeout(long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_idle_quit(void)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_parlist_quit(void)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_txreq_quit(void)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_rsstreq_quit(void)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_par_quit(void)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_meas_quit(void)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_rsst_quit(void)
{
  return fsm_idle; /* TODO: Implement this handler */
}


/* **************************************************************
 * Main State Machine
 * ************************************************************** */
/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_packet_trans[])(struct sk_buff *) = {
  &fsm_idle_packet,
  &fsm_c_parlist_packet,
  &fsm_c_txreq_packet,
  &fsm_c_rsstreq_packet,
  &fsm_s_par_packet,
  &fsm_s_meas_packet,
  &fsm_s_rsst_packet,
};

/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_timeout_trans[])(long)  = {
  &fsm_idle_timeout,
  &fsm_c_parlist_timeout,
  &fsm_c_txreq_timeout,
  &fsm_c_rsstreq_timeout,
  &fsm_s_par_timeout,
  &fsm_s_meas_timeout,
  &fsm_s_rsst_timeout,
};

/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_quit_trans[])(void) = {
  &fsm_idle_quit,
  &fsm_c_parlist_quit,
  &fsm_c_txreq_quit,
  &fsm_c_rsstreq_quit,
  &fsm_s_par_quit,
  &fsm_s_meas_quit,
  &fsm_s_rsst_quit,
};

static int fsm_dispatch_timeout(struct fsm *fsm, long data)
{
  int rc;
  rc = down_interruptible(&fsm->sem);
  if (0 == rc) {
    fsm->cur_state = fsm_timeout_trans[fsm->cur_state](data);
  }
  up(&fsm->sem);
  return rc;
}

static int fsm_dispatch_packet(struct fsm *fsm, struct sk_buff *skb)
{
  int rc;
  rc = down_interruptible(&fsm->sem);
  if (0 == rc) {
    fsm->cur_state = fsm_packet_trans[fsm->cur_state](skb);
  }
  up(&fsm->sem);
  return rc;
}

static int fsm_dispatch_quit(struct fsm *fsm)
{
  int rc;
  rc = down_interruptible(&fsm->sem);
  if (0 == rc) {
    fsm->cur_state = fsm_quit_trans[fsm->cur_state]();
  }
  up(&fsm->sem);
  return rc;
}

/* **************************************************************
 *            Mason packet utility functions
 * ************************************************************** */
/*
 * Returns a pointer to the tail structure (aka signature) if the
 * packet header indicates that one is included. Otherwise, returns
 * NULL.
 */
static struct masontail *mason_tail(const struct sk_buff *skb)
{
  struct masonhdr *hdr = mason_hdr(skb);
  void *typehdr = mason_typehdr(skb);
  if (!hdr->sig) {
    return NULL;
  } else {
    switch (hdr->type) {
    case MASON_INIT:
      return typehdr + sizeof(struct init_masonpkt);
    case MASON_PAR:
      return typehdr + sizeof(struct par_masonpkt);
    case MASON_PARLIST:
      return typehdr + sizeof(struct parlist_masonpkt) + 
	((struct parlist_masonpkt *)typehdr)->len;
    case MASON_TXREQ:
      return typehdr + sizeof(struct txreq_masonpkt);
    case MASON_MEAS:
      return typehdr + sizeof(struct meas_masonpkt);
    case MASON_RSSTREQ:
      return typehdr + sizeof(struct rsstreq_masonpkt);
    case MASON_RSST:
      return typehdr + sizeof(struct rsst_masonpkt) +
	((struct rsst_masonpkt *)typehdr)->len;
    case MASON_ABORT:
      return typehdr + sizeof(struct abort_masonpkt);
    default:
      printk(KERN_ERR "Invalid Mason packet type received\n");
      return NULL;
    }
  }
}


/* **************************************************************
 *                   Network functions
 * ************************************************************** */
int mason_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
  return 0;
}

static struct packet_type mason_packet_type = {
	.type = __constant_htons(ETH_P_MASON),
	.func = mason_rcv,
};

/* **************************************************************
 *                   Module functions
 * ************************************************************** */
static int __init mason_init(void)
{
	printk(KERN_INFO "Loading Mason Protocol Module\n");
	
	dev_add_pack(&mason_packet_type);

	return 0;
}

static void __exit mason_exit(void)
{
	printk(KERN_INFO "Unloading Mason Protocol Module\n");

	dev_remove_pack(&mason_packet_type);
}

module_init(mason_init);
module_exit(mason_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);	
MODULE_DESCRIPTION(DRIVER_DESC);

