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

/*
 * Main Mason receive function
 */
int mason_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
  return 0;
}

static struct packet_type mason_packet_type = {
	.type = __constant_htons(ETH_P_MASON),
	.func = mason_rcv,
};

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

