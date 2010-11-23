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
#include <linux/skbuff.h>
#include <linux/random.h>
#include <net/net_namespace.h>


#include "if_mason.h"
#include "mason.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("David R. Bild <drbild@umich.edu>");
MODULE_AUTHOR("Indu Reddy <inreddyp@umich.edu>");	
MODULE_DESCRIPTION("Mason Protocol");

static short int is_initiator = 0;
module_param(is_initiator, short, 0);
MODULE_PARM_DESC(is_initiator, "1 if the module should initiate a round of mason test\n");

static struct net_device *mason_dev;
static struct fsm *cur_fsm;

/* **************************************************************
 * State Machine transition functions
 * ************************************************************** */
static enum fsm_state fsm_idle_packet(struct rnd_info *rnd, struct sk_buff *skb)
{
  enum fsm_state ret;
  struct masonhdr *hdr;
  struct init_masonpkt *typehdr;
  struct masonid *sender;
  struct sk_buff *reply;

  hdr = mason_hdr(skb);
  switch (hdr->type) {
  case MASON_INIT:
    if (!pskb_may_pull(skb, sizeof(struct init_masonpkt))) {
      ret = fsm_idle;
      goto out;
    }
    
    /* Save info from packet */
    hdr = mason_hdr(skb);
    typehdr = (struct init_masonpkt *) mason_typehdr(skb);
    
    rnd->dev = skb->dev;
    rnd->rnd_id = ntohl(hdr->rnd_id);
    if (0 > add_identity(rnd, ntohs(hdr->sender_id), typehdr->pub_key)) 
      goto err;
    
    sender = rnd->tbl->ids[ntohs(hdr->sender_id)];
    sender->hwaddr = kmalloc(skb->dev->addr_len, GFP_KERNEL);
    if (!sender->hwaddr || !dev_parse_header(skb, sender->hwaddr)) 
      goto err;

    /* Send PAR message */
    reply = create_mason_par(rnd);
    if (!reply) 
      goto err;

    printk(KERN_INFO "Sending PAR message in reply to INIT");
    dev_queue_xmit(reply);
    ret = fsm_c_parlist;
    goto out;
  default:
    ret = fsm_idle;
    goto out;
  }
  
 err:
  /* TODO: Cleanup round info structures */
  ret = fsm_idle;  
  
 out:
  kfree_skb(skb);
  return ret;
}

static enum fsm_state fsm_c_parlist_packet(struct rnd_info *rnd, struct sk_buff *skb){
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_txreq_packet(struct rnd_info *rnd, struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_rsstreq_packet(struct rnd_info *rnd, struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_par_packet(struct rnd_info *rnd, struct sk_buff *skb)
{
  struct masonhdr *hdr;
  struct par_masonpkt *typehdr;

  hdr = mason_hdr(skb);
  switch (hdr->type) {
  case MASON_PAR:
    if (!pskb_may_pull(skb, sizeof(*typehdr))) 
      goto out;
    typehdr = mason_typehdr(skb);
    
    printk(KERN_INFO "Received PAR message; adding identity\n");
    add_identity(rnd, ++rnd->tbl->max_id, typehdr->pub_key);
    goto out;
  default:
    goto out;
  }

  out:
    kfree_skb(skb);
    return fsm_s_par; 
}

static enum fsm_state fsm_s_meas_packet(struct rnd_info *rnd, struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_rsst_packet(struct rnd_info *rnd, struct sk_buff *skb)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_idle_timeout(struct rnd_info *rnd, long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_parlist_timeout(struct rnd_info *rnd, long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_txreq_timeout(struct rnd_info *rnd, long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_rsstreq_timeout(struct rnd_info *rnd, long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_par_timeout(struct rnd_info *rnd, long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_meas_timeout(struct rnd_info *rnd, long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_rsst_timeout(struct rnd_info *rnd, long data)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_idle_quit(struct rnd_info *rnd)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_parlist_quit(struct rnd_info *rnd)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_txreq_quit(struct rnd_info *rnd)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_c_rsstreq_quit(struct rnd_info *rnd)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_par_quit(struct rnd_info *rnd)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_meas_quit(struct rnd_info *rnd)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_s_rsst_quit(struct rnd_info *rnd)
{
  return fsm_idle; /* TODO: Implement this handler */
}

static enum fsm_state fsm_idle_initiate(struct rnd_info *rnd)
{
  struct sk_buff *skb;

  /* Configure the round id */
  rnd->my_id = 0;
  rnd->tbl->max_id = 0;
  rnd->pkt_id = 0;
  get_random_bytes(&rnd->rnd_id, sizeof(rnd->rnd_id));
  //get_random_bytes(&rnd->pub_key, sizeof(rnd->pub_key));

  /* Add ourself to the id table */
  add_identity(rnd, 0, rnd->pub_key);

  /* Create the packet */
  skb = create_mason_init(rnd);
  if (!skb)
    return fsm_idle;
  
  dev_queue_xmit(skb);
  return fsm_s_par;
}

/* **************************************************************
 * Main State Machine
 * ************************************************************** */
/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_packet_trans[])(struct rnd_info *, struct sk_buff *) = {
  &fsm_idle_packet,
  &fsm_c_parlist_packet,
  &fsm_c_txreq_packet,
  &fsm_c_rsstreq_packet,
  &fsm_s_par_packet,
  &fsm_s_meas_packet,
  &fsm_s_rsst_packet,
};

/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_timeout_trans[])(struct rnd_info *, long)  = {
  &fsm_idle_timeout,
  &fsm_c_parlist_timeout,
  &fsm_c_txreq_timeout,
  &fsm_c_rsstreq_timeout,
  &fsm_s_par_timeout,
  &fsm_s_meas_timeout,
  &fsm_s_rsst_timeout,
};

/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_quit_trans[])(struct rnd_info *) = {
  &fsm_idle_quit,
  &fsm_c_parlist_quit,
  &fsm_c_txreq_quit,
  &fsm_c_rsstreq_quit,
  &fsm_s_par_quit,
  &fsm_s_meas_quit,
  &fsm_s_rsst_quit,
};

/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_initiate_trans[])(struct rnd_info *) = {
  &fsm_idle_initiate,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
};

static int fsm_dispatch_timeout(struct fsm *fsm, long data)
{
  int rc;
  rc = down_interruptible(&fsm->sem);
  if (0 == rc) {
    if (fsm_timeout_trans[fsm->cur_state])
      fsm->cur_state = fsm_timeout_trans[fsm->cur_state](fsm->rnd, data);
  }
  up(&fsm->sem);
  return rc;
}

static int fsm_dispatch_packet(struct fsm *fsm, struct sk_buff *skb)
{
  int rc;
  rc = down_interruptible(&fsm->sem);
  if (0 == rc) {
    if (fsm_packet_trans[fsm->cur_state])
      fsm->cur_state = fsm_packet_trans[fsm->cur_state](fsm->rnd, skb);
  }
  up(&fsm->sem);
  return rc;
}

static int fsm_dispatch_quit(struct fsm *fsm)
{
  int rc;
  rc = down_interruptible(&fsm->sem);
  if (0 == rc) {
    if (fsm_quit_trans[fsm->cur_state])
      fsm->cur_state = fsm_quit_trans[fsm->cur_state](fsm->rnd);
  }
  up(&fsm->sem);
  return rc;
}

static int fsm_dispatch_initiate(struct fsm *fsm)
{
  int rc;
  rc = down_interruptible(&fsm->sem);
  if (0 == rc) {
    if (fsm_initiate_trans[fsm->cur_state])
      fsm->cur_state = fsm_initiate_trans[fsm->cur_state](fsm->rnd);
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

/*
 * Create a Mason packet, with room past the header for 'len' bytes of data
 */
static struct sk_buff *create_mason_packet(struct rnd_info *rnd, int len) {
  struct sk_buff *skb;
  struct masonhdr *hdr;
  struct net_device *dev;

  if (rnd->dev)
    dev = rnd->dev;
  else
    dev = mason_dev;
  
  skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + sizeof(*hdr) + len, GFP_KERNEL);
  if (!skb) {
    printk(KERN_ERR "Failed to allocate sk_buff for Mason packet\n");
    return NULL;
  }

  skb->dev = dev;
  skb->protocol = htons(ETH_P_MASON);
  
  skb_reserve(skb, LL_RESERVED_SPACE(dev));
  skb_reset_network_header(skb);

  /* Setup the header */
  skb_put(skb, sizeof(*hdr));
  hdr = mason_hdr(skb);
  hdr->version = MASON_VERSION;
  hdr->sig = 0;
  hdr->rnd_id = htonl(rnd->rnd_id);
  hdr->sender_id = htons(rnd->my_id);
  hdr->pkt_uid = htons(rnd->pkt_id++);

  return skb;
}

static struct sk_buff *create_mason_par(struct rnd_info *rnd)
{
  struct sk_buff *skb;
  struct masonhdr *hdr;
  struct par_masonpkt *typehdr;

  skb = create_mason_packet(rnd, sizeof(struct par_masonpkt));
  if (!skb)
    goto out;

  /* Set the type in the header */
  hdr = mason_hdr(skb);
  hdr->type = MASON_PAR;

  /* Set the type-specific data */
  skb_put(skb, sizeof(struct par_masonpkt));
  typehdr = (struct par_masonpkt *)mason_typehdr(skb);
  memcpy(typehdr->pub_key, rnd->pub_key, sizeof(typehdr->pub_key));

  /* Set the LL header */
  if (0 > dev_hard_header(skb, skb->dev, ntohs(skb->protocol), rnd->tbl->ids[0]->hwaddr, NULL, skb->len)) {
    printk(KERN_ERR "Failed to set device hard header on Mason Protocol packet\n");
    kfree_skb(skb);
    skb = NULL;
  }

 out:
  return skb;
}

static struct sk_buff *create_mason_init(struct rnd_info *rnd) 
{
  struct sk_buff *skb;
  struct masonhdr *hdr;
  struct init_masonpkt *typehdr;

  skb = create_mason_packet(rnd, sizeof(struct init_masonpkt));
  if (!skb)
    goto out;

  /* Set the type in the header */
  hdr = mason_hdr(skb);
  hdr->type = MASON_INIT;

  /* Set the type-specific data */
  skb_put(skb, sizeof(struct init_masonpkt));
  typehdr = (struct init_masonpkt *)mason_typehdr(skb);
  memcpy(typehdr->pub_key, rnd->pub_key, sizeof(typehdr->pub_key));

  /* Set the LL header */
  if (0 > dev_hard_header(skb, skb->dev, ntohs(skb->protocol), skb->dev->broadcast, NULL, skb->len)) {
    printk(KERN_ERR "Failed to set device hard header on Mason Protocol packet\n");
    kfree_skb(skb);
    skb = NULL;
  }
  
 out:
  return skb;
}


/* **************************************************************
 *                  Round Info utility functions
 * ************************************************************** */
static struct rnd_info *new_rnd_info(void)
{
  struct rnd_info *ret;
  ret = (struct rnd_info *) kzalloc(sizeof(struct rnd_info), GFP_KERNEL);
  if (!ret)
    goto out;

  ret->rnd_id = 0;
  ret->tbl = (struct id_table *) kzalloc(sizeof(*ret->tbl), GFP_KERNEL);
  if (ret->tbl) 
    goto out; 
  
  kfree(ret);
  ret = NULL;
  
 out:
  return ret;
}

static void free_rnd_info(struct rnd_info *ptr)
{
  kfree(ptr->tbl);
  kfree(ptr);
}

static struct fsm *new_fsm(void)
{
  struct fsm *ret;
  ret = (struct fsm *) kzalloc(sizeof(struct fsm), GFP_KERNEL);
  if (ret)
    fsm_init(ret);
  return ret;
}

static void free_fsm(struct fsm *ptr)
{
  kfree(ptr);
}

static int add_identity(struct rnd_info *rnd, __u16 sender_id, __u8 *pub_key)
{
  struct id_table *tbl;
  struct masonid *id;

  tbl = rnd->tbl;  
  if (tbl->ids[sender_id]) {
    printk(KERN_INFO "Trying to add Mason protocol identity which already exists\n");
    return -EINVAL;
  }

  id = kmalloc(sizeof(struct masonid), GFP_KERNEL);
  if (!id) {
    printk(KERN_ERR "Failed to allocate memeory for Mason protocol: masonid in id_table\n");
    return -ENOMEM;
  }
  tbl->ids[sender_id] = id;

  id->id = sender_id;
  memcpy(id->pub_key, pub_key, sizeof(id->pub_key));
  id->head = NULL;
  id->hwaddr = NULL;

  return 0;
}

/* **************************************************************
 *                   Network functions
 * ************************************************************** */
int mason_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
  struct masonhdr *hdr;
  int rc = 0;
  
  /* Drop packet if not addressed to us */
  if (skb->pkt_type == PACKET_OTHERHOST)
    goto out;

  /* Verify the version */
  if (!pskb_may_pull(skb, sizeof(struct masonhdr)))
    goto out;

  skb_reset_network_header(skb);  
  skb_pull(skb, sizeof(struct masonhdr));
  hdr = mason_hdr(skb);
  if (MASON_VERSION != hdr->version) {
    printk(KERN_INFO "Dropping packet with invalid Mason version number: %i != %i\n", MASON_VERSION, hdr->version);
    goto out;
  }

  printk(KERN_INFO "Dispatching Mason protocol packet\n");
  fsm_dispatch_packet(cur_fsm, skb);
  return rc;
  
 out:
  kfree_skb(skb);
  return rc;
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
  mason_dev = dev_get_by_name(&init_net, DEV_NAME); /* TODO: Find the
						       device by
						       feature, rather
						       than by name.
						       Register for
						       net_device
						       notification
						       chain to handle
						       device addition
						       and removal. */
  if (!mason_dev) {
    printk(KERN_ERR "Failed to find net_device for Mason protocol\n");
    return -EINVAL;
  }

  
  cur_fsm = new_fsm();
  if (!cur_fsm) {
    printk(KERN_ERR "Failed to allocate memory for struct fsm\n");
    dev_put(mason_dev);
    return -ENOMEM;
  }

  cur_fsm->rnd = new_rnd_info();

  if (!cur_fsm->rnd) {
    printk(KERN_ERR "Failed to allocate memory for struct rnd_info\n");
    dev_put(mason_dev);
    free_fsm(cur_fsm);
    return -ENOMEM;
  }
  
  dev_add_pack(&mason_packet_type);

  if (1 == is_initiator) {
    msleep(5000);
    fsm_dispatch_initiate(cur_fsm);
  }
  
  return 0;
}

static void __exit mason_exit(void)
{
  printk(KERN_INFO "Unloading Mason Protocol Module\n");
  if (mason_dev)
    dev_put(mason_dev);
  if (cur_fsm) {
    if (cur_fsm->rnd)
      free_rnd_info(cur_fsm->rnd);
    free_fsm(cur_fsm);
  }
  dev_remove_pack(&mason_packet_type);
}

module_init(mason_init);
module_exit(mason_exit);



