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

MODULE_DESCRIPTION("Mason Protocol");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Indu Reddy <inreddyp@umich.edu>");	
MODULE_AUTHOR("David R. Bild <drbild@umich.edu>");


static short int init = 0;
module_param(init, short, 0);
MODULE_PARM_DESC(init, "1 if the module should initiate a round of mason test\n");

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
    
    dev_hold(skb->dev);
    rnd->dev = skb->dev;
    rnd->rnd_id = ntohl(hdr->rnd_id);
    if (0 > add_identity(rnd, ntohs(hdr->sender_id), typehdr->pub_key)) 
      goto err;
    
    sender = rnd->tbl->ids[ntohs(hdr->sender_id)];
    sender->hwaddr = kmalloc(skb->dev->addr_len, GFP_ATOMIC);
    if (!sender->hwaddr || !dev_parse_header(skb, sender->hwaddr)) 
      goto err;
#ifdef MASON_DEBUG
    printk(KERN_DEBUG "Mason initiator hwaddr:%x:%x:%x:%x:%x:%x\n",
	   sender->hwaddr[0], sender->hwaddr[1], sender->hwaddr[2], sender->hwaddr[3], sender->hwaddr[4], sender->hwaddr[5]);
#endif
    

    /* Set the public key */
    get_random_bytes(rnd->pub_key, sizeof(rnd->pub_key));

    /* Send PAR message */
    reply = create_mason_par(rnd);
    if (!reply) 
      goto err;

#ifdef MASON_DEBUG
    printk(KERN_DEBUG "Sending Mason PAR message in reply to INIT\n");
#endif
    dev_queue_xmit(reply);
    mod_fsm_timer(&rnd->timer, CLIENT_TIMEOUT);
    ret = fsm_c_parlist;
    goto out;
  default:
    ret = fsm_idle;
    goto out;
  }
  
 err:
  reset_rnd_info(rnd);
  ret = fsm_idle;  
  
 out:
  kfree_skb(skb);
  return ret;
}

static enum fsm_state fsm_c_parlist_packet(struct rnd_info *rnd, struct sk_buff *skb){
  enum fsm_state ret;
  struct masonhdr *hdr;
  struct parlist_masonpkt *parlisthdr;
  struct txreq_masonpkt *txreqhdr;

  hdr = mason_hdr(skb);
  switch (hdr->type) {
  case MASON_PARLIST:
    if (!pskb_may_pull(skb, sizeof(struct parlist_masonpkt)))
      goto out;
    /* TODO: Handle the PARLIST packet */
    goto out;
  case MASON_TXREQ:
    if (!pskb_may_pull(skb, sizeof(struct txreq_masonpkt)))
      goto out;
    /* TODO: Handle the TXREQ packet */
    goto out;
  case MASON_ABORT:
    goto abort;
  default:
    goto out;
  }

 out:
  kfree_skb(skb);
  return fsm_c_parlist; 

 abort:
#ifdef MASON_DEBUG
  printk(KERN_DEBUG "Mason Protocol client received ABORT message.  Aborting\n");
#endif
  reset_rnd_info(rnd);
  kfree_skb(skb);
  return fsm_idle;
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
  struct sk_buff *reply;

  hdr = mason_hdr(skb);
  switch (hdr->type) {
  case MASON_PAR:
    if (!pskb_may_pull(skb, sizeof(*typehdr))) 
      goto out;
    typehdr = mason_typehdr(skb);
    if (rnd->tbl->max_id < MAX_PARTICIPANTS) {
#ifdef MASON_DEBUG
      printk(KERN_DEBUG "Received PAR message. Adding identity\n");
#endif
      add_identity(rnd, ++rnd->tbl->max_id, typehdr->pub_key);
      goto out;
    } else {
#ifdef MASON_DEBUG
      printk(KERN_DEBUG "Received PAR message.  Participant limit exceeded.  Aborting\n");
#endif
      reply = create_mason_abort(rnd);
      if (reply)
	dev_queue_xmit(reply);
      reset_rnd_info(rnd);
      goto abort;
    }
  default:
    goto out;
  }
  
 out:
  kfree_skb(skb);
  return fsm_s_par; 
  
 abort:
  kfree_skb(skb);
  return fsm_idle;
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
  printk(KERN_ERR "Mason Protocol FSM received timeout in idle state. This should not occur\n");
  return fsm_idle; /* We're already in idle, so ignore any errant timeouts */
}

static enum fsm_state fsm_client_timeout(struct rnd_info *rnd, long data)
{
#ifdef MASON_DEBUG
  printk(KERN_DEBUG "Mason Protocol client timed out waiting for packets\n");
#endif
  reset_rnd_info(rnd);
  return fsm_idle;  
}

static enum fsm_state fsm_s_par_timeout(struct rnd_info *rnd, long data)
{
  struct sk_buff *reply;

#ifdef MASON_DEBUG
  printk(KERN_DEBUG "Mason Protocol initiator timed out waiting for PAR packets.\n");
#endif

  if (rnd->tbl->max_id >= MIN_PARTICIPANTS) {
    while (NULL != (reply = create_mason_parlist(rnd))) {
#ifdef MASON_DEBUG
      printk(KERN_DEBUG "Sending Mason PARLIST packet\n");
#endif
      dev_queue_xmit(reply);
    }
    reply = create_mason_next_txreq(rnd);
    if (reply) {
#ifdef MASON_DEBUG
      printk(KERN_DEBUG "Sending Mason MEAS packet\n");
#endif
      dev_queue_xmit(reply);
      mod_fsm_timer(&rnd->timer, MEAS_TIMEOUT);
      goto out;
    } else {
#ifdef MASON_DEBUG
      printk(KERN_DEBUG "Unable to create Mason MEAS packet.  Aborting round\n");
#endif
      goto abort;
    }
  }
  else {
#ifdef MASON_DEBUG
    printk(KERN_DEBUG "Not enough participants.  Aborting round\n");
#endif
    goto abort;
  }


 out:
  return fsm_s_meas;
  
 abort:
  reply = create_mason_abort(rnd);
  if (reply)
    dev_queue_xmit(reply);
  reset_rnd_info(rnd);
  return fsm_idle; 
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
  get_random_bytes(rnd->pub_key, sizeof(rnd->pub_key));

  /* Create the packet */
  skb = create_mason_init(rnd);
  if (!skb)
    return fsm_idle;
  
#ifdef MASON_DEBUG
  printk(KERN_DEBUG "Sending Mason INIT message\n");
#endif
  dev_queue_xmit(skb);
  mod_fsm_timer(&rnd->timer, PAR_TIMEOUT);
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
  &fsm_client_timeout,
  &fsm_client_timeout,
  &fsm_client_timeout,
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

static void __fsm_dispatch(struct fsm *fsm, struct fsm_input *input)
{
  struct fsm_timer *timer;

  switch (input->type) {
  case fsm_packet :
    if (fsm_packet_trans[fsm->cur_state])
      fsm->cur_state = fsm_packet_trans[fsm->cur_state](fsm->rnd, input->data.skb);
    break;
  case fsm_timeout :
    timer = (struct fsm_timer *) input->data.data;
    if ( (timer->idx == timer->expired_idx) && fsm_timeout_trans[fsm->cur_state])
      fsm->cur_state = fsm_timeout_trans[fsm->cur_state](fsm->rnd, input->data.data);
    break;
  case fsm_quit :
    if (fsm_quit_trans[fsm->cur_state])
      fsm->cur_state = fsm_quit_trans[fsm->cur_state](fsm->rnd);
    break;
  case fsm_initiate :
    if (fsm_initiate_trans[fsm->cur_state])
      fsm->cur_state = fsm_initiate_trans[fsm->cur_state](fsm->rnd);
    break;
  default:
    printk(KERN_ERR "Invalid Mason Protocol FSM input type received\n");
    break;
  }
}

static void fsm_dispatch_process(struct work_struct *work)
{
  struct fsm_dispatch *dis = container_of(work, struct fsm_dispatch, work);
  struct fsm *fsm = dis->fsm;

  if (!fsm || !fsm->rnd)
    goto out;

  if (0 == down_interruptible(&fsm->sem)) {
    __fsm_dispatch(fsm, dis->input);
    up(&fsm->sem);
  }
  
 out:
  kfree(dis->input);
  kfree(dis);
}

static int fsm_dispatch_interrupt(struct fsm *fsm, struct fsm_input *input)
{
  int rc = 0;
  struct fsm_dispatch *dis;

  if (!fsm )
    goto out;

  if (!fsm->rnd) {
    fsm->rnd = new_rnd_info();
    fsm->rnd->fsm = fsm;
  }

  rc = down_trylock(&fsm->sem);
  if (0 == rc) {
    __fsm_dispatch(fsm, input);
    up(&fsm->sem);
  } else {
    dis = kmalloc(sizeof(*dis), GFP_ATOMIC);
    if (unlikely(!dis)) {
      rc = -ENOMEM;
      goto free_input;
    }
    
    dis->fsm = fsm;
    dis->input = input;
    INIT_WORK(&dis->work, fsm_dispatch_process);
    schedule_work(&dis->work);
    goto out;
  }

 free_input:
  kfree(input);
  
 out:
  return rc;
}

/* **************************************************************
 * Timers
 * ************************************************************** */
static void fsm_timer_callback(unsigned long data) 
{
  struct fsm_timer *timer = (struct fsm_timer *) data;
  struct fsm_input *input;

  timer->expired_idx = timer->idx;

  input = kzalloc(sizeof(*input), GFP_ATOMIC);
  if (!input)
    return;
  input->type = fsm_timeout;
  input->data.data = data;
  fsm_dispatch_interrupt(timer->rnd->fsm, input);
}

static void init_fsm_timer(struct fsm_timer *timer, struct rnd_info *rnd)
{
  timer->rnd = rnd;
  timer->idx = 1;
  timer->expired_idx = 0;
  setup_timer(&timer->tl, fsm_timer_callback, (unsigned long) timer);
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
  
  skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + sizeof(*hdr) + len, GFP_ATOMIC);
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

  skb = create_mason_packet(rnd, sizeof(*typehdr));
  if (!skb)
    goto out;

  /* Set the type in the header */
  hdr = mason_hdr(skb);
  hdr->type = MASON_INIT;

  /* Set the type-specific data */
  typehdr = (struct init_masonpkt *)mason_typehdr(skb);
  skb_put(skb, sizeof(struct init_masonpkt));
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

static struct sk_buff *create_mason_parlist(struct rnd_info *rnd)
{
  struct sk_buff *skb;
  struct masonhdr *hdr;

  /* TODO: Implement this function */

  return NULL;
}

static struct sk_buff *create_mason_next_txreq(struct rnd_info *rnd)
{
  struct sk_buff *skb;
  struct masonhdr *hdr;

  /* TODO: Implement this function */

  return NULL;
}

static struct sk_buff *create_mason_abort(struct rnd_info *rnd)
{
  struct sk_buff *skb;
  struct masonhdr *hdr;

  skb = create_mason_packet(rnd, 0);
  if (!skb)
    goto out;
  
  /* Set the type in the header */
  hdr = mason_hdr(skb);
  hdr->type = MASON_ABORT;

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
static struct rnd_info *__setup_rnd_info(struct rnd_info *ptr)
{
  if (!ptr)
    return NULL;

  ptr->rnd_id = 0;
  init_fsm_timer(&ptr->timer, ptr);
  ptr->tbl = (struct id_table *) kzalloc(sizeof(*ptr->tbl), GFP_ATOMIC);
  if (!ptr->tbl) {
    kfree(ptr);
    ptr = NULL;
  }

  return ptr;
}

static struct rnd_info *new_rnd_info(void)
{
  struct rnd_info *ret;
  ret = (struct rnd_info *) kzalloc(sizeof(struct rnd_info), GFP_ATOMIC);
  if (!ret)
    goto out;

  ret =  __setup_rnd_info(ret);

 out:
  return ret;
}

static struct rnd_info *reset_rnd_info(struct rnd_info *ptr)
{
  if (!ptr)
    return NULL;
  
  if (ptr->dev) {
    dev_put(ptr->dev);
    ptr->dev = NULL;
  }
  del_fsm_timer(&ptr->timer);    
  if (ptr->tbl)
    free_id_table(ptr->tbl);

  return __setup_rnd_info(ptr);
}

static void free_rnd_info(struct rnd_info *ptr)
{
  if (!ptr)
    return;

  if (ptr->dev)
    dev_put(ptr->dev);
  del_fsm_timer(&ptr->timer);
  if (ptr->tbl)
    free_id_table(ptr->tbl);
  
  kfree(ptr);
}

static void free_id_table(struct id_table *ptr)
{
  int i;

  if (!ptr)
    return;

  for (i = 0; i < MAX_PARTICIPANTS; ++i) {
    if (ptr->ids[i])
      free_identity(ptr->ids[i]);
  }

  kfree(ptr);
}

static struct fsm *new_fsm(void)
{
  struct fsm *ret;
  ret = (struct fsm *) kzalloc(sizeof(struct fsm), GFP_ATOMIC);
  if (ret)
    fsm_init(ret);
  return ret;
}

static void free_fsm(struct fsm *ptr)
{
  kfree(ptr);
}
   
static void free_rssi_obs_list(struct rssi_obs *head)
{
  struct rssi_obs *next = head;

  if (!head)
    return;

  do {
    head = next;
    next = head->next;
    kfree(head);
  } while (next);
}

static void free_identity(struct masonid *ptr)
{
  if (ptr->hwaddr)
    kfree(ptr->hwaddr);
  
  if (ptr->head)
    free_rssi_obs_list(ptr->head);

  kfree(ptr);
}

static int add_identity(struct rnd_info *rnd, __u16 sender_id, __u8 *pub_key)
{
  struct id_table *tbl;
  struct masonid *id;

  tbl = rnd->tbl;  
  if (tbl->ids[sender_id]) {
    printk(KERN_ERR "Trying to add Mason protocol identity which already exists\n");
    return -EINVAL;
  }

  id = kmalloc(sizeof(struct masonid), GFP_ATOMIC);
  if (!id) {
    printk(KERN_ERR "Failed to allocate memeory for Mason protocol: masonid in id_table\n");
    return -ENOMEM;
  }
  tbl->ids[sender_id] = id;

  id->id = sender_id;
  memcpy(id->pub_key, pub_key, sizeof(id->pub_key));
  id->head = NULL;
  id->hwaddr = NULL;

#ifdef MASON_DEBUG
  printk(KERN_DEBUG "Added Mason Identity: rnd:%u sender_id:%u pub_key:%x%x%x%x...\n", 
	 rnd->rnd_id, id->id, id->pub_key[0], id->pub_key[1], id->pub_key[2], id->pub_key[3]);
#endif  

  return 0;
}

/* **************************************************************
 *                   Network functions
 * ************************************************************** */
int mason_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
  struct fsm_input *input;
  struct masonhdr *hdr;
  int rc = 0;
  
  /* Drop packet if not addressed to us */
  if (skb->pkt_type == PACKET_OTHERHOST)
    goto free_skb;

  /* Verify the version */
  if (!pskb_may_pull(skb, sizeof(struct masonhdr)))
    goto free_skb;

  skb_reset_network_header(skb);  
  skb_pull(skb, sizeof(struct masonhdr));
  hdr = mason_hdr(skb);
  if (MASON_VERSION != hdr->version) {
    printk(KERN_ERR "Dropping packet with invalid Mason version number: %i != %i\n", MASON_VERSION, hdr->version);
    goto free_skb;
  }

  /* Verify the round number */
  if (cur_fsm->rnd && (cur_fsm->rnd->rnd_id != 0) && (cur_fsm->rnd->rnd_id != ntohl(hdr->rnd_id)) ) {
    printk(KERN_INFO "Dropping packet with differing round id: %u != %u\n", cur_fsm->rnd->rnd_id, ntohl(hdr->rnd_id));
    goto free_skb;
  }

#ifdef MASON_DEBUG
  printk(KERN_DEBUG "Dispatching Mason protocol packet\n");
#endif
  input = kmalloc(sizeof(*input), GFP_ATOMIC);
  if (!input)
    goto free_skb;
  input->type = fsm_packet;
  input->data.skb = skb;
  fsm_dispatch_interrupt(cur_fsm, input);
  return rc;
  
 free_skb:
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
  struct fsm_input *input;
  
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
  
  dev_add_pack(&mason_packet_type);

  if (1 == init) {
    msleep(1500);
    input = kzalloc(sizeof(*input), GFP_ATOMIC);
    if (!input)
      goto out;
    input->type = fsm_initiate;
    fsm_dispatch_interrupt(cur_fsm, input);
  }
  
 out:
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



