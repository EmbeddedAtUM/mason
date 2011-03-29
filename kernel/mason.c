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
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <net/net_namespace.h>

#include "if_mason.h"
#include "mason.h"

MODULE_DESCRIPTION("Mason Protocol");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Indu Reddy <inreddyp@umich.edu>");	
MODULE_AUTHOR("David R. Bild <drbild@umich.edu>");

static short int numids = 1;
module_param(numids, short, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(numids, "Number of identities to present, Defaults is 1.\n");

#define PFS_INIT_NAME "mason_initiate"
#define PFS_INIT_MAX_SIZE IFNAMSIZ
static struct proc_dir_entry *pfs_init = NULL;
static struct sock *nl_sk = NULL;
static struct workqueue_struct *dispatch_wq = NULL;
static LIST_HEAD(fsm_list);
static DEFINE_SPINLOCK(fsm_list_lock);
static unsigned long fsm_list_flags = 0;

/* **************************************************************
 * State Machine transition functions
 * ************************************************************** */
static void fsm_init_client(struct fsm *fsm, struct sk_buff *skb)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;
  
  if (0 == down_interruptible(&fsm->sem)) {
    switch (mason_type(skb)) {
    case MASON_INIT:
      if (!pskb_may_pull(skb, sizeof(struct init_masonpkt))) 
	goto err;
      
      if (0 != mason_sender_id(skb)) 
	goto err;

      mason_logi_label(rnd, "joining round");

      /* Save info from packet */
      rnd_info_set_dev(rnd, skb->dev);
      rnd->rnd_id = mason_round_id(skb);
      if (0 > add_identity(rnd, 0, mason_init_pubkey(skb))
	  || 0 > set_identity_hwaddr(rnd->tbl->ids[0], skb)) {
	mason_logd_label(rnd, "failed to add identity of initiator");
	goto err;
      }
      
      /* Set the public key */
      get_random_bytes(rnd->pub_key, sizeof(rnd->pub_key));      
      
      /* Send PAR message */
      if (0 != send_mason_packet(create_mason_par(rnd), rnd->tbl->ids[0]->hwaddr))  
	goto err;
      mod_fsm_timer(fsm, CLIENT_PARLIST_TIMEOUT);
      ret = fsm_c_parlist;
      goto out;
    default:
      goto err;
    }
  } else {
    del_fsm(fsm, free_rnd_info);
    goto free_skb;
  }
  
 err:
  del_fsm(fsm, free_rnd_info);
  ret = fsm_term;  
  
 out:
  fsm->cur_state = ret;
  up(&fsm->sem);
  
 free_skb:
  kfree_skb(skb);  
}


static void import_mason_parlist(struct rnd_info *rnd, struct sk_buff *skb)
{
  unsigned int i, count, start_id;
  __u8 *data;

  if (!pskb_may_pull(skb, sizeof(struct parlist_masonpkt))) {
    mason_loge_label(rnd, "PARLIST packet is too short");
    return;
  }
  
  /* Verify the values in the parlist header are reasonable */
  count = mason_parlist_count(skb);
  start_id = mason_parlist_id(skb);

  if (!pskb_may_pull(skb, count * RSA_LEN + sizeof(struct parlist_masonpkt))) {
    mason_logi_label(rnd, "PARLIST packet claims more data than available");
    return;
  }
  if (start_id + count - 1 > MAX_PARTICIPANTS) {
    mason_logi_label(rnd, "PARLIST packet claims invalid ids");
    return;
  }
  
  /* Add the participants to the identity table */
  data = mason_data(skb);
  for(i = start_id; i < count + start_id; ++i) {
    add_identity(rnd, i, data);
    data += RSA_LEN;
  }
}

static __u16 select_next_txreq_id(struct rnd_info *rnd) 
{
  __u16 rand_num;
  get_random_bytes(&rand_num, sizeof(rand_num));
  rnd->txreq_id = (rand_num % rnd->tbl->max_id) + 1;
  ++rnd->txreq_cnt;
  return rnd->txreq_id;
}

static enum fsm_state
handle_parlist(struct rnd_info *rnd, struct sk_buff *skb)
{
  del_fsm_timer(&rnd->fsm);
  import_mason_parlist(rnd, skb);
  mod_fsm_timer(&rnd->fsm, CLIENT_TIMEOUT);
  return fsm_c_parlist;
}

static enum fsm_state
handle_txreq(struct rnd_info  *rnd, struct sk_buff *skb)
{
  struct sk_buff *skbr = NULL;
  if (pskb_may_pull(skb, sizeof(struct txreq_masonpkt))) {
    del_fsm_timer(&rnd->fsm);
    if (mason_txreq_id(skb) == rnd->my_id) {
      skbr = create_mason_meas(rnd);
      if (skbr) {
	log_send_netlink(rnd->rnd_id, rnd->my_id, 0, mason_packet_id(skbr));
	bcast_mason_packet(skbr);
      } 
    }
    mod_fsm_timer(&rnd->fsm, CLIENT_TIMEOUT);
  }
  return fsm_c_txreq;
}

static enum fsm_state handle_c_meas(struct rnd_info *rnd, struct sk_buff *skb)
{
  del_fsm_timer(&rnd->fsm);
  log_receive_netlink(rnd->rnd_id, rnd->my_id, 0, mason_packet_id(skb), mason_sender_id(skb), mason_rssi(skb));
  record_new_obs(rnd->tbl, mason_sender_id(skb), mason_packet_id(skb), mason_rssi(skb));
  mod_fsm_timer(&rnd->fsm, CLIENT_TIMEOUT);
  return fsm_c_txreq;
}

static enum fsm_state handle_rsstreq(struct rnd_info *rnd, struct sk_buff *skb)
{
  struct create_rsst_state state = {
    .cur_id = 1,
    .cur_obs = NULL,
  };
  
  if (pskb_may_pull(skb, sizeof(struct rsstreq_masonpkt))) {
    del_fsm_timer(&rnd->fsm);
    if (mason_rsstreq_id(skb) == rnd->my_id) {
      while (! bcast_mason_packet(create_mason_rsst(rnd, &state))) {
 /* Repeat. */
      }
      return fsm_c_finish(rnd);
    } else {
      mod_fsm_timer(&rnd->fsm, CLIENT_TIMEOUT);
      return fsm_c_rsstreq;
    }
  }
  else {
    return fsm_c_rsstreq;
  } 
}

static inline enum fsm_state fsm_c_abort(struct rnd_info *rnd, const char *msg)
{
  mason_logi_label(rnd, "client aborting: %s", msg);
  return fsm_c_finish(rnd);
}

static enum fsm_state fsm_c_finish(struct rnd_info *rnd)
{
  mason_logi_label(rnd, "finished round: %u", rnd->rnd_id);
  del_fsm(&rnd->fsm, free_rnd_info);
  return fsm_term;
}

static enum fsm_state fsm_c_parlist_packet(struct fsm *fsm, struct sk_buff *skb)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;

  switch (mason_type(skb)) {
  case MASON_PARLIST:
    ret = handle_parlist(rnd, skb);
    break;
  case MASON_TXREQ:
    ret = handle_txreq(rnd, skb);
    break;
  case MASON_MEAS:
    ret = handle_c_meas(rnd, skb);
    break;
  case MASON_ABORT:
    ret = fsm_c_abort(rnd, "received ABORT packet from initiator");
    break;
  default:
    ret = fsm_c_parlist;
    break;
  }

  kfree_skb(skb);
  return ret; 
}


static enum fsm_state fsm_c_txreq_packet(struct fsm *fsm, struct sk_buff *skb)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;
  
  switch(mason_type(skb)) {
  case MASON_TXREQ:
    ret = handle_txreq(rnd, skb);
    break;
  case MASON_MEAS:
    ret = handle_c_meas(rnd, skb);
    break;
  case MASON_RSSTREQ:
    ret = handle_rsstreq(rnd, skb);
    break;
  case MASON_ABORT:
    ret = fsm_c_abort(rnd, "received ABORT packet from initiator");
    break;
  default:
    ret = fsm_c_txreq;
    break;
  }
  
  kfree_skb(skb);
  return ret;
}

static enum fsm_state fsm_c_rsstreq_packet(struct fsm *fsm, struct sk_buff *skb)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;

  switch (mason_type(skb)) {
  case MASON_RSSTREQ:
    ret = handle_rsstreq(rnd, skb);
    break;
  default:
    ret = fsm_c_rsstreq;
    break;
  }
  
  kfree_skb(skb);
  return ret;
}

static inline enum fsm_state fsm_s_abort(struct rnd_info *rnd, const char *msg)
{
  mason_logi_label(rnd, "initiator aborting: %s", msg);
  bcast_mason_packet(create_mason_abort(rnd));
  return fsm_s_finish(rnd);
}

static enum fsm_state fsm_s_finish(struct rnd_info *rnd)
{
  mason_logi_label(rnd, "finished round");
  del_fsm(&rnd->fsm, free_rnd_info);
  return fsm_term;
}

static enum fsm_state handle_par(struct rnd_info *rnd, struct sk_buff *skb)
{
  if (!pskb_may_pull(skb, sizeof(struct par_masonpkt))) 
    return fsm_s_par;

  if (MAX_PARTICIPANTS - 1 == rnd->tbl->max_id)
    return fsm_s_abort(rnd, "participant limit exceeded");
  
  del_fsm_timer(&rnd->fsm);
  if (0 > add_identity(rnd, ++rnd->tbl->max_id, mason_par_pubkey(skb))
      || 0 > set_identity_hwaddr(rnd->tbl->ids[rnd->tbl->max_id], skb)  ) {
    return fsm_s_abort(rnd, "unable to add identity from PAR packet");
  }
  mod_fsm_timer(&rnd->fsm, PAR_TIMEOUT);
  log_addr_netlink(rnd->rnd_id, rnd->tbl->max_id, skb);

  return fsm_s_par;
}

static enum fsm_state handle_s_meas(struct rnd_info *rnd, struct sk_buff *skb)
{
  if (mason_sender_id(skb) != rnd->txreq_id) 
    return fsm_s_meas;
  del_fsm_timer(&rnd->fsm);
  log_receive_netlink(rnd->rnd_id, rnd->my_id, 0, mason_packet_id(skb), mason_sender_id(skb), mason_rssi(skb));
  record_new_obs(rnd->tbl, mason_sender_id(skb), mason_packet_id(skb), mason_rssi(skb));
  return handle_next_txreq(rnd);
}

static enum fsm_state handle_rsst(struct rnd_info *rnd, struct sk_buff *skb)
{
  if (!pskb_may_pull(skb, sizeof(struct rsst_masonpkt)))
    return fsm_s_rsst;
  
  import_mason_rsst(rnd, skb);
  return handle_next_rsstreq(rnd, mason_rsst_is_frag(skb));
}

static enum fsm_state handle_next_txreq(struct rnd_info *rnd)
{
  /* Send next txreq if needed */
  if (rnd->txreq_cnt < rnd->tbl->max_id * TXREQ_PER_ID_AVG) {
    if (0 != bcast_mason_packet(create_mason_txreq(rnd, select_next_txreq_id(rnd))))
      return fsm_s_abort(rnd, "failed to send TXREQ packet");
    mod_fsm_timer(&rnd->fsm, MEAS_TIMEOUT);
    return fsm_s_meas;
  }

  /* Otherwise, start the rsstreqs */  
  rnd->txreq_id = 1;
  return handle_next_rsstreq(rnd, 1);
}

static enum fsm_state handle_next_rsstreq(struct rnd_info *rnd, const unsigned char cont)
{
  if (!cont)
    ++rnd->txreq_id;

  if (rnd->txreq_id > rnd->tbl->max_id) {
    return fsm_s_finish(rnd);
  }

  if (bcast_mason_packet(create_mason_rsstreq(rnd, rnd->txreq_id)))
    return fsm_s_abort(rnd, "failed to send RSSTREQ packet");
  mod_fsm_timer(&rnd->fsm, RSST_TIMEOUT);
  return fsm_s_rsst;
}

static enum fsm_state fsm_s_par_packet(struct fsm *fsm, struct sk_buff *skb)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;

  switch (mason_type(skb)) {
  case MASON_PAR:
    ret = handle_par(rnd, skb);
    break;
  default:
    ret = fsm_s_par;
    break;
  }
  
  kfree_skb(skb);
  return ret;   
}

static enum fsm_state fsm_s_meas_packet(struct fsm *fsm, struct sk_buff *skb)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;

  switch(mason_type(skb)) {
  case MASON_MEAS :
    ret = handle_s_meas(rnd, skb);
    break;
  default:
    ret = fsm_s_meas;
    break;
  }

  kfree_skb(skb);
  return ret;
}

static enum fsm_state fsm_s_rsst_packet(struct fsm *fsm, struct sk_buff *skb)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;
  
  switch (mason_type(skb)) {
  case MASON_RSST:
    ret = handle_rsst(rnd, skb);
    break;
  default:
    ret = fsm_s_rsst;
  }
  
  kfree_skb(skb);
  return ret;
}

static enum fsm_state fsm_client_timeout(struct fsm *fsm)
{
  GET_RND_INFO(fsm, rnd);
  return fsm_c_abort(rnd, "client timeout expired");
}

static enum fsm_state fsm_s_par_timeout(struct fsm *fsm)
{
  GET_RND_INFO(fsm, rnd);
  enum fsm_state ret;
  __u16 cur_id = 1;
  
  mason_logd_label(rnd, "initiator timed out while waiting for PAR packet");
  if (rnd->tbl->max_id >= MIN_PARTICIPANTS) {
    mason_logi_label(rnd, "total participants: %u", rnd->tbl->max_id);
    while (0 == bcast_mason_packet(create_mason_parlist(rnd, &cur_id)));
    ret = handle_next_txreq(rnd);
  } else {
    ret = fsm_s_abort(rnd, "not enough participants");
  }
  
  return ret;
}

static enum fsm_state fsm_s_meas_timeout(struct fsm *fsm)
{
  GET_RND_INFO(fsm, rnd);
  mason_logd_label(rnd, "initiator timed out while waiting for MEAS packet");
  return handle_next_txreq(rnd);  
}  

static enum fsm_state fsm_s_rsst_timeout(struct fsm *fsm)
{
  GET_RND_INFO(fsm, rnd);
  mason_logd_label(rnd, "initiator timed out while waiting for RSST packet");
  return handle_next_rsstreq(rnd, 0);
}

static void fsm_start_initiator(struct fsm *fsm, struct net_device *dev)
{
  enum fsm_state ret;
  GET_RND_INFO(fsm, rnd);

  if (0 == down_interruptible(&fsm->sem)) {
  /* Configure the round id */
  rnd->my_id = 0;
  rnd->tbl->max_id = 0;
  rnd->pkt_id = 0;
  get_random_bytes(&rnd->rnd_id, sizeof(rnd->rnd_id));
  get_random_bytes(rnd->pub_key, sizeof(rnd->pub_key));
  rnd->dev = dev;
  
  mason_logi_label(rnd, "initiating round");
  
  /* Send the INIT packet */
  if (0 != bcast_mason_packet(create_mason_init(rnd))) {
    ret = fsm_s_abort(rnd, "failed to send INIT packet");
  } else {
    mason_logd_label(rnd, "setting timer delay to PAR_TIMEOUT");
    mod_fsm_timer(&rnd->fsm, PAR_TIMEOUT);
    ret = fsm_s_par;
  }
  
  fsm->cur_state = ret;
  up(&fsm->sem);
  } else {
    mason_logd_label(rnd, "Unabled to send INIT message");
    del_fsm(fsm, free_rnd_info);
    ret = fsm_term;
  }
}

/* **************************************************************
 * Main State Machine
 * ************************************************************** */
/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_packet_trans[])(struct fsm *fsm, struct sk_buff *) = {
  NULL,
  &fsm_c_parlist_packet,
  &fsm_c_txreq_packet,
  &fsm_c_rsstreq_packet,
  &fsm_s_par_packet,
  &fsm_s_meas_packet,
  &fsm_s_rsst_packet,
  NULL
};

/* Functions must be ordered same as fsm_state enum declaration */
static enum fsm_state (*fsm_timeout_trans[])(struct fsm *fsm)  = {
  NULL,
  &fsm_client_timeout,
  &fsm_client_timeout,
  &fsm_client_timeout,
  &fsm_s_par_timeout,
  &fsm_s_meas_timeout,
  &fsm_s_rsst_timeout,
  NULL
};

static void __fsm_dispatch(struct fsm *fsm, struct fsm_input *input)
{
  struct fsm_timer *timer;

  switch (input->type) {
  case fsm_packet :
    if (fsm_packet_trans[fsm->cur_state])
      fsm->cur_state = fsm_packet_trans[fsm->cur_state](fsm, input->data.skb);
    break;
  case fsm_timeout :
    timer = (struct fsm_timer *) input->data.data;
    if ( (timer->idx == timer->expired_idx) && fsm_timeout_trans[fsm->cur_state])
      fsm->cur_state = fsm_timeout_trans[fsm->cur_state](fsm);
    break;
  default:
    mason_loge("invalid fsm input received");
    break;
  }
}

static void fsm_dispatch_process(struct work_struct *work)
{
  struct fsm_dispatch *dis = container_of(work, struct fsm_dispatch, work);
  struct fsm *fsm = dis->fsm;

  if (!fsm)
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
    queue_work(dispatch_wq, &dis->work);
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
  fsm_dispatch_interrupt(container_of(timer, struct fsm, timer), input);
}

static void init_fsm_timer(struct fsm_timer *timer)
{
  timer->idx = 1;
  timer->expired_idx = 0;
  setup_timer(&timer->tl, fsm_timer_callback, (unsigned long) timer);
}

/* **************************************************************
 *            Mason packet utility functions
 * ************************************************************** */
/*
 * Returns a pointer to the start of any variable length data.  This
 * is just past the end of the typehdr.
 */
extern void *mason_data(const struct sk_buff *skb)
{
  switch (mason_type(skb)) {
  case MASON_INIT:    return ((void *)mason_typehdr(skb)) + sizeof(struct init_masonpkt);
  case MASON_PAR:     return ((void *)mason_typehdr(skb)) + sizeof(struct par_masonpkt);
  case MASON_PARLIST: return ((void *)mason_typehdr(skb)) + sizeof(struct parlist_masonpkt);
  case MASON_TXREQ:   return ((void *)mason_typehdr(skb)) + sizeof(struct txreq_masonpkt);
  case MASON_MEAS:    return ((void *)mason_typehdr(skb)) + sizeof(struct meas_masonpkt);
  case MASON_RSSTREQ: return ((void *)mason_typehdr(skb)) + sizeof(struct rsstreq_masonpkt);
  case MASON_RSST:    return ((void *)mason_typehdr(skb)) + sizeof(struct rsst_masonpkt);
  case MASON_ABORT:   return ((void *)mason_typehdr(skb)) + sizeof(struct abort_masonpkt);
  default:
    mason_loge("invalid packet type received");
    return NULL;
  }
}

/*
 * Returns a pointer to the tail structure (aka signature) if the
 * packet header indicates that one is included. Otherwise, returns
 * NULL.
 *
 * TODO: Add checks to ensure that the sk_buff actually contains
 * enough data for the return pointer to be valid
 */
extern struct masontail *mason_tail(const struct sk_buff *skb)
{
  if (!mason_is_signed(skb)) {
    return NULL;
  } else {
    switch (mason_type(skb)) {
    case MASON_PARLIST:
      return mason_data(skb) + 	mason_parlist_count(skb) * RSA_LEN;
    case MASON_RSST:
      return mason_typehdr(skb) + sizeof(struct rsst_masonpkt) +
	((struct rsst_masonpkt *)mason_typehdr(skb))->len;
    case MASON_INIT:
    case MASON_PAR:
    case MASON_TXREQ:
    case MASON_MEAS:
    case MASON_RSSTREQ:
    case MASON_ABORT:
      return mason_data(skb);
    default:
      mason_loge("invalid packet type received");
      return NULL;
    }
  }
}

/*
 * Create a Mason packet, with room past the header for 'len' bytes of data
 */
static struct sk_buff *create_mason_packet(struct rnd_info *rnd, unsigned short type, int len) {
  struct sk_buff *skb;
  struct masonhdr *hdr;
  struct net_device *dev;

  dev = rnd->dev;
  
  skb = alloc_skb(LL_ALLOCATED_SPACE(dev) + sizeof(*hdr) + len, GFP_ATOMIC);
  if (!skb) {
    mason_loge_label(rnd, "failed to allocate sk_buff");
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
  hdr->type = type;
  hdr->sig = 0;
  hdr->rnd_id = htonl(rnd->rnd_id);
  hdr->sender_id = htons(rnd->my_id);
  hdr->pkt_uid = htons(rnd->pkt_id++);
  hdr->rssi = 0;

  return skb;
}

static struct sk_buff *create_mason_par(struct rnd_info *rnd)
{
  struct sk_buff *skb;
  struct par_masonpkt *typehdr;

  skb = create_mason_packet(rnd, MASON_PAR, sizeof(struct par_masonpkt));
  if (!skb)
    return NULL;

  /* Set the type-specific data */
  skb_put(skb, sizeof(struct par_masonpkt));
  typehdr = (struct par_masonpkt *)mason_typehdr(skb);
  memcpy(typehdr->pub_key, rnd->pub_key, sizeof(typehdr->pub_key));
  return skb;
}

static struct sk_buff *create_mason_init(struct rnd_info *rnd) 
{
  struct sk_buff *skb;
  struct init_masonpkt *typehdr;

  skb = create_mason_packet(rnd, MASON_INIT, sizeof(*typehdr));
  if (!skb)
    return NULL;

  /* Set the type-specific data */
  typehdr = (struct init_masonpkt *)mason_typehdr(skb);
  skb_put(skb, sizeof(struct init_masonpkt));
  memcpy(typehdr->pub_key, rnd->pub_key, sizeof(typehdr->pub_key));
  return skb;
}

/*
 * Creates a parlist packet containing the RSA keys of the
 * participants in sequential order by id.  Stops when the packet is
 * full or the last participant has been added.
 *
 * [masonhdr][start_id][count][pub_key][pub_key][pub_key][pub_key]...
 *
 * @start_id pointer to an integer indicating the id with which to
 * begin.  If the packet is filled before all identities have been
 * used, this integer is changed to the first id not included.  The
 * function can thus be called again, to create a packet with the
 * remaining identities.
 *
 * @return the sk_buff containing the packet. NULL if no participants
 * remain or an allocation error occurred.
 */
static struct sk_buff *create_mason_parlist(struct rnd_info *rnd, __u16 *start_id)
{  
  struct sk_buff *skb;
  struct parlist_masonpkt *typehdr;
  __u16 num_ids, i;
  __u8 *data;

  /* Exit if no more ids to send */
  if (*start_id > rnd->tbl->max_id)
    return NULL;
  
  /* Determine number of ids to include in packet */
  num_ids =  min( rnd->tbl->max_id - *start_id + 1,  (__u16) (rnd->dev->mtu - sizeof(struct masonhdr) - sizeof(struct parlist_masonpkt)) / RSA_LEN );

  /* Build the packet */
  skb = create_mason_packet(rnd, MASON_PARLIST, sizeof(struct parlist_masonpkt) + num_ids * RSA_LEN);
  if (!skb)
    return NULL;

  /* Set the type-specific data */
  typehdr = (struct parlist_masonpkt *)mason_typehdr(skb);
  skb_put(skb, sizeof(struct parlist_masonpkt));
  typehdr->start_id = htons(*start_id);
  typehdr->count = htons(num_ids);  

  data = (__u8 *)(typehdr + 1);
  for (i = *start_id; i < num_ids + *start_id; ++i) {
    skb_put(skb, RSA_LEN);
    memcpy(data, rnd->tbl->ids[i]->pub_key, RSA_LEN);
    data += RSA_LEN; 
  }
  *start_id += num_ids; 

  return skb;
}

static void import_mason_rsst(struct rnd_info *rnd, struct sk_buff *skb)
{
  __u16 remain;
  __u8 *data;
  __u16 sender_id;
  __u16 pkt_cnt;

  if (!pskb_may_pull(skb, sizeof(struct rsst_masonpkt)) 
      || !pskb_may_pull(skb, sizeof(struct rsst_masonpkt) + mason_rsst_len(skb))) {
    goto err;
  }

  mason_logd_label(rnd, "RSST from observer id: %u", mason_sender_id(skb));

  remain = mason_rsst_len(skb);
  data = mason_data(skb);
  while (0 < remain) {
    if (7 > remain)
      goto err;
    sender_id = ntohs(*(__u16 *)data);
    data += 2;
    remain -= 2;
    pkt_cnt = ntohs(*(__u16 *)data);
    data += 2;
    remain -= 2;
    if (pkt_cnt * 3 > remain)
      goto err;
    for (; pkt_cnt > 0; --pkt_cnt) {
      mason_logd_label(rnd, "Received: time_or_position:unknown packet_id:%u sender_id:%u rssi:%d", ntohs(*(__u16 *)data), sender_id, *(__s8*)(data+2));
      data += 3;
      remain -= 3;
    }
  }
  
  return;

 err:
  mason_loge_label(rnd, "RSST packet is invalid");
}

/* Packet format is [frag:1][len:2]([sender_id:2][pkt_cnt:2]([pkt_id:2][rssi])+)+  */
static struct sk_buff *create_mason_rsst(struct rnd_info *rnd, struct create_rsst_state *state)
{
  struct sk_buff *skb;
  struct rsst_masonpkt *typehdr;
  __u8 *data;
  __u16 pkt_cnt;
  __u16 *pkt_cnt_p;
  unsigned int max_len, remain;

  max_len = rnd->dev->mtu - sizeof(struct masonhdr) - sizeof(struct rsst_masonpkt);

  /* Build the packet */
  /* Allocate a fullsize skb and fill it until full, or the end of the
   * data is reached. This requires only one iteration through the
   * id_table, as opposed to first computing the exact number of bytes
   * to allocate and then writing the data to an exact-sized skb.
   */
  skb = create_mason_packet(rnd, MASON_RSST, sizeof(struct rsst_masonpkt) + max_len);
  if (!skb)
    return ERR_PTR(-ENOMEM);
  
  /* Set space for the type-specific data */
  typehdr = (struct rsst_masonpkt *)mason_typehdr(skb);
  skb_put(skb, sizeof(*typehdr));

  /* Start writing the data */
  data = mason_data(skb);
  remain = max_len;
  for (; state->cur_id <= rnd->tbl->max_id; ++state->cur_id) {
    /* Check if there are packets to be reported for this ID */
    if (!rnd->tbl->ids[state->cur_id])
      continue;
    if (!state->cur_obs)
      state->cur_obs = rnd->tbl->ids[state->cur_id]->head;
    if (!state->cur_obs)
      continue;
    
    /* Check for room to add at least one packet for new sender */
    if (7 > remain)
      goto frag;
    
    /* Add new sender */
    *(__u16 *)data = htons(state->cur_id);
    data += 2;
    remain -= 2;
    
    /* Add as many packets as we can */
    pkt_cnt = 0;
    pkt_cnt_p = (__u16 *)data;
    data += 2;
    remain -= 2;
    while (state->cur_obs) {
      if (3 > remain) {
	*pkt_cnt_p = htons(pkt_cnt);
	goto frag;
      }
      *(__u16 *)data = htons(state->cur_obs->pkt_id);
      data += 2;
      remain -= 2;
      *data = state->cur_obs->rssi;
      data += 1;
      remain -= 1;
      ++pkt_cnt;
      state->cur_obs = state->cur_obs->next;
    }
    
    *pkt_cnt_p = htons(pkt_cnt);
  }
  typehdr->frag = 0;
  goto finish;
  
 frag:
  typehdr->frag = 1;
  
 finish:
  if (remain == max_len) {
    kfree_skb(skb);
    return NULL;
  } else {
    typehdr->len = htons(max_len - remain);
    skb_put(skb, ntohs(typehdr->len));
    return skb;
  }
}

static struct sk_buff *create_mason_txreq(struct rnd_info *rnd, __u16 id)
{
  struct sk_buff *skb;
  struct txreq_masonpkt *typehdr;

  skb = create_mason_packet(rnd, MASON_TXREQ, sizeof(struct txreq_masonpkt));
  if (!skb)
    return NULL;

  /* Set the type header */
  typehdr = (struct txreq_masonpkt *)mason_typehdr(skb);
  skb_put(skb, sizeof(*typehdr));
  typehdr->id = htons(id);
  return skb;
}

static struct sk_buff *create_mason_rsstreq(struct rnd_info *rnd, __u16 id)
{
  struct sk_buff *skb;
  struct rsstreq_masonpkt *typehdr;
  
  skb = create_mason_packet(rnd, MASON_RSSTREQ, sizeof(struct rsstreq_masonpkt));
  if (!skb)
    return NULL;

  /* Set the type header */
  typehdr = (struct rsstreq_masonpkt *)mason_typehdr(skb);
  skb_put(skb, sizeof(*typehdr));
  typehdr->id = htons(id);
  return skb;
}

static struct sk_buff *create_mason_meas(struct rnd_info *rnd)
{
  return create_mason_packet(rnd, MASON_MEAS, 0);
}

static struct sk_buff *create_mason_abort(struct rnd_info *rnd)
{
  return create_mason_packet(rnd, MASON_ABORT, 0);
}

static int bcast_mason_packet(struct sk_buff *skb)
{
  return send_mason_packet(skb, NULL);
}

static int send_mason_packet(struct sk_buff *skb, unsigned char *hwaddr)
{
  int rc = 0;
  if (!skb)
    return -EINVAL;
  if (!hwaddr)
    hwaddr = skb->dev->broadcast;
  if (0 > (rc = dev_hard_header(skb, skb->dev, ntohs(skb->protocol), hwaddr, NULL, skb->len))) {
    mason_loge("failed to set device hard header on sk_buff");
    kfree_skb(skb);
  } else {
    mason_logd("sent %s packet", mason_type_str(skb));
    dev_queue_xmit(skb);
    rc = 0;
  }
  return rc;
}

/* **************************************************************
 *                  Round Info utility functions
 * ************************************************************** */
static struct rnd_info *__setup_rnd_info(struct rnd_info *ptr)
{
  if (!ptr)
    return NULL;

  ptr->tbl = (struct id_table *) kzalloc(sizeof(*ptr->tbl), GFP_ATOMIC);
  if (!ptr->tbl) 
    goto fail_tbl;
  ptr->rnd_id = 0;
  ptr->my_id = 0;
  ptr->pkt_id = 0;
  ptr->txreq_id = 0;
  ptr->txreq_cnt = 0;
  fsm_init(&ptr->fsm);
  return ptr;
  
 fail_tbl:
  kfree(ptr);
  return NULL;
}

static struct rnd_info *new_rnd_info(void)
{
  struct rnd_info *rnd;
  rnd = (struct rnd_info *) kzalloc(sizeof(struct rnd_info), GFP_ATOMIC);
  if (!rnd)
    return NULL;
  return  __setup_rnd_info(rnd);
}

/* Ensure that the contained fsm has been unlinked from fsm_list
   before calling.  The del_fsm(), call_rcu() mechanism does this. */
static void free_rnd_info(struct fsm *fsm)
{
  GET_RND_INFO(fsm, rnd);
  
  /* Ensure that no more references to fsm exist */
  del_fsm_timer(fsm);
  flush_workqueue(dispatch_wq);
  
  if (rnd->tbl)
    free_id_table(rnd->tbl);
  if (rnd->dev)
    dev_put(rnd->dev);
  
  kfree(rnd);
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

static void fsm_init(struct fsm *fsm) {
  if (fsm) {
    add_fsm(fsm);
    sema_init(&fsm->sem, 1);
    init_fsm_timer(&fsm->timer);
    fsm->cur_state = fsm_start;
  }
};

static void del_fsm_all(void)
{
  struct fsm *fsm;

  rcu_read_lock();
  list_for_each_entry_rcu(fsm, &fsm_list, fsm_list) {
    del_fsm_timer(fsm);
  }
  rcu_read_unlock();

  /* Ensures all pending dispatches are dispatched. */
  destroy_workqueue(dispatch_wq);
  
  /* TODO: All init FSMs should send an abort */

  /* Free all the fsms */
  rcu_read_lock();
  list_for_each_entry_rcu(fsm, &fsm_list, fsm_list) {
    del_fsm(fsm, free_rnd_info);
  }
  rcu_read_unlock();
}

static void del_fsm(struct fsm *fsm, void (*free_child)(struct fsm *)) 
{
  spin_lock_irqsave(&fsm_list_lock, fsm_list_flags);
  list_del_rcu(&fsm->fsm_list);
  spin_unlock_irqrestore(&fsm_list_lock, fsm_list_flags);
  fsm->__free_child = free_child;
  call_rcu(&fsm->rcu, __del_fsm_callback);
}

static void __del_fsm_callback(struct rcu_head *rp)
{
  __free_fsm(container_of(rp, struct fsm, rcu));
}

/*
 * This should be called in or after the update phase of the fsm_list
 * rcu delete.  To ensure all references are gone, we must cancel the
 * timer and empty the dispatch queue.
 */
static void __free_fsm(struct fsm *fsm)
{
  del_fsm_timer(fsm);
  flush_workqueue(dispatch_wq);
  fsm->__free_child(fsm);
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
    mason_loge_label(rnd, "attempt to add identity that already exists.  Ignoring");
    return -EINVAL;
  }

  id = kmalloc(sizeof(struct masonid), GFP_ATOMIC);
  if (!id) {
    mason_loge_label(rnd, "failed to allocate memory for 'struct masonid'");
    return -ENOMEM;
  }
  id->id = sender_id;
  memcpy(id->pub_key, pub_key, sizeof(id->pub_key));
  id->head = NULL;
    id->hwaddr = NULL;

  tbl->ids[sender_id] = id;
  if (rnd->tbl->max_id < sender_id)
    rnd->tbl->max_id = sender_id;
  
  /* If this is our identity, record the number assigned by the initiator */
  if (0 == memcmp(rnd->pub_key, id->pub_key, RSA_LEN)) {
    rnd->my_id = sender_id;
    mason_logd_label(rnd, "initiator assigned id:%u", sender_id);
  }  
  mason_logd_label(rnd, "added identity: rnd:%u sender_id:%u pub_key:%x%x%x%x...", 
		   rnd->rnd_id, id->id, id->pub_key[0], id->pub_key[1], id->pub_key[2], id->pub_key[3]);
  return 0;
}

static int set_identity_hwaddr(struct masonid *id, const struct sk_buff *skb)
{
  if (!id->hwaddr && !(id->hwaddr = kmalloc(skb->dev->addr_len, GFP_ATOMIC)))
    return -ENOMEM;  
  return dev_parse_header(skb, id->hwaddr);
}

static void record_new_obs(struct id_table *tbl, __u16 id, __u16 pkt_id, __s8 rssi)
{
  struct masonid *msnid;
  struct rssi_obs *prev_obs, *obs;

  if (!tbl || (id > tbl->max_id) || !tbl->ids[id])
    return;
  
  msnid = tbl->ids[id];
  prev_obs = msnid->head;
  
  obs = kzalloc(sizeof(*obs), GFP_ATOMIC);
  if (!obs)
    return;
  obs->sender_id = msnid;
  obs->pkt_id = pkt_id;
  obs->rssi = rssi;
  obs->next = prev_obs;
  msnid->head = obs;
  
  //mason_logd_label(rnd, "recorded new RSSI. sender_id:%u pkt_id:%u rssi:%d", id, pkt_id, rssi);
}

/* **************************************************************
 *                   Network functions
 * ************************************************************** */
static void mason_rcv_init(struct sk_buff *skb) {
  struct rnd_info *rnd;
  unsigned int i;
  
  for (i = 0; i < numids; ++i) {
    rnd = new_rnd_info();
    if (!rnd) {
      mason_logd("Unable to create new client for received INIT");
      break;
    }
    fsm_init_client(&rnd->fsm, skb_get(skb)); 
  }
}

static void mason_rcv_all_fsm(struct sk_buff *skb) {
  struct fsm_input *input;
  struct fsm *fsm;
  struct rnd_info *rnd;

  rcu_read_lock();
  list_for_each_entry_rcu( fsm, &fsm_list, fsm_list) {    
    rnd = container_of(fsm, struct rnd_info, fsm);
    
    /* Verify the round number of non-init packet*/
    if (rnd->rnd_id  != mason_round_id(skb)) {
      mason_logd_label(rnd, "dropping packet with non-matching round id: %u", mason_round_id(skb));
      continue;
    }
    
    /* Optimization for TXREQ packets.  Only pass the packet to the
     * FSM if the request ID matches that of this FSM
     */
    if (mason_type(skb) == MASON_TXREQ && mason_txreq_id(skb) != rnd->my_id) {
      mod_fsm_timer(fsm, CLIENT_TIMEOUT); /* We don't acquire the FSM
					     semaphore, so this timer
					     update may be unsafe.
					     This attacker
					     optimization should be
					     removed in a released
					     version anyway. */
      continue;
    }

    /* Pass the packet to the FSM */
    input = kmalloc(sizeof(*input), GFP_ATOMIC);
    if (!input)
      continue;
    
    input->type = fsm_packet;
    input->data.skb = skb_get(skb);
    
    if (input->data.skb)
      fsm_dispatch_interrupt(fsm, input);    
    else
      kfree(input);
  }
  rcu_read_unlock();
}

static int mason_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev) {
  int rc = 0;
  
  /* Drop packet if not addressed to us */
  if (skb->pkt_type == PACKET_OTHERHOST)
    goto free_skb;

  /* Verify the version */
  if (!pskb_may_pull(skb, sizeof(struct masonhdr)))
    goto free_skb;

  /* Check for valid header */
  skb_reset_network_header(skb);  
  skb_pull(skb, sizeof(struct masonhdr));
  if (MASON_VERSION != mason_version(skb)) {
    mason_logi("dropping packet with invalid version. got:%u expected:%u", mason_version(skb), MASON_VERSION);
    goto free_skb;
  }
  mason_logd("<%u> received %s packet from id:%u", mason_round_id(skb), mason_type_str(skb), mason_sender_id(skb));

  /* If INIT packet, create client fsm(s), passing the client packet to them */
  if (mason_type(skb) == MASON_INIT) {
    mason_rcv_init(skb);
    goto free_skb;
  }
  
  /* Otherwise, Deliver the packet to each fsm */
  mason_rcv_all_fsm(skb);
  
 free_skb:
  kfree_skb(skb);
  return rc;
}

static struct packet_type mason_packet_type = {
  .type = __constant_htons(ETH_P_MASON),
  .func = mason_rcv,
};

/* **************************************************************
 * Proc FS 
 * ************************************************************** */
static int write_pfs_init(struct file *file, const char *buffer,  unsigned long count, void *data) {
  char iface[PFS_INIT_MAX_SIZE+1];
  struct net_device *dev;
  struct rnd_info *rnd;

  memset(iface, 0, PFS_INIT_MAX_SIZE+1);
  if (count > PFS_INIT_MAX_SIZE)
    count = PFS_INIT_MAX_SIZE;
  
  if ( copy_from_user(iface, buffer, count) )
    return -EFAULT;
 
  dev = dev_get_by_name(&init_net, iface);
  if (!dev) {
    mason_logd("write_pfs_init: invalid dev name: '%s'", iface);
    return -EINVAL;
  }

  rnd = new_rnd_info();
  if (!rnd)
    goto fail_rnd;
  fsm_start_initiator(&rnd->fsm, dev);
  return count;

 fail_rnd:
  dev_put(dev);
  return -ENOMEM;
}

static int create_pfs_init(void)
{
  pfs_init = create_proc_entry(PFS_INIT_NAME, S_IFREG|S_IWUSR, init_net.proc_net);
  if (!pfs_init) {
    mason_loge("Unable to create %s proc file", PFS_INIT_NAME);
    remove_proc_entry(PFS_INIT_NAME, init_net.proc_net);
    return -ENOMEM;
  }

  pfs_init->write_proc = write_pfs_init;
  pfs_init->uid = 0;
  pfs_init->gid = 0;
  pfs_init->size = 0;

  return 0;
}

static inline void remove_pfs_init(void)
{
  remove_proc_entry(PFS_INIT_NAME, init_net.proc_net);
}

/* **************************************************************
 *                  Netlink functions
 * ************************************************************** */
static int init_netlink(void)
{
  nl_sk = netlink_kernel_create(&init_net, NETLINK_MASON, MASON_NL_GRP, receive_netlink, NULL, THIS_MODULE);
  if (!nl_sk)
    return -EFAULT;
  else
    return 0;
}

static void receive_netlink(struct sk_buff *skb)
{
  if (skb)
    kfree_skb(skb);
}

static void destroy_netlink(void) 
{
  if (nl_sk)
    netlink_kernel_release(nl_sk);
}

static void log_receive_netlink(__u32 rnd_id, __u16 my_id, __u16 pos, __u16 pkt_id, 
				__u16 sender_id, __s8 rssi)
{
#ifdef MASON_LOG_RECV
  struct sk_buff *skb = NULL;
  struct nlmsghdr *nlh;
  struct mason_nl_recv *rec;

  skb = alloc_skb(NLMSG_SPACE(sizeof(struct mason_nl_recv)), GFP_ATOMIC);
  if (! skb)
    return;
  
  nlh = NLMSG_PUT(skb, 0, 0, MASON_NL_RECV, sizeof(struct mason_nl_recv));
  rec = (struct mason_nl_recv *)NLMSG_DATA(nlh);
  set_mason_nl_recv(rec, rnd_id, my_id, pos, pkt_id, sender_id, rssi);
  netlink_broadcast(nl_sk, skb, 0, MASON_NL_GRP, GFP_ATOMIC);
  return;

 nlmsg_failure: /* Goto in NLMSG_PUT macro */
  kfree_skb(skb);
#endif
}

static void log_send_netlink(__u32 rnd_id, __u16 my_id, __u16 pos, __u16 pkt_id)
{
#ifdef MASON_LOG_SEND
  struct sk_buff *skb = NULL;
  struct nlmsghdr *nlh;
  struct mason_nl_send *snd;

  if (NULL == (skb = alloc_skb(NLMSG_SPACE(sizeof(struct mason_nl_send)), GFP_ATOMIC)))
    return ;
  
  nlh = NLMSG_PUT(skb, 0, 0, MASON_NL_SEND, sizeof(struct mason_nl_send));
  snd = (struct mason_nl_send *)NLMSG_DATA(nlh);
  set_mason_nl_send(snd, rnd_id, my_id, pos, pkt_id);
  netlink_broadcast(nl_sk, skb, 0, MASON_NL_GRP, GFP_ATOMIC);
  return;

 nlmsg_failure: /* Goto in NLMSG_PUT macro */
  kfree_skb(skb);
#endif
}

static void log_addr_netlink(__u32 rnd_id, __u16 id, struct sk_buff *skb_addr)
{
#ifdef MASON_LOG_ADDR
  struct sk_buff *skb = NULL;
  struct nlmsghdr *nlh;
  struct mason_nl_addr *adr;
  int addrlen;
  char *addr;
  
  if (!skb_addr || (12 < (addrlen = skb_addr->dev->addr_len)))
    return;
  
  if (NULL == (skb = alloc_skb(NLMSG_SPACE(sizeof(struct mason_nl_addr)), GFP_ATOMIC)))
    return;
  
  addr = kmalloc(skb_addr->dev->addr_len, GFP_ATOMIC);
  if (!addr)
    goto malloc_failure;
  if  (0 > dev_parse_header(skb_addr, addr))
    goto parse_failure;
  
  nlh = NLMSG_PUT(skb, 0, 0, MASON_NL_ADDR, sizeof(struct mason_nl_addr));
  adr = (struct mason_nl_addr *)NLMSG_DATA(nlh);
  set_mason_nl_addr(adr, rnd_id, id, addrlen, addr);
  netlink_broadcast(nl_sk, skb, 0, MASON_NL_GRP, GFP_ATOMIC);
  return;
  
 nlmsg_failure: /* Goto in NLMSG_PUT macro */
 parse_failure:
  kfree(addr);
 malloc_failure:
  kfree_skb(skb);
#endif
}

/* **************************************************************
 *                   Module functions
 * ************************************************************** */
static int __init mason_init(void)
{
  int rc;

  mason_logi("Loading Mason Protocol module");

  if (NULL == (dispatch_wq = create_singlethread_workqueue("mason"))) {
    mason_loge("failed to create the dispatch workqueue");
    rc = -ENOMEM;
    goto fail_wq;
  }
  
  if (0 > (rc = create_pfs_init()))
    goto fail_procfs;
  
  if (0 > init_netlink())
    goto fail_nl;

  dev_add_pack(&mason_packet_type);
  return 0;
  
 fail_nl:
  remove_pfs_init();
 fail_procfs:
  destroy_workqueue(dispatch_wq);
 fail_wq:
  return rc;
}

static void __exit mason_exit(void)
{
  mason_logi("Unloading Mason Protocol module");
  dev_remove_pack(&mason_packet_type);
  del_fsm_all();
  
  remove_pfs_init();
  destroy_netlink();
}

module_init(mason_init);
module_exit(mason_exit);
