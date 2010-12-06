/* mason.h --- 
 * 
 * Filename: mason.h
 * Author: David Bild <drbild@umich.edu>
 * Created: 11/18/2010
 * 
 * Description: Private definitions for mason protocol (L3 kernel
 *              implementation).
 */
#ifndef _MASON_H
#define _MASON_H

#include <linux/rcupdate.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/netdevice.h>

#define MIN_PARTICIPANTS 1
#define MAX_PARTICIPANTS 400

#define CLIENT_TIMEOUT 500
#define PAR_TIMEOUT 100
#define MEAS_TIMEOUT 30
#define RSST_TIMEOUT 100

#define TXREQ_PER_ID_AVG 4

struct fsm_timer {
  struct timer_list tl;
  unsigned long idx;
  unsigned long expired_idx; /* When the timer expires, this is set to
				idx.  If the timer is re-added before
				the fsm_input corresponding to the
				expiry is processed, then, at the time
				of processing, idx > expired_idx.  If
				idx==expired_idx, the timer has not
				been reset.  In most cases, if idx >
				expired_idx, then the timeout should
				be ignored. */  
};

enum fsm_state {
  fsm_start     = 0,
  fsm_c_parlist = 1,
  fsm_c_txreq   = 2,
  fsm_c_rsstreq = 3,
  fsm_s_par     = 4,
  fsm_s_meas    = 5,
  fsm_s_rsst    = 6,
  fsm_term      = 7,
};

enum fsm_input_type {
  fsm_packet  = 0,
  fsm_timeout = 1,
};

struct rnd_info;
struct fsm {
  struct list_head fsm_list;
  struct rcu_head  rcu;
  struct semaphore sem;
  enum fsm_state cur_state;
  struct fsm_timer timer;
  void (*__free_child)(struct fsm *);
};

struct fsm_input {
  enum fsm_input_type type;
  union {
    long data;
    struct sk_buff *skb;} data;
};

struct fsm_dispatch {
  struct work_struct work;
  struct fsm *fsm;
  struct fsm_input *input;
};

/* **************************************************************
 * Timers
 * ************************************************************** */
static void fsm_timer_callback(unsigned long data);
static void init_fsm_timer(struct fsm_timer *timer);

static inline void mod_fsm_timer(struct fsm *fsm, unsigned long msec)
{
  if (fsm) {
    ++fsm->timer.idx;
    mod_timer(&fsm->timer.tl, jiffies + msecs_to_jiffies(msec));
  }
}

static inline void del_fsm_timer(struct fsm *fsm)
{
  if (fsm)
    del_timer(&fsm->timer.tl);
}

/* **************************************************************
 *    State Machine Declarations
 * ************************************************************** */
static void fsm_init(struct fsm *fsm);
static void del_fsm(struct fsm *fsm, void (*free_child)(struct fsm *));
static void del_fsm_all(void);
static void __del_fsm_callback(struct rcu_head *rp);
static void __free_fsm(struct fsm *fsm);

#define add_fsm(ptr) do {spin_lock_irqsave(&fsm_list_lock, fsm_list_flags); \
    list_add_rcu(&ptr->fsm_list, &fsm_list);				\
    spin_unlock_irqrestore(&fsm_list_lock, fsm_list_flags);		\
  } while(0)


#define FIRST_FSM list_first_entry(&fsm_list, struct fsm, fsm_list)

static int fsm_dispatch_interrupt(struct fsm *fsm, struct fsm_input *input);
static void fsm_dispatch_process(struct work_struct *work);
static void __fsm_dispatch(struct fsm *fsm, struct fsm_input *input);

static enum fsm_state fsm_c_parlist_packet(struct fsm *fsm, struct sk_buff *skb);
static enum fsm_state fsm_c_txreq_packet(struct fsm *fsm, struct sk_buff *skb);
static enum fsm_state fsm_c_rsstreq_packet(struct fsm *fsm, struct sk_buff *skb);
static enum fsm_state fsm_s_par_packet(struct fsm *fsm, struct sk_buff *skb);
static enum fsm_state fsm_s_meas_packet(struct fsm *fsm, struct sk_buff *skb);
static enum fsm_state fsm_s_rsst_packet(struct fsm *fsm, struct sk_buff *skb);

static enum fsm_state fsm_client_timeout(struct fsm *fsm);
static enum fsm_state fsm_s_par_timeout(struct fsm *fsm);
static enum fsm_state fsm_s_meas_timeout(struct fsm *fsm);
static enum fsm_state fsm_s_rsst_timeout(struct fsm *fsm);

static void fsm_start_initiator(struct fsm *fsm, struct net_device *dev);
static void fsm_init_client(struct fsm *fsm, struct sk_buff *skb);

static enum fsm_state handle_parlist(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state handle_txreq(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state handle_c_meas(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state handle_rsstreq(struct rnd_info *rnd, struct sk_buff *skb);
static inline enum fsm_state fsm_c_abort(struct rnd_info *rnd);
static enum fsm_state fsm_c_finish(struct rnd_info *rnd);

static enum fsm_state handle_par(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state handle_s_meas(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state handle_rsst(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state handle_next_txreq(struct rnd_info *rnd);
static enum fsm_state handle_next_rsstreq(struct rnd_info *rnd, const unsigned char cont);
static inline enum fsm_state fsm_s_abort(struct rnd_info *rnd);
static enum fsm_state fsm_s_finish(struct rnd_info *rnd);

/* **************************************************************
 * Debug methods
 * ************************************************************** */
#define MASON_KLOG "mason: "
#define MASON_KLOG_TERM "\n"

#ifdef MASON_DEBUG
#define mason_logd(str, ...) \
  printk(KERN_DEBUG MASON_KLOG str MASON_KLOG_TERM, ##__VA_ARGS__)
#else
#define mason_logd(str, ...)
#endif

#define mason_logi(str, ...) \
  printk(KERN_INFO MASON_KLOG str MASON_KLOG_TERM, ##__VA_ARGS__)

#define mason_loge(str, ...) \
  printk(KERN_ERR MASON_KLOG str MASON_KLOG_TERM, ##__VA_ARGS__)

/* **************************************************************
 * Round data
 * ************************************************************** */
/* Forward declaration */
struct masonid;
struct rssi_obs;

/* RSSI Observations */
struct rssi_obs {
  struct masonid *sender_id;
  __u16 pkt_id;
  __s8  rssi;
  struct rssi_obs *next;
};

/* Identity Management */
struct masonid {
  __u8  pub_key[RSA_LEN];
  __u16 id;  /* This id must be a assigned by the initiator to ensure
		that it is unique */
  unsigned char *hwaddr;
  struct rssi_obs* head;
};

struct id_table {
  struct masonid *ids[MAX_PARTICIPANTS];
  __u16 max_id;
};

/* Information associated with a round */
struct rnd_info {
  struct fsm fsm;
  __u32 rnd_id;
  __u16 my_id;
  __u16 pkt_id;
  __u8  pub_key[RSA_LEN];
  __u16 txreq_id;
  __u16 txreq_cnt; 
  struct net_device *dev;
  struct id_table *tbl;
};

static inline void rnd_info_set_dev(struct rnd_info *rnd, struct net_device *dev)
{
  if (rnd->dev)
    dev_put(rnd->dev);
  dev_hold(dev);
  rnd->dev = dev;
}

#define GET_RND_INFO(fsmptr, rnd) struct rnd_info *rnd = container_of(fsmptr, struct rnd_info, fsm)

static struct rnd_info *new_rnd_info(void);
static void free_rnd_info(struct fsm *fsm);
static void free_id_table(struct id_table *ptr);
static void free_rssi_obs_list(struct rssi_obs *ptr);
static void free_identity(struct masonid *ptr);
static int add_identity(struct rnd_info *rnd, __u16 sender_id, __u8 *pub_key);
static int set_identity_hwaddr(struct masonid *id, const struct sk_buff *skb);
static void record_new_obs(struct id_table *tbl, __u16 id, __u16 pkt_id, __s8 rssi);

/* **************************************************************
 *              Mason Packet utility functions
 * ************************************************************** */
static struct sk_buff *create_mason_packet(struct rnd_info *rnd, unsigned short type, int len);
static int send_mason_packet(struct sk_buff *skb, unsigned char *hwaddr);
static int bcast_mason_packet(struct sk_buff *skb);
static struct sk_buff *create_mason_init(struct rnd_info *rnd);
static struct sk_buff *create_mason_par(struct rnd_info *rnd);
static struct sk_buff *create_mason_parlist(struct rnd_info *rnd, __u16 *start_id);
static struct sk_buff *create_mason_txreq(struct rnd_info *rnd, __u16 id);
static struct sk_buff *create_mason_meas(struct rnd_info *rnd);
static struct sk_buff *create_mason_abort(struct rnd_info *rnd);
static struct sk_buff *create_mason_rsstreq(struct rnd_info *rnd, __u16 id);
struct create_rsst_state {
  __u16 cur_id;
  struct rssi_obs *cur_obs;
};
static struct sk_buff *create_mason_rsst(struct rnd_info *rnd, struct create_rsst_state *state);

static void import_mason_parlist(struct rnd_info *rnd, struct sk_buff *skb);
static void import_mason_rsst(struct rnd_info *rnd, struct sk_buff *skb);
static __u16 select_next_txreq_id(struct rnd_info *rnd);

#endif /* _MASON_H */



