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

#include <linux/netdevice.h>
#include <linux/spinlock.h>

#define MAX_PARTICIPANTS 400
#define DEV_NAME "tiwlan0"

/* **************************************************************
 *    State Machine Declarations
 * ************************************************************** */
enum fsm_state {
  fsm_idle      = 0,
  fsm_c_parlist = 1,
  fsm_c_txreq   = 2,
  fsm_c_rsstreq = 3,
  fsm_s_par     = 4,
  fsm_s_meas    = 5,
  fsm_s_rsst    = 6,
  fsm_terminal  = 255,
};

enum fsm_input_type {
  fsm_packet  = 0,
  fsm_timeout = 1,
  fsm_quit    = 2,
  fsm_initiate = 3
};

struct rnd_info;
struct fsm {
  struct semaphore sem;
  enum fsm_state cur_state;
  struct rnd_info *rnd;
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

static struct fsm *new_fsm(void);
static void free_fsm(struct fsm *ptr);

static inline void fsm_init(struct fsm *fsm) {
  sema_init(&fsm->sem, 1);
  fsm->cur_state = fsm_idle;
};

static int fsm_dispatch_interrupt(struct fsm *fsm, struct fsm_input *input);
static void fsm_dispatch_process(struct work_struct *work);
static void __fsm_dispatch(struct fsm *fsm, struct fsm_input *input);

static enum fsm_state fsm_idle_packet(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state fsm_c_parlist_packet(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state fsm_c_txreq_packet(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state fsm_c_rsstreq_packet(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state fsm_s_par_packet(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state fsm_s_meas_packet(struct rnd_info *rnd, struct sk_buff *skb);
static enum fsm_state fsm_s_rsst_packet(struct rnd_info *rnd, struct sk_buff *skb);

static enum fsm_state fsm_idle_timeout(struct rnd_info *rnd, long data);
static enum fsm_state fsm_c_parlist_timeout(struct rnd_info *rnd, long data);
static enum fsm_state fsm_c_txreq_timeout(struct rnd_info *rnd, long data);
static enum fsm_state fsm_c_rsstreq_timeout(struct rnd_info *rnd, long data);
static enum fsm_state fsm_s_par_timeout(struct rnd_info *rnd, long data);
static enum fsm_state fsm_s_meas_timeout(struct rnd_info *rnd, long data);
static enum fsm_state fsm_s_rsst_timeout(struct rnd_info *rnd, long data);

static enum fsm_state fsm_idle_quit(struct rnd_info *rnd);
static enum fsm_state fsm_c_parlist_quit(struct rnd_info *rnd);
static enum fsm_state fsm_c_txreq_quit(struct rnd_info *rnd);
static enum fsm_state fsm_c_rsstreq_quit(struct rnd_info *rnd);
static enum fsm_state fsm_s_par_quit(struct rnd_info *rnd);
static enum fsm_state fsm_s_meas_quit(struct rnd_info *rnd);
static enum fsm_state fsm_s_rsst_quit(struct rnd_info *rnd);

static enum fsm_state fsm_idle_initiate(struct rnd_info *rnd);

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
  short max_id;
};

/* Information associated with a round */
struct rnd_info {
  __u32 rnd_id;
  __u16 my_id;
  __u16 pkt_id;
  __u8 pub_key[RSA_LEN];
  struct net_device *dev;
  struct id_table *tbl;
};

static struct rnd_info *new_rnd_info(void);
static void free_rnd_info(struct rnd_info *ptr);
static struct rnd_info *reset_rnd_info(struct rnd_info *ptr); 

static void free_id_table(struct id_table *ptr);
static void free_rssi_obs_list(struct rssi_obs *ptr);

static void free_identity(struct masonid *ptr);
static int add_identity(struct rnd_info *rnd, __u16 sender_id, __u8 *pub_key);

/* **************************************************************
 *              Mason Packet utility functions
 * ************************************************************** */
static struct sk_buff *create_mason_packet(struct rnd_info *rnd, int len);
static struct sk_buff *create_mason_init(struct rnd_info *rnd);
static struct sk_buff *create_mason_par(struct rnd_info *rnd);

#endif /* _MASON_H */



