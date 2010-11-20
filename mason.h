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
#include <linux/semaphore.h>

#define MAX_PARTICIPANTS 400


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

/*
 * This enum is not used, but is left here to show the
 * types of inputs used.
enum fsm_input {
  fsm_packet  = 0,
  fsm_timeout = 1,
  fsm_quit    = 2
};
*/

struct fsm {
  struct semaphore sem;
  enum fsm_state cur_state;
};

static inline void fsm_init(struct fsm *fsm) {
  init_MUTEX(&fsm->sem);
  fsm->cur_state = fsm_idle;
}

static int fsm_dispatch_timeout(struct fsm *fsm, long data);
static int fsm_dispatch_packet(struct fsm *fsm, struct sk_buff *skb);
static int fsm_dispatch_quit(struct fsm *fsm);

static enum fsm_state fsm_idle_packet(struct sk_buff *skb);
static enum fsm_state fsm_c_parlist_packet(struct sk_buff *skb);
static enum fsm_state fsm_c_txreq_packet(struct sk_buff *skb);
static enum fsm_state fsm_c_rsstreq_packet(struct sk_buff *skb);
static enum fsm_state fsm_s_par_packet(struct sk_buff *skb);
static enum fsm_state fsm_s_meas_packet(struct sk_buff *skb);
static enum fsm_state fsm_s_rsst_packet(struct sk_buff *skb);

static enum fsm_state fsm_idle_timeout(long data);
static enum fsm_state fsm_c_parlist_timeout(long data);
static enum fsm_state fsm_c_txreq_timeout(long data);
static enum fsm_state fsm_c_rsstreq_timeout(long data);
static enum fsm_state fsm_s_par_timeout(long data);
static enum fsm_state fsm_s_meas_timeout(long data);
static enum fsm_state fsm_s_rsst_timeout(long data);

static enum fsm_state fsm_idle_quit(void);
static enum fsm_state fsm_c_parlist_quit(void);
static enum fsm_state fsm_c_txreq_quit(void);
static enum fsm_state fsm_c_rsstreq_quit(void);
static enum fsm_state fsm_s_par_quit(void);
static enum fsm_state fsm_s_meas_quit(void);
static enum fsm_state fsm_s_rsst_quit(void);


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
};

/* Information associated with a round */
struct rnd_info {
  __u32 rnd_id;
  struct fsm fsm;
  struct net_device dev;
  struct id_table *ids;
};

#endif /* _MASON_H */



