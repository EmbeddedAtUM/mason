
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

#define MAX_PARTICIPANTS 3
#define RSA_LEN 20
#define MAX_BUFFER_SIZE 10000

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
  int rssi_obs_count;
  unsigned char *hwaddr;
  struct rssi_obs* head;
};

struct id_table {
  struct masonid *ids[MAX_PARTICIPANTS];
};

/*
struct receiver_info {
	__u16 receiver_id;
	struct id_table* tbl;
}*/

struct create_rsst_st {
	int start_participant;
};

struct pkt_size_info {
	size_t pkt_size;
	int final_participant;
};

struct pkt_id_and_rssi {
	__u16 pkt_id;
	__s8 rssi;
};

struct id_and_count {
	__u16 id;
	int rssi_obs_count;
};

static struct logfile {
	char buffer[MAX_BUFFER_SIZE];
	int length;
} mason_log;

extern struct rnd_info {
  __u32 rnd_id;
  __u16 my_id;
  __u16 pkt_id;
  __u8 pub_key[RSA_LEN];
  struct net_device *dev;
  struct id_table *tbl;
};

/* Need to be deleted when mason.h is ready*/
struct mason_hdr {
	__u16 id;
};
extern  struct sk_buff * create_rsst_pkt(struct rnd_info *rnd, struct create_rsst_st *state);
#endif /* _MASON_H */



