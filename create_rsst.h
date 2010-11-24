
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

struct create_rsst_st {
	int start_participant;
};

struct pkt_size_info {
	size_t pkt_size;
	int final_participant;
};

struct pkt_id_and_rssi {
	__u16 id;
	__u16 pkt_id;
	__s8 rssi;
};

extern  struct sk_buff * create_rsst_pkt(struct id_table *table, struct create_rsst_st *state);
#endif /* _MASON_H */



