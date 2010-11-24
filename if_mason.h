/* if_mason.h --- 
 * 
 * Filename: if_mason.h
 * Author: David Bild <drbild@umich.edu>
 * Created: 11/05/2010
 * 
 * Description: Public network interface definitions for mason
 *              protocol (L3 kernel implementation).
 */
#ifndef _IF_MASON_H
#define _IF_MASON_H

#include <linux/types.h>
#include <linux/skbuff.h>

/* Packet sizes */
#define LL_MTU  1500 /* TODO: This should be determined dynamically from
			the active device */

/* Mason Protocol ethertype*/
#define ETH_P_MASON   0x2355
#define MASON_VERSION 0x0

/* RSA SIGNATURE */
#define RSA_LEN (768/8)

/*  MASON PACKETS */
/* mason packet types */
#define MASON_INIT    0x0
#define MASON_PAR     0x1
#define MASON_PARLIST 0x2
#define MASON_TXREQ   0x3
#define MASON_MEAS    0x4
#define MASON_RSSTREQ 0x5
#define MASON_RSST    0x6
#define MASON_ABORT   0x7

/* header for all mason packets */
#define MASON_HDR_LEN 1
struct masonhdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
  __u8 sig:1,
    type:4,
    version:3;
#elif defined (__BIG_ENDIAN_BITFIELD)
  __u8 version:3,
    type:4,
    sig:1;
#else
#error "Please fix architecture bitfield endianness in <asm/byteorder.h>"
#endif
  __s8   rssi;
  __be32 rnd_id;
  __be16 sender_id;
  __be16 pkt_uid;
} __attribute__((__packed__));

static inline struct masonhdr *mason_hdr(const struct sk_buff *skb)
{
  return (struct masonhdr *)skb_network_header(skb);
}

/* initiate packet */
struct init_masonpkt {
  __u8 pub_key[RSA_LEN];
} __attribute__((__packed__));

/* participate packet */
struct par_masonpkt {
  __u8 pub_key[RSA_LEN];
} __attribute__((__packed__));

/* participant list packet */
struct parlist_masonpkt {
  __be16 len;
} __attribute__((__packed__));

/* transmit request packet */
struct txreq_masonpkt {
  __be16 id;
} __attribute__((__packed__));

/* rssi measurement packet */
struct meas_masonpkt {
  __be16 id;
} __attribute__((__packed__));

/* RSST request packet */
struct rsstreq_masonpkt {
  __be16 id;
} __attribute__((__packed__));

/* RSST packet */
struct rsst_masonpkt {
  __be16 len;
  __u8   frag; /*
		* 0x0 if this is the final packet 
		* 0x1 if additional packets are required to complete
		*     transmission of the full RSST
		*/
} __attribute__((__packed__));

/* Abort packet */
struct abort_masonpkt {
} __attribute__((__packed__));

/* 
 * Tail of packet containing signature.  The inclusion of a tail is
 * indicated by the 'sig' bit in the header.
 */
struct masontail {
  __u8 sig[RSA_LEN];
};

static inline void *mason_typehdr(const struct sk_buff *skb)
{
  return mason_hdr(skb) + 1;
}

static struct masontail *mason_tail(const struct sk_buff *skb);



#endif /* _IF_MASON_H */
