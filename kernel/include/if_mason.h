/*
 * Copyright 2010, 2011 The Regents of the University of Michigan
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

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

#ifdef __KERNEL__
#include <linux/skbuff.h>
#endif

#ifndef __KERNEL__
#include <asm/byteorder.h>
#endif

/* Mason Protocol ethertype*/
#define ETH_P_MASON   0x2355
#define MASON_VERSION 0x0

/* RSA SIGNATURE */
#define RSA_LEN (768/8)

/*  MASON PACKETS */
/* mason packet types */
#define MASON_INIT    0x0
#define MASON_PAR     0x1
#define MASON_PARACK  0x2
#define MASON_PARLIST 0x3
#define MASON_TXREQ   0x4
#define MASON_MEAS    0x5
#define MASON_RSSTREQ 0x6
#define MASON_RSST    0x7
#define MASON_ABORT   0x8

static const char __attribute__((__unused__)) *MASON_TYPES[] = {
  "INIT",
  "PAR",
  "PARACK",
  "PARLIST",
  "TXREQ",
  "MEAS",
  "RSSTREQ",
  "RSST",
  "ABORT",
};

/* header for all mason packets */
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

#ifdef __KERNEL__
static inline struct masonhdr *mason_hdr(const struct sk_buff *skb)
{
  return (struct masonhdr *)skb_network_header(skb);
}

static inline __u32 mason_round_id(const struct sk_buff *skb)
{
  return ntohl(mason_hdr(skb)->rnd_id);
}

static inline __u16 mason_sender_id(const struct sk_buff *skb)
{
  return ntohs(mason_hdr(skb)->sender_id);
}

static inline __u16 mason_packet_id(const struct sk_buff *skb)
{
  return ntohs(mason_hdr(skb)->pkt_uid);
}

static inline __s8 mason_rssi(const struct sk_buff *skb)
{
  return mason_hdr(skb)->rssi;
}

static inline unsigned short mason_type(const struct sk_buff *skb)
{
  return mason_hdr(skb)->type;
}

static inline unsigned short mason_is_signed(const struct sk_buff *skb)
{
  return mason_hdr(skb)->sig;
}

static inline unsigned short mason_version(const struct sk_buff *skb)
{
  return mason_hdr(skb)->version;
}

static inline const char* mason_type_str(const struct sk_buff *skb){
  return MASON_TYPES[mason_type(skb)];
}

static inline void *mason_typehdr(const struct sk_buff *skb)
{
  return mason_hdr(skb) + 1;
}
#endif

/* initiate packet */
struct init_masonpkt {
  __u8 pub_key[RSA_LEN];
} __attribute__((__packed__));

#ifdef __KERNEL__
static inline __u8 *mason_init_pubkey(const struct sk_buff *skb)
{
  return ((struct init_masonpkt *)(mason_typehdr(skb)))->pub_key;
}
#endif

/* participate packet */
struct par_masonpkt {
  __u8 pub_key[RSA_LEN];
} __attribute__((__packed__));

#ifdef __KERNEL__
static inline __u8 *mason_par_pubkey(const struct sk_buff *skb)
{
  return ((struct par_masonpkt *)(mason_typehdr(skb)))->pub_key;
}
#endif

/* participate acknowledgement packet */
struct parack_masonpkt {
  __u16 id;
  __u8 pub_key[RSA_LEN];
} __attribute__((__packed__));

#ifdef __KERNEL__
static inline __u16 mason_parack_id(const struct sk_buff *skb)
{
  return ntohs(((struct parack_masonpkt *)(mason_typehdr(skb)))->id);
}

static inline __u8 *mason_parack_pubkey(const struct sk_buff *skb)
{
  return ((struct parack_masonpkt *)(mason_typehdr(skb)))->pub_key;
}
#endif

/* participant list packet */
struct parlist_masonpkt {
  __be16 start_id; /* ID assigned to the first key in the packet */
  __be16 count; /* Number of keys in this packet */
} __attribute__((__packed__));

#ifdef __KERNEL__
static inline __u16 mason_parlist_id(const struct sk_buff *skb)
{
  return ntohs(((struct parlist_masonpkt *)mason_typehdr(skb))->start_id);
}

static inline __u16 mason_parlist_count(const struct sk_buff *skb)
{
  return ntohs(((struct parlist_masonpkt *)mason_typehdr(skb))->count);
}
#endif

/* transmit request packet */
struct txreq_masonpkt {
  __be16 id;
} __attribute__((__packed__));

#ifdef __KERNEL__
static inline __u16 mason_txreq_id(const struct sk_buff *skb)
{
  return ntohs(((struct txreq_masonpkt *)mason_typehdr(skb))->id);
}
#endif

/* rssi measurement packet */
struct meas_masonpkt {
} __attribute__((__packed__));

/* RSST request packet */
struct rsstreq_masonpkt {
  __be16 id;
} __attribute__((__packed__));

#ifdef __KERNEL__
static inline __u16 mason_rsstreq_id(const struct sk_buff *skb)
{
  return ntohs(((struct rsstreq_masonpkt *)mason_typehdr(skb))->id);
}
#endif

/* RSST packet */
struct rsst_masonpkt {
  __u8   frag; /*
		* 0x0 if this is the final packet 
		* 0x1 if additional packets are required to complete
		*     transmission of the full RSST
		*/
  __be16 len;
} __attribute__((__packed__));

#ifdef __KERNEL__
static inline __u16 mason_rsst_len(const struct sk_buff *skb)
{
  return ntohs(((struct rsst_masonpkt *)mason_typehdr(skb))->len);
}

static inline __u8 mason_rsst_is_frag(const struct sk_buff *skb)
{
  return ((struct rsst_masonpkt *)mason_typehdr(skb))->frag;
}
#endif

/* Abort packet */
struct abort_masonpkt {
} __attribute__((__packed__));

#ifdef __KERNEL__
/*
 * Returns pointer to the start of any variable length data the packet
 * may contain.  This is just past the end of the typehdr.
 */
extern void *mason_data(const struct sk_buff *skb);
#endif

/* 
 * Tail of packet containing signature.  The inclusion of a tail is
 * indicated by the 'sig' bit in the header.
 */
struct masontail {
  __u8 sig[RSA_LEN];
};

#ifdef __KERNEL__
extern struct masontail *mason_tail(const struct sk_buff *skb);
#endif

#endif /* _IF_MASON_H */
