/* mason.h --- 
 * 
 * Filename: mason.h
 * Author: David Bild <drbild@umich.edu>
 * Created: 11/05/2010
 * 
 * Description: Kernel module for mason protocol (L3 network layer
 * implementation.
 */

#include <linux/types.h>

/* Mason Protocol ethertype*/
#define ETH_P_MASON 0x2355

/* RSA SIGNATURE */
#define RSA_LEN 768/8

/*  MASON PACKETS */
/* mason packet types */
#define MASON_INIT    0x0
#define MASON_PAR     0x1
#define MASON_PARLIST 0x2
#define MASON_TXREQ   0x3
#define MASON_MEAS    0x4
#define MASON_DONE    0x5
#define MASON_RSST    0x6

/* Packet sizes */
#define LL_MTU  1500

/* Identity Management */
struct masonid {
  __u8   pub_key[RSA_LEN];
  __be16 id;  /* This id must be a assigned by the initiator to ensure that it is unique */
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
#error "Please fix <asm/byteorder.h>"
#endif
  __s8   rssi;
  __be64 uid;
} __attribute((packed))__;

/* initiate packet */
struct initpkt {
  struct masonhdr hdr;
  __u8 pub_key[RSA_LEN];
} __attribute((packed))__;

/* participate packet */
struct parpkt {
  struct masonhdr hdr;
  __u8 pub_key[RSA_LEN];
} __attribute((packed))__;

/* participant list packet */
struct parlistpkt {
  struct masonhdr hdr;
  __be16 num_ids;
} __attribute((packed))__;

/* transmit request packet */
struct txreqpkt {
  struct masonhdr hdr;
  __be16 id;
} __attribute__((packed))__;

/* rssi measurement packet */
struct measpkt {
  struct masonhdr hdr;
  __be16 id;
} __attribute__((packed))__;

/* measurement done packet */
struct donepkt {
  struct masonhdr hdr;
} __attribute__((packed))__;

/* RSST packet */
struct rsstpkt {
  struct masonhdr hdr;
  __be16 len;
} __attribute__((packed))__;


