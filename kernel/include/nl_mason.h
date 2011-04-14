/* nl_mason.h --- 
 * 
 * Filename: nl_mason.h
 * Author: David R. Bild
 * Created: 12/07/2010
 * 
 * Description: Mason netlink header definitions for kernel and userspace
 */

#ifndef _NL_MASON_H
#define _NL_MASON_H

#include <linux/netlink.h>

#define NETLINK_MASON 25

#define MASON_NL_GRP 1

#define MASON_NL_RECV 0
#define MASON_NL_SEND 1
#define MASON_NL_ADDR 2

#define MASON_NL_SIZE 20 /* mason_nl_addr is largest */

struct mason_nl_recv {
  __be32 rnd_id;
  __be16 my_id;
  __be16 pkt_id;
  __be16 sender_id;
  __s8 rssi;
  __be64 time_ns;
}__attribute__((__packed__)); /* 19 bytes */

struct mason_nl_send {
  __be32 rnd_id;
  __be16 my_id;
  __be16 pkt_id;
  __be64 time_ns;
}__attribute__((__packed__)); /* 16 bytes */

struct mason_nl_addr {
  __be32 rnd_id;
  __be16 id;
  __be16 addrlen;  /* max value is 12 */
  char   addr[12];
}__attribute__((__packed__)); /* 20 bytes */


#ifdef __KERNEL__
static inline void set_mason_nl_addr(struct mason_nl_addr *adr, __u32 rnd_id,
				     __u16 id, __u16 addrlen, char hwaddr[])
{
  if (!adr || !hwaddr || 12 < addrlen)
    return;
  adr->rnd_id = htonl(rnd_id);
  adr->id = htons(id);
  adr->addrlen = htons(addrlen);
  memcpy(adr->addr, hwaddr, addrlen);
}

static inline void set_mason_nl_recv(struct mason_nl_recv *rec, __u32 rnd_id,
				     __u16 my_id, __u16 pkt_id, __u16 sender_id,
				     __s8 rssi, ktime_t ktime)
{
  if (!rec)
    return;
  rec->rnd_id = htonl(rnd_id);
  rec->my_id = htons(my_id);
  rec->pkt_id = htons(pkt_id);
  rec->sender_id = htons(sender_id);
  rec->rssi = rssi;
  rec->time_ns = __cpu_to_be64(ktime_to_ns(ktime));
}

static inline void set_mason_nl_send(struct mason_nl_send *snd, __u32 rnd_id,
				     __u16 my_id, __u16 pkt_id, ktime_t ktime)
{
  if (!snd)
    return;
  snd->rnd_id = htonl(rnd_id);
  snd->my_id = htons(my_id);
  snd->pkt_id = htons(pkt_id);
  snd->time_ns =  __cpu_to_be64(ktime_to_ns(ktime));
}
#endif

#endif /* _NL_MASON_H */
