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
#define MASON_NL_MSG  3

#define MASON_NL_SIZE 26 /* mason_nl_msg is largest */

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

struct mason_nl_msg {
  __be32 rnd_id;
  __be16 my_id;
  __be64 time_ns;
  char msg[12];
}__attribute__((__packed__)); /* 26 bytes  */

#ifdef __KERNEL__
static inline void set_mason_nl_msg(struct mason_nl_msg *pkt, const __u32 rnd_id, const __u16 my_id,
				    const ktime_t ktime, const unsigned char msglen, const char msg[])
{
  if (!pkt || !pkt || sizeof(pkt->msg) < msglen)
    return;
  pkt->rnd_id = htonl(rnd_id);
  pkt->my_id = htons(my_id);
  pkt->time_ns = __cpu_to_be64(ktime_to_ns(ktime));
  memcpy(pkt->msg, msg, msglen);
}

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
