/* nl_mason.h --- 
 * 
 * Filename: nl_mason.h
 * Author: David R. Bild
 * Created: 12/07/2010
 * 
 * Description: Mason netlink header definitions for kernel and userspace
 */

#include <linux/netlink.h>

#define NETLINK_MASON 25

#define MASON_NL_GRP 1

#define MASON_NL_RECV 0
#define MASON_NL_SEND 1

struct mason_nl_recv {
  __be32 rnd_id;
  __be16 my_id;
  __be16 pos;
  __be16 pkt_id;
  __be16 sender_id;
  __s8 rssi;
};

struct mason_nl_send {
  __be32 rnd_id;
  __be16 my_id;
  __be16 pos;
  __be16 pkt_id;
};

static inline void set_mason_nl_recv(struct mason_nl_recv *rec, __u32 rnd_id,
					__u16 my_id, __u16 pos, __u16 pkt_id, 
					__u16 sender_id, __s8 rssi)
{
  if (!rec)
    return;
  rec->rnd_id = htonl(rnd_id);
  rec->my_id = htons(my_id);
  rec->pos = htons(pos);
  rec->pkt_id = htons(pkt_id);
  rec->sender_id = htons(sender_id);
  rec->rssi = rssi;
}
