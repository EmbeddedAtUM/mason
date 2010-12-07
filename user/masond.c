/* masond.c --- 
 * 
 * Filename: masond.c
 * Author: David R. Bild
 * Created: 12/07/2010
 * 
 * Description: User-space daemon for logging mason protocol packets
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "../nl_mason.h"

#define DAEMON_NAME "masond"
#define PID_FILE "/var/run/"DAEMON_NAME".pid"

struct sockaddr_nl src_addr;
struct nlmsghdr *nlh ;
int sock_fd;

void signal_handler(int sig)
{
  switch(sig) {
  default:
    /* TODO: Properly shutdown on signals */
    break;
  }
}

/* TODO: Daemonize */
/* TODO: Check for errors, properly */
void main() {
  struct nlmsghdr *nlh = NULL;
  struct msghdr msg;
  struct iovec iov;
  struct mason_nl_recv *rec;

  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MASON);
  
  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();
  src_addr.nl_groups = MASON_NL_GRP;
  bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

  nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct mason_nl_recv)));
  memset(nlh, 0, NLMSG_SPACE(sizeof(struct mason_nl_recv)));
  
  iov.iov_base = (void *)nlh;
  iov.iov_len = NLMSG_SPACE(sizeof(struct mason_nl_recv));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  while (1) {
    recvmsg(sock_fd, &msg, 0);
    rec = NLMSG_DATA(nlh);
    printf("Received: rnd:%u my_id:%u time_or_position:%u packet_id:%u sender_id:%u rssi:%d\n", 
	   ntohl(rec->rnd_id), ntohs(rec->my_id), ntohs(rec->pos), ntohs(rec->pkt_id),
	   ntohs(rec->sender_id), rec->rssi); 
  }
  
}
