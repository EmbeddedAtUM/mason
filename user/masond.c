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

/* masond.c --- 
 * 
 * Filename: masond.c
 * Author: David R. Bild
 * Created: 12/07/2010
 * 
 * Description: User-space daemon for logging mason protocol packets
 */

#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netinet/in.h>

#if defined(__linux__)
#  include <endian.h>
#  if defined(ANDROID)
#    define be16toh(x) betoh16(x)
#    define be32toh(x) betoh32(x)
#    define be64toh(x) betoh64(x)
#  endif
#elif defined(__FreeBSD__) || defined(__NetBSD__)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be32toh(x) betoh32(x)
#  define be64toh(x) betoh64(x)
#endif

#include "nl_mason.h"

#define DAEMON_NAME "masond"
#define PID_FILE "/var/run/"DAEMON_NAME".pid"

unsigned char daemonize;
char *logfile = NULL;
FILE *logfd   = NULL;
volatile unsigned char running;
struct sigaction act;

struct sockaddr_nl src_addr;
struct nlmsghdr *nlh = NULL;
int sock_fd;

void usage(int argc, char *argv[], FILE *fd) 
{
  if (argc >= 1) {
    fprintf(fd, "Usage: %s -nh -f[file]\n", argv[0]);
    fprintf(fd, "  Options:\n");
    fprintf(fd, "        -n\tDo not daemonize\n");
    fprintf(fd, "        -f\tFile for MEAS packet transmissions and receptions\n");
    fprintf(fd, "          \tShould include fully qualified pathname\n");
    fprintf(fd, "        -h\tShow this message\n");
  }
}

void signal_handler(int sig)
{
  switch(sig) {
  case SIGHUP:
    if (NULL != logfd)
      fflush(logfd);
    break;
  case SIGINT:
    running = 0;
    break;
  case SIGTERM:
    running = 0;
    break;
  default:
    syslog(LOG_WARNING, "Ignoring unhandled signal (%d) %s", sig, strsignal(sig));
  }
}

int config_signal_handlers(void) 
{
  memset(&act, 0, sizeof(act));
  act.sa_handler = signal_handler;
  if (0 > sigaction(SIGTERM, &act, NULL)
      || 0 > sigaction(SIGINT, &act, NULL)
      || 0 > sigaction(SIGHUP, &act, NULL)) {
    return -1;
  }
  return 0;
}

int parseopt(int argc, char *argv[])
{
  int c;
  daemonize = 1;
  while( (c = getopt(argc, argv, "nhf:")) != -1) {
    switch(c){
    case 'h':
      usage(argc, argv, stdout);
      return 1;
    case 'n':
      daemonize = 0;
      break;
    case 'f':
      logfile = optarg;
      break;
    case '?':
      if (optopt == 'f') {
	fprintf(stderr, "Option -%c requires an argument\n", optopt);
	usage(argc, argv, stderr);
	return -EINVAL; 
      } else {
	fprintf(stderr, "Unrecognized option -%c\n", optopt);
	usage(argc, argv, stderr);
	return -EINVAL;
      }
    }
  }
  if (NULL == logfile) {
    fprintf(stderr, "Option -f is required\n");
    usage(argc, argv, stderr);
    return -EINVAL;
  }
  return 0;
}

int config_nl_socket(void)
{
  sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_MASON);
  if (-1 == sock_fd)
    return -1;
  return 0;
}

int bind_nl_socket(void) 
{
  memset(&src_addr, 0, sizeof(src_addr));
  src_addr.nl_family = AF_NETLINK;
  src_addr.nl_pid = getpid();
  src_addr.nl_groups = MASON_NL_GRP;
  if (-1 == bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr))) 
    return -1;
  return 0;
}

void close_nl_socket(void) 
{
  if (0 < sock_fd) 
    close(sock_fd);
}

/* TODO: It would be good to provide some validation of the pathname.
   E.g., the canonical pathname should live in /sdcard/ or /var/ */
int open_log_file(void) 
{  
  logfd = fopen(logfile, "a");
  if (NULL == logfd)
    return -1;
  return 0;
}

int close_log_file(void)
{
  if (logfd) {
    if (EOF == fclose(logfd))
      return -1;
  }
  return 0;
}

void log_packets(void)
{
  int nlhlen = NLMSG_SPACE(MASON_NL_SIZE);
  struct nlmsghdr *nlh = NULL;
  struct mason_nl_recv *recvmsg;
  struct mason_nl_send *sendmsg;
  struct mason_nl_addr *addrmsg;
  struct mason_nl_msg  *msgmsg;
  unsigned int len;
  int prc, i;
  nlh = (struct nlmsghdr *)malloc(nlhlen);
  
  while (running) {
    memset(nlh, 0, nlhlen);
    
    len = recv(sock_fd, nlh, nlhlen, 0);
    if (len < sizeof(*nlh)) 
      continue;
    
    switch (nlh->nlmsg_type) {
    case MASON_NL_RECV:
      if (nlh->nlmsg_len < sizeof(*recvmsg) ||
	  len < NLMSG_SPACE(sizeof(*recvmsg)))
	continue;
      recvmsg = (struct mason_nl_recv *)NLMSG_DATA(nlh);
      if (0 > (prc = 
	       fprintf(logfd, "Received: rnd:%u my_id:%u time:%"PRIu64" packet_id:%u sender_id:%u rssi:%d\n", 
		       ntohl(recvmsg->rnd_id), ntohs(recvmsg->my_id), be64toh(recvmsg->time_ns), ntohs(recvmsg->pkt_id),
		       ntohs(recvmsg->sender_id), recvmsg->rssi))) {
	syslog(LOG_ERR, "failed to log recvmsg: %s\n", strerror(prc));
      } 
      break;
    case MASON_NL_SEND:
      if (nlh->nlmsg_len < sizeof(*sendmsg) ||
	  len < NLMSG_SPACE(sizeof(*sendmsg)))
	continue;
      sendmsg = (struct mason_nl_send *)NLMSG_DATA(nlh);
      if (0 > (prc = 
	       fprintf(logfd, "Sent: rnd:%u my_id:%u time:%"PRIu64" packet_id:%u\n", ntohl(sendmsg->rnd_id), 
		       ntohs(sendmsg->my_id), be64toh(sendmsg->time_ns), ntohs(sendmsg->pkt_id)))) {
	syslog(LOG_ERR, "failed to log sendmsg: %s\n", strerror(prc));
      }
      break;
    case MASON_NL_MSG:
      if (nlh->nlmsg_len < sizeof(*msgmsg) ||
	  len < NLMSG_SPACE(sizeof(*msgmsg)))
	continue;
      msgmsg = (struct mason_nl_msg *)NLMSG_DATA(nlh);
      if (0 > (prc =
	       fprintf(logfd, "%s: rnd:%u my_id:%u time:%"PRIu64"\n", msgmsg->msg,
		       ntohl(msgmsg->rnd_id), ntohs(msgmsg->my_id), be64toh(msgmsg->time_ns)))){
	syslog(LOG_ERR, "failed to log msmsg: %s\n", strerror(prc));
      }
      break;
    case MASON_NL_ADDR:
      if (nlh->nlmsg_len < sizeof(*addrmsg) ||
	  len < NLMSG_SPACE(sizeof(*addrmsg)))
	continue;
      addrmsg = (struct mason_nl_addr *)NLMSG_DATA(nlh);
      fprintf(logfd, "Addr: rnd:%u id:%u hwaddr:", ntohl(addrmsg->rnd_id), ntohs(addrmsg->id));
      for(i = 0; i < (ntohs(addrmsg->addrlen) <= 12 ? ntohs(addrmsg->addrlen) : 12); ++i) {
	if (0 != i)
	  fprintf(logfd, ":");
	fprintf(logfd, "%02X", (unsigned char)addrmsg->addr[i]);
      }
      fprintf(logfd, "\n");
    default:
      break;
    }

    if (NULL != logfd) /* TODO: Fix SIGUP and remove this flush */
      fflush(logfd);   /* SIGHUP doesn't seem to work on the Android
			  phones.  Only the first SIGHUP is
			  delivered. So, we flush after every line.*/
    
  }
  
}

int main(int argc, char *argv[]) 
{
  int rc;
    
  running = 1;

  rc = parseopt(argc, argv);
  if (rc < 0)
    return EXIT_FAILURE;
  else if (0 > rc)
    return EXIT_SUCCESS;
  
  rc = config_signal_handlers();
  if (rc < 0) {
    perror("configure signals");
    rc = EXIT_FAILURE;
    goto fail_signal;
  }

  rc = open_log_file();
  if (rc < 0) {
    perror("log file");
    rc = EXIT_FAILURE;
    goto fail_file;
  }
  
  rc = config_nl_socket();
  if (rc < 0) {
    perror("open netlink socket");
    rc = EXIT_FAILURE;
    goto fail_socket;
  }
  
  if (1 == daemonize) {
    if (-1 == daemon(0, 0)) {
      perror("daemonize");
      rc =  EXIT_FAILURE;
      goto fail_daemon;
    }
  }
  
  rc = bind_nl_socket();
  if (rc < 0) {
    syslog(LOG_ERR, "bind netlink socket: %s\n", strerror(errno));
    rc = EXIT_FAILURE;
    goto fail_bind;
  }
    
  /* Main Loop in log_packets */
  log_packets();
  
  rc = EXIT_SUCCESS;
  syslog(LOG_INFO, "daemon exiting\n");
 fail_bind:
  close_nl_socket();
 fail_daemon:
 fail_socket:
  if (-1 == close_log_file())
    syslog(LOG_INFO, "close log file: %s\n", strerror(errno));
 fail_file:
 fail_signal:
  return rc;
}
