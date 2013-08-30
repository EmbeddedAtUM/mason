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

/* masonloopd.c --- 
 * 
 * Filename: masonloopd.c
 * Author: David R. Bild
 * Created: 12/07/2010
 * 
 * Description: User-space daemon for initiating mason tests
 * periodically.
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#define DAEMON_NAME "masond"
#define PID_FILE "/var/run/"DAEMON_NAME".pid"

#define MASON_INIT_PF "/proc/net/mason_initiate"

unsigned char daemonize;
char *device = NULL;
unsigned int period = 0;

void usage(int argc, char *argv[], FILE *fd) 
{
  if (argc >= 1) {
    fprintf(fd, "Usage: %s -nh -t[period] -D[device]\n", argv[0]);
    fprintf(fd, "  Options:\n");
    fprintf(fd, "        -n\tDo not daemonize\n");
    fprintf(fd, "        -t\tTime between tests in seconds\n");
    fprintf(fd, "        -D\tName of device on which to send requests\n");
    fprintf(fd, "        -h\tShow this message\n");
  }
}

int parseopt(int argc, char *argv[])
{
  int c;
  daemonize = 1;
  while( (c = getopt(argc, argv, "nt:D:h")) != -1) {
    switch(c){
    case 'h':
      usage(argc, argv, stdout);
      return 1;
    case 'n':
      daemonize = 0;
      break;
    case 't':
      period = strtol(optarg, NULL, 10);
      break;
    case 'D':
      device = optarg;
      break;
    case '?':
      if (optopt == 't' || optopt == 'D') {
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
  if (NULL == device) {
    fprintf(stderr, "Option -D is required\n");
    usage(argc, argv, stderr);
    return -EINVAL;
  }
  if (1 > period) {
    fprintf(stderr, "Option -t is required\n");
    usage(argc, argv, stderr);
    return -EINVAL;
  }
  return 0;
}

int main(int argc, char *argv[]) 
{
  int rc;
  FILE *initfd;
    
  rc = parseopt(argc, argv);
  if (rc < 0)
    return EXIT_FAILURE;
  else if (0 > rc)
    return EXIT_SUCCESS;
  
  if (1 == daemonize) {
    if (-1 == daemon(0, 0)) {
      perror("daemonize");
      rc =  EXIT_FAILURE;
      goto fail_daemon;
    }
  }
    
  /* Main Loop in log_packets */
  while (1) {
    sleep(period);
    
    initfd = fopen(MASON_INIT_PF, "w");
    if (!initfd)
      continue;

    fprintf(initfd, "%s", device);
    fclose(initfd);
  }
  
  rc = EXIT_SUCCESS;
  syslog(LOG_INFO, "daemon exiting\n");
 fail_daemon:
  return rc;
}
