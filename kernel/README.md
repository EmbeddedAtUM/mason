Mason Linux Kernel Module
===================

This is the main prototype implementation of the Mason collection
protocol as a Linux kernel module.

Warning
-------

This code is a prototype and likely contains security bugs.  It is
intended for research use only.


Interface
---------

**/sys/module/mason/parameters/numids** Write the number of (Sybil)
  identities to claim to this file. Default is 1, i.e., not Sybil.

**/proc/net/mason_initiate** Write anything to this file to initiate a
  round of the Mason test.

**netlink** The kernel module uses netlink to communication the
  observed RSSIs to userspace.  See `include/nl_mason.h` for the
  packet definitions and the top-level `user` directory for an example
  of their use.
