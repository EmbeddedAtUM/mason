Mason Userspace Tools
=====================

These are userspace tools for interacting with the Mason kernel module.

masond
------

A daemon for logging the observed and reported RSSIs to disk.  This serves two purposes.  

1. It's an example documenting the use of the netlink interface to the kernel module
2. It records the RSSIs for offline analysis or execution of the classification phase.

masonloopd
----------

A daemon for periodically initiating a round of the Mason test, useful
for long-duration, unattended experimentation.  The tools in the
top-level experiment directory are more useful for interactive
experiments.
