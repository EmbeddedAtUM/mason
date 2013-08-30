Mason
=====

> Sybil-detection for ad hoc wireless networks

Description
-----------

The Mason test is a protocol for detecting Sybil identities in 802.11
ad hoc wireless networks.  See our [technical
report](http://coming.soon) for a full description.

Status
------

This code is the prototype implementation of the Mason protocol used
for our experiments.  It is not feature complete and likely contains
security bugs and is intended for research use only.


Directory Structure
-------------------

*experiment/* programs to control the Mason prototype during experiments

*kernel/* the main Linux kernel module implementing the collection phase

*user/* userspace tools to control the kernel module during experiments

*wireshark/* a wireshark dissector for the Mason protocol packets


People
------

* [David R. Bild](http://www.davidbild.org) ([github](http://github.com/drbild/))
* [Yue Liu](http://ziyang.eecs.umich.edu/~liuyue/)
* [Prof. Robert P. Dick](http://robertdick.org)
* [Prof. Z. Morley Mao](http://web.eecs.umich.edu/~zmao/)
* [Prof. Dan S. Wallach](http://www.cs.rice.edu/~dwallach/)


License
-------
Copyright 2010, 2011, 2013 The Regents of the University of Michigan

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
