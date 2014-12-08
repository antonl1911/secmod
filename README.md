secmod
======

Small module and userspace program to prevent predefined apps from running

Compile by running 'make'. Then insmod ./secmod.ko, and launch seccon_user.
By default, list of prohibited apps is taken from seccon.conf file in current directory.
Tested on Ubuntu 12.04 x86, Ubuntu 14.04 x86_64.
