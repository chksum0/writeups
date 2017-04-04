#!/usr/bin/env python

## connect to server
## make sure qemu-mips and gdb-multiarch are installed
## put bender_safe in the same directory
## put the token from the server in commands.gdb file
## and execute the script

import string
import subprocess
import os

test = ''
prev_ret = 0
ret = 0
FNULL = open(os.devnull, 'w')


def launch_bender(token, port=1234):
    print "launch bender"
    bender = subprocess.Popen(["qemu-mips", "-g", str(port), "./bender_safe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    print "launch gdb"
    gdb = subprocess.Popen(["gdb-multiarch", "-x", "commands.gdb"], stdout=FNULL, stderr=FNULL)
    print "launch send bender token"
    print bender.communicate(token + '\n')
    print "wait bender"
    ret = bender.wait()
    print "wait gdb"
    gdb.wait()
    print "finish"
    return ret

while True:
    for c in string.printable:
        last_ret = ret
        print test + c
        ret = launch_bender(test + c)
        print "ret", ret
        if last_ret != ret:
            test = test + c
            break

    print test
