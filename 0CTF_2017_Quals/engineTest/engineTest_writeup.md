# engineTest Challenge Write-up
_Written by Michael Kajiloti_

## Overview
We receive an archive that contains 5 files:
- __engineTest__ - 64 ELF executable
- __cp__ - binary file, st argument of engineTest
- __ip__ - binary file, 2nd arugment of engineTest
- __op__ - binary file, 4th argument of engineTest
- __go.sh__ - bash script that ties it all together. Prompts you to enter the flag and executes engineTest with the 3 binary files and stdin as arguments:
```sh
#!/bin/sh
echo "input the flag:"
exec ./engineTest ./cp ./ip /dev/stdin ./op
```
Executing go.sh and entering a random string as input prints our the message _" Wrong! "_.
Cool...

## Opening the black box
We start by opening engineTest in IDA.
Inside main, we can see that the program begins by opening all 4 arguments as files.
After that it moves on to reading data from them and parsing/storing their content in memory.

### Parsing cp - building the machine
It starts with the __cp__ file:
- reads first 2 qwords: bitfield_size and cp_size
- creates an array by the size of the (cp_size*40) and reads the rest of the cp data into it.

Seems like __cp__ consists of 2 size qwords and then an array of 40 byte records (5 qwords). When organized in such a manner in a hex editor, its easy to a spot an enum in the 5th qword value from 0x112 till 0x8828 (bitfield_size+1).

Afterwards, it calls the function which serves as _initialize_machine_. Inside it builds its main struct (refereed to as MACHINE), and stores the data from cp, empty bitfield of size bitfield_size (initialized with 10b), and array of qwords of the size of cp_size filled with seemingly random data from cp.

Yeah whatever...

### Parsing ip - looks familiar
It the moves on to parsing __ip__ file:
- reads the first qword: ip_size
- creates a qword array (ip_qwords) by the size of ip_size and reads the the rest of the ip data into it.

The qwords in ip start from 0x2 and go up to 0x111..

### Parsing stdin - starting to make sense
Then user input is read in an interesting way:
Essentialy ip_qwords array is iterated and for each value, a bit is read from user input and sent to the function _set_machine_bit_ together with the current value from the ip_qwords and the MACHINE struct:
```c
__int64 __fastcall set_machine_bit(MACHINE *machine, int *bit_offset_qword, int bit_value);
```
This function sets the bit from the input, at the offset determined by ip_qword, into the machine bitfield member.
Looking around in IDA, we can also find a complementary function used many times throughout the program
```c
__int64 __fastcall read_machine_bit(MACHINE *machine, int bit_offset_qword);
```
This one returns the bit at the specified offset from the machine's bitfield.

We now know the flag size, since 0x110 bits are read => flag is 34 characters long (including '\n').

### Running the machine - Where the magic happens
Now the main logic function of the program is executed:
```c
__int64 __fastcall execute_cp_instructions(MACHINE* machine)
```
We can multiple calls to _read_machine_bit_ in different branches and finally a call to _set_machine_bit_.
Reversing this function makes everything clear!
Here the records from cp are iterated, parsed, and "executed" using those functions.
Turns out cp is code for a custom Virtual Machine with 4 operation types (opcodes), and each 40 byte record is an instruction that reads 2-3 bits from the bitfield using calls to _get_machine_bit_ performs a logical operation, and writes the resulting bit back into bitfield using _set_machine_bit_.

The order of instruction execution is non-linear, determined at _initialize_machine_, but is constant for cp.

The following structs describe the details.
```c
// CP is composed by this type of records
struct INSTRUCTION
{
    OP_TYPE op_type;                // type of instruction - see OP_TYPE
    __int64 opr_1;                  // first operand - address in memory
    __int64 opr_2;                  // first operand - address in memory
    __int64 opr_3;                  // third operand (optional) - address in memory
    __int64 output_addr;            // output address in memory/instruction_id - where output bit is written in memory
}
```
```c
// Operation types
enum __int64 OP_TYPE
{
    OP_AND = 1;                     // logical AND between opr_1 and opr_2
    OP_OR = 2;                      // logical OR between opr_1 and opr_2
    OP_XOR = 3;                     // logical XOR between opr_1 and opr_2
    OP_CONDITIONAL_COPY = 4         // If opr_1 is set: return opr_2, else return opr_3
}
```
```c
// Now we can also fully map machine struct
struct MACHINE
{
    __int64 memory_size;                                // first qword in cp
    __int64 instruction_count;                          // second qword in cp
    instruction* instructions_cp[instruction_count];    // array of instructions from cp
    BYTE memory_bitfield[memory_size/(8)];              // bitfield of size memory_size in bits
    __int64 order_of_instructions;                      // array of instruction_ids (offsets in instructions_cp) that determines the order of instruction execution       
    __int64 unknown;                                    // not important
}
```
With that information, it also makes sense that our input is written into the MACHINE's bitfield (memory). The bits from our input are written to the beginning of the memory and serve as the input/key, which the machine uses during its processing (in certain instructions) to determine the output.

### Parsing op - Stop saying Wrong!
Talking about output, after that function, the program moves to its final logic loop, where it parses __op__ file.
This is done after the machine has executed all of its instructions and written its output in memory.
__op__ contains offsets similar to __ip__, but this time, these offsets are used to read data from the machine's memory, instead of writing to it. Specifically these offsets point to the last 0x40 bits in the machine's bitfield to read an 8 byte string at offsets 0x87e9-0x8828 (the end of the memory). This 8 byte string was in our case: _" Wrong! "_, but we can be sure that something else will be written there if we input the flag.

Looking at the instructions that determine the bits at these offsets, we can see that they are of OP_TYPE 4. Since OP_TYPE 4 is a conditional copy operation, and all of these instructions depend on the same condition (same bit at opr_1 = 0x87e8), The bits at opr_2 or opr_3 must form the _" Wrong! "_ string. A quick check shows that this string is formed by the bits at opr_3, while the opr_2 bits form the string "Correct!". This means the bit at 0x87e8 must be set (1), in order to be correct, so we now have the first condition we need to meet.

### Billions of other conditions
Actually we know more than that. Since this CTF uses a standard structure for flags: flag{this_is_the_flag} we know that the flag starts with "_flag{_" and ends with "_}_", so we can also use their corresponding bit values as conditions.

But we still have thousands of other condition checks, how can we reverse that?

## Time To Crack

### The long and stupid road taken
Since this write-up is long enough, I wont describe in detail the long and ugly process. Let's just say it involves heavy recursion, binary trees, and pain. This is what I got in return:

```
flag{        _*f_B1ll(ion)_g@t5s}
```

So close! missing only 8 characters...
Of course, you can write a decent brute-forcer for that, go to a vacation for a week, come back and enjoy the full flag (or see that the brute-forcer crashed because of a typo...).
But since this CTF is supposed to be doable in a matter of a single day, I probably missed something.

### Why not use this instead - Things you learn in CTF
How about solving it in 10 seconds instead?
Using the Z3 Prover from Microsoft, you can do just that.
Simply speaking, Z3 is a magical program that solves complex equations and logical problems, as long as you can define the problem. Sometimes, it really looks like magic.
So I wrote a python script that uses z3, defined the dataset and known conditions, and pressed the magic button (run).

```py
import struct, z3

data = open("cp", "rb").read()
memory = []
mapped_memory = {}
solver = z3.Solver()

#break string into bits (and reverse the order to match memory layout) and return as a string
def get_bits(string):
    bytes = (ord(b) for b in string)
    bit_string = ""
    for b in bytes:
        bits = bin(b)[2:]
        bit_string += ('0' * (8 - len(bits)) + bits)[::-1]

    return bit_string

#add known condition bits
def add_bits(start, bit_string):
    pos = 0
    for i in bit_string:
        solver.add(memory[start+pos] == int(i))
        pos +=1

#initialize solver object with conditions
def init_solver():

    # initialize memory with bit vectors of size 1
    for i in xrange(0x8829):
        memory.append(z3.BitVec(i, 1))

    # set basic condition for each bit vector
    for bitfield in memory:
        solver.add(z3.Or(bitfield == 0, bitfield == 1))

    # set known bits
    solver.add(memory[0] == 0)
    solver.add(memory[1] == 1)
    solver.add(memory[0x87e8] == 1)
    add_bits(2, get_bits("flag{"))
    add_bits(0x10a, get_bits("}"))

    # set all cp conditions
    for i in xrange(0x8717):
        loc = i*40 + 16
        op_type = struct.unpack("<Q",data[loc:loc+8])[0]
        opr_1 = struct.unpack("<Q",data[loc+8:loc+16])[0]
        opr_2 = struct.unpack("<Q",data[loc+16:loc+24])[0]
        opr_3 = struct.unpack("<Q",data[loc+24:loc+32])[0]
        out_addr = struct.unpack("<Q",data[loc+32:loc+40])[0]

        if op_type == 1:
            solver.add(memory[opr_1] & memory[opr_2] == memory[out_addr])
        elif op_type == 2:
            solver.add(memory[opr_1] | memory[opr_2] == memory[out_addr])
        elif op_type == 3:
            solver.add(memory[opr_1] ^ memory[opr_2] == memory[out_addr])
        elif op_type == 4:
            solver.add(z3.Or(z3.And(memory[opr_1] == 1, memory[opr_2] == memory[out_addr]), z3.And(memory[opr_1] == 0, memory[opr_3] == memory[out_addr])))

#does the magic
def magic():
    init_solver()

    # check if its possible to solve this
    if solver.check() == z3.sat:
        solver_model = solver.model()
        #copy solution from model to mapped_memory dictionary
        for i in xrange(0x8829):
            mapped_memory[i] = solver_model[memory[i]].as_long()
    else:
        print 'FAIL!'

    return mapped_memory

# prints flag from mapped memory
def print_flag():
    next_byte = ""
    decoded_message = ""
    i = 2
    while i < 0x113:
        if i in mapped_memory:
            next_byte = str(mapped_memory[i]) + next_byte
            i += 1
            if len(next_byte) == 8:
                decoded_message += chr(int(next_byte, 2))

                next_byte = ""

        else:
            i += 8 - len(next_byte)
            decoded_message += ' '
            next_byte = ""

    print decoded_message

magic()
print_flag()
```

And just like magic the flag appeared...

#### This is actually kind of clever
At last we have the full flag, and its a good one:
```
flag{wind*w(s)_*f_B1ll(ion)_g@t5s}
```


_Thanks to Neatsun Ziv for working on this with me._



