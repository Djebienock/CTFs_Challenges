from pwn import *

# Configuration
exe = ELF("./forge")
libc = ELF("./libc.so.6")  # Adaptez selon la libc fournie

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

def start():
    if args.REMOTE:
        return remote("SERVER_IP", PORT)
    else:
        return process(exe.path)

io = start()

# Helper functions
def forge(size, data):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b": ", str(size).encode())
    io.sendafter(b": ", data)

def temper(index, size, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b": ", str(index).encode())
    io.sendlineafter(b": ", str(size).encode())
    io.sendafter(b": ", data)

def inspect(index):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b": ", str(index).encode())

def melt(index):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b": ", str(index).encode())

# --- VOTE STRATÉGIE D'EXPLOITATION ICI ---

io.interactive()
