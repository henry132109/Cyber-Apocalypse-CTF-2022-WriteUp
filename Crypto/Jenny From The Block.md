## Skills involved: identify a possible known plain text attack

The source code is an implementation of a block cipher. As recap:
- *A block cipher is a deterministic algorithm operating on fixed-length groups of bits, called blocks*.
- There are various *[modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC)* for block cipher. Except the simple and insecure ECB mode, all other modes make modification to subsequent blocks using the previous blocks to avoid encoding the same plaintext blocks into identical blocks.
- In such modes an initialization vector is used. It is changed each time so that similar message gets encoded differently with the same key.

Observe this part of the code:
```python
def encrypt(msg, password):
    h = sha256(password).digest()
    if len(msg) % BLOCK_SIZE != 0:
        msg = pad(msg, BLOCK_SIZE)
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    ct = b''
    for block in blocks:
        enc_block = encrypt_block(block, h)
        h = sha256(enc_block + block).digest()
        ct += enc_block
```

The key `h` is determined only by the plaintext and the ciphertext for any block other than the first one, without considering the key.
This means as long as we have full control over only 1 block, we have information to all subsequent blocks.
Note that "Command executed: cat secret.txt\n" is 33 bytes long, greater than the block size. We can thus carry out a known plaintext attack.

My final code:
```python
from hashlib import sha256
# Command executed: cat secret.txt makes up 32 bytes :) for plaintext attack
BLOCK_SIZE = 32
b = b'Command executed: cat secret.txt'
e = bytes(bytearray.fromhex('d1fcff212f6f4e9b5e65b01134b8c167783d68c0348859d4674bf8af8d27260cc5f5c7bfffd003b5ac59a6805b3b8a60c12a0fe82b76a59a04b68432bdaba957cac0dad4d709cc46951a2f3ba6656a88efe7a3bab84a36c21ec84e261fa4fba01bc0ea4bcce9b11c9d8aa53c41e63777f8d9adea4f40ed9f10de4b1cd858af2582543ce3ecbdfdac51ea38ca9eddb27e43926f2663cc64bf1dad1959298384856612f198ff248004782f9fb530b1ad29d0c7d9debe47e6e680e85f6122218f65a22946ea1b982f95dc9c4f2282b8feb5541e9c0a12435713f6d7eb1fb468d25e3576f3947ba8446fd41c76adffdacc8147bf6736e15c8e1b6ea2ed68133082cd'))

def decrypt_block(block, secret):
  dec_block = b''
  for i in range(BLOCK_SIZE):
    val = (block[i]-secret[i]) % 256
    dec_block += bytes([val])
  return dec_block

e_blocks = [e[i:i+BLOCK_SIZE] for i in range(0, len(e), BLOCK_SIZE)]
pt = b''
for (i, e_block) in enumerate(e_blocks):
  b_frag = b[BLOCK_SIZE*i:BLOCK_SIZE*(i+1)]
  #print(e_block+b_frag)
  h = sha256(e_block+b_frag).digest()
  if BLOCK_SIZE*(i+1)>=len(e):
    break
  next_b = decrypt_block(e[BLOCK_SIZE*(i+1):BLOCK_SIZE*(i+2)], h)
  b += next_b

print(b)
```

Output:
`Command executed: cat secret.txt\nIn case Jenny malfunctions say the following phrase: Melt My Eyez, See Your Future  \nThe AI system will shutdown and you will gain complete control of the spaceship.\n- Danbeer S.A.\nHTB{b451c_b10ck_c1ph3r_15_w34k!!!}\n\x07\x07\x07\x07\x07\x07\x07`

**Flag: HTB{b451c_b10ck_c1ph3r_15_w34k!!!}**
