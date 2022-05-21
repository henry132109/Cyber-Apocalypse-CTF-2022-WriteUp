## Skills involved: ECB padding attack, PKCS7 padding

Following the recap on *block ciphers* in the previous Jenny challenge, this challenge features ECB, in which chunks with the same content gets encrypted exactly the same way.

As we have control over the length of the plaintext, we can carry out famous attack known as padding oracle attack. But first we have to understand block ciphers a bit more.
- Messages are padded to the block size and there are a number of [padding schemes](https://en.wikipedia.org/wiki/Padding_(cryptography))
- PKCS#7 is used by default for the pycrypto package pad method.

Here is an illustration of PCKS#7 padding for block size 16:
```
        --------padding---------
DEADBEEF0c0c0c0c0c0c0c0c0c0c0c0c

                ----padding-----
DEADBEEFDEADBEEF0808080808080808

                                 -------------padding------------
DEADBEEFDEADBEEFDEADBEEFDEADBEEF 10101010101010101010101010101010  // a new block is inserted if the original does not need padding

                                   ------------padding-----------
DEADBEEFDEADBEEFDEADBEEFDEADBEEF 990f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
```

By pushing 1 letter into a new chunk, we can get that letter by bruteforcing all the possible letters (I used Python's `string.ascii_letters+string.digits+string.punctuation`).
Then we can push 1 more letter into the new chunk while using the previous value. This can be continued until the whole flag is recovered.

We now need to find the block boundary - and when our input is 11 bytes (22 hex symbols), a new chunk was created (the ciphertext got longer).

With the knowledge that 16-12=4 bytes is needed to fill the first chunk, we can write this code:

```
import nclib, string, time
nc = nclib.Netcat(( '159.65.89.199', 32234 ))
nc.recv_until('> ')
payload = bytes("00"*4+"10"*16+"ff"*7, 'ascii')
#print(payload)
nc.send( payload ) 
response = nc.recv_until('> ')
if response[32:64] == response[-3-32:-3]:
  #print ("Sanity check passed") 
  flag = ""
  for i in range(1, 64):
    (s, j) = (i//16, 16-i%16)
    hex_j = hex(j)[0::2]
    for c in string.ascii_letters + string.digits + string.punctuation :
      payload = bytes( "00"*4 + ((c+flag).encode('utf-8')).hex() + hex_j * 16 + "ff"*7 , 'ascii')
      #print(payload)
      nc.send(payload)
      response = nc.recv_until('> ')
      if response[32:64] == response[-3-32-s*32:-3-s*32]:
        print(c)
        flag = c+flag
        break
    else:
      print("Not found")
      break
  print(flag)
else:
  print("Sanity check failed")
```
