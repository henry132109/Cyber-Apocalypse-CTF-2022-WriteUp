## Skills involved: Python, installing pip packages

In cryptography, secure communication between 2 parties can be established by a *public key exchange*. A common, simple method is [Diffie–Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange).

Usually the number chosen must be between 2 and p-1 (inclusively). Because this is an easy challenge, my public key, however, will not be validated. So I could just set it to 0 to make shared_secret 0. This nullifies any randomness.

As I have practised in [PicoGym](https://play.picoctf.org/), I already had the [pycrypto](https://pypi.org/project/pycrypto/) package installed in a linux environment.

My code (recreated after the event):
```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
import hashlib
decrypted = b"Initialization Sequence - Code 0"
def encrypt(decrypted):
    key = hashlib.md5(long_to_bytes(0)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.encrypt(decrypted)
    return message
print(encrypt(decrypted).hex())
```

**Flag: HTB{7h15_p2070c0l_15_pr0tec73d_8y_D@nb3er_c0pyr1gh7_1aws}**
