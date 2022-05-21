## Skills involved: identify weak code, Python, elementary math

I initially thought about doing cryptanalysis over the decoded blocks but it was a total overthinking.
Inside the source file, we noticed a custom Pseudo Random Number Generator (PRNG):

```python
class PRNG:
    def __init__(self, seed):
        self.p = 0x2ea250216d705
        self.a = self.p
        self.b = int.from_bytes(os.urandom(16), 'big')
        self.rn = seed

    def next(self):
        self.rn = ((self.a * self.rn) + self.b) % self.p
        return self.rn
```

This PRNG is very problematic, because:
```
self.rn = ((self.a * self.rn) + self.b) % self.p       
        = (self.a * self.rn) % self.p + self.b % self.p
        = (self.p * self.rn) % self.p + self.b % self.p
        = self.b % self.p
```

The last key intercepted is the used key all along.
With that in mind we can simply reverse the encryption process.

My final code:
```python
def deriveKey(key):
    derived_key = []
    for i, char in enumerate(key):
        previous_letters = key[:i]
        new_number = 1
        for j, previous_char in enumerate(previous_letters):
            if previous_char > char:
                derived_key[j] += 1
            else:
                new_number += 1
        derived_key.append(new_number)
    return derived_key

def transpose(array):
    return [row for row in map(list, zip(*array))]

def flatten(array):
    return "".join([i for sub in array for i in sub])


key = "729513912306026"
derived_key = deriveKey(key)

def twistedColumnarDecrypt(ct):
    width = len(key) #constant
    width_inv = len(ct)//width
    blocks = [ct[i:i+width_inv] for i in range(0, len(ct), width_inv)] # unflatten
    blocks = [b[::-1] for b in blocks] # sdrawkcab
    blocks = [blocks[derived_key[i]-1] for i in range(width)] # unkey
    blocks = transpose(blocks)
    return flatten(blocks)

for ct in ['VEOAOTNRDCEEIFHIVHMVOETYDEDTESTHTCHLSRPDAIYAATOSTEGIIIOCIPYLTNOTLRTRNLEEUNBEOSFNANDHTUFTEETREEEEOEDHNRNYA',
'AAVPDESEETURAFFDUCEDAEECNEMOROCEANHPTTGROITCYSSSETTSKTTRLRIUAVSONOISECNJISAFAATAPATWORIRCETYUIPUEEHHAIHOG',
'NABPSVKELHRIALDVEHLORCNNOERUNGTAEEEHEHDORLIEEAOTITUTEAUEARTEFISESGTAYAGBTHCEOTWLSNTWECESHHBEIOYPNCOLICCAF',
'NIRYHFTOSSNPECMPNWSHFSNUTCAGOOAOTGOITRAEREPEEPWLHIPTAPEOOHPNSKTSAATETTPSIUIUOORSLEOAITEDFNDUHSNHENSESNADR',
'NUTFAUPNKROEOGNONSRSUWFAFDDSAAEDAIFAYNEGYSGIMMYTAANSUOEMROTRROUIIOODLOIRERVTAMNITAHIDNHRENIFTCTNLYLOTFINE']:
    print(twistedColumnarDecrypt(ct))
```

**Flag: HTB{THELCGISVULNERABLEWENEEDTOCHANGEIT}**

Remark: LCG refers to [Linear Congruential Generator](https://en.wikipedia.org/wiki/Linear_congruential_generator), which is not secure.
