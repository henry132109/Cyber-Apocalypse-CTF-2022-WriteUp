## Skills involved: can 'string' be called reversing at all?

I opened up the executable in Hex Editor:

<img width="530" alt="image" src="https://user-images.githubusercontent.com/26480299/169565458-2f51f1e5-d859-48c6-8a9c-a7243bb0b6f6.png">

In it the strings in output.txt can be found followed by a single character. This highly suggests a substition cipher.
Replacing all ciphertext with the letter plaintext gives the flag straight away.

**Flag: HTB{l1n34r_t1m3_but_pr3tty_sl0w!}**

Remark: Doing it with plain ol' Notepad is actually faster.
