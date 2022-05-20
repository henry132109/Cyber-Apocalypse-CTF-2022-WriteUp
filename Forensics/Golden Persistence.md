## Skills involved: NTUSER.dat Analysis

I viewed the NTUSER.dat with [Registry Explorer](https://ericzimmerman.github.io/#!index.md) from Eric Zimmerman.

I knew nothing about red/blue team and the hunt took some time. But eventually I reached `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`.

![image](https://user-images.githubusercontent.com/26480299/169578680-e2113a62-02cc-4190-a407-7afb25f61548.png)

Decoding the base64 payload and filtering out chunks gives a power shell code. There are also some ciphertext segments spread throughout the registry hive to avoid detection.

After running the safe commands, the `$DecryptedString` contains the flag:

**Flag: HTB{g0ld3n_F4ng_1s_n0t_st34lthy_3n0ugh}**

Remark: While writing this write-up I found this [nice explanation](https://pentestlab.blog/2019/10/01/persistence-registry-run-keys/) on achieving persistance with registry run keys.
