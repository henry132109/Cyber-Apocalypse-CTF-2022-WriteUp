## Skills involved: command chaining
Pre-CTF Guide: You have to use `nc ip port` to connect to this server.

This is a basic example of *command chaining*, in which we end the original command and append another command to our liking.
This concept can be used for SQL or other injections as well.

![image](https://user-images.githubusercontent.com/26480299/169344640-12758e0c-db80-457f-98a7-0665e3604219.png)

Paths are also not sanitized, leading to free *directory traversal*.

![image](https://user-images.githubusercontent.com/26480299/169345122-09b8c600-3e7e-4ef4-bc04-aaa249bfaa66.png)

**Flag: HTB{GTFO_4nd_m4k3_th3_b35t_4rt1f4ct5}**
