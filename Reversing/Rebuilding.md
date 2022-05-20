Skills involved: reverse engineering (with Ghidra)

This is my first reverse engineering challenge and my first time using Ghidra. It was rather easy to setup and work with.

After analyzing the file I got the code for main function:
```c
undefined8 main(int param_1,long param_2)

{
  int __c;
  size_t sVar1;
  undefined8 uVar2;
  int local_14;
  int local_10;
  int local_c;
  
  if (param_1 != 2) {
    puts("Missing required argument");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  local_14 = 0;
  sVar1 = strlen(*(char **)(param_2 + 8));
  if (sVar1 == 0x20) {
    for (local_10 = 0; local_10 < 0x20; local_10 = local_10 + 1) {
      printf("\rCalculating");
      for (local_c = 0; local_c < 6; local_c = local_c + 1) {
        if (local_c == local_10 % 6) {
          __c = 0x2e;
        }
        else {
          __c = 0x20;
        }
        putchar(__c);
      }
      fflush(stdout);
      local_14 = local_14 +
                 (uint)((byte)(encrypted[local_10] ^ key[local_10 % 6]) ==
                       *(byte *)((long)local_10 + *(long *)(param_2 + 8)));
      usleep(200000);
    }
    puts("");
    if (local_14 == 0x20) {
      puts("The password is correct");
      uVar2 = 0;
    }
    else {
      puts("The password is incorrect");
      uVar2 = 0xffffffff;
    }
  }
  else {
    puts("Password length is incorrect");
    uVar2 = 0xffffffff;
  }
  return uVar2;
}
```

I found out that I could double click on external variables to go to its declaration and found out the `encrypted` text.
Doing the same tells me the key is `humans`. When trying to XOR them however, I get gibberish.

Upon closer inspection I noticed in the cross-reference column (XREF) there are writes (W), double clicking them revealed:
```c
void _INIT_1(void)

{
  puts("Preparing secret keys");
  key[0] = 'a';
  key[1] = 'l';
  key[2] = 'i';
  key[3] = 'e';
  key[4] = 'n';
  key[5] = 's';
  return;
}
```

Using `aliens` as the key reveals the flag.

**Flag: HTB{h1d1ng_1n_c0nstruct0r5_1n1t}**
