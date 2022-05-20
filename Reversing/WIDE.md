## Skills involved: guessing?

I didn't use any reversing skills at all for this challenge.

I opened db.ex in HEX editor, which revealed the encrypted string. Some characters aren't printable so it's preferrable to work with their HEX values.

We know that the flag format is HTF{...}. With the first letter of the encrypted flag being H, I decided to compute the (bitwise) XOR as it's quite common in cryptography (yes I used Excel):

![image](https://user-images.githubusercontent.com/26480299/169563818-0b64eda6-e214-407b-880f-cd4c1aa31f34.png)

The +27 pattern does continue until 270. Assuming the +27 pattern will continue, I guessed the key to be 15 = 270 % 255.

With this the whole flag can be recovered.

**Flag: HTB{str1ngs_4r3nt_4lw4ys_4sc11}**

Remark: Microsoft's Hex Editor extension in VSCode turns out to give the base64 dump when we try to copy characters.
```js
String.fromCharCode(...atob("SE90Kh/z0Iy2lHx1cRJI+MWT029pDS0c1ZGzuMcjUA==").split("").map((x,i)=>x.charCodeAt(0)^(27*i)%255))
```
