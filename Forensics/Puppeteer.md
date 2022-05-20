## Skills involved: Windows Event Log Analysis

I feel like learning a lot out of every forensics challenge. Plus they don't really require insights and are suitable at late night.

We have quite a number of event log files. I narrowed down the range by:
- Removing all 68KB files, as they contain nothing at all.
- Look for files with PowerShell or Shell, as these files usually contain the commands run by malicious actors.

I noticed inside the `Microsoft-Windows-PowerShell%4Operational` log, there is a large chunk of Powershell commands.

<img width="411" alt="image" src="https://user-images.githubusercontent.com/26480299/169575731-032b8b47-a747-4204-bc0f-f17caf8a3f3b.png">

Execute only the safe commands reveals the flag. (CreateThread is DEFINITELY not safe).

**Flag: HTB{b3wh4r3_0f_th3_b00t5_0f_just1c3...}**
