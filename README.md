# HuaweiPasswordTool
Tool for enc/dec huawei format password

### Requires on Debian 11
```
apt install cmake make g++ libssl1.1 libssl-dev
```
### Build
```
$ git clone https://github.com/0xuserpag3/HuaweiPasswordTool.git
$ cd HuaweiPasswordTool
$ mkdir build && cd build
$ cmake ..
$ make
```
### Usage:
```
$ ./hw_passwd 
Usage: ./hw_passwd [-e [-f]] [-d] [-s] <file or - (STDIN)>
 -e Encrypt raw password
 -d Decrypt sanitized password
 -s Print sanitized password
 -f Format password($1pwd$, $2pwd$). Example: -f 2
 ```
### Encrypt:
```
$ echo -n 123 | md5sum
202cb962ac59075b964b07152d234b70  -
```
```
$ echo -n 123 | md5sum | cut -f 1 -d ' ' -z | ./hw_passwd -s -e -f 2
[+] 202cb962ac59075b964b07152d234b70:$2OR@jUBxH)5#*,ZQZTlZ&apos;&apos;C,Y1.^DuAEr|%H6,o$#u(*Z317-kS=.&lt;IJb:&apos;-U&gt;GQ%!&lt;1gB&gt;#QfN6[VQO5$
```
```
$ echo -n 123 | ./hw_passwd -s -e -f 2
[+] 123:$2l@#zH4{W,Mi*{Q0A$*7/JkMnLI&gt;gs&apos;P&quot;/:#7e1W7$
```
### Decrypt:
```
$ echo -n '$2l@#zH4{W,Mi*{Q0A$*7/JkMnLI&gt;gs&apos;P&quot;/:#7e1W7$' | ./hw_passwd -s -d
[+] $2l@#zH4{W,Mi*{Q0A$*7/JkMnLI&gt;gs&apos;P&quot;/:#7e1W7$:123
```
```
$ cat passlist.txt 
$2OR@jUBxH)5#*,ZQZTlZ&apos;&apos;C,Y1.^DuAEr|%H6,o$#u(*Z317-kS=.&lt;IJb:&apos;-U&gt;GQ%!&lt;1gB&gt;#QfN6[VQO5$
$2l@#zH4{W,Mi*{Q0A$*7/JkMnLI&gt;gs&apos;P&quot;/:#7e1W7$
```
```
$ ./hw_passwd -s -d passlist.txt
[+] $2OR@jUBxH)5#*,ZQZTlZ&apos;&apos;C,Y1.^DuAEr|%H6,o$#u(*Z317-kS=.&lt;IJb:&apos;-U&gt;GQ%!&lt;1gB&gt;#QfN6[VQO5$:202cb962ac59075b964b07152d234b70
[+] $2l@#zH4{W,Mi*{Q0A$*7/JkMnLI&gt;gs&apos;P&quot;/:#7e1W7$:123
```
