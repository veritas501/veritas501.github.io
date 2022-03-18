---
title: Reversing.kr writeup
tags:
  - RE
  - Reversing.kr
date: 2017/3/4
---

开坑，此处更新[reversing.kr](http://reversing.kr)的re题的wp。希望我能坚持下去。

reversing.kr是棒子的一个逆向网站，题目质量不错（学长推荐的），欢迎各位学bin的来摩擦。

## Easy Crack

直接拖到ida，shift+f12查看字符串，定位关键函数：

![](fmt_7a75a4b3423fa94b646e387ce24f7b33.png)


直接拼出flag：`Ea5yR3versing`


## Easy Keygen


> Find the Name when the Serial is 5B134977135E7D13

直接拖到ida，关键代码在main函数里。

![](fmt_e0eb9a21b74c825ebe3eb73c22b9220d.png)

应该不用我解释了，上python：

```python
serial = '5B134977135E7D13'.decode('hex')
key=[0x10,0x20,0x30]
name=''

for i in range(len(serial)):
	name+=chr(ord(serial[i])^key[i%3])
print name
```

flag:`K3yg3nm3`


## Easy Unpack


> Find the OEP
> ex) 00401000

脱个简单的压缩壳而已，脱壳环境xp sp3。

用esp定律轻松来到壳的段尾：

![](fmt_51e5905681a36a36ff5cb2d9bf0d52d0.png)

f8到oep

![](fmt_a7308642ee1771e6d2e3a000eb4bc2bd.png)

lordpe转储，importREC修复，脱壳成功。

![](fmt_3ad296241072c6b71a5391ee8bc9e0d4.png)

所以flag：`00401150`


## Music Player

> This MP3 Player is limited to 1 minutes.
> You have to play more than one minute.
> 
> There are exist several 1-minute-check-routine.
> After bypassing every check routine, you will see the perfect flag.

先让他放到一分钟，有一个弹窗提示，

![](fmt_7f20f837596f8c0908f64d297ed89149.png)

由于是vb，下断点BP rtcMsgBox，重新运行

![](fmt_9384c9d6a0d71c2e44734ca2b8c0fc39.png)

向上翻，可以发现有一个jl可以跳过这段代码，而比较的值为0xEA60,即60000，就是一分钟，那我们把jl改成jmp。

到一分钟以后跳出了：

![](fmt_f01a83b98ce0cbc8ca1ca7ff4dda07c6.png)

下断点 bp RaiseException 重载

再次跳出窗口时成功断下，打开堆栈调用的窗口：

![](fmt_bec2dbb6dc23a28dc4d8e57d80e2e7dc.png)

来到

![](fmt_c953974544a3f8f03e9ac732753db252.png)

把jge改成jmp，保存以后重载

成功得到flag：`LIstenCare`

![](fmt_a08cb2c1fba624e074d43a7e330c15cf.png)


## Replace

意图很明显，你输入正确的key，下面就是提示正确。这题有趣就有趣在你随便输一个数，这个程序一般是会炸的

![](fmt_f8b0a75a0a9a596dece5609898a4481a.png)

那我们就分析一下。

根据字符串来到这里：

![](fmt_dd13af5ebd0ae6d0bdadf500ec44aacb.png)

发现上面有个jmp不科学。更上面的一个jmp跳到了一个更奇怪的地方：


![](fmt_9daaebe8ea5770928c850d9e261e7d77.png)


我也卡不出这些代码是些什么，估计是汇编手写的，那就动态跟踪一下看看。

上面有个GetBlgItemInt，是用来获取用户输入的，先在那里下断。

```
0040104C   > \56            push esi                                 ;  Case 3EB of switch 0040103A
0040104D   .  8B75 08       mov esi,dword ptr ss:[ebp+0x8]
00401050   .  6A 00         push 0x0                                 ; /IsSigned = FALSE
00401052   .  6A 00         push 0x0                                 ; |pSuccess = NULL
00401054   .  68 EA030000   push 0x3EA                               ; |ControlID = 3EA (1002.)
00401059   .  56            push esi                                 ; |hWnd = 000E07D8 ('Replace',class='#32770')
0040105A   .  FF15 9C504000 call dword ptr ds:[<&USER32.GetDlgItemIn>; \GetDlgItemInt
00401060   .  A3 D0844000   mov dword ptr ds:[0x4084D0],eax          ;  int to 0x4084d0
00401065   >  E8 05360000   call Replace.0040466F
0040106A   .  33C0          xor eax,eax
0040106C   .  E9 1F360000   jmp Replace.00404690
00401071   .  EB 11         jmp short Replace.00401084
00401073   .  68 34 60 40 0>ascii "h4`@",0                           ;  Correct!
00401078   .  68 E9030000   push 0x3E9                               ; |ControlID = 3E9 (1001.)
0040107D   .  56            push esi                                 ; |hWnd = 000E07D8 ('Replace',class='#32770')
0040107E   .  FF15 A0504000 call dword ptr ds:[<&USER32.SetDlgItemTe>; \SetDlgItemTextA
00401084   >  B8 01000000   mov eax,0x1
00401089   .  90            nop
0040108A   .  90            nop
```

call Replace.0040466F那里跟过去

![](fmt_f38b716739fd71a55d488ea64ef1f7ff.png)

可见应该是作者把call当jmp用，而且那两句mov的地址引起了我的注意，可见这是一段SMC的代码。

跟了一下，操作大致如下，把输入的值转换为整型放到eax，然后把eax的值存到0x4084D0，并+1、+1、+0x601605C7、+1、+1，然后把0x4084D0的值存到eax，把eax的值及其+1对应的地址的机器码修改为0x90。为了达成目的，我们需要让0x401071、0x401072是nop，才会显示correct！

因此只要我们输入值+1+1+0x601605C7+1+1=0x401071，由此需要溢出，用0x100401071-1-1-0x601605C7-1-1

flag:`2687109798`


## ImagePrc

看样子应该是在程序上画画，然后对图片进行判断。

根据字符串“wrong”找到核心代码：

![](fmt_ebcf185a2496ec9986f3fadef29f8f36.png)

用reshacker把资源dump出来以后写个脚本解密即可

```python
from PIL import Image

width = 200
height = 150

image_file = open('Data_1.bin', 'rb')
data = image_file.read()
image = Image.frombuffer('RGB', (width, height), data, 'raw', 'RGB')
image = image.transpose(Image.FLIP_TOP_BOTTOM)
image.show()
image_file.close()
```

![](fmt_eebe3cf464a099cacac1e639fc858438.png)

flag:`GOT`


## Easy ELF

这题我不能用ida的f5键，那就看汇编分析吧。
（已经部分重命名）
首先到main函数：

![](fmt_27f4dd2d7e2ab55c7656de5f1a99bb84.png)

可见主体在calc函数里面：

```
.text:08048451 calc            proc near               ; CODE XREF: main+2Ap
.text:08048451                 push    ebp
.text:08048452                 mov     ebp, esp
.text:08048454                 movzx   eax, ds:input+1
.text:0804845B                 cmp     al, '1'         ; input[1]='1'
.text:0804845D                 jz      short loc_8048469
.text:0804845F                 mov     eax, 0
.text:08048464                 jmp     loc_80484F5
.text:08048469 ; ---------------------------------------------------------------------------
.text:08048469
.text:08048469 loc_8048469:                            ; CODE XREF: calc+Cj
.text:08048469                 movzx   eax, ds:input
.text:08048470                 xor     eax, 34h        ; xor [0],0X34
.text:08048473                 mov     ds:input, al
.text:08048478                 movzx   eax, ds:input+2 ; xor [2],0X32
.text:0804847F                 xor     eax, 32h
.text:08048482                 mov     ds:input+2, al
.text:08048487                 movzx   eax, ds:input+3 ; xor [3],0x88
.text:0804848E                 xor     eax, 0FFFFFF88h
.text:08048491                 mov     ds:input+3, al
.text:08048496                 movzx   eax, ds:input+4 ; [4] = 'X'
.text:0804849D                 cmp     al, 'X'
.text:0804849F                 jz      short loc_80484A8 ; [5] = 0
.text:080484A1                 mov     eax, 0
.text:080484A6                 jmp     short loc_80484F5
.text:080484A8 ; ---------------------------------------------------------------------------
.text:080484A8
.text:080484A8 loc_80484A8:                            ; CODE XREF: calc+4Ej
.text:080484A8                 movzx   eax, ds:input+5 ; [5] = 0
.text:080484AF                 test    al, al
.text:080484B1                 jz      short loc_80484BA ; cmp [2],0x7C
.text:080484B3                 mov     eax, 0
.text:080484B8                 jmp     short loc_80484F5
.text:080484BA ; ---------------------------------------------------------------------------
.text:080484BA
.text:080484BA loc_80484BA:                            ; CODE XREF: calc+60j
.text:080484BA                 movzx   eax, ds:input+2 ; cmp [2],0x7C
.text:080484C1                 cmp     al, 7Ch
.text:080484C3                 jz      short loc_80484CC ; CMP [0],0X78
.text:080484C5                 mov     eax, 0
.text:080484CA                 jmp     short loc_80484F5
.text:080484CC ; ---------------------------------------------------------------------------
.text:080484CC
.text:080484CC loc_80484CC:                            ; CODE XREF: calc+72j
.text:080484CC                 movzx   eax, ds:input   ; CMP [0],0X78
.text:080484D3                 cmp     al, 78h
.text:080484D5                 jz      short loc_80484DE
.text:080484D7                 mov     eax, 0
.text:080484DC                 jmp     short loc_80484F5
.text:080484DE ; ----------------------
-----------------------------------------------------
.text:080484DE
.text:080484DE loc_80484DE:                            ; CODE XREF: calc+84j
.text:080484DE                 movzx   eax, ds:input+3
.text:080484E5                 cmp     al, 0DDh        ; CMP [3],0XDD
.text:080484E7                 jz      short loc_80484F0
.text:080484E9                 mov     eax, 0
.text:080484EE                 jmp     short loc_80484F5
.text:080484F0 ; ---------------------------------------------------------------------------
.text:080484F0
.text:080484F0 loc_80484F0:                            ; CODE XREF: calc+96j
.text:080484F0                 mov     eax, 1
.text:080484F5
.text:080484F5 loc_80484F5:                            ; CODE XREF: calc+13j
.text:080484F5                                         ; calc+55j ...
.text:080484F5                 pop     ebp
.text:080484F6                 retn
.text:080484F6 calc            endp
.text:080484F6
```

直接跑脚本：
```python
flag=''
flag+=chr(0x78^0x34)
flag+='1'
flag+=chr(0x7c^0x32)
flag+=chr(0xdd^0x88)
flag+='X'
print flag
```
flag:`L1NUX`

## ransomware

首先readme告诉我们，被加密的文件原来是一个exe文件。

运行程序发现乱码，因为是韩国人的网站，猜测上面应该是韩文，这不是重点，我们仍然可以分析。

首先程序加了upx壳，简单脱掉不解释了。

想载入ida，但发现分析异常缓慢，OD看了一下，发现加了花式nop指令：

![](fmt_2a9997d0197bc2843d3594b6f1db1e4e.png)

那就写个脚本去掉：

```python
data = open('run.exe','rb').read()
data = data.replace('\x60\x61\x90\x50\x58\x53\x5b','\x90\x90\x90\x90\x90\x90\x90')
open('run_dejunk.exe','wb').write(data)
```


再丢到ida里就能分析了：

![](fmt_d0f429412a0d77b5c0bd9e538489804d.png)

这里我们根据pe文件中一点：

![](fmt_8693cdbe6940879d3e507395ad61aa56.png)

就是这句话在固定的位置上（虽然这句话能改，而且不影响程序运行，但一般我们是不会去修改的，所以可以利用）

```
enc='C7F2E2FFAFE3ECE9FBE5FBE1ACF0FBE5E2E0E7BEE4F9B7E8F9E2B3F3E5ACCBDCCDA6F1F8FEE9'.decode('hex')

dec='This program cannot be run in DOS mode'
key=''

enc = list(enc)
dec = list(dec)
for i in range(len(enc)):
	enc[i] = (~ord(enc[i]))&255
	key += chr(ord(dec[i])^enc[i])
print key
```

得到key = "letsplaychess"

解密文件：

```
data_c = open('file','rb').read()
data_d=''
key='letsplaychess'
key_len = len(key)
for i in range(len(data_c)):
	data_d += chr(ord(key[i%key_len])^(~ord(data_c[i]))&255)

open('file.exe','wb').write(data_d)
```

运行file.exe得到flag：`Colle System`


## CSHOP

这题很迷，我同时放上我的解题过程和网上的过程。

我打开窗口，发现只有一个空白的窗口，我习惯性的点了点鼠标，敲了敲键盘，结果按到空格的时候出现了这个：

![](fmt_d0e27f0f55bb5d851305e02ac84034dd.png)

提交发现就是flag。。。。


**接着放网上的方法：**

这题是一个C#的题，打开是一个空白的对话框，用dnSpy反编译，看到new了一个按钮，但大小却是0

![](fmt_1b9a978897824c29a880002b330126ed.png)

可以修改IL指令把size改大点，然后按钮就显示出来了，其实不改也行，由于按钮的TabIndex是0，当焦点在按钮上时，按空格键相当于点击按钮，所以打开程序后按下空格flag就出来了

flag:`P4W6RP6SES`


## Direct3D\_FPS

这题很迷，我电脑上打开这个程序是白屏的，又只能靠字符串来猜测程序了。23333

![](fmt_eec339308e369f6391ec4e14b39c9eb6.png)

在Game_clear的函数中，发现messagebox的text参数很可疑，我猜是flag，交叉引用发现有异或加密：

![](fmt_a821fb6b7eb662aadbc7531f8cc54780.png)

![](fmt_c08a6ce36718e08821bb581d5965e191.png)

byte_409184这个地方看起来很重要，但是靠ida静态分析我没能得出这里面的数据是什么。

大致上逻辑是：

i = sub_403440();
flag[i] ^= byte_409184[528*i];

那我们用OD动态分析试试看：

![](fmt_bac7ecc2f754d5cb6d2fb9660d2e9a49.png)

发现 byte\_409184[528\*i] = 4\*i。
所以flag[i] ^= 4i;

写个python脚本解密一下即可：

```python
flag_c='436B666B62756C694C455C455F5A461C07252529701734390116494C20150B0FF7EBFAE8B0FDEBBCF4CCDA9FF5F0E8CEF0A9'.decode('hex')
flag_d=''
for i in range(len(flag_c)):
	flag_d += chr(ord(flag_c[i])^4*i)
print flag_d
#Congratulation~ Game Clear! Password is Thr3EDPr0m
```

flag:`Thr3EDPr0m`

## HateIntel

mac上的程序，但我们有万能的ida。


主函数：
```
int sub_2224()
{
  char key; // [sp+4h] [bp-5Ch]@1
  int int_4; // [sp+54h] [bp-Ch]@1
  signed __int32 key_len; // [sp+58h] [bp-8h]@1
  signed __int32 i; // [sp+5Ch] [bp-4h]@1
  char vars0; // [sp+60h] [bp+0h]@2

  int_4 = 4;
  printf("Input key : ");
  scanf("%s", &key);
  key_len = strlen(&key);
  enc((signed __int32)&key, int_4);
  for ( i = 0; i < key_len; ++i )
  {
    if ( (unsigned __int8)*(&vars0 + i - 0x5C) != byte_3004[i] )// key cmp
    {
      puts("Wrong Key! ");
      return 0;
    }
  }
  puts("Correct Key! ");
  return 0;
}
```

enc:
```
signed __int32 __fastcall enc(signed __int32 len_key, int int_4)
{
  int _4; // [sp+0h] [bp-14h]@1
  char *key; // [sp+4h] [bp-10h]@1
  int i; // [sp+8h] [bp-Ch]@1
  signed __int32 j; // [sp+Ch] [bp-8h]@2

  key = (char *)len_key;
  _4 = int_4;
  for ( i = 0; i < _4; ++i )                    // 加密4次
  {
    for ( j = 0; ; ++j )
    {
      len_key = strlen(key);
      if ( len_key <= j )
        break;
      key[j] = calc(key[j], 1);
    }
  }
  return len_key;
}
```

calc:

```
int __fastcall calc(unsigned __int8 key_char, int _1)
{
  int ch; // [sp+8h] [bp-8h]@1
  int i; // [sp+Ch] [bp-4h]@1

  ch = key_char;
  for ( i = 0; i < _1; ++i )
  {
    ch *= 2;
    if ( ch & 256 )
      ch |= 1u;
  }
  return (unsigned __int8)ch;
}
```

直接写脚本爆破：

```python
def calc(result):
	for i in range(32,128):
		k = i
		for j in range(4):
			tmp = k*2
			if tmp & 0x100:
				tmp |= 1
			k = tmp & 255
		if k == result:
			return chr(i)

f_c = '44F6F557F5C696B656F51425D4F596E63747275736479603E6F3A392'.decode('hex')
f_d = ''

for ch in f_c:
	f_d+=calc(ord(ch))
	
print f_d
#Do_u_like_ARM_instructi0n?:)
```

flag:`Do_u_like_ARM_instructi0n?:)`


## Flash Encrypt

这题只要工具好就能做

网上下载ffdec。

用ffdec反编译swf，在设置中选上自动反混淆

来到帧1：

![](fmt_1e0823d6dbc4598be2da89797ce9cb73.png)

提示是按钮2 （4），查看脚本：

![](fmt_5c187ba5dc08cbd2a4eb21fe5d7c3d36.png)

需要输入1456，然后到帧3，

如此下来，依次输入：
1456，25，44，8，88，20546即可。

flag:`16876`


## Position

题目描述：
> Find the Name when the Serial is 76876-77776
> This problem has several answers.
> Password is ***p

ida载入，根据字符串来到这里：

![](fmt_0a8d66d1dd47948abca2b8d4f7b15d24.png)

到calc函数内部：

![](fmt_df74fa4535d0b0c4e6668cde65c54156.png)

![](fmt_f56c73ff52fd82ff57528aaf5dc136be.png)

![](fmt_f4aa551f379bee49d2a11f2116102775.png)

分析得逻辑如下：

```
v7=name[0]
v8 = (v7 & 1) + 5
v59 = ((v7 >> 4) & 1) + 5
v53 = ((v7 >> 1) & 1) + 5
v55 = ((v7 >> 2) & 1) + 5
v57 = ((v7 >> 3) & 1) + 5

v9=name[1]
v45 = (v9 & 1) + 1
v51 = ((v9 >> 4) & 1) + 1
v47 = ((v9 >> 1) & 1) + 1
v10 = ((v9 >> 2) & 1) + 1
v49 = ((v9 >> 3) & 1) + 1

v8+v10=serial[0]
v57+v49==serial[1]
v53+v51==serial[2]
v55+v45==serial[3]
v59+v47==serial[4]

=====================

v26=name[2]
v27 = (v26 & 1) + 5
v60 = ((v26 >> 4) & 1) + 5
v54 = ((v26 >> 1) & 1) + 5
v56 = ((v26 >> 2) & 1) + 5
v58 = ((v26 >> 3) & 1) + 5

v28=name[3]
v46 = (v28 & 1) + 1
v52 = ((v28 >> 4) & 1) + 1
v48 = ((v28 >> 1) & 1) + 1
v29 = ((v28 >> 2) & 1) + 1
v50 = ((v28 >> 3) & 1) + 1


v27+v29==serial[5]
v58+v50==serial[6]
v54+v52==serial[7]
v56+v46==serial[8]
v60+v48==serial[9]
```

脚本爆破：

```python
serial='7687677776'

for i in range(ord('a'),ord('z')+1):
	for j in range(ord('a'),ord('z')+1):
		v7=i
		v9=j

		v8 = (v7 & 1) + 5
		v59 = ((v7 >> 4) & 1) + 5
		v53 = ((v7 >> 1) & 1) + 5
		v55 = ((v7 >> 2) & 1) + 5
		v57 = ((v7 >> 3) & 1) + 5

		v45 = (v9 & 1) + 1
		v51 = ((v9 >> 4) & 1) + 1
		v47 = ((v9 >> 1) & 1) + 1
		v10 = ((v9 >> 2) & 1) + 1
		v49 = ((v9 >> 3) & 1) + 1

		if v8+v10==int(serial[0]) and v57+v49==int(serial[1]) and v53+v51==int(serial[2]) and v55+v45==int(serial[3]) and v59+v47==int(serial[4]):
			print chr(i),chr(j)

print '==============='

for i in range(ord('a'),ord('z')+1):
	for j in range(ord('a'),ord('z')+1):
		v26=i
		v28=j

		v27 = (v26 & 1) + 5
		v60 = ((v26 >> 4) & 1) + 5
		v54 = ((v26 >> 1) & 1) + 5
		v56 = ((v26 >> 2) & 1) + 5
		v58 = ((v26 >> 3) & 1) + 5

		v46 = (v28 & 1) + 1
		v52 = ((v28 >> 4) & 1) + 1
		v48 = ((v28 >> 1) & 1) + 1
		v29 = ((v28 >> 2) & 1) + 1
		v50 = ((v28 >> 3) & 1) + 1
		
		if v27+v29==int(serial[5]) and v58+v50==int(serial[6]) and v54+v52==int(serial[7]) and v56+v46==int(serial[8]) and v60+v48==int(serial[9]):
			print chr(i),chr(j)
```

输出如下：
```
b u
c q
f t
g p
===============
a y
b m
c i
e x
f l
g h
h u
i q
j e
k a
l t
m p
n d
```

由于name第四位为'p'，所以可能的name为：
```
bump
cqmp
ftmp
gpmp
```

提交`bump`时成功，flag：`bump`