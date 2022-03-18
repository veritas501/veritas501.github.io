---
title:  HCTF GAME RE - 零碎的逆向
tags:
  - RE
  - CTF
  - HCTF GAME
date: 2017/3/1
---

首先不要误会，这几道题不是因为简单而放在零碎中。


## 思维混乱的出题人	

下载：http://pan.baidu.com/s/1i57edOp 密码：61z7

说句实话，我做完后感觉这题的确有些混乱，我尽量简单的说。

先随便跑跑，发现随便输入最后会显示`What do you his mother's want to do!`，OD载入，查找字符串，发现3个比较可疑的字符串`tutushigecaiji`，`aGN0ZntpdF9pc19ub3RfZmxhZyF9`和`What do you his mother's want to do!`，第一个字符串让我感觉到了出题者和土土<s>某种微妙的关系</s>。动态调试后可知0x013E2B70是一个gets之类获取用户输入的函数，不是重点，略过。
![](20170215222815023.png)
比较微妙的是，当我们f8小心单步后可以发现：
![](20170215222846586.png)

 当我们执行完CALL 0x13E1070后，字符串`hctf{it_is_not_flag!}`出现在了我们的堆栈区，所以我用IDA看了一下这个CALL，发现0x61（‘=’）这个字节：
![](20170215222851892.png)

理所当然的想到了base64，拿`aGN0ZntpdF9pc19ub3RfZmxhZyF9`进行base64解密得到了我们看到的字符串`hctf{it_is_not_flag!}`，合理推测flag应该是由某个base64字串解密得到。

回头看一下，我们现在还有一个字符串没有用到：`tutushigecaiji`，我们总不能把出题人想的这么坏，写个和题目无关的字符串只为了<s>吐槽</s>一下土土吧？我们到字符串的附近下断，动态跟踪一下，发现此处：
![](20170215222857486.png)

程序在循环利用写在0x0059F6E4出的字节码进行某种解密，我们就在跳转的前面轻轻摁一下f4，发现此时数据窗口出现了两个可疑字符串：
![](20170215222901493.png)

我们把它拼起来，得到`aGN0ZntJdF8xc190aDNfZmxhRyF9`,base64解密一下得到flag：`hctf{It_1s_th3_flaG!}`


## easy-shell

下载：http://pan.baidu.com/s/1i5OEU5v 密码：6x5w

首先扫下壳：
![](20170215223201588.png)

正如文件的名字，是个vmp壳，说真的我挺害怕这个壳的。

**前排提醒：此处调试用的OD不能是原版OD，你可以使用网上各大论坛改的OD，比如52pojie，学破解，飘云阁等等。调试时需要Strong OD，FKVMP，忽略异常等。（你应该需要在XP上调试）**

OD载入，先如下设置：
![](20170215223205506.png)

在此时的代码处右键选择FKVMP>>start，点击OD上方的L按钮，找到retn：
![](20170215223210869.png)

记录retn的地址：`0x00571903`

接着在OD上下断点：`bp VirtualProtect`，按f9运行，观察堆栈区：
![](20170215223214646.png)

直到NewProtect = READONLY：

![](20170215223218209.png)

此时alt+B，断点界面取消或禁用断点，然后alt+M，对text段下内存访问断点：

![](20170215223223432.png)

f9一下，取消text段的访问断点，来到这里：

![](20170215223227740.png)

掏出我们之前记录下的retn地址：ctrl+G转到然后f2下断：

![](20170215223232494.png)

f9一下，取消retn的断点，再对text段下内存访问断点，f9一下，来到了我们的oep：
![](20170215223236084.png)

（此时我们可以对oep下硬件执行断点，方便下次调试，不用再重复之前那些动作）

我们现在可以用lordpe dump一下镜像，虽然IAT没有修复，但是IDA还是能分析部分的。

ida载入，找到关键函数：
```cpp
int sub_401000()
{
  int v0; // eax@1
  int v1; // esi@1
  signed int v2; // eax@2
  unsigned int v3; // eax@4
  char *v4; // ecx@4
  char *v5; // edx@4
  __int16 v7; // [sp+8h] [bp-50h]@1
  char v8; // [sp+Ah] [bp-4Eh]@1
  char v9; // [sp+Ch] [bp-4Ch]@1
  __int16 v10; // [sp+24h] [bp-34h]@1
  char v11[28]; // [sp+28h] [bp-30h]@2
  int v12; // [sp+44h] [bp-14h]@1
  __int16 v13; // [sp+48h] [bp-10h]@1
  int v14; // [sp+4Ch] [bp-Ch]@1
  char v15; // [sp+50h] [bp-8h]@1

  v8 = 0;
  qmemcpy(&v9, word_40B90C, 24u);
  LOBYTE(v13) = 0;
  v7 = 0x201;
  v15 = 0;
  v12 = 0x4030201;
  LOBYTE(v12) = 'f';
  BYTE1(v12) ^= 'n';
  HIWORD(v12) = 'ga';                           // flag
  v14 = 0x4030201;
  v10 = word_40B90C[12];
  v13 = 0;
  v0 = sub_401311((int)&v12, (int)&unk_40B928); // 'r' 
  v1 = v0;
  if ( v0 )
  {
    sub_40111D(v11, 26, v0);
    sub_4014E4(v1);
    LOBYTE(v7) = v7 ^ 'f';                      // gg
    HIBYTE(v7) ^= 'e';
    LOBYTE(v14) = v14 ^ 'b';                    // cool
    BYTE1(v14) ^= 'm';
    BYTE2(v14) ^= 'l';
    BYTE3(v14) ^= 'h';
    v2 = 0;
    do
    {
      v11[v2] = (v11[v2] - 3) ^ '3';
      ++v2;
    }
    while ( v2 < 25 );
    v3 = 25;
    v4 = v11;
    v5 = &v9;
    while ( *(_DWORD *)v5 == *(_DWORD *)v4 )
    {
      v3 -= 4;
      v4 += 4;
      v5 += 4;
      if ( v3 < 4 )
      {
        if ( *v4 != *v5 )
          break;
        sub_401328(&v14);
        return 0;
      }
    }
  }
  sub_401328(&v7);
  return 0;
}
```

忽略中间的n多细节，我们只看两段：
```cpp
do
    {
      v11[v2] = (v11[v2] - 3) ^ '3';
      ++v2;
    }
while ( v2 < 25 );
...
while ( *(_DWORD *)v5 == *(_DWORD *)v4 )
{
	v3 -= 4;
	v4 += 4;
	v5 += 4;
	if ( v3 < 4 )
	{
		if ( *v4 != *v5 )
			break;
		sub_401328(&v14); //打印函数（cool）
		return 0;
	}
}
sub_401328(&v7);//打印函数（GG）
```
结合OD动态调试，我们发现，函数是将写在0x0012ff48处的数据做`byte = (byte - 3) ^ '3'`变换：
![](20170215223240319.png)

然后和写在0x0012FF2C处的数据一位一位比较，如果相同则输出’cool‘：
![](20170215223246619.png)

由此用py写出反函数：
```python
enc = [0x56,0x53,0x42,0x50,0x4B,0x5F,0x56,0x6F,0x65,0x7F,0x61,0x6F,0x0D,0x7C,0x71,0x6F,0x63,0x7F,0x6F,0x63,0x79,0x0D,0x7C,0x62,0x49]
dec=[]
for i in range(len(enc)):
	dec.append(chr(((enc[i])^0x33)+3))
print ''.join(dec)

#hctf{oh_YOU_ARE_SO_SMART}
```
得flag：`hctf{oh_YOU_ARE_SO_SMART}`

后话：如果你知道vs编译出来的程序的用户函数一般都从data段最前面开始，而且你有成功猜到这道题的主函数在0x401000处的话，这道题会简单很多：首先下一个退出断点：BP ExitProcess，运行后断下，ctrl+G来到401000，发现代码完整，接着在数据窗口ctrl+G来到401000，对401000下硬件执行断点，重新载入，f9运行，程序成功断在401000处，然后和上面一样，很快就解得了flag。

## coder

下载：http://pan.baidu.com/s/1c1ZyuM8 密码：mugh

一开始，我是打算用正常的做re题的方法来解的，先跑跑，逆代码，分析，写反函数之类的来解，但我失败了，大概是水平不够。但我们依然有方法解题。

惯例扔到ida里，在main函数的加密函数中有如下一段：
```cpp
    printf("encrypt ok, your key is ", buf);
    for ( k = 0; k <= 4; ++k )
      printf("%02x", *((_BYTE *)&pt_key1 + k));
    for ( l = 0; l <= 9; ++l )
      printf("%02x", *((_BYTE *)&pt_key2 + l));
    for ( m = 0; m < size; ++m )
    {
      *((_BYTE *)&pt_key1 + m % 5) = sub_401766(*((_BYTE *)&pt_key1 + m % 5), 2u);
      *((_BYTE *)&pt_key2 + m % 10) = sub_401766(*((_BYTE *)&pt_key2 + m % 10), 4u);
      *((_BYTE *)buf + m) ^= *((_BYTE *)&pt_key1 + m % 5) ^ *((_BYTE *)&pt_key2 + m % 10);// 将原始文件读入内存，在内存中加密，然后写出
    }
    v8 = open(*(const char **)(v12 + 24), 0x41, 0x1B6LL);
    write(v8, buf, size);
    close(v8);
    putchar(10);
    free(buf);
```
由此我们知道，key1为5位，key2为10位，加密过程可以大致表示为：
`enc[i] ^= key3[i%10]`，其中key3为10位，`key3[i] = key1[i%5] ^ key2[i]`。

但我们现在不知道sub_401766函数是做什么的，起初我怀疑这个函数会对key做某种变换，导致每一轮加密用的key都不一样（满足某种函数关系），我试着分析了一下，但关系实在不好找，以为要GG，但我们打开flag.mp4文件，看到文件尾部为：
![](20170215223611606.png)

非常整齐，十个一组，所以我的顾虑打消了，key3应该是不会改变的。

flag的格式为mp4，这个条件我们不能漏下，我随便打开了我硬盘上的几个mp4文件，发现前八个字节都是相同的，为
`dec1 = [0x00,0x00,0x00,0x20,0x66,0x74,0x79,0x70]`：
![](20170215223615371.png)

而加密后的文件头8个字节为：`enc1 = [0xFC,0x3E,0x96,0x1E,0xFE,0xDC,0xD9,0x32]`

我们将两者进行异或，得到`xor1 = [0xFC,0x3E,0x96,0x3E,0x98,0xA8,0xA0,0x42]`

如果没有猜错，文件的结尾出应该是一串相同的字符，就像我手头的这个文件一样：
![](20170215223619184.png)

那么我们用python脚本：
```python
file_end = [0x3e,0x96,0x06,0x98,0xa8,0xa0,0x42,0x34,0x8a,0xfc,0x3e,0x96,0x06,0x98,0xa8,0xa0,0x42,0x34,0x8a,0xfc]
xor1 = [0xFC,0x3E,0x96,0x3E,0x98,0xA8,0xA0,0x42]

for i in range(10):
	print 'i=',i
	for j in range(8):
		print xor1[j]^file_end[i+j]
	print '===='
```
观察输出有如下一段：
```cpp
====
i= 9
0
0
0
56
0
0
0
0
====
```
这就验证了我们的猜想，只是flag.mp4的文件头的第4字节和我手头的MP4文件不同。根据file_end，从而我们得到了真正的`key3 = [0xFC,0x3E,0x96,0x06,0x98,0xA8,0xA0,0x42,0x34,0x8a]`

我们利用key3对flag.mp4进行解密：
```python
key3 = [0xFC,0x3E,0x96,0x06,0x98,0xA8,0xA0,0x42,0x34,0x8a]
i=0
fp = open(r'D:\flag.mp4','rb')
stream = list(fp.read())
fp.close()
out = []
for ch in stream:
	out.append(chr(ord(ch)^key3[i%10]))
	i += 1
out = ''.join(out)
fp = open(r'D:\flag_dec.mp4','wb')
fp.write(out)
fp.close()
```
打开解密后的视频：
![](20170215223622887.png)
嗯，flag：`hctf{L0ng_CSS_Seems_SHORT!}`


## 奇怪的代码

下载：http://pan.baidu.com/s/1nvjruXV 密码：3y72

题目描述：
> 部分思路来自：https://github.com/xoreaxeaxeax/movfuscator  ，但比这个要简单的多

首先看了上面那和github的网站，是一个混淆器，可以生成只含有mov指令的程序，作者是这样说的：

> The M/o/Vfuscator (short 'o', sounds like "mobfuscator") compiles programs into "mov" instructions, and only "mov" instructions. Arithmetic, comparisons, jumps, function calls, and everything else a program needs are all performed through mov operations; there is no self-modifying code, no transport-triggered calculation, and no other form of non-mov cheating.
>
> The basic effects of the process can be seen in overview, which illustates compiling a simple prime number function with gcc and the M/o/Vfuscator.

而这题只有一个函数是被混淆的。

首先ida载入，大致分析完了程序的流程：

main函数：

![](img_QndsbTdhbEtXdVJkblREbGZFN3NXRlVUcTZxTmNHNHhoVjRRcDFBWXpFREk5MVNyMkZxejJnPT0.png)

make_arr()生成数组：

![](img_QndsbTdhbEtXdVJkblREbGZFN3NXQnhvZzBqUGx5QTBvOEFKcW54M3hEd0J1cTVxYVduQlp3PT0.png)

check校验函数：

![](img_QndsbTdhbEtXdVJkblREbGZFN3NXSGJtdW1vWnh0L25nOWRKZFgrVGRLZnNKb1YwV05JUTJnPT0.png)

其中最主要的就是check函数了。

首先分析出了4种array里的数据所满足的关系：

arr1[x] = (x/256)^(x%256)
arr2[x] = x
arr3[x] = 256\*x
arr4[x] = 4\*x

由此可用python写出解密函数(不想仔细分析了，直接爆破)：

```python
def arr1(n):
    return (n//256)^(n%256)
def arr3(n):
    return 256*n
def arr4(n):
    return 4*n
def magic(n):
    num=[0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88]
    return num[n]
def decrypt(mag,enc_list):
    for i in range(256):
        enc1=arr1(arr3(mag)+i)
        if enc1 == enc_list[0]:
            for j in range(256):
                enc2 = arr1(arr3(enc1)+j)
                if enc2 == enc_list[1]:
                    for m in range(256):
                        enc3 = arr1(arr3(enc2)+m)
                        if enc3 == enc_list[2]:
                            for n in range(256):
                                enc4 = arr1(arr3(enc3)+n)
                                if enc4 == enc_list[3]:
                                    return chr(i)+chr(j)+chr(m)+chr(n)


flag_enc=[0x79,0x1E,0x7F,0x12,0x47,0x3C,0x55,0x26,0x6C,0x05,0x71,0x2E,0x2D,0x43,0x37,0x52,0x27,0x54,0x20,0x49,0x08,0x6F,0x30,0x44,0x18,0x47,0x2A,0x45,0xE7,0x91,0xAE,0xD3]
flag_dec=''
for grp in range(8):
    flag_dec+=decrypt(magic(grp),flag_enc[grp*4:(grp+1)*4])
print flag_dec
```

得到flag：`hgame{is_it_intersting_to_moov?}`