---
title: HCTF GAME RE - Windows礼包
tags:
  - RE
  - CTF
  - HCTF GAME
date: 2017/3/1
---

> 所谓逆向的过程就是不断学习新事物，不断积累的过程  可能你第一眼看到一种算法：woc，这是什么玩意？
> 但当你深思熟虑后会发现：这不是我之前看到过的xx加密的变种吗？ 可能你第一眼看到一种新的语言写的程序：woc，xx语言我不会。
> 但当你深思熟虑后会发现：这语言和之前的xx语言很类似啊
> 而这些都得靠积累：一是积累逆向工程实力(比如看汇编)，二是积累正向工程的能力(比如coding) 
> 希望大家能在逆向中学到如何快速学习新事物，以及如何整理现有的知识应对未知的挑战
>  
> 这次是一个windows专题，里面会涉及到一些和windows相关的知识点，也会涉及到部分coding。enjoy it
> 
> broken windows -> open windows -> security windows
> 


## Broken Windows

bin下载：http://pan.baidu.com/s/1jIhsNX0 密码：5pqh

![](20170202114645044.png)


先查一下壳，UPX的，拿工具脱一下或者手脱，用一下ESP定律脱也很快，这不是重点。

丢到IDA里面，定位到关键代码：

```cpp
DWORD __stdcall sub_401020(LPVOID lpThreadParameter)
{
  int v1; // eax@1
  int v2; // eax@1
  unsigned int v3; // eax@1
  int v4; // ecx@1

  v1 = encrypt((int)pt_input);
  v2 = encrypt(v1);
  encrypt(v2);
  v3 = 32;
  v4 = 0;
  while ( pt_input[v4] == flag_enc[v4] )
  {
    v3 -= 4;
    ++v4;
    if ( v3 < 4 )
    {
      MessageBoxA(0, Caption, Caption, 0);
      return 0;
    }
  }
  return 0;
}
```

```cpp
DWORD __stdcall sub_401160(LPVOID lpThreadParameter)
{
  encrypt((int)flag_enc);
  return 0;
}
```

```cpp
int __usercall sub_401080@<eax>(int pt_input@<edi>)
{
  int v1; // ebx@1
  signed int i; // esi@1
  int j; // eax@1
  char v4; // cl@3
  char v5; // cl@5
  char v6; // cl@5
  char v7; // dl@5
  char v8; // cl@7
  char v9; // cl@7
  char v10; // dl@7
  char v11; // cl@9
  char v12; // cl@9
  char v13; // dl@9
  char v14; // cl@11

  v1 = 1 - pt_input;
  i = 0;
  j = pt_input;
  while ( 1 )
  {
    v4 = __ROL1__(*(_BYTE *)j, 3);
    *(_BYTE *)j = v4;
    if ( i >= 1 )
      *(_BYTE *)j = v4 ^ *(_BYTE *)(i + pt_input - 1);
    v5 = __ROL1__(*(_BYTE *)j, 4);
    v6 = v5 + 3;
    v7 = __ROL1__(*(_BYTE *)(j + 1), 3);
    *(_BYTE *)j = v6;
    *(_BYTE *)(j + 1) = v7;
    if ( j + v1 >= 1 )
      *(_BYTE *)(j + 1) = v7 ^ v6;
    v8 = __ROL1__(*(_BYTE *)(j + 1), 4);
    v9 = v8 + 3;
    v10 = __ROL1__(*(_BYTE *)(j + 2), 3);
    *(_BYTE *)(j + 1) = v9;
    *(_BYTE *)(j + 2) = v10;
    if ( j + 2 - pt_input >= 1 )
      *(_BYTE *)(j + 2) = v10 ^ v9;
    v11 = __ROL1__(*(_BYTE *)(j + 2), 4);
    v12 = v11 + 3;
    v13 = __ROL1__(*(_BYTE *)(j + 3), 3);
    *(_BYTE *)(j + 2) = v12;
    *(_BYTE *)(j + 3) = v13;
    if ( j + 3 - pt_input >= 1 )
      *(_BYTE *)(j + 3) = v13 ^ v12;
    v14 = __ROL1__(*(_BYTE *)(j + 3), 4);
    *(_BYTE *)(j + 3) = v14 + 3;
    i += 4;
    j += 4;
    if ( i >= 32 )
      break;
    v1 = 1 - pt_input;
  }
  return pt_input + 1;
}
```
dump出的flag_enc：

```
0x68, 0x23, 0x51, 0x8d, 0xc8, 0xc9, 0x1f, 0x93,
0xf3, 0xfa, 0xff, 0x9e, 0x37, 0x77, 0x1b, 0x83,
0x81, 0x69, 0x6d, 0x46, 0x64, 0xcf, 0x4b, 0xad,
0x6a, 0xa8, 0xaa, 0xea, 0x41, 0x45, 0x7b, 0xab
```

我们分析encrypt函数，先大致梳理一遍：

```cpp
int __usercall encrypt@<eax>(int pt_input@<edi>)
{
	v1 = 1 - pt_input;
	i = 0;
	j = pt_input;
	while(1){
		v4 = rol(*j, 3);
		*j = v4;
		if (i >= 1){
			*j = v4 ^ pt_input[i-1];
		}
		v5 = rol(*j, 4);
		v6 = v5 + 3;
		v7 = rol(*(j+1), 3);
		*j = v6;
		*(j+1) = v7;
		*(j+1) = v7 ^ v6;
		v8 = rol(*(j+1), 4);
		v9 = v8 + 3;
		v10 = rol(*(j+2), 3);
		*(j+1) = v9;
		*(j+2) = v10;
		*(j+2) = v10 ^ v9;
		v11 = rol(*(j+2), 4);
		v12 = v11 + 3;
		v13 = rol(*(j+3), 3);
		*(j+2) = v12;
		*(j+3) = v13;
		*(j+3) = v13 ^ v12;
		v14 = rol(*(j+3), 4);
		*(j+3) = v14 + 3;
		i += 4;
		j += 4;
		if(i >= 32){
			break;
		}
	}
	return pt_input + 1;
}
```
再精简一下：

```cpp
int __usercall encrypt@<eax>(int pt_input@<edi>)
{
	v1 = 1 - pt_input;
	i = 0;
	j = pt_input;
	while(1){
		*j = rol(*j, 3);
		if (i >= 1){
			*j = *j ^ *(j-1);
		}
		*j = rol(*j, 4) + 3;

		*(j+1) = rol(*(j+1), 3) ^ *j;
		*(j+1) = rol(*(j+1), 4) + 3;

		*(j+2) = rol(*(j+2), 3) ^ *(j+1);
		*(j+2) = rol(*(j+2), 4) + 3;

		*(j+3) = rol(*(j+3), 3) ^ *(j+2);
		*(j+3) = rol(*(j+3), 4) + 3;
		
		i += 4;
		j += 4;
		if(i >= 32){
			break;
		}
	}
	return pt_input + 1;
}
```
由此逻辑就清楚了，他是4个为一组进行加密（其实还是一位一位加密），写出加密函数：

```cpp
unsigned char rol(unsigned char des,unsigned char mv){
	unsigned char ret;
	ret = (des << mv) | ((des << mv) >> 8);
	return ret;
}

unsigned char ror(unsigned char des,unsigned char mv){
	unsigned char ret;
	ret = (des >> mv) | ((des << 8) >> mv);
	return ret;
}

void encrypt(unsigned char * pt) {
	pt[0] = rol(pt[0], 7) + 3;
    for (int i = 1; i < 32; i++) {
	    pt[i] = rol(pt[i], 3) ^ pt[i-1];
	    pt[i] = rol(pt[i], 4) + 3;
	}
}
```
通过加密函数轻松写出解密函数：

```cpp
void decrypt(unsigned char *pt) {
	for (int i = 31; i > 0; i--) {
		pt[i] = ror(pt[i] - 3, 4);
		pt[i] = ror(pt[i] ^ pt[i - 1], 3);
	}
	pt[0] = ror(pt[0] - 3, 7);
}
```

完整的解密程序：

```cpp
#include <stdio.h>

unsigned char rol(unsigned char des, unsigned char mv);
unsigned char ror(unsigned char des, unsigned char mv);
void encrypt(unsigned char * pt);
void decrypt(unsigned char *pt);

unsigned char flag_enc[33] = {
	0x68, 0x23, 0x51, 0x8d, 0xc8, 0xc9, 0x1f, 0x93,
	0xf3, 0xfa, 0xff, 0x9e, 0x37, 0x77, 0x1b, 0x83,
	0x81, 0x69, 0x6d, 0x46, 0x64, 0xcf, 0x4b, 0xad,
	0x6a, 0xa8, 0xaa, 0xea, 0x41, 0x45, 0x7b, 0xab,
	0x00};

int main(void) {
	encrypt(flag_enc); 
	decrypt(flag_enc + 2); 
	decrypt(flag_enc + 1); 
	decrypt(flag_enc);
	for (int i = 0; i < 32; ++i){ 
		putchar(flag_enc[i]); 
	}
	getchar();
	return 0;
}

unsigned char rol(unsigned char des, unsigned char mv){
	unsigned char ret;
	ret = (des << mv) | ((des << mv) >> 8);
	return ret;
}

unsigned char ror(unsigned char des, unsigned char mv){
	unsigned char ret;
	ret = (des >> mv) | ((des << 8) >> mv);
	return ret;
}

void encrypt(unsigned char * pt) {
	pt[0] = rol(pt[0], 7) + 3;
	for (int i = 1; i < 32; i++) {
		pt[i] = rol(pt[i], 3) ^ pt[i - 1];
		pt[i] = rol(pt[i], 4) + 3;
	}
}

void decrypt(unsigned char *pt) {
	for (int i = 31; i > 0; i--) {
		pt[i] = ror(pt[i] - 3, 4);
		pt[i] = ror(pt[i] ^ pt[i - 1], 3);
	}
	pt[0] = ror(pt[0] - 3, 7);
}
```
最终的flag：hctf{do_you_have_broken_window?}

## Open Windows

bin下载：http://pan.baidu.com/s/1midkZCO 密码：b7f0

![](20170202141531604.png)



**（这题目前还有一些不明白的地方，先把大佬的wp扔上来）**

话不多说，直接上ida代码（已注释）
1. DialogProc
![](20170202142211458.png)
![](20170202142221317.png)
这里可以看出一点东西，1.程序对监听了每次按键，来看看msdn上关于WM_KEYUP的解释：https://msdn.microsoft.com/en-us/library/windows/desktop/ms646281(v=vs.85).aspx根据里面可以看出这个wParam是按键对应的virtual-key code

2.对每一次按键，有一个累加器和一个累乘器，同时对按键进行记录（图中sub_4012E0对应c++ vector的push_back，这里没看出来没什么关系）

3.最后在接受到程序退出的信号时，对整个输入进行校验，前提是累加器的值为771, 累乘器的值为0x63A421C737F6FFE0, 同时输入长度应该为10个字符，也就是对应十次按键

接下来来看check函数，动态一调就可以发现check的参数就是对应键盘输入的virtual-key code，还是ida：
![](20170202142452352.png)
好，现在又知道了一些信息：input长度为10,这个前面提到过，每个按键的virtual-key code应该是A-Zhttps://msdn.microsoft.com/en-us/library/windows/desktop/dd375731(v=vs.85).aspx这里可以看出A-Z就对应键盘的A-Z，这个没有问题。
先不看下去，其实知道上面这些信息后就可以推flag的每个字节了。

整理一下：
1.len(flag) == 10
2.for x in flag: x in A-Z
3.add all ord(x) in flag == 771
4.mul all ord(x) in flag == 0x63A421C737F6FFE0

这里可以直接爆破10个字节，不过恐怕得跑一天。
一个更好的方法：先分解0x63A421C737F6FFE0
![](20170202142602588.png)
83=0x53 = S
79=O
好，这3个字符就确定了，29(23)×2不对，x5也不对，那只能x3了
又确定两个87=W 69=E
好接下来只剩5个了，爆破走起

```python
mulsum = 0x63A421C737F6FFE0/83/83/87/69/79
addsum = 771-83*2-79-87-69

solve=[0,0,0,0,0]

for solve[0] in range(ord('A'),ord('Z')+1):
	for solve[1] in range(ord('A'),ord('Z')+1):
		for solve[2] in range(ord('A'),ord('Z')+1):
			for solve[3] in range(ord('A'),ord('Z')+1):
				for solve[4] in range(ord('A'),ord('Z')+1):
					add_tmp = 0
					mul_tmp = 1
					for x in solve:
						add_tmp += x
						mul_tmp *= x
					if addsum == add_tmp and mulsum == mul_tmp:
						print [chr(x) for x in solve]
```
脚本有重复输出，5个字符get：
['D', 'F', 'K', 'L', 'Q']
现在所有字符都拿到了：SSOWEDFKLQ 但不知道顺序

接下去看ida：
check_arr 是一个 16\*16的数组，存放的值为0和1，上面必要的代码我都注释了，大概就是flag的每一字节都和该字节后面所有字节做比较得出的结果再去和check_arr里存放的内容比对，即，该数组对应了一种flag
的顺序关系（已知每个flag位和其他flag位的大小关系，大于为1，其他情况为0），虽然check_arr大小为16\*16 ，但仔细看可以发现只用到了10\*10（才不是我把10写错成了0x10><)

![](20170202142946349.png)

可以看到check_arr第一列都是0，因为自己和自己比较永远是相等，所以check永远是0
那然后我们怎么做才能还原出顺序呢？
我们可以数啊 (
上面字符从小到大排好：

```python
a='SSOWEDFKLQ'
a=list(a)
list.sort(a)
''.join(a)
#result DEFKLOQSSW
```
check_arr 第一行4个1 即 比flag[0]小的有4个，flag[0] = s[4] = 'L'去掉L， DEFKOQSSW  第二行3个1：flag[1] = s[3] = 'K'。。。这样下去，最后可以得到flag，嫌麻烦的话写个脚本：

```python
check_count = [4,3,5,3,3,4,1,0,1,0]
a='SSOWEDFKLQ'

a=list(a)
list.sort(a)
flag=[]

for x in check_count:
	flag.append(a[x])
	a.remove(a[x])
	
print ''.join(flag)

#result: LKSOQWEDSF
```
flag就是 LKSOQWEDSF
打开程序手打测试成功


## Security Windows

bin下载：http://pan.baidu.com/s/1kUVf7UJ 密码：z2y7

![](20170202143332130.png)


没壳，先OD上跑跑熟悉一下，然后无情丢到IDA里：
定位关键函数（带注释）：

```cpp
BYTE *sub_401200()
{
  BYTE *result; // eax@1
  signed int i; // eax@2
  int _ch; // ecx@3
  char v3; // dl@3
  int v4; // ecx@3
  char v5; // dl@3
  int v6; // ecx@3
  signed int j; // eax@4
  char v8; // cl@5
  int v9; // eax@6
  char *v10; // ecx@6
  signed int k; // esi@6
  char v12; // dl@7
  signed int l; // eax@8
  int v14; // edx@9
  char v15; // cl@9
  int v16; // edx@9
  char v17; // cl@9
  int v18; // edx@9
  unsigned int v19; // edi@10
  void *v20; // esi@10
                                                // pt_input = 403420
  result = (BYTE *)strlen(pt_input_0);          // input length = 32
  if ( result == (BYTE *)32 )
  {
    i = 0;
    do
    {
      _ch = (unsigned __int8)pt_input_1[i];
      pt_input_0[i] = byte_4021D0[(unsigned __int8)pt_input_0[i]];
      v3 = byte_4021D0[_ch];
      v4 = (unsigned __int8)pt_input_2[i];
      pt_input_1[i] = v3;
      v5 = byte_4021D0[v4];
      v6 = (unsigned __int8)pt_input_3[i];
      pt_input_2[i] = v5;
      pt_input_3[i] = byte_4021D0[v6];
      i += 4;                                   // 4 bytes 一组
    }
    while ( i < 32 );                           // (变换1)从byte_4021D0[255]到pt_input 做字符映射
    j = 0;
    do
    {
      v8 = __ROL1__(pt_input_0[j], 4);          // (变换2)对每一位:ch = rol(ch,4) ^ 34
      pt_input_0[j++] = v8 ^ 34;
    }
    while ( j < 32 );
    v9 = 0;
    v10 = (char *)&pt_input_31;                 // v10为第32位(下标31)
    k = 16;
    do
    {
      v12 = *v10;
      *v10 = pt_input_0[v9];
      pt_input_0[v9++] = v12;
      --v10;
      --k;
    }
    while ( k );                                // (变换3)倒序重排
    l = 0;
    do
    {
      v14 = (unsigned __int8)pt_input_1[l];
      pt_input_0[l] = byte_4021D0[(unsigned __int8)pt_input_0[l]];
      v15 = byte_4021D0[v14];
      v16 = (unsigned __int8)pt_input_2[l];
      pt_input_1[l] = v15;
      v17 = byte_4021D0[v16];
      v18 = (unsigned __int8)pt_input_3[l];
      pt_input_2[l] = v17;
      pt_input_3[l] = byte_4021D0[v18];
      l += 4;
    }
    while ( l < 32 );                           // (变换4)从byte_4021D0[255]到pt_input 做第二次字符映射
    sub_401000();                               // (变换5)base64加密
    v19 = 43;                                   // 加密后43位
    v20 = &flag_enc;                            // 0x402154
    result = sub_401140();                      // (变换6)CryptEncrypt加密
    while ( *(_DWORD *)result == *(_DWORD *)v20 )
    {
      v19 -= 4;
      v20 = (char *)v20 + 4;
      result += 4;
      if ( v19 < 4 )
      {
        if ( *(_BYTE *)v20 == *result && *((_BYTE *)v20 + 1) == result[1] && *((_BYTE *)v20 + 2) == result[2] )
          result = (BYTE *)MessageBoxA(0, "You won!", "congratulation", 0);
        return result;
      }
    }
  }
  return result;
}
```

```cpp
BYTE *sub_401000()
{
  int v0; // esi@1
  signed int i; // ecx@1
  unsigned int j; // eax@1
  unsigned __int8 v3; // dl@3
  unsigned __int8 v4; // bl@3
  unsigned __int8 v5; // dl@4
  char v6; // si@5

  v0 = 1 - (_DWORD)pt_input_0;
  i = 0;
  j = 0;
  while ( 1 )                                   // 猜测 base64
  {
    v3 = 16 * (pt_input_0[i] & 3);              // v3 = 16 * (input[i] & 3)
    *(&des_0 + j) = asc_402188[(unsigned int)(unsigned __int8)pt_input_0[i] >> 2];// des[j+2] = asc[input[i] >> 2]
    v4 = v3;                                    // v4 = v3
    if ( (signed int)(&pt_input_0[v0] + i) >= 32 )// if(i+1 >= 32)
    {
      des_1[j] = asc_402188[v3];                // des[1+j] = asc[v3]
      des_2_3[j / 2] = '==';                    // des[j/2+2] = des[j/2+3] = 0x3D
      des_4[j] = 0;                             // des[j+4] = 0
      return &des_0;                            // << break && return
    }
    v5 = 4 * (pt_input_1[i] & 0xF);             // v5 = 4 * (input[1+i] & 0xF)
    des_1[j] = asc_402188[v4 | ((unsigned int)(unsigned __int8)pt_input_1[i] >> 4)];// des[j+1] = asc[v4 | input[1+i]>>4]
    if ( (signed int)(&pt_input_0[2 - (signed int)pt_input_0] + i) >= 32 )// if(i + 2 >= 32)
      break;
    v6 = pt_input_2[i];                         // v6 = input[2+i]
    LOBYTE(des_2_3[j / 2]) = asc_402188[v5 | ((unsigned int)(unsigned __int8)pt_input_2[i] >> 6)];// des[j/2 + 2] = asc[v5 | input[2+i] >> 6]
    *((_BYTE *)&des_3 + j) = asc_402188[v6 & 0x3F];// des[j+3] = asc[v6 & 0x3F]
    i += 3;                                     // i += 3
    j += 4;                                     // j += 4
    if ( i >= 32 )                              // if(i >= 32)
    {
      *(&des_0 + j) = 0;                        // des[j] = 0
      return &des_0;
    }
    v0 = 1 - (_DWORD)pt_input_0;
  }
  LOBYTE(des_2_3[j / 2]) = asc_402188[v5];      // des[j/2 + 2] = asc[v5]
  *(_WORD *)((char *)&des_3 + j) = '=';         // des[j+3] = 0x3D
  return &des_0;
}
```

```cpp
BYTE *sub_401140()
{
  DWORD pdwDataLen; // [sp+0h] [bp-10h]@1
  HCRYPTKEY phKey; // [sp+4h] [bp-Ch]@1
  HCRYPTPROV phProv; // [sp+8h] [bp-8h]@1
  HCRYPTHASH phHash; // [sp+Ch] [bp-4h]@1

  CryptAcquireContextA(&phProv, 0, "Microsoft Base Cryptographic Provider v1.0", 1u, 0xF0000000);
  CryptCreateHash(phProv, 0x8003u, 0, 0, &phHash);
  CryptHashData(phHash, pbData, strlen((const char *)pbData), 0);// pbData = 'vidar_aaa'
  CryptDeriveKey(phProv, 0x6801u, phHash, 0, &phKey);
  pdwDataLen = 44;
  CryptEncrypt(phKey, 0, 1, 0, &des_0, &pdwDataLen, 0x2Cu);
  CryptDestroyKey(phKey);
  CryptDestroyHash(phHash);
  CryptReleaseContext(phProv, 0);
  return &des_0;
}
```
dump出的flag_enc：

```
0xAF,0xA5,0x92,0x3C,0x0C,0xB1,0x1C,0x33,0x56,0x66,0x3F,
0x37,0x17,0x3E,0x2A,0xE0,0xFF,0xE9,0x97,0x29,0xEC,0x76,
0x85,0xF8,0xA7,0x5F,0x85,0xCB,0x7B,0x42,0xC9,0x04,0xCB,
0x9D,0x12,0x58,0x2D,0x25,0xA4,0xB0,0xC7,0x0F,0xB9,0xE0
```
dump出的byte_4021D0[255]：

```
0x07,0x0E,0x15,0x1C,0x23,0x2A,0x31,0x38,0x3F,0x46,
0x4D,0x54,0x5B,0x62,0x69,0x70,0x77,0x7E,0x85,0x8C,
0x93,0x9A,0xA1,0xA8,0xAF,0xB6,0xBD,0xC4,0xCB,0xD2,
0xD9,0xE0,0xE7,0xEE,0xF5,0xFC,0x03,0x0A,0x11,0x18,
0x1F,0x26,0x2D,0x34,0x3B,0x42,0x49,0x50,0x57,0x5E,
0x65,0x6C,0x73,0x7A,0x81,0x88,0x8F,0x96,0x9D,0xA4,
0xAB,0xB2,0xB9,0xC0,0xC7,0xCE,0xD5,0xDC,0xE3,0xEA,
0xF1,0xF8,0xFF,0x06,0x0D,0x14,0x1B,0x22,0x29,0x30,
0x37,0x3E,0x45,0x4C,0x53,0x5A,0x61,0x68,0x6F,0x76,
0x7D,0x84,0x8B,0x92,0x99,0xA0,0xA7,0xAE,0xB5,0xBC,
0xC3,0xCA,0xD1,0xD8,0xDF,0xE6,0xED,0xF4,0xFB,0x02,
0x09,0x10,0x17,0x1E,0x25,0x2C,0x33,0x3A,0x41,0x48,
0x4F,0x56,0x5D,0x64,0x6B,0x72,0x79,0x80,0x87,0x8E,
0x95,0x9C,0xA3,0xAA,0xB1,0xB8,0xBF,0xC6,0xCD,0xD4,
0xDB,0xE2,0xE9,0xF0,0xF7,0xFE,0x05,0x0C,0x13,0x1A,
0x21,0x28,0x2F,0x36,0x3D,0x44,0x4B,0x52,0x59,0x60,
0x67,0x6E,0x75,0x7C,0x83,0x8A,0x91,0x98,0x9F,0xA6,
0xAD,0xB4,0xBB,0xC2,0xC9,0xD0,0xD7,0xDE,0xE5,0xEC,
0xF3,0xFA,0x01,0x08,0x0F,0x16,0x1D,0x24,0x2B,0x32,
0x39,0x40,0x47,0x4E,0x55,0x5C,0x63,0x6A,0x71,0x78,
0x7F,0x86,0x8D,0x94,0x9B,0xA2,0xA9,0xB0,0xB7,0xBE,
0xC5,0xCC,0xD3,0xDA,0xE1,0xE8,0xEF,0xF6,0xFD,0x04,
0x0B,0x12,0x19,0x20,0x27,0x2E,0x35,0x3C,0x43,0x4A,
0x51,0x58,0x5F,0x66,0x6D,0x74,0x7B,0x82,0x89,0x90,
0x97,0x9E,0xA5,0xAC,0xB3,0xBA,0xC1,0xC8,0xCF,0xD6,
0xDD,0xE4,0xEB,0xF2,0xF9
```
dump出的asc_402188字符串：“ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/”


解密就是加密的反函数，加密的最后一步是调用CryptEncrypt，所以我们调用CryptDecrypt将flag_enc解密第一层，由于我此时并不会使用上面的一系列函数，所以我可以通过OD修改原程序，使他调用CryptDecrypt来解密flag_enc。
查询
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379913(v=vs.85).aspx
和
https://msdn.microsoft.com/en-us/library/windows/desktop/aa379924(v=vs.85).aspx
得：

```cpp
BOOL WINAPI CryptDecrypt(
  _In_    HCRYPTKEY  hKey,
  _In_    HCRYPTHASH hHash,
  _In_    BOOL       Final,
  _In_    DWORD      dwFlags,
  _Inout_ BYTE       *pbData,
  _Inout_ DWORD      *pdwDataLen
);
```

```cpp
BOOL WINAPI CryptEncrypt(
  _In_    HCRYPTKEY  hKey,
  _In_    HCRYPTHASH hHash,
  _In_    BOOL       Final,
  _In_    DWORD      dwFlags,
  _Inout_ BYTE       *pbData,
  _Inout_ DWORD      *pdwDataLen,
  _In_    DWORD      dwBufLen
);
```
我们这样修改程序：
![](20170202145934425.png)

并在合适时机把flag_enc写入0x004033DC：

![](20170202150305801.png)


接着跑完这段代码，flag_enc成功解密(第6层)：
![](20170202150419145.png)

flag_enc_5:DHreXw4Zeh0gT9LiVdL1Hd4OHRAZHdJV0skgweIgT8k=

由于之前做过base64相关的re，看的还是比较准的，直接base64解密（第5层）：

flag_enc_4：

```
0x0c,0x7a,0xde,0x5f,0x0e,0x19,0x7a,0x1d,
0x20,0x4f,0xd2,0xe2,0x55,0xd2,0xf5,0x1d,
0xde,0x0e,0x1d,0x10,0x19,0x1d,0xd2,0x55,
0xd2,0xc9,0x20,0xc1,0xe2,0x20,0x4f,0xc9
```

第4层直接用py搞定（第4层）：

```python
a=[
0x07,0x0E,0x15,0x1C,0x23,0x2A,0x31,0x38,0x3F,0x46,
0x4D,0x54,0x5B,0x62,0x69,0x70,0x77,0x7E,0x85,0x8C,
0x93,0x9A,0xA1,0xA8,0xAF,0xB6,0xBD,0xC4,0xCB,0xD2,
0xD9,0xE0,0xE7,0xEE,0xF5,0xFC,0x03,0x0A,0x11,0x18,
0x1F,0x26,0x2D,0x34,0x3B,0x42,0x49,0x50,0x57,0x5E,
0x65,0x6C,0x73,0x7A,0x81,0x88,0x8F,0x96,0x9D,0xA4,
0xAB,0xB2,0xB9,0xC0,0xC7,0xCE,0xD5,0xDC,0xE3,0xEA,
0xF1,0xF8,0xFF,0x06,0x0D,0x14,0x1B,0x22,0x29,0x30,
0x37,0x3E,0x45,0x4C,0x53,0x5A,0x61,0x68,0x6F,0x76,
0x7D,0x84,0x8B,0x92,0x99,0xA0,0xA7,0xAE,0xB5,0xBC,
0xC3,0xCA,0xD1,0xD8,0xDF,0xE6,0xED,0xF4,0xFB,0x02,
0x09,0x10,0x17,0x1E,0x25,0x2C,0x33,0x3A,0x41,0x48,
0x4F,0x56,0x5D,0x64,0x6B,0x72,0x79,0x80,0x87,0x8E,
0x95,0x9C,0xA3,0xAA,0xB1,0xB8,0xBF,0xC6,0xCD,0xD4,
0xDB,0xE2,0xE9,0xF0,0xF7,0xFE,0x05,0x0C,0x13,0x1A,
0x21,0x28,0x2F,0x36,0x3D,0x44,0x4B,0x52,0x59,0x60,
0x67,0x6E,0x75,0x7C,0x83,0x8A,0x91,0x98,0x9F,0xA6,
0xAD,0xB4,0xBB,0xC2,0xC9,0xD0,0xD7,0xDE,0xE5,0xEC,
0xF3,0xFA,0x01,0x08,0x0F,0x16,0x1D,0x24,0x2B,0x32,
0x39,0x40,0x47,0x4E,0x55,0x5C,0x63,0x6A,0x71,0x78,
0x7F,0x86,0x8D,0x94,0x9B,0xA2,0xA9,0xB0,0xB7,0xBE,
0xC5,0xCC,0xD3,0xDA,0xE1,0xE8,0xEF,0xF6,0xFD,0x04,
0x0B,0x12,0x19,0x20,0x27,0x2E,0x35,0x3C,0x43,0x4A,
0x51,0x58,0x5F,0x66,0x6D,0x74,0x7B,0x82,0x89,0x90,
0x97,0x9E,0xA5,0xAC,0xB3,0xBA,0xC1,0xC8,0xCF,0xD6,
0xDD,0xE4,0xEB,0xF2,0xF9]
b=[
0x0c,0x7a,0xde,0x5f,0x0e,0x19,0x7a,0x1d,
0x20,0x4f,0xd2,0xe2,0x55,0xd2,0xf5,0x1d,
0xde,0x0e,0x1d,0x10,0x19,0x1d,0xd2,0x55,
0xd2,0xc9,0x20,0xc1,0xe2,0x20,0x4f,0xc9]

for chb in b:
    for i in range(len(a)):
        if a[i] == chb :
            print(i+1,end = ',')
```

得到flag_enc_3:

```
148,54,178,233,2,223,54,187,224,121,30,142,195,30,35,187,178,2,187,112,223,187,30,195,30,175,224,247,142,224,121,175
```



数组倒序（第3层），继续py：

```python
a=[148,54,178,233,2,223,54,187,224,121,30,142,195,30,35,187,178,2,187,112,223,187,30,195,30,175,224,247,142,224,121,175]

for i in reversed(range(len(a))):
    print(a[i],end=',')
```

得到flag_enc_2：

```
175,121,224,142,247,224,175,30,195,30,187,223,112,187,2,178,187,35,30,195,142,30,121,224,187,54,223,2,233,178,54,148
```

第2层和第1层由于计算量不大，我直接一位一位用的爆破，py:

```python
a=[
0x07,0x0E,0x15,0x1C,0x23,0x2A,0x31,0x38,0x3F,0x46,
0x4D,0x54,0x5B,0x62,0x69,0x70,0x77,0x7E,0x85,0x8C,
0x93,0x9A,0xA1,0xA8,0xAF,0xB6,0xBD,0xC4,0xCB,0xD2,
0xD9,0xE0,0xE7,0xEE,0xF5,0xFC,0x03,0x0A,0x11,0x18,
0x1F,0x26,0x2D,0x34,0x3B,0x42,0x49,0x50,0x57,0x5E,
0x65,0x6C,0x73,0x7A,0x81,0x88,0x8F,0x96,0x9D,0xA4,
0xAB,0xB2,0xB9,0xC0,0xC7,0xCE,0xD5,0xDC,0xE3,0xEA,
0xF1,0xF8,0xFF,0x06,0x0D,0x14,0x1B,0x22,0x29,0x30,
0x37,0x3E,0x45,0x4C,0x53,0x5A,0x61,0x68,0x6F,0x76,
0x7D,0x84,0x8B,0x92,0x99,0xA0,0xA7,0xAE,0xB5,0xBC,
0xC3,0xCA,0xD1,0xD8,0xDF,0xE6,0xED,0xF4,0xFB,0x02,
0x09,0x10,0x17,0x1E,0x25,0x2C,0x33,0x3A,0x41,0x48,
0x4F,0x56,0x5D,0x64,0x6B,0x72,0x79,0x80,0x87,0x8E,
0x95,0x9C,0xA3,0xAA,0xB1,0xB8,0xBF,0xC6,0xCD,0xD4,
0xDB,0xE2,0xE9,0xF0,0xF7,0xFE,0x05,0x0C,0x13,0x1A,
0x21,0x28,0x2F,0x36,0x3D,0x44,0x4B,0x52,0x59,0x60,
0x67,0x6E,0x75,0x7C,0x83,0x8A,0x91,0x98,0x9F,0xA6,
0xAD,0xB4,0xBB,0xC2,0xC9,0xD0,0xD7,0xDE,0xE5,0xEC,
0xF3,0xFA,0x01,0x08,0x0F,0x16,0x1D,0x24,0x2B,0x32,
0x39,0x40,0x47,0x4E,0x55,0x5C,0x63,0x6A,0x71,0x78,
0x7F,0x86,0x8D,0x94,0x9B,0xA2,0xA9,0xB0,0xB7,0xBE,
0xC5,0xCC,0xD3,0xDA,0xE1,0xE8,0xEF,0xF6,0xFD,0x04,
0x0B,0x12,0x19,0x20,0x27,0x2E,0x35,0x3C,0x43,0x4A,
0x51,0x58,0x5F,0x66,0x6D,0x74,0x7B,0x82,0x89,0x90,
0x97,0x9E,0xA5,0xAC,0xB3,0xBA,0xC1,0xC8,0xCF,0xD6,
0xDD,0xE4,0xEB,0xF2,0xF9]


b=[175,121,224,142,247,224,175,30,195,30,187,223,
112,187,2,178,187,35,30,195,142,30,121,224,187,54,
223,2,233,178,54,148]

def rol(d,m):
	return (((d<<m)%255) or (d<<m>>8))

for j in range(len(b)):
    for i in range(30,128):
        if rol(a[i],4)^34 == b[j]:
            print chr(i+1),
```

得到flag_dec：

```
hctf{there_is_no_perfect_window}
```