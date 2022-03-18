---
title:  HCTF GAME RE - JAVA系列
tags:
  - RE
  - CTF
  - HCTF GAME
date: 2017/3/1
---

这次HCTF GAME一共有三道java的逆向，都是z神出的。题目还是很基础的，但我作为一个java零基础的菜鸡，这些题目是够我做了。


## re?

下载：http://pan.baidu.com/s/1kUZjUB1 密码：u4uw

> hint:逆向不止是汇编

这其实就是一道代码审计题。

解压jar，得到图片`ctf.jpg`。用jd-gui.exe反编译，得到源码：

```java
package game;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main
{
  public static void main(String[] args)
    throws Exception
  {
    new Main().m();
  }

  private void m() throws Exception {
    System.out.print("Now give me flag: ");
    BufferedReader strin = new BufferedReader(new InputStreamReader(System.in));
    String flag = strin.readLine();
    InputStream is = getClass().getResourceAsStream("/game/ctf.jpg");
    int len = is.available();
    if (len < 20008) {
      throw new Exception("res error");
    }

    long r = 10000L;
    while (r != 0L) {
      r -= is.skip(r);
    }
    byte[] key = new byte[16];
    int l = 0;
    while (l != 16) {
      l += is.read(key, l, 16 - l);
    }

    r = 10000L;
    while (r != 0L) {
      r -= is.skip(r);
    }
    byte[] iv = new byte[16];
    l = 0;
    while (l != 16) {
      l += is.read(iv, l, 16 - l);
    }

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKeySpec skey = new SecretKeySpec(key, "AES");
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    cipher.init(1, skey, ivSpec);
    byte[] en = cipher.doFinal(flag.getBytes());
    byte[] tFlag = { 69, -101, 74, -127, -13, 110, 17, -103, 112, -111, -87, 87, 45, -110, 38, -11 };
    if (Arrays.equals(en, tFlag))
      System.out.println("hctf{" + flag + "}");
    else
      System.out.println("try again");
  }
}
```
看一下代码，就是一个简单的AES解密，用python写出解密函数：
```python
from Crypto.Cipher import AES
fp = open("ctf.jpg",'rb')
fp.read(10000)
key = fp.read(16)
fp.read(10000)
iv = fp.read(16)
fp.close()

mode = AES.MODE_CBC
aes_obj = AES.new(bytes(key),mode,bytes(iv))

flag_enc = [69, -101, 74, -127, -13, 110, 17, -103, 112, -111, -87, 87, 45, -110, 38, -11]
for i in range(len(flag_enc)):
	if flag_enc[i]<0:
		flag_enc[i]+=256
	flag_enc[i] = chr(flag_enc[i])
flag_enc = ''.join(flag_enc)

flag = aes_obj.decrypt(flag_enc)
print flag
```

得到：`AES_1s_b3TteR\0x03\0x03\0x03`

除去后面的padding并加上`hctf{}`得到flag：`hctf{AES_1s_b3TteR}`


## explorer的奇怪番外4

下载：http://pan.baidu.com/s/1eSh1HQE 密码：urap

> 这次我们继续玩java逆向(审计)。
> 当然这次的逆向(审计)就没有上次的那么简单了。首先你需要对java的classloader有一个了解才行。
> 话不多说，jar在此
> hint:好好学java 

老方法。先扔到jd-gui.exe里。

发现4个class：
`0CC175B9C0F1B6A831C399E269772661.class`
`B51E17DBDB36295E7AB7541157AE7480.class`
`Main.class`
`myClass.class`

jar里完整的源码我就不放了，看到两段：

```java
myClass mc = new myClass();
Class clazz = mc.loadClass("hgame2.checkFlag");
Method c = clazz.getMethod("trueMain", (Class[])null);
c.invoke(null, new Object[0]);
```

```java
try {
	res = res.substring(0, l + 1) + md5(className.getBytes()) + ".class";
} catch (NoSuchAlgorithmException e) {
	e.printStackTrace();
}
```

得知，以上加密的两个class的名字是原来名字的md5值，由代码知一个为 checkFlag ，MD5破解得另一
个为 a ，当然这不是重点。

分析myClass知，class中的内容使用AES加密的。

key的生成：
```java
private static String code = "explorer";
...
MessageDigest md = null;
try {
	md = MessageDigest.getInstance("MD5");
} catch (NoSuchAlgorithmException e) {
	e.printStackTrace();
}
assert (md != null);
md.update(code.getBytes());
byte[] key = md.digest();
```
iv:`String ivStr = "****************";`

python解密：
```python
from Crypto.Cipher import AES
import hashlib
enc1 = open("0CC175B9C0F1B6A831C399E269772661.class",'rb').read()
enc2 = open("B51E17DBDB36295E7AB7541157AE7480.class",'rb').read()
key = hashlib.md5('explorer').digest()
iv = '****************'

mode = AES.MODE_CBC
obj1 = AES.new(key,mode,iv)
obj2 = AES.new(key,mode,iv)
dec1= obj1.decrypt(enc1)
dec2= obj2.decrypt(enc2)

fp = open('dec_0CC175B9C0F1B6A831C399E269772661.class','wb')
fp.write(dec1)
fp.close()

fp = open('dec_B51E17DBDB36295E7AB7541157AE7480.class','wb')
fp.write(dec2)
fp.close()
```

此处提醒一下，key那里用的是digest()，我之前误把digest()写成了hexdigest()，结果解不出来。
举例：
md5 = hashlib.md5('adsf') 
md5.digest() //返回: '\x05\xc1*(s48l\x94\x13\x1a\xb8\xaa\x00\xd0\x8a' 
md5.hexdigest() //返回: '05c12a287334386c94131ab8aa00d08a' 

从而我们得到了两个解密后的class，把它们用压缩软件再塞回jar，再次用jd-gui打开jar，反编译出刚才解密的两个class的代码：

dec_0CC175B9C0F1B6A831C399E269772661.class:
```java
package hgame2;

import java.util.Arrays;

public class a
{
  public static boolean check(String flag)
  {
    byte[] var100 = flag.getBytes();

    byte[] var72 = new byte[var100.length + 2];
    System.arraycopy(var100, 0, var72, 0, var100.length);
    byte[] var140 = new byte[var72.length / 3 * 4];
    byte[] var82 = var140;
    int var17 = 0;
    int var18 = 0;

    while (var17 < var100.length) {
      var82[var18] = (byte)(var72[var17] >>> 2 & 0x3F);
      var82[(var18 + 1)] = (byte)(var72[(var17 + 1)] >>> 4 & 0xF | var72[var17] << 4 & 0x3F);
      var82[(var18 + 2)] = (byte)(var72[(var17 + 2)] >>> 6 & 0x3 | var72[(var17 + 1)] << 2 & 0x3F);
      var82[(var18 + 3)] = (byte)(var72[(var17 + 2)] & 0x3F);
      var17 += 3;
      var18 += 4;
    }
    var17 = 0;

    while (var17 < var82.length) {
      int var10000 = var82[var17];

      if (var10000 < 26) {
        var82[var17] = (byte)(var82[var17] + 65);
      }
      else {
        var10000 = var82[var17];
        byte var10001 = 52;

        if (var10000 < var10001) {
          var82[var17] = (byte)(var82[var17] + 97 - 26);
        }
        else {
          var10000 = var82[var17];
          var10001 = 62;

          if (var10000 < var10001) {
            var82[var17] = (byte)(var82[var17] + 48 - 52);
          }
          else {
            var10000 = var82[var17];
            var10001 = 63;

            if (var10000 < var10001) {
              var82[var17] = 43;
            }
            else {
              var140 = var82;
              int var136 = var17;
              var140[var136] = 47;
            }
          }
        }
      }
      var17++;
    }

    int var10000 = var82.length;
    byte var10001 = 1;
    var17 = var10000 - var10001;

    while (var17 > var100.length * 4 / 3) {
      var82[var17] = 61;
      var17--;
    }

    for (int i = 0; i < var82.length; i++) {
      var82[i] = (byte)(var82[i] ^ 0xCC);
    }

    byte[] f = { -107, -74, -118, -92, -81, -1, -126, -127, -127, -117, -118, -89, -106, -108, -122, -86, -127, -102, -126, -86, -127, -101, -7, -4, -106, -108, -123, -74, -81, -1, -98, -122, -82, -95, -81, -15 };
    return Arrays.equals(var82, f);
  }
}
```

dec_B51E17DBDB36295E7AB7541157AE7480.class:
```java
package hgame2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;

public class checkFlag
{
  public static void trueMain()
    throws IOException
  {
    System.out.print("Now give me flag: ");
    BufferedReader strin = new BufferedReader(new InputStreamReader(System.in));
    String flag = strin.readLine();
    if (a.check(flag))
      System.out.println("hctf{" + flag + "}");
    else
      System.out.println("try again");
  }
}
```

主要的算法在dec_0CC175B9C0F1B6A831C399E269772661.class中。首先是一个base64，应该能看出来，后边是一个简单的异或。

python解密：
```python
import base64
c=[-107, -74, -118, -92, -81, -1, -126, -127, -127, -117, -118, -89, -106, -108, -122, -86, -127, -102, -126, -86, -127, -101, -7, -4, -106, -108, -123, -74, -81, -1, -98, -122, -82, -95, -81, -15 ]
for i in range(len(c)):
	if c[i]<0:
		c[i]+=256
		c[i] ^= 0xCC
		c[i] = chr(c[i])
c = ''.join(c)
print 'hctf{'+base64.b64decode(c)+'}'
```
flag:`hctf{c1assL0ader_1S_1nter3stIng}`

## explorer的奇怪番外7

下载：http://pan.baidu.com/s/1gf7OdRP 密码：ma6u

> 这次我们继续玩java手机apk逆向。
> 所有，到底有没有人会安卓开发呢Orz 
> 话不多说，apk在此
> hint:好好学java&安卓代码 

工具用的jeb。安卓逆向，首先想到的是找找有没有字符串做参考，来到`values\strings.xml`，发现字段：
```xml
<string name="check_flag">
        check_flag</string>
<string name="enter_password">
        enter password</string>
```
挺好的，再来到`values\public.xml`，找到字段：
```xml
<public id="0x7f04001a" name="check_flag" type="layout" />
...
<public id="0x7f060015" name="check_flag" type="string" />
...
<public id="0x7f0c0054" name="check_flag" type="id" />

```
最后通过type为“id”的public id (2131492948)找到了相关的代码：
```java
protected void onCreate(Bundle arg3) {
        super.onCreate(arg3);
        this.setContentView(2130968602);
        this.editText = this.findViewById(2131492949);
        this.button = this.findViewById(2131492948);
        this.textView = this.findViewById(2131492950);
        this.button.setOnClickListener(new View$OnClickListener() {
            public void onClick(View arg11) {
                String v6 = checkFlag.this.editText.getText().toString();
                try {
                    MessageDigest v4 = MessageDigest.getInstance("MD5");
                    v4.update(v6.getBytes());
                    if(!Arrays.equals(v4.digest(), new byte[]{-73, 14, 42, 13, -123, 91, 77, -57, -79, -22, 52, -88, -87, -47, 3, 5})) {
                        return;
                    }

                    MessageDigest v7 = MessageDigest.getInstance("sha-256");
                    v7.update(v6.getBytes());
                    checkFlag.this.textView.setText("hctf{" + checkFlag.bytes2Hex(v7.digest()) + "}");
                }
                catch(NoSuchAlgorithmException v0) {
                    v0.printStackTrace();
                }
            }
        });
    }
```


代码的意思就是获取输入，对输入进行md5加密，加密结果和已知数据比较，如果想等，则对输入进行sha256加密，结果加上‘hctf{}’就是flag了。
得到flag_md5:`{-73, 14, 42, 13, -123, 91, 77, -57, -79, -22, 52, -88, -87, -47, 3, 5}`
把signed转换成unsigned再hex：
```python
enc = [-73, 14, 42, 13, -123, 91, 77, -57, -79, -22, 52, -88, -87, -47, 3, 5]

for i in range(len(enc)):
	enc[i] = chr(enc[i] % 256)

print ''.join(enc).encode('hex')
```
得到flag_md5:`b70e2a0d855b4dc7b1ea34a8a9d10305`

md5在线解密：http://www.md5online.org/

结果为：`Gabriel`

sha256加密得：`0c030df5a4e7477d218012c0121ebce6d61bb8dc46e0a6c4f8e1cc8091b946a5`

最后flag：`hctf{0c030df5a4e7477d218012c0121ebce6d61bb8dc46e0a6c4f8e1cc8091b946a5}`
