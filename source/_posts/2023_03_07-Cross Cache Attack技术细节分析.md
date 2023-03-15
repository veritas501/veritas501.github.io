---
title: Cross Cache Attack技术细节分析
tags:
  - kernel
date: 2023/3/7
---


关于cross page attack攻击的手法，在[安全客上的这篇文章](https://www.anquanke.com/post/id/285919#h2-2)和[CVE-2022-29582的这篇博客](https://ruia-ruia.github.io/2022/08/05/CVE-2022-29582-io-uring/#how-to-free-a-page)中说的比较详细，我也是在这两篇文章的基础上加入自己的理解。



首先，当我们调用`kfree()`时会经过如下的路径，简单过一下这个路径，因为这不太重要。

```
kfree() / kmem_cache_free()
slab_free()
do_slab_free()
__slab_free()
```

在kfree中，会先用`virt_to_head_page()`取出page，判断下这个page是不是slab page，这是page的一个属性。多数情况下，得到page是slab page，从而跳过4202-4211行，调用`slab_free()`。

```c
// >>> mm/slub.c:4191
/* 4191 */ void kfree(const void *x)
/* 4192 */ {
/* 4193 */ 	struct page *page;
/* 4194 */ 	void *object = (void *)x;
------
/* 4201 */ 	page = virt_to_head_page(x);
/* 4202 */ 	if (unlikely(!PageSlab(page))) {
------
/* 4210 */ 		return;
/* 4211 */ 	}
/* 4212 */ 	slab_free(page->slab_cache, page, object, NULL, 1, _RET_IP_);
```

`slab_free()`是`do_slab_free()`的包装，没啥好说。

```c
// >>> mm/slub.c:3160
/* 3160 */ static __always_inline void slab_free(struct kmem_cache *s, struct page *page,
/* 3161 */ 				      void *head, void *tail, int cnt,
/* 3162 */ 				      unsigned long addr)
/* 3163 */ {
------
/* 3168 */ 	if (slab_free_freelist_hook(s, &head, &tail))
/* 3169 */ 		do_slab_free(s, page, head, tail, cnt, addr);
```

`do_slab_free()`开始有点重要了，正如注释中所说，它是kfree的fastpath，所以开启了`__always_inline`确保运行速度。fastpath干的事情很简单，判断下当前要释放的object所在的page是不是当前cpu的active page，如果是，直接设置freelist pointer；否则，fallback到slowpath，即`__slab_free()`。

```c
// >>> mm/slub.c:3101
/* 3101 */ /*
/* 3102 */  * Fastpath with forced inlining to produce a kfree and kmem_cache_free that
/* 3103 */  * can perform fastpath freeing without additional function calls.
/* 3104 */  *
/* 3105 */  * The fastpath is only possible if we are freeing to the current cpu slab
/* 3106 */  * of this processor. This typically the case if we have just allocated
/* 3107 */  * the item before.
/* 3108 */  *
/* 3109 */  * If fastpath is not possible then fall back to __slab_free where we deal
/* 3110 */  * with all sorts of special processing.
/* 3111 */  *
/* 3112 */  * Bulk free of a freelist with several objects (all pointing to the
/* 3113 */  * same page) possible by specifying head and tail ptr, plus objects
/* 3114 */  * count (cnt). Bulk free indicated by tail pointer being set.
/* 3115 */  */
/* 3116 */ static __always_inline void do_slab_free(struct kmem_cache *s,
/* 3117 */ 				struct page *page, void *head, void *tail,
/* 3118 */ 				int cnt, unsigned long addr)
/* 3119 */ {
------
/* 3121 */ 	struct kmem_cache_cpu *c;
------
/* 3134 */ 		c = raw_cpu_ptr(s->cpu_slab);
------
/* 3141 */ 	if (likely(page == c->page)) {
/* 3142 */ 		void **freelist = READ_ONCE(c->freelist);
/* 3143 */ 
/* 3144 */ 		set_freepointer(s, tail_obj, freelist);
------
/* 3155 */ 	} else
/* 3156 */ 		__slab_free(s, page, head, tail_obj, cnt, addr);
```

在`do_slab_free()`中，我们第一次接触到这个很重要的结构体`struct kmem_cache_cpu`。它以指针的形式存在于结构体`struct kmem_cache`中。可以看到`cpu_slab`前面有`__percpu`参数，即每个CPU都有一个`cpu_slab`结构体。`kmem_cache_cpu`中的page就是我们常说的active page，freelist就是这个active page中的freelist。`partial`中存放的是非满的page。

```c
// >>> include/linux/slub_def.h:43
/* 43 */ struct kmem_cache_cpu {
/* 44 */ 	void **freelist;	/* Pointer to next available object */
/* 45 */ 	unsigned long tid;	/* Globally unique transaction id */
/* 46 */ 	struct page *page;	/* The slab from which we are allocating */
/* 47 */ #ifdef CONFIG_SLUB_CPU_PARTIAL
/* 48 */ 	struct page *partial;	/* Partially allocated frozen slabs */
/* 49 */ #endif
-------
/* 53 */ };

// >>> include/linux/slub_def.h:84
/*  84 */ struct kmem_cache {
/*  85 */ 	struct kmem_cache_cpu __percpu *cpu_slab;
/*  86 */ 	/* Used for retrieving partial slabs, etc. */
/*  87 */ 	slab_flags_t flags;
/*  88 */ 	unsigned long min_partial;
/*  89 */ 	unsigned int size;	/* The size of an object including metadata */
/*  90 */ 	unsigned int object_size;/* The size of an object without metadata */
/*  91 */ 	struct reciprocal_value reciprocal_size;
/*  92 */ 	unsigned int offset;	/* Free pointer offset */
/*  93 */ #ifdef CONFIG_SLUB_CPU_PARTIAL
/*  94 */ 	/* Number of per cpu partial objects to keep around */
/*  95 */ 	unsigned int cpu_partial;
/*  96 */ #endif
------
/* 136 */ };
```



当我们想做cross page attack时，其实就是想知道如何才能把目标slab的page释放掉。这在代码中由函数`discard_slab()`来完成（内部调用`free_slab()`，再调用`__free_slab()`，最后调用`__free_pages()`）。



从`__slab_free()`开始到`discard_slab()` 的调用链如下：

![](image-20230306162459082.png)

首先，程序会判断当前释放object所在的page是否是active slab或是否已经在partial list中，如果是就会直接free 这个object（加入freelist等操作），否则才会调用到`put_cpu_partial()`，这段逻辑在`__slab_free()`中，看起来有点复杂，**但其实归纳起来就是，只有一个非active的满page尝试释放其中的一个object时才会进入`put_cpu_partial()`。（需要多思考两遍）**

```c
// >>> mm/slub.c:2984
/* 2984 */ static void __slab_free(struct kmem_cache *s, struct page *page,
/* 2985 */ 			void *head, void *tail, int cnt,
/* 2986 */ 			unsigned long addr)
/* 2987 */ 
/* 2988 */ {
------
/* 3005 */ 	do {
------
/* 3010 */ 		prior = page->freelist;
/* 3011 */ 		counters = page->counters;
/* 3012 */ 		set_freepointer(s, tail, prior);
    			// frozen和counters是union关系，这一步就设置了new.frozen
/* 3013 */ 		new.counters = counters;
    			// frozen是指page在partial list中
/* 3014 */ 		was_frozen = new.frozen;
/* 3015 */ 		new.inuse -= cnt; // page中多少个object在被使用
    			// 如果当前page为满状态，则没有freelist，所以prior == NULL，
    			// 且因为是满状态，所以也不在partial中，因此 was_frozen == 0
/* 3016 */ 		if ((!new.inuse || !prior) && !was_frozen) {
/* 3017 */ 
    				// !prior 是说之前没有freeslit，即page为满状态
/* 3018 */ 			if (kmem_cache_has_cpu_partial(s) && !prior) { 
------
/* 3026 */ 				new.frozen = 1; // 得走到这里
------
    		// 简单理解成一个原子的交换，默认就会break出来
/* 3044 */ 	} while (!cmpxchg_double_slab(s, page,
/* 3045 */ 		prior, counters,
/* 3046 */ 		head, new.counters,
/* 3047 */ 		"__slab_free"));
------
    		// 正常就是NULL
/* 3049 */ 	if (likely(!n)) {
/* 3050 */ 
    			// 如果page之前就在was_frozen中会走这里
/* 3051 */ 		if (likely(was_frozen)) {
------
    			// 之前是满状态，需要新加到partial list中，走这里
/* 3057 */ 		} else if (new.frozen) {
------
    				// 调用目标函数， put_cpu_partial()
/* 3062 */ 			put_cpu_partial(s, page, 1); // <--- 目标！
```



进入`put_cpu_partial()` 后有两条路径，判断条件是当前partial list中的pobjects个数是否超过了阈值，如果没有超过，则直接将目标page加入到cpu的partial list中并刷新partial list的各个参数即可；否则需要调用目标函数`unfreeze_partials()`将当前CPU的partial链表中的page转移到Node管理的partial链表尾部。

```c
// >>> mm/slub.c:2389
/* 2389 */ static void put_cpu_partial(struct kmem_cache *s, struct page *page, int drain)
/* 2390 */ {
/* 2391 */ #ifdef CONFIG_SLUB_CPU_PARTIAL
/* 2392 */ 	struct page *oldpage;
/* 2393 */ 	int pages;
/* 2394 */ 	int pobjects;
/* 2395 */ 
/* 2396 */ 	preempt_disable();
/* 2397 */ 	do {
/* 2398 */ 		pages = 0;
/* 2399 */ 		pobjects = 0;
/* 2400 */ 		oldpage = this_cpu_read(s->cpu_slab->partial);
/* 2401 */ 
/* 2402 */ 		if (oldpage) {
/* 2403 */ 			pobjects = oldpage->pobjects;
/* 2404 */ 			pages = oldpage->pages;
    				// partial list 是否满了，如果满了，走下面if中的逻辑
    				// pobjects 为当前的partial链表中free object的count，后者为count的阈值
					// #define slub_cpu_partial(s)		((s)->cpu_partial)
/* 2405 */ 			if (drain && pobjects > slub_cpu_partial(s)) {
/* 2406 */ 				unsigned long flags;
------
/* 2411 */ 				local_irq_save(flags);
    					// 调用目标函数 unfreeze_partials()
/* 2412 */ 				unfreeze_partials(s, this_cpu_ptr(s->cpu_slab)); // <--- 目标！
------
/* 2419 */ 		}
/* 2420 */ 
    			// 正常逻辑，将目标page加入partial list中
/* 2421 */ 		pages++;
/* 2422 */ 		pobjects += page->objects - page->inuse;
/* 2423 */ 
/* 2424 */ 		page->pages = pages;
/* 2425 */ 		page->pobjects = pobjects;
/* 2426 */ 		page->next = oldpage;
```

> PS，上面这个代码是基于5.13的。
>
> 可以看到5.13中`pobjects += page->objects - page->inuse;`也就是说partial算的是objects的个数。
>
> 但在新版内核（5.16开始）中改成了这样：
>
> ```c
> static void put_cpu_partial(struct kmem_cache *s, struct page *page, int drain)
> {
> 	struct page *oldpage;
> 	struct page *page_to_unfreeze = NULL;
> 	unsigned long flags;
> 	int pages = 0;
> [......]
> 	oldpage = this_cpu_read(s->cpu_slab->partial);
> 
> 	if (oldpage) {
> 		if (drain && oldpage->pages >= s->cpu_partial_pages) {
> [......]
> 			page_to_unfreeze = oldpage;
> 			oldpage = NULL;
> 		} else {
> 			pages = oldpage->pages;
> 		}
> 	}
> 
> 	pages++; // +1
> 
> 	page->pages = pages;
> 	page->next = oldpage;
> [......]
> }
> ```
>
> 从而partial计算的是page的个数。
>
> 不过这貌似也不是说前者有啥BUG，毕竟我们前面讨论过，`put_cpu_partial()`只有在满状态page想释放object的时候才会进入，那么`page->objects - page->inuse`基本也是1了。

最后一步，`unfreeze_partials()`会将当前CPU的partial链表中的非空的page转移到Node管理的partial链表尾部。对于那些空的page，会调用`discard_slab()`进行释放，这也是我们做cross page attack的目的所在。

```c
// >>> mm/slub.c:2321
/* 2321 */ static void unfreeze_partials(struct kmem_cache *s,
/* 2322 */ 		struct kmem_cache_cpu *c)
/* 2323 */ {
/* 2324 */ #ifdef CONFIG_SLUB_CPU_PARTIAL
/* 2325 */ 	struct kmem_cache_node *n = NULL, *n2 = NULL;
/* 2326 */ 	struct page *page, *discard_page = NULL;
/* 2327 */ 
/* 2328 */ 	while ((page = slub_percpu_partial(c))) {
/* 2329 */ 		struct page new;
/* 2330 */ 		struct page old;
/* 2331 */ 
/* 2332 */ 		slub_set_percpu_partial(c, page);
------
/* 2343 */ 		do {
/* 2344 */ 
/* 2345 */ 			old.freelist = page->freelist;
/* 2346 */ 			old.counters = page->counters;
/* 2347 */ 			VM_BUG_ON(!old.frozen);
/* 2348 */ 
/* 2349 */ 			new.counters = old.counters;
/* 2350 */ 			new.freelist = old.freelist;
/* 2351 */ 
/* 2352 */ 			new.frozen = 0;
/* 2353 */ 
/* 2354 */ 		} while (!__cmpxchg_double_slab(s, page,
/* 2355 */ 				old.freelist, old.counters,
/* 2356 */ 				new.freelist, new.counters,
/* 2357 */ 				"unfreezing slab"));
/* 2358 */ 
    			// 当前page为空，且node的partial数不小于最小值（一般都满足）
    			// 就会将此page加入到discard page的列表中
/* 2359 */ 		if (unlikely(!new.inuse && n->nr_partial >= s->min_partial)) {
/* 2360 */ 			page->next = discard_page;
/* 2361 */ 			discard_page = page;
/* 2362 */ 		} else {
/* 2363 */ 			add_partial(n, page, DEACTIVATE_TO_TAIL);
/* 2364 */ 			stat(s, FREE_ADD_PARTIAL);
/* 2365 */ 		}
/* 2366 */ 	}
------
    		// 将discard page列表中的page依次通过discard_slab()释放
/* 2371 */ 	while (discard_page) {
/* 2372 */ 		page = discard_page;
/* 2373 */ 		discard_page = discard_page->next;
/* 2374 */ 
/* 2375 */ 		stat(s, DEACTIVATE_EMPTY);
/* 2376 */ 		discard_slab(s, page);
/* 2377 */ 		stat(s, FREE_SLAB);
/* 2378 */ 	}
/* 2379 */ #endif	/* CONFIG_SLUB_CPU_PARTIAL */
/* 2380 */ }
```



综上这么一通分析，如果想释放一个slab page，我们需要这样做：

1. 查看基本信息

```
admin@vm:~$ sudo cat /sys/kernel/slab/filp/object_size # 每个object的大小
256
admin@vm:~$ sudo cat /sys/kernel/slab/filp/objs_per_slab # 每个slab中可容纳多少object
16
admin@vm:~$ sudo cat /sys/kernel/slab/filp/cpu_partial # cpu partial list最大阈值
13
```

2. 堆喷，收拾目标cache在kernel中的内存碎片
3. 申请`(cpu_partial + 1) * objs_per_slab = (13 + 1) * 16`个object

在极少数情况下，这些object会正好放在14个slab中；由于多数情况下在申请object前，多多少少会有几个object已经占用了一个slab，因此我们的object会分布于15个slab中，且第15个slab**非满**。下面我们就不进行分类讨论了，只画多数情况时的图（其实也只是细节上的出入）

![](image-20230307101148982.png)

4. 申请`objs_per_slab - 1 = 15`个object

为什么是`objs_per_slab - 1`呢？因为这样能保证之前未满的第15个slab必满，且多出来的object不会导致第16个slab满。

![](image-20230307101639174.png)

5. 申请一个漏洞object，后续用来UAF

6. 申请`objs_per_slab + 1 = 16`个object

这样就会让之前半满的第16个slab变成全满状态，并制造出第17个slab。

![](image-20230308092751773.png)

7. 触发漏洞object的UAF

之前流程图分析过，由于漏洞object所在的第16个slab是满的，因此会触发`put_cpu_partial()`，但由于cpu partial list 非满，所以现在还不会进入`unfreeze_partials()`。

![](image-20230308093143298.png)

8. 我们将漏洞object前后各`objs_per_slab = 16`个object释放，从而让第16个slab进入全空状态

因为虽然内核可能开了freelist harden和freelist random保护，但从page的角度来说，依然是顺序的。因此前后各`objs_per_slab = 16`个object释放就能让第16个slab进入全空状态。（当然这也会导致第15和第17个slab进入半空状态，不过这不影响）

在第16个slab第一次从全满进入半满时，就会触发`put_cpu_partial()`将其放入 cpu partial list中。之后直到全空都不会再进入`put_cpu_partial()`。

![](image-20230308093307884.png)

9. 将1~14个slab中各释放一个object，将其从全满状态进入半满状态

这将对每个page触发一次`put_cpu_partial()`。由于`14 = cpu_partial + 1`，因此这必将导致最后几次在进入`put_cpu_partial()`时发现cpu partial list满了，从而进入`unfreeze_partials()`逻辑。然后发现第16个slab已经进入了全空状态，从而调用`discard_slab()`将这个page进行释放。



我写了个kernel module demo演示 cross page attack的完整过程：

- https://github.com/veritas501/cross_page_attack_demo

```c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/slub_def.h>

#define OBJ_SIZE 512
#define OBJ_NUM (0x1000)

#define loge(fmt, ...) pr_err("%s:%d " fmt "\n", "attack_demo", \
                              __LINE__, ##__VA_ARGS__)

struct my_struct {
    union {
        char data[OBJ_SIZE];
        struct {
            void (*func)(void);
            char paddings[OBJ_SIZE - 8];
        };
    };
} __attribute__((aligned(OBJ_SIZE)));

static struct kmem_cache *my_cachep;
struct my_struct **tmp_ms;
struct my_struct *random_ms;

void hello_func(void) {
    loge("---> hello_func()");
}

void hack_func(void) {
    loge("---> hack_func(): cross page attack success");
}

static int __init km_init(void) {
#define OO_SHIFT 16
#define OO_MASK ((1 << OO_SHIFT) - 1)
    int i, offset, cpu_partial, objs_per_slab;
    struct page *realloc;
    void *target_page_virt;
    void *realloc_page_virt;
    unsigned long page_size;
    int page_order;
    struct my_struct *ms;
    int uaf_idx;

    tmp_ms = kmalloc(OBJ_NUM * 8, GFP_KERNEL);
    my_cachep = kmem_cache_create(
        "my_struct", sizeof(struct my_struct), 0,
        SLAB_HWCACHE_ALIGN | SLAB_PANIC | SLAB_ACCOUNT, NULL);

    loge("cache info:");
    loge(">> my_cachep->name: %s", my_cachep->name);
    cpu_partial = my_cachep->cpu_partial;
    loge(">> cpu_partial: %d", cpu_partial);
    objs_per_slab = my_cachep->oo.x & OO_MASK;
    loge(">> objs_per_slab: %u", objs_per_slab);
    loge(">> object_size: 0x%x", my_cachep->object_size);
    page_size = my_cachep->object_size * objs_per_slab;
    page_order = get_order(page_size);
    loge(">> so page size: 0x%lx, page order: %d\n", page_size, page_order);

    random_ms = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    loge("alloc a random object at %px\n", random_ms);

    loge("=== STEP 1 ===");
    loge(">> alloc `cpu_partial + 1` = %d pages of objects,", cpu_partial + 1);
    loge(">> each page contains `objs_per_slab` = %d objects\n", objs_per_slab);
    for (i = 0, offset = 0; i < (objs_per_slab * (cpu_partial + 1)); i++) {
        tmp_ms[offset + i] = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    }
    offset += i;

    loge("=== STEP 2 ===");
    loge(">> alloc `objs_per_slab - 1` = %d objects\n", objs_per_slab - 1);
    for (i = 0; i < objs_per_slab - 1; i++) {
        tmp_ms[offset + i] = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    }
    offset += i;

    loge("=== STEP 3 ===");
    loge(">> alloc a vulnerable object for UAF");
    uaf_idx = offset++;
    ms = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    tmp_ms[uaf_idx] = ms;
    target_page_virt = (void *)((unsigned long)ms &
                                ~(unsigned long)(page_size - 1));
    loge(">> vuln object index: %d", uaf_idx);
    loge(">> vuln object at %px, page: %px", ms, target_page_virt);
    loge(">> set function pointer to `hello()` and call it\n");
    ms->func = (void *)hello_func;
    ms->func();

    loge("=== STEP 4 ===");
    loge(">> alloc `objs_per_slab + 1` = %d objects\n", objs_per_slab + 1);
    for (i = 0; i < objs_per_slab + 1; i++) {
        tmp_ms[offset + i] = kmem_cache_alloc(my_cachep, GFP_KERNEL);
    }
    offset += i;

    loge("=== STEP 5 ===");
    loge(">> free the vulnerable object, now it's UAF\n");
    kmem_cache_free(my_cachep, ms);

    loge("=== STEP 6 ===");
    loge(">> make vuln page is empty\n");
    for (i = 1; i < objs_per_slab; i++) {
        kmem_cache_free(my_cachep, tmp_ms[uaf_idx + i]);
        kmem_cache_free(my_cachep, tmp_ms[uaf_idx - i]);
        tmp_ms[uaf_idx + i] = NULL;
        tmp_ms[uaf_idx - i] = NULL;
    }

    loge("=== STEP 7 ===");
    loge(">> free one object per page\n");
    for (i = 0; i < (objs_per_slab * (cpu_partial + 1)); i++) {
        if (i % objs_per_slab == 0) {
            if (tmp_ms[i]) {
                kmem_cache_free(my_cachep, tmp_ms[i]);
                tmp_ms[i] = NULL;
            }
        }
    }

    loge("let's check if we can get the vuln page ...");
    realloc = alloc_pages(GFP_KERNEL, page_order);
    realloc_page_virt = page_address(realloc);
    loge("realloc page at %px", realloc_page_virt);
    if (realloc_page_virt == target_page_virt) {
        loge("realloc SUCCESS :)");
    } else {
        loge("cross page attack failed :(");
        return 0;
    }

    loge("assume we has the ability to overwrite the content of page");
    for (i = 0; i < page_size / 8; i++) {
        ((void **)realloc_page_virt)[i] = (void *)hack_func;
    }

    loge("now, let's call func again (UAF)");
    ms->func();

    free_page((unsigned long)realloc_page_virt);
    return 0;
}

static void __exit km_exit(void) {
    int i;

    for (i = 0; i < OBJ_NUM; i++) {
        if (tmp_ms[i]) {
            kmem_cache_free(my_cachep, tmp_ms[i]);
        }
    }
    kmem_cache_free(my_cachep, random_ms);
    kmem_cache_destroy(my_cachep);
    kfree(tmp_ms);
    loge("Bye");
}

module_init(km_init);
module_exit(km_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("X++D && veritas");
MODULE_DESCRIPTION("Cross Page Attack Demo Module.");
MODULE_VERSION("0.1");
```



![](image-20230307193059916.png)