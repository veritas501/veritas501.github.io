---
title: 对system无法get shell的探索
tags:
  - PWN
  - glibc
date: 2017/8/27
---

有的时候，我们会遇到明明漏洞正常但用system无法get shell的情况。

下面以我目前已知的几种情况来讨论。

## 定制的libc

有些情况，服务器的libc可能是定制的，故意除去了system函数。

作为一道题，肯定有其他方法来 get flag，一般是用 open ,read,write来print flag。


## 使用函数禁用了一些系统调用号

在我的[HITCON-training writeup](http://veritas501.space/2017/05/23/HITCON-training%20writeup/)一文中的lab2中，题目使用了PRCTL函数限制了我们的syscall，当然这种情况是execve用不了，system就更不用说了。


## 漏洞利用时覆盖了环境变量

这种情况是本文讨论的重点，因为服务器并没有对system函数做出限制，没有get shell会很抓狂。

我们从源码看起，为什么覆盖了环境变量会影响system。

在[glibc/stdlib/stdlib.h](https://code.woboq.org/userspace/glibc/stdlib/stdlib.h.html)中有声明

```cpp
/* Execute the given line as a shell command.
	
   This function is a cancellation point and therefore not marked with
   __THROW.  */
extern int system (const char *__command) __wur;
```


代码在[glibc/sysdeps/posix/system.c](https://code.woboq.org/userspace/glibc/sysdeps/posix/system.c.html)

首先在line 186

```cpp
weak_alias (__libc_system, system)
```

`__libc_system`:
```cpp
int
__libc_system (const char *line)
{
  if (line == NULL)
    /* Check that we have a command processor available.  It might
       not be available after a chroot(), for example.  */
    return do_system ("exit 0") == 0;

  return do_system (line);
}
```

`do_system`:

```cpp
#define        SHELL_PATH        "/bin/sh"        /* Path of the shell.  */
#define        SHELL_NAME        "sh"                /* Name to give it.  */


#ifdef _LIBC_REENTRANT
static struct sigaction intr, quit;
static int sa_refcntr;
__libc_lock_define_initialized (static, lock);

# define DO_LOCK() __libc_lock_lock (lock)
# define DO_UNLOCK() __libc_lock_unlock (lock)
# define INIT_LOCK() ({ __libc_lock_init (lock); sa_refcntr = 0; })
# define ADD_REF() sa_refcntr++
# define SUB_REF() --sa_refcntr
#else
# define DO_LOCK()
# define DO_UNLOCK()
# define INIT_LOCK()
# define ADD_REF() 0
# define SUB_REF() 0
#endif


/* Execute LINE as a shell command, returning its status.  */
static int
do_system (const char *line)
{
  int status, save;
  pid_t pid;
  struct sigaction sa;
#ifndef _LIBC_REENTRANT
  struct sigaction intr, quit;
#endif
  sigset_t omask;

  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  __sigemptyset (&sa.sa_mask);

  DO_LOCK ();
  if (ADD_REF () == 0)
    {
      if (__sigaction (SIGINT, &sa, &intr) < 0)
        {
          (void) SUB_REF ();
          goto out;
        }
      if (__sigaction (SIGQUIT, &sa, &quit) < 0)
        {
          save = errno;
          (void) SUB_REF ();
          goto out_restore_sigint;
        }
    }
  DO_UNLOCK ();

  /* We reuse the bitmap in the 'sa' structure.  */
  __sigaddset (&sa.sa_mask, SIGCHLD);
  save = errno;
  if (__sigprocmask (SIG_BLOCK, &sa.sa_mask, &omask) < 0)
    {
#ifndef _LIBC
      if (errno == ENOSYS)
        __set_errno (save);
      else
#endif
        {
          DO_LOCK ();
          if (SUB_REF () == 0)
            {
              save = errno;
              (void) __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL);
            out_restore_sigint:
              (void) __sigaction (SIGINT, &intr, (struct sigaction *) NULL);
              __set_errno (save);
            }
        out:
          DO_UNLOCK ();
          return -1;
        }
    }

#ifdef CLEANUP_HANDLER
  CLEANUP_HANDLER;
#endif

#ifdef FORK
  pid = FORK ();
#else
  pid = __fork ();
#endif
  if (pid == (pid_t) 0)
    {
      /* Child side.  */
      const char *new_argv[4];
      new_argv[0] = SHELL_NAME;
      new_argv[1] = "-c";
      new_argv[2] = line;
      new_argv[3] = NULL;

      /* Restore the signals.  */
      (void) __sigaction (SIGINT, &intr, (struct sigaction *) NULL);
      (void) __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL);
      (void) __sigprocmask (SIG_SETMASK, &omask, (sigset_t *) NULL);
      INIT_LOCK ();

      /* Exec the shell.  */
      (void) __execve (SHELL_PATH, (char *const *) new_argv, __environ);
      _exit (127);
    }
  else if (pid < (pid_t) 0)
    /* The fork failed.  */
    status = -1;
  else
    /* Parent side.  */
    {
      /* Note the system() is a cancellation point.  But since we call
         waitpid() which itself is a cancellation point we do not
         have to do anything here.  */
      if (TEMP_FAILURE_RETRY (__waitpid (pid, &status, 0)) != pid)
        status = -1;
    }

#ifdef CLEANUP_HANDLER
  CLEANUP_RESET;
#endif

  save = errno;
  DO_LOCK ();
  if ((SUB_REF () == 0
       && (__sigaction (SIGINT, &intr, (struct sigaction *) NULL)
           | __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL)) != 0)
      || __sigprocmask (SIG_SETMASK, &omask, (sigset_t *) NULL) != 0)
    {
#ifndef _LIBC
      /* glibc cannot be used on systems without waitpid.  */
      if (errno == ENOSYS)
        __set_errno (save);
      else
#endif
        status = -1;
    }
  DO_UNLOCK ();

  return status;
}
```

注意到这一段

```cpp
#ifdef FORK
  pid = FORK ();
#else
  pid = __fork ();
#endif
  if (pid == (pid_t) 0)
    {
      /* Child side.  */
      const char *new_argv[4];
      new_argv[0] = SHELL_NAME;
      new_argv[1] = "-c";
      new_argv[2] = line;
      new_argv[3] = NULL;

      /* Restore the signals.  */
      (void) __sigaction (SIGINT, &intr, (struct sigaction *) NULL);
      (void) __sigaction (SIGQUIT, &quit, (struct sigaction *) NULL);
      (void) __sigprocmask (SIG_SETMASK, &omask, (sigset_t *) NULL);
      INIT_LOCK ();

      /* Exec the shell.  */
      (void) __execve (SHELL_PATH, (char *const *) new_argv, __environ);
      _exit (127);
    }
  else if (pid < (pid_t) 0)
    /* The fork failed.  */
    status = -1;
  else
    /* Parent side.  */
    {
      /* Note the system() is a cancellation point.  But since we call
         waitpid() which itself is a cancellation point we do not
         have to do anything here.  */
      if (TEMP_FAILURE_RETRY (__waitpid (pid, &status, 0)) != pid)
        status = -1;
    }
```


可以看到，system是fork了一个进程，然后利用execve去执行命令。然后`_exit(127)`结束这个进程。

`SHELL_PATH`和`new_argv`都没什么问题，有问题的是`__environ`。


转到[glibc/posix/environ.c](https://code.woboq.org/userspace/glibc/posix/environ.c.html)

```cpp
/* This file just defines the `__environ' variable (and alias `environ').  */

#include <unistd.h>
#include <stddef.h>

/* This must be initialized; we cannot have a weak alias into bss.  */
char **__environ = NULL;
weak_alias (__environ, environ)

/* The SVR4 ABI says `_environ' will be the name to use
   in case the user overrides the weak alias `environ'.  */
weak_alias (__environ, _environ)
```

查看关于`__environ`的所有调用，有一处比较在意，在`__libc_start_main`

转到[glibc/csu/libc-start.c](https://code.woboq.org/userspace/glibc/csu/libc-start.c.html#148)


```cpp
# define LIBC_START_MAIN __libc_start_main

......

/* Note: the fini parameter is ignored here for shared library.  It
   is registered with __cxa_atexit.  This had the disadvantage that
   finalizers were called in more than one place.  */
STATIC int
LIBC_START_MAIN (int (*main) (int, char **, char ** MAIN_AUXVEC_DECL),
                 int argc, char **argv,
#ifdef LIBC_START_MAIN_AUXVEC_ARG
                 ElfW(auxv_t) *auxvec,
#endif
                 __typeof (main) init,
                 void (*fini) (void),
                 void (*rtld_fini) (void), void *stack_end)
{
  /* Result of the 'main' function.  */
  int result;

  __libc_multiple_libcs = &_dl_starting_up && !_dl_starting_up;

#ifndef SHARED
  char **ev = &argv[argc + 1];

  __environ = ev;
  
......
```

所以`__environ`填的就是我们的`envp`，如果超长的栈溢出覆盖了环境变量，do_system中fork出来的子进程访问到非法指针就crash了，get shell就会（有可能）失败，这个时候就应该使用execve并把envp填NULL了。

