---
layout: single
title: SLAE Assignment 3 - Egg Hunter Shellcode
date: 2020-5-03
classes: wide
header:
  teaser: /assets/images/slae/SHELLCODING32.png
tags:
    - Shellcoding
    - Linux
    - x86
    - SLAE
---

![](/assets/images/slae/SHELLCODING32.png)

## Introduction
This is the third post of the SLAE exam assignments serie.  

The goal of this assignement is to study about Egg Hunter shellcode and create a working demo.
The payload used with the demo should be easily configurable. 

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE/tree/master/Assignment-03-Egg_hunter_shellcode)

## The Egg Hunter technique

### Overview

The Egg Hunter technique is used when the available space to inject a shellcode is very limited.
The technique takes its name from the fact that it hunts through all the memory range for a predefined string pattern that is called the "egg".
This egg is appended in front of the real payload previously injected into memory and that we want to execute.
When the egg hunter payload finds the egg, it redirects code execution flow to the real payload.

### A reference paper

When I started my research to learn more about this technique, I quickly came across the well known Skape's paper 
[Safely Searching Process Virtual Address Space](http://hick.org/code/skape/papers/egghunt-shellcode.pdf) that I strongly encourage you to read if you are unfamiliar with the subject.
In this very well explained document, Skape presents the requirements for the egg hunter and different implementations for both Linux and Windows operating systems.

The requirements are that the egg hunter should be robust, as small as possible and run quickly due to the context in which it is aimed to be used,
and the three implementations for Linux are using the access system call for the first two one and the sigaction for the third one.

Because it is presented as the smallest and the fastest one, I've chosen to implement the sigaction one and to implement the work-arounds for the robustness problems. (A flag direction problem, and another in certain conditions if ebx is a valid signal number)

Furthermore, Skape has also determined that it is best to use an eight bytes egg (2 * 4 bytes signature), because the four bytes signature used for the searching will be stored in memory so there is a risk that the egg hunter finds himself before it finds the real payload.

### The memory paging

During the study of the previous document, I came accross the page alignment operation whose purpose I did not understand at first, 
so after some searches I found a very instructive tutorial from Ciro Santilli :
[x86 Paging Tutorial](https://cirosantilli.com/x86-paging)

To briefly summarize : 

In x86 32bits architecture, the 20 top bits of the Virtual Address Space represents the page part (we can see this as the "page number") and the 12 lower bits are the offsets part,
the first page goes from 0x00000000 to 0x00000FFF then the next one starts at 0X00001000, etc... also if we make the math, the size of a page is 0x1000 => 4096KB.

The access rights of a process on memory is handled per page, so if a process doesn't have the right to access the first byte of a page, it means it will not be able to access any bytes of this page.

So in the case of the Egg Hunter, it means we can directly try to access the next page, and it's where the page alignment operation comes into place :

By using an "or 0xFFF" operation on a memory address, we set its 12 offsets bytes to 1 so we obtain the address of the last byte of its page.
Then if we increment this address by one, we obtain the address of the first byte of the next page.

*Also good to know, by default, on Linux x86 32bits operating system, the process memory goes from 0x00000000 to 0xBFFFFFFF and the Kernel memory from 0xC0000000 to 0xFFFFFFFF*

### The sigaction syscall

The sigaction syscall number :
```c
#/usr/include/i386-linux-gnu/asm/unistd_32.h
#define __NR_sigaction 67
```

And in the sigaction manpage we can read the following :

```plaintext
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);

signum specifies the signal and can be any valid signal except SIGKILL and SIGSTOP.
If act is non-NULL, the new action for signal signum is installed from act.  If oldact is non-NULL, the previous action is saved in oldact.
	...
RETURN VALUE
       sigaction() returns 0 on success; on error, -1 is returned, and errno is set to indicate the error.

ERRORS
       EFAULT act or oldact points to memory which is not a valid part of the process address space.
       EINVAL An invalid signal was specified.  This will also be generated if an attempt is made to change
              the action for SIGKILL or SIGSTOP, which cannot be caught or ignored.
	...
sigaction() can be called with a NULL second argument to query the current signal handler.   It  can
also  be  used  to  check whether a given signal is valid for the current machine by calling it with
NULL second and third arguments.
```

So like explained in the Skape's paper, sigaction try to access a sigaction structure when its second argument (ECX) is not null.
If ECX point to a memory address which is not valid for the process, sigaction return the EFAULT error.
```c
#/usr/include/asm-generic/errno-base.h
#define	EFAULT		14	/* Bad address */
```
So we can call the sigaction syscall and check its return value : 
- if it's EFAULT value then we call sigaction with ECX pointing on the first byte of the next page, 
- else we check the current address pointed by ECX for the egg value, 

If the value pointed by ECX is the same as the egg, we check the value at the following address,  
- if it's the same, we redirect code execution flow to the following address that will point on the payload we want to execute.  
- else if it's not the same value as the egg, we go to the next address and we call sigaction to check if it's a valid address and we restart the loop   

#### More robustness

First we can see that if ECX is set to a null pointer (when the egg hunter will reach the last address in memory and loop to the first address 0x00000000)  
The return value will be EINVAL, because sigaction will query the current signal handler for the action to execute and the signal handler will return EINVAL because we will use an invalid signal number.

So we have three solutions here :
- 'xor ecx, ecx' at the begining of the egg hunter, so it will start to search at the adress 0x00001000 but it will crash if it loop in memory
- check for the EINVAL value too after the sigaction call, but two bytes longer thant the next one 
- or check if ZF is set to 0 after we increment ECX

Then /usr/include/asm/signal.h, we can see that the first valid signal value is 1 so setting EBX to 0 will resolve the problems that may occur when EBX is a valid signal number.

```c
#define SIGHUP		 1
#define SIGINT		 2
#define SIGQUIT		 3
#define SIGILL		 4
...
```
And finally for the problem that may occur when the direction flag is set to 1, we just need to set it to 0 with "cld" 

## The assembly code

```nasm
; Shellcode length : 35 bytes

global _start
section .text

_start:

    xor ebx, ebx        ; set ebx to an invalid signal number
    cld                 ; Ensure that we search in memory in the reverse stack order
			; from lower to higher memory address

next_page:
    or cx, 0xfff        ; Set ecx pointing to the last byte of the current page

next_address:
    inc ecx             ; Next offset, and next page if cx is set to 0x0fff			
    jz next_page        ; Check ZF => if ecx set to 0x0, go to the next page
    
    push byte 0x43      ; sigaction syscall number
    pop eax
    int 0x80         

    cmp al, 0xf2        ; check if EFAULT (0x00 - 0x0e (-14) = 0xf2)
    jz next_page        ; if EFAULT go to next page

    mov eax, 0x50905090 ; set eax to the egg signature value
    mov edi, ecx        ; set edi to point to the address we want to check

    scasd               ; test for the first four bytes of the egg
                        ; scasd compare eax with bytes at the address set in edi,
                        ; then increment the edi register (DF is set to 0)
    jnz next_address    ; if it's not the egg signature go to the next address

    scasd               ; test for the four last bytes of the egg
    jnz next_address    ; if it's not go to the next address

    jmp edi             ; Jump to the true payload,
                        ; The address following the egg
```
## The hunt

First we will compile the egg hunter and get the shellcode :

```plaintext
root@kali:~# ./compile.sh egghunter
[x] Assembling...
[x] Linking...
[x] Done !

Shellcode : 
"\\x31\\xdb\\xfc\\x66\\x81\\xc9\\xff\\x0f\\x41\\x74\\xf8\\x6a\\x43\\x58\\xcd\\x80\\x3c\\xf2
\\x74\\xef\\xb8\\x90\\x50\\x90\\x50\\x89\\xcf\\xaf\\x75\\xea\\xaf\\x75\\xe7\\xff\\xe7"
```

Then we add it to the following python script (note that the egg is appended to a Hello World shellcode) :

```c
#!/usr/bin/python3
from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv

libc = CDLL("libc.so.6")

egg = "\\x90\\x50\\x90\\x50"

egghunter = \
"\\x31\\xdb\\xfc\\x66\\x81\\xc9\\xff\\x0f\\x41\\x74\\xf8\\x6a\\x43\\x58\\xcd\\x80\\x3c
\\xf2\\x74\\xef\\xb8\\x90\\x50\\x90\\x50\\x89\\xcf\\xaf\\x75\\xea\\xaf\\x75\\xe7\\xff\\xe7"

payload = egg * 2 + \
"\\x31\\xdb\\xf7\\xe3\\xb0\\x04\\xb3\\x01\\x68\\x72\\x6c\\x64\\x0a\\x68\\x6f\\x20\\x57\\x6f
\\x68\\x48\\x65\\x6c\\x6c\\x89\\xe1\\xb2\\x0c\\xcd\\x80\\xb0\\x01\\xcd\\x80"

# Write Hello World shellcode :
#    xor ebx, ebx
#    mul ebx
#    mov al, 0x4
#    mov bl, 0x1
#
#    push 0x0a646c72
#    push 0X6f57206f
#    push 0x6c6c6548
#    mov ecx, esp
#    mov dl, 0xc
#    int 0x80
#
#    mov al, 0x1
#    int 0x80

egghunter = bytes.fromhex(egghunter.replace('\\x', ''))
payload = bytes.fromhex(payload.replace('\\x', ''))


print("Egg hunter length : {}".format(len(egghunter)))
print("Payload length : {}".format(len(payload) - 8))

c_shell_p = c_char_p(payload)
c_egg_p = c_char_p(egghunter)

# We call the egg hunter shellcode only 
launch = cast(c_egg_p, CFUNCTYPE(c_char_p))
launch()
```
And we run it :

```plaintext
root@kali:~# ./exec-shellcode.py 
Egg hunter length : 35
Payload length : 33
Hello World
```

Seems we've caught the egg. 

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)  
Student ID: PA-14186***
