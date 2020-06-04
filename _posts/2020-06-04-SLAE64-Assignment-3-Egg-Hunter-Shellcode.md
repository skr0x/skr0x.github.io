---
layout: single
title: SLAE64 Assignment 3 - Egg Hunter Shellcode
date: 2020-6-04
classes: wide
header:
  teaser: /assets/images/slae/SHELLCODING64.png
tags:
    - Shellcoding
    - Linux
    - x64
    - SLAE64
---

![](/assets/images/slae/SHELLCODING64.png)

## Introduction
This third assignment is to create an Egg Hunter shellcode and a working demo, with a payload easily configurable. 

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE64/tree/master/Assignment-03-Egg_hunter_shellcode)

## The Egg Hunter technique

I will reuse the same technique as for the SLAE 32 assignment, I will not explain the technique again so if you want to know more about the principle of the egg hunter please take a look at the links below :  
[My blog post for the SLAE 32bits](http://skrox.fr/SLAE-Assignment-3-Egg-Hunter-Shellcode/)  
[A reference paper by Skape : Safely Searching Process Virtual Address Space](http://hick.org/code/skape/papers/egghunt-shellcode.pdf)  
[A tutoril on memory paging : x86 Paging Tutorial](https://cirosantilli.com/x86-paging)

### A minor difference 

The syscall sigaction has been replaced by the rt_sigaction syscall, which take an additional argument :  

From the manual page :  
```plaintext
The original Linux system call was named sigaction().  However, with the addition of real-time sig‐
nals in Linux 2.2, the fixed-size, 32-bit sigset_t type supported by that system call was no longer
fit for purpose.  Consequently, a new system call, rt_sigaction(), was added to support an enlarged
sigset_t type.  The new system call takes a fourth argument, size_t sigsetsize, which specifies the
size in bytes of the signal sets in act.sa_mask and oldact.sa_mask.  This argument is currently re‐
quired  to  have  the  value sizeof(sigset_t) (or the error EINVAL results).  The glibc sigaction()
wrapper function hides these details from us, transparently calling rt_sigaction() when the  kernel
provides it.
```
The fourth argument is sigsetsize which is the value of sizeof(sigset_t) 
The old one was 32-bits and it has been enlarged so we can assume that the new one is 64bits...

But it's better to be sure, from /usr/include/asm-generic/signal.h we can see :
```c
#define _NSIG		64
#define _NSIG_BPW	__BITS_PER_LONG
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)

	... ...

typedef struct {
	unsigned long sig[_NSIG_WORDS];
} sigset_t;
```
So we need to know the _NSIG_WORDS (_NSIG / _NSIG_BPW) size to know the sigset_t size.
We have the value of _NSIG which is 64

For _NSIG_BPW it is set to __BITS_PER_LONG so we need to look into /usr/include/x86_64-linux-gnu/asm/bitsperlong.h
```c
#if defined(__x86_64__) && !defined(__ILP32__)
# define __BITS_PER_LONG 64
#else
# define __BITS_PER_LONG 32
#endif
```
ILP32 envirronment is for 32-bit Linux systems, 64-bit Linux systems are LP64,
So this is were we can find the __BITS_PER_LONG definition and see that a long is 64 bits 

Finally the sigset_t size is sizeof(unsigned long sig[64 / 64])), the size of an array of one long so 8 bytes.

## The assembly code 

```nasm
; shellcode length 45 bytes

_start:

     xor esi, esi       ; set RSI to 0 to start from 0x000000001000 memory address

;    lea rsi, [rel _start - 0x1000]  
                        ; uncomment to test the egghunter with shellcode.cpp, 
                        ; will start from the current memory page 
                        ; after "next_page" instructions 
                        ; and so we will not wait hours to see if the egghunter works

    cld                 ; Ensure that we search in memory in the reverse stack order
			; from lower to higher memory address

    push 8              ; sigset_t size
    pop r10             ; R10 set to sigsetsize

next_page:
    or si, 0xfff        ; Set RSI pointing to the last byte of the current page

next_address:
    inc rsi             ; Next offset, and next page if RSI is set to 0x0fff			
    jz next_page        ; if RSI point to 0x00 (null ptr) got to next_page

    xor edi, edi        ; set RDI to invalid signum (for more robustness cf. Skape paper)
    push 13
    pop rax             ; rt_sigaction syscall number
    cdq                 ; set RDX to null pointer
    syscall

    cmp al, 0xf2        ; check if EFAULT
    jz next_page        ; if EFAULT go to next page

    mov eax, 0x50905090 ; set EAX to our egg signature value
    mov rdi, rsi        ; set RDI to point to the address we want to check

    scasd               ; test for the first four bytes of the egg
                        ; scasd compare EAX with DWORD at the address set in RDI,
                        ; then increment the RDI register (DF is set to 0)
    jnz next_address    ; if it's not our egg signature go to the next address

    scasd               ; test for the four last bytes of the egg
    jnz next_address    ; if it's not go to the next address

    jmp rdi             ; Jump to our true payload,
                        ; The address following our egg
```
## The hunt

For the demonstration I've uncommented the second line :  
lea rsi, [rel _start - 0x1000]
Because it take a lot much more time to search through all memory in x64 

```plaintext
root@kali:~# ./compile.sh sigaction-egghunter
[x] Assembling...
[x] Linking...
[x] Dumped shellcode :
\x48\x8d\x35\xf9\xef\xff\xff\xfc\x6a\x08\x41\x5a\x66\x81\xce\xff\x0f\x48\xff
\xc6\x74\xf6\x31\xff\x6a\x0d\x58\x99\x0f\x05\x3c\xf2\x74\xea\xb8\x90\x50\x90
\x50\x48\x89\xf7\xaf\x75\xe4\xaf\x75\xe1\xff\xe7
```

Then we add it to the following c++ code :

```c
#include <iostream>

#define EGG "\x90\x50\x90\x50"

unsigned char egghunter[] = "\x48\x8d\x35\xf9\xef\xff\xff\xfc\x6a\x08\x41\x5a\x66\x81\xce\xff\x0f\x48\xff\xc6\x74\xf6\x31\xff\x6a\x0d\x58\x99\x0f\x05\x3c\xf2\x74\xea\xb8\x90\x50\x90\x50\x48\x89\xf7\xaf\x75\xe4\xaf\x75\xe1\xff\xe7";


unsigned char payload[] = EGG EGG \
"\x48\xb8\x48\x65\x6c\x6c\x6f\x20\x21\x0a\x50\x48\x89\xe6\x31\xff\xf7\xe7\xff\xc7\xb2\x08\xff\xc0\x0f\x05\xb0\x3c\x0f\x05";
/*
"Hello !\n" payload
 
    mov rax,0x0A21206f6c6c6548
    push rax
    mov rsi, rsp

    xor edi, edi
    mul edi
    inc edi
    mov dl, 8
    inc eax
    syscall

    mov al, 60
    syscall
*/


int main() {

    std::cout << "Payload size : " << sizeof(payload) - 9 << std::endl;
    std::cout << "Egghunter size : " << sizeof(egghunter) - 1 << std::endl;

    void (* hunt)() = (void (*)()) egghunter;

    hunt();
    return 0;
}
```
And we run it :

```plaintext
skrox@kali:~$ g++ -fno-stack-protector -z execstack -o shellcode shellcode.cpp 
skrox@kali:~$ ./shellcode 
Payload size : 30
Egghunter size : 50
Hello !

```

And it's over, see you next time :)

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-
linux/index.html)  
Student ID: PA-14186***
