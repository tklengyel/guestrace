int3 
and eax, dword ptr [rax]
add byte ptr [rax], al
push 0x30
pop fs
mov ds, ecx
mov es, ecx
mov ecx, dword ptr fs:[rip + 0x40]
mov esp, dword ptr [rcx + 4]
push 0x23
push rdx
pushfq 
push 2
add edx, 8
popfq 
or byte ptr [rsp + 1], 2
push 0x1b
push qword ptr [rip - 0x20fcfc]
push 0
push rbp
push rbx
push rsi
push rdi
mov ebx, dword ptr fs:[rip + 0x1c]
push 0x3b
mov esi, dword ptr [rbx + 0x124]
push qword ptr [rbx]
mov dword ptr [rbx], 0xffffffff
mov ebp, dword ptr [rsi + 0x28]
push 1
sub esp, 0x48
sub ebp, 0x29c
mov byte ptr [rsi + 0x13a], 1
cmp ebp, esp
jne 0xfffffffffffffffb
and dword ptr [rbp + 0x2c], 0
test byte ptr [rsi + 3], 0xdf
mov dword ptr [rsi + 0x128], ebp
jne 0xfffffffffffffeb0
mov ebx, dword ptr [rbp + 0x60]
mov edi, dword ptr [rbp + 0x68]
mov dword ptr [rbp + 0xc], edx
mov dword ptr [rbp + 8], 0xbadb0d00
mov dword ptr [rbp], ebx
mov dword ptr [rbp + 4], edi
sti 
mov edi, eax
shr edi, 8
and edi, 0x10
mov ecx, edi
add edi, dword ptr [rsi + 0xbc]
mov ebx, eax
and eax, 0xfff
cmp eax, dword ptr [rdi + 8]
jae 0xfffffffffffffde2
cmp ecx, 0x10
jne 0xce
mov ecx, dword ptr [rsi + 0x88]
xor esi, esi
or esi, dword ptr [rcx + 0xf70]
je 0xce
push rdx
push rax
call qword ptr [rip - 0x7d69056c]
pop rax
pop rdx
inc dword ptr fs:[rip + 0x6b0]
mov esi, edx
xor ecx, ecx
mov edx, dword ptr [rdi + 0xc]
mov edi, dword ptr [rdi]
mov cl, byte ptr [rax + rdx]
mov edx, dword ptr [rdi + rax*4]
sub esp, ecx
shr ecx, 2
mov edi, esp
test byte ptr [rbp + 0x72], 2
jne 0xf7
test byte ptr [rbp + 0x6c], 1
je 0x103
cmp esi, dword ptr [rip - 0x7d6907b0]
jae 0x331
rep movsd dword ptr [rdi], dword ptr [rsi]
test byte ptr [rbp + 0x6c], 1
je 0x121
mov ecx, dword ptr fs:[rip + 0x124]
mov edi, dword ptr [rsp]
mov dword ptr [rcx + 0x13c], ebx
mov dword ptr [rcx + 0x12c], edi
mov ebx, edx
test byte ptr [rip - 0x7d6c3978], 0x40
setne byte ptr [rbp + 0x12]
jne 0x4b4
call rbx ######################################this is where the magic happens##########################################
test byte ptr [rbp + 0x6c], 1
je 0x170
mov esi, eax
call qword ptr [rip - 0x7d7f8e98]
or al, al
jne 0x47b
mov eax, esi
mov ecx, dword ptr fs:[rip + 0x124]
test byte ptr [rcx + 0x134], 0xff
jne 0x499
mov edx, dword ptr [rcx + 0x84]
or edx, edx
jne 0x499
mov esp, ebp
cmp byte ptr [rbp + 0x12], 0
jne 0x4c0
mov ecx, dword ptr fs:[rip + 0x124]
mov edx, dword ptr [rbp + 0x3c]
mov dword ptr [rcx + 0x128], edx
cli 
test byte ptr [rbp + 0x72], 2
jne 0x199
test byte ptr [rbp + 0x6c], 1
je 0x200
mov ebx, dword ptr fs:[rip + 0x124]
test byte ptr [rbx + 2], 2
je 0x1ae
push rax
push rbx
call 0xa5957
pop rax
mov byte ptr [rbx + 0x3a], 0
cmp byte ptr [rbx + 0x56], 0
je 0x200
mov ebx, ebp
mov dword ptr [rbx + 0x44], eax
mov dword ptr [rbx + 0x50], 0x3b
mov dword ptr [rbx + 0x38], 0x23
mov dword ptr [rbx + 0x34], 0x23
mov dword ptr [rbx + 0x30], 0
mov ecx, 1
call qword ptr [rip - 0x7d7f8ea4]
push rax
sti 
push rbx
push 0
push 1
call 0x731e5
pop rcx
call qword ptr [rip - 0x7d7f8ea8]
mov eax, dword ptr [rbx + 0x44]
cli 
jmp 0x199
lea ecx, dword ptr [rcx]
mov edx, dword ptr [rsp + 0x4c]
mov dword ptr fs:[rip], edx
mov ecx, dword ptr [rsp + 0x48]
mov esi, dword ptr fs:[rip + 0x124]
mov byte ptr [rsi + 0x13a], cl
test dword ptr [rsp + 0x2c], 0xffff23ff
jne 0x2a8
test dword ptr [rsp + 0x70], 0x20000
jne 0xc6c
test word ptr [rsp + 0x6c], 0xfff9
je 0x2fe
cmp word ptr [rsp + 0x6c], 0x1b
bt word ptr [rsp + 0x6c], 0
cmc 
ja 0x2ec
cmp word ptr [rbp + 0x6c], 8
je 0x265
lea esp, dword ptr [rbp + 0x50]
pop fs
lea esp, dword ptr [rbp + 0x54]
pop rdi
pop rsi
pop rbx
pop rbp
cmp word ptr [rsp + 8], 0x80
ja 0xc88
add esp, 4
test dword ptr [rsp + 4], 1
jne 0x28c
pop rdx
pop rcx
popfq 
jmp rdx
iretd 
test dword ptr [rsp + 8], 0x100
jne 0x28b
pop rdx
add esp, 4
and dword ptr [rsp], 0xfffffdff
popfq 
pop rcx
sti 
sysexit 
iretd 
nop 
test dword ptr [rbp + 0x70], 0x20000
jne 0x2be
test dword ptr [rbp + 0x6c], 1
je 0x22a
xor ebx, ebx
mov esi, dword ptr [rbp + 0x18]
mov edi, dword ptr [rbp + 0x1c]
mov dr7, rbx
mov dr0, rsi
mov ebx, dword ptr [rbp + 0x20]
mov dr1, rdi
mov dr2, rbx
mov esi, dword ptr [rbp + 0x24]
mov edi, dword ptr [rbp + 0x28]
mov ebx, dword ptr [rbp + 0x2c]
mov dr3, rsi
mov dr6, rdi
mov dr7, rbx
jmp 0x22a
mov eax, dword ptr [rsp + 0x44]
add esp, 0x30
pop gs