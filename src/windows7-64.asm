fffff80002698640: int3 
fffff80002698641: add eax, edi
fffff80002698643: mov qword ptr gs:[0x10], rsp
fffff8000269864c: mov rsp, qword ptr gs:[0x1a8]
fffff80002698655: push 0x2b
fffff80002698657: push qword ptr gs:[0x10]
fffff8000269865f: push r11
fffff80002698661: push 0x33
fffff80002698663: push rcx
fffff80002698664: mov rcx, r10
fffff80002698667: sub rsp, 8
fffff8000269866b: push rbp
fffff8000269866c: sub rsp, 0x158
fffff80002698673: lea rbp, qword ptr [rsp + 0x80]
fffff8000269867b: mov qword ptr [rbp + 0xc0], rbx
fffff80002698682: mov qword ptr [rbp + 0xc8], rdi
fffff80002698689: mov qword ptr [rbp + 0xd0], rsi
fffff80002698690: mov byte ptr [rbp - 0x55], 2
fffff80002698694: mov rbx, qword ptr gs:[0x188]
fffff8000269869d: prefetchw byte ptr [rbx + 0x1d8]
fffff800026986a4: stmxcsr dword ptr [rbp - 0x54]
fffff800026986a8: ldmxcsr dword ptr gs:[0x180]
fffff800026986b1: cmp byte ptr [rbx + 3], 0
fffff800026986b5: mov word ptr [rbp + 0x80], 0
fffff800026986be: je 0x110
fffff800026986c4: mov qword ptr [rbp - 0x50], rax
fffff800026986c8: mov qword ptr [rbp - 0x48], rcx
fffff800026986cc: mov qword ptr [rbp - 0x40], rdx
fffff800026986d0: test byte ptr [rbx + 3], 3
fffff800026986d4: mov qword ptr [rbp - 0x38], r8
fffff800026986d8: mov qword ptr [rbp - 0x30], r9
fffff800026986dc: je 0xa3
fffff800026986de: call 0x14b0
fffff800026986e3: test byte ptr [rbx + 3], 0x80
fffff800026986e7: je 0xeb
fffff800026986e9: mov ecx, 0xc0000102
fffff800026986ee: rdmsr 
fffff800026986f0: shl rdx, 0x20
fffff800026986f4: or rax, rdx
fffff800026986f7: cmp qword ptr [rbx + 0xb8], rax
fffff800026986fe: je 0xeb
fffff80002698700: cmp qword ptr [rbx + 0x1b0], rax
fffff80002698707: je 0xeb
fffff80002698709: mov rdx, qword ptr [rbx + 0x1b8]
fffff80002698710: bts dword ptr [rbx + 0x4c], 0xb
fffff80002698715: dec word ptr [rbx + 0x1c4]
fffff8000269871c: mov qword ptr [rdx + 0x80], rax
fffff80002698723: sti 
fffff80002698724: call 0xc00
fffff80002698729: jmp 0xfa
fffff8000269872b: test byte ptr [rbx + 3], 0x40
fffff8000269872f: je 0xfa
fffff80002698731: lock bts dword ptr [rbx + 0x100], 8
fffff8000269873a: mov rax, qword ptr [rbp - 0x50]
fffff8000269873e: mov rcx, qword ptr [rbp - 0x48]
fffff80002698742: mov rdx, qword ptr [rbp - 0x40]
fffff80002698746: mov r8, qword ptr [rbp - 0x38]
fffff8000269874a: mov r9, qword ptr [rbp - 0x30]
fffff8000269874e: nop 
fffff80002698750: sti 
fffff80002698751: mov qword ptr [rbx + 0x1e0], rcx
fffff80002698758: mov dword ptr [rbx + 0x1f8], eax
fffff8000269875e: mov qword ptr [rbx + 0x1d8], rsp
fffff80002698765: mov edi, eax
fffff80002698767: shr edi, 7
fffff8000269876a: and edi, 0x20
fffff8000269876d: and eax, 0xfff
fffff80002698772: lea r10, qword ptr [rip + 0x2320c7]
fffff80002698779: lea r11, qword ptr [rip + 0x232100]
fffff80002698780: test dword ptr [rbx + 0x100], 0x80
fffff8000269878a: cmovne r10, r11
fffff8000269878e: cmp eax, dword ptr [rdi + r10 + 0x10]
fffff80002698793: jae 0x442
fffff80002698799: mov r10, qword ptr [rdi + r10]
fffff8000269879d: movsxd r11, dword ptr [r10 + rax*4]
fffff800026987a1: mov rax, r11
fffff800026987a4: sar r11, 4
fffff800026987a8: add r10, r11
fffff800026987ab: cmp edi, 0x20
fffff800026987ae: jne 0x1c0
fffff800026987b0: mov r11, qword ptr [rbx + 0xb8]
fffff800026987b7: cmp dword ptr [r11 + 0x1740], 0
fffff800026987bf: je 0x1c0
fffff800026987c1: mov qword ptr [rbp - 0x50], rax
fffff800026987c5: mov qword ptr [rbp - 0x48], rcx
fffff800026987c9: mov qword ptr [rbp - 0x40], rdx
fffff800026987cd: mov rbx, r8
fffff800026987d0: mov rdi, r9
fffff800026987d3: mov rsi, r10
fffff800026987d6: call qword ptr [rip + 0x231f34]
fffff800026987dc: mov rax, qword ptr [rbp - 0x50]
fffff800026987e0: mov rcx, qword ptr [rbp - 0x48]
fffff800026987e4: mov rdx, qword ptr [rbp - 0x40]
fffff800026987e8: mov r8, rbx
fffff800026987eb: mov r9, rdi
fffff800026987ee: mov r10, rsi
fffff800026987f1: nop word ptr [rax + rax]
fffff80002698800: and eax, 0xf
fffff80002698803: je 0x280
fffff80002698809: shl eax, 3
fffff8000269880c: lea rsp, qword ptr [rsp - 0x70]
fffff80002698811: lea rdi, qword ptr [rsp + 0x18]
fffff80002698816: mov rsi, qword ptr [rbp + 0x100]
fffff8000269881d: lea rsi, qword ptr [rsi + 0x20]
fffff80002698821: test byte ptr [rbp + 0xf0], 1
fffff80002698828: je 0x200
fffff8000269882a: cmp rsi, qword ptr [rip + 0x2317cf]
fffff80002698831: cmovae rsi, qword ptr [rip + 0x2317c7]
fffff80002698839: nop dword ptr [rax]
fffff80002698840: lea r11, qword ptr [rip + 0x79]
fffff80002698847: sub r11, rax
fffff8000269884a: jmp r11
fffff8000269884d: nop dword ptr [rax]
fffff80002698850: mov rax, qword ptr [rsi + 0x70]
fffff80002698854: mov qword ptr [rdi + 0x70], rax
fffff80002698858: mov rax, qword ptr [rsi + 0x68]
fffff8000269885c: mov qword ptr [rdi + 0x68], rax
fffff80002698860: mov rax, qword ptr [rsi + 0x60]
fffff80002698864: mov qword ptr [rdi + 0x60], rax
fffff80002698868: mov rax, qword ptr [rsi + 0x58]
fffff8000269886c: mov qword ptr [rdi + 0x58], rax
fffff80002698870: mov rax, qword ptr [rsi + 0x50]
fffff80002698874: mov qword ptr [rdi + 0x50], rax
fffff80002698878: mov rax, qword ptr [rsi + 0x48]
fffff8000269887c: mov qword ptr [rdi + 0x48], rax
fffff80002698880: mov rax, qword ptr [rsi + 0x40]
fffff80002698884: mov qword ptr [rdi + 0x40], rax
fffff80002698888: mov rax, qword ptr [rsi + 0x38]
fffff8000269888c: mov qword ptr [rdi + 0x38], rax
fffff80002698890: mov rax, qword ptr [rsi + 0x30]
fffff80002698894: mov qword ptr [rdi + 0x30], rax
fffff80002698898: mov rax, qword ptr [rsi + 0x28]
fffff8000269889c: mov qword ptr [rdi + 0x28], rax
fffff800026988a0: mov rax, qword ptr [rsi + 0x20]
fffff800026988a4: mov qword ptr [rdi + 0x20], rax
fffff800026988a8: mov rax, qword ptr [rsi + 0x18]
fffff800026988ac: mov qword ptr [rdi + 0x18], rax
fffff800026988b0: mov rax, qword ptr [rsi + 0x10]
fffff800026988b4: mov qword ptr [rdi + 0x10], rax
fffff800026988b8: mov rax, qword ptr [rsi + 8]
fffff800026988bc: mov qword ptr [rdi + 8], rax
fffff800026988c0: test dword ptr [rip + 0x187dbe], 0x40
fffff800026988ca: jne 0x4e0
fffff800026988d0: call r10
fffff800026988d3: inc dword ptr gs:[0x2238]
fffff800026988db: mov rbx, qword ptr [rbp + 0xc0]
fffff800026988e2: mov rdi, qword ptr [rbp + 0xc8]
fffff800026988e9: mov rsi, qword ptr [rbp + 0xd0]
fffff800026988f0: mov r11, qword ptr gs:[0x188]
fffff800026988f9: test byte ptr [rbp + 0xf0], 1
fffff80002698900: je 0x415
fffff80002698906: mov rcx, cr8
fffff8000269890a: or cl, byte ptr [r11 + 0x1f0]
fffff80002698911: or ecx, dword ptr [r11 + 0x1c4]
fffff80002698918: jne 0x4ac
fffff8000269891e: cli 
fffff8000269891f: mov rcx, qword ptr gs:[0x188]
fffff80002698928: cmp byte ptr [rcx + 0x7a], 0
fffff8000269892c: je 0x345
fffff8000269892e: mov qword ptr [rbp - 0x50], rax
fffff80002698932: xor eax, eax
fffff80002698934: mov qword ptr [rbp - 0x48], rax
fffff80002698938: mov qword ptr [rbp - 0x40], rax
fffff8000269893c: mov qword ptr [rbp - 0x38], rax
fffff80002698940: mov qword ptr [rbp - 0x30], rax
fffff80002698944: mov qword ptr [rbp - 0x28], rax
fffff80002698948: mov qword ptr [rbp - 0x20], rax
fffff8000269894c: pxor xmm0, xmm0
fffff80002698950: movaps xmmword ptr [rbp - 0x10], xmm0
fffff80002698954: movaps xmmword ptr [rbp], xmm0
fffff80002698958: movaps xmmword ptr [rbp + 0x10], xmm0
fffff8000269895c: movaps xmmword ptr [rbp + 0x20], xmm0
fffff80002698960: movaps xmmword ptr [rbp + 0x30], xmm0
fffff80002698964: movaps xmmword ptr [rbp + 0x40], xmm0
fffff80002698968: mov ecx, 1
fffff8000269896d: mov cr8, rcx
fffff80002698971: sti 
fffff80002698972: call 0xffffffffffff4a90
fffff80002698977: cli 
fffff80002698978: mov ecx, 0
fffff8000269897d: mov cr8, rcx
fffff80002698981: mov rax, qword ptr [rbp - 0x50]
fffff80002698985: mov rcx, qword ptr gs:[0x188]
fffff8000269898e: test dword ptr [rcx], 0x40020000
fffff80002698994: je 0x384
fffff80002698996: mov qword ptr [rbp - 0x50], rax
fffff8000269899a: test byte ptr [rcx + 2], 2
fffff8000269899e: je 0x36e
fffff800026989a0: call 0x9a2e0
fffff800026989a5: mov rcx, qword ptr gs:[0x188]
fffff800026989ae: test byte ptr [rcx + 3], 0x40
fffff800026989b2: je 0x380
fffff800026989b4: lea rsp, qword ptr [rbp - 0x80]
fffff800026989b8: xor rcx, rcx
fffff800026989bb: call 0xe80
fffff800026989c0: mov rax, qword ptr [rbp - 0x50]
fffff800026989c4: ldmxcsr dword ptr [rbp - 0x54]
fffff800026989c8: xor r10, r10
fffff800026989cb: cmp word ptr [rbp + 0x80], 0
fffff800026989d3: je 0x3d3
fffff800026989d5: mov qword ptr [rbp - 0x50], rax
fffff800026989d9: call 0x1440
fffff800026989de: mov rax, qword ptr gs:[0x188]
fffff800026989e7: mov rax, qword ptr [rax + 0x70]
fffff800026989eb: mov rax, qword ptr [rax + 0x100]
fffff800026989f2: or rax, rax
fffff800026989f5: je 0x3cf
fffff800026989f7: cmp word ptr [rbp + 0xf0], 0x33
fffff800026989ff: jne 0x3cf
fffff80002698a01: mov r10, qword ptr [rbp + 0xe8]
fffff80002698a08: mov qword ptr [rbp + 0xe8], rax
fffff80002698a0f: mov rax, qword ptr [rbp - 0x50]
fffff80002698a13: mov r8, qword ptr [rbp + 0x100]
fffff80002698a1a: mov r9, qword ptr [rbp + 0xd8]
fffff80002698a21: xor edx, edx
fffff80002698a23: pxor xmm0, xmm0
fffff80002698a27: pxor xmm1, xmm1
fffff80002698a2b: pxor xmm2, xmm2
fffff80002698a2f: pxor xmm3, xmm3
fffff80002698a33: pxor xmm4, xmm4
fffff80002698a37: pxor xmm5, xmm5
fffff80002698a3b: mov rcx, qword ptr [rbp + 0xe8]
fffff80002698a42: mov r11, qword ptr [rbp + 0xf8]
fffff80002698a49: mov rbp, r9
fffff80002698a4c: mov rsp, r8
fffff80002698a4f: swapgs 
fffff80002698a52: sysret 
fffff80002698a55: mov rdx, qword ptr [rbp + 0xb8]
fffff80002698a5c: mov qword ptr [r11 + 0x1d8], rdx
fffff80002698a63: mov dl, byte ptr [rbp - 0x58]
fffff80002698a66: mov byte ptr [r11 + 0x1f6], dl
fffff80002698a6d: cli 
fffff80002698a6e: mov rsp, rbp
fffff80002698a71: mov rbp, qword ptr [rbp + 0xd8]
fffff80002698a78: mov rsp, qword ptr [rsp + 0x100]
fffff80002698a80: sti 
fffff80002698a81: ret 
fffff80002698a82: cmp edi, 0x20
fffff80002698a85: jne 0x4a2
fffff80002698a87: mov dword ptr [rbp - 0x80], eax
fffff80002698a8a: mov qword ptr [rbp - 0x78], rcx
fffff80002698a8e: mov qword ptr [rbp - 0x70], rdx
fffff80002698a92: mov qword ptr [rbp - 0x68], r8
fffff80002698a96: mov qword ptr [rbp - 0x60], r9
fffff80002698a9a: call 0xffffffffffff88b0
fffff80002698a9f: or eax, eax
fffff80002698aa1: mov eax, dword ptr [rbp - 0x80]
fffff80002698aa4: mov rcx, qword ptr [rbp - 0x78]
fffff80002698aa8: mov rdx, qword ptr [rbp - 0x70]
fffff80002698aac: mov r8, qword ptr [rbp - 0x68]
fffff80002698ab0: mov r9, qword ptr [rbp - 0x60]
fffff80002698ab4: mov qword ptr [rbx + 0x1d8], rsp
fffff80002698abb: je 0x132
fffff80002698ac1: lea rdi, qword ptr [rip + 0x231dd8]
fffff80002698ac8: mov esi, dword ptr [rdi + 0x10]
fffff80002698acb: mov rdi, qword ptr [rdi]
fffff80002698ace: cmp eax, esi
fffff80002698ad0: jae 0x4a2
fffff80002698ad2: lea rdi, qword ptr [rdi + rsi*4]
fffff80002698ad6: movsx eax, byte ptr [rax + rdi]
fffff80002698ada: or eax, eax
fffff80002698adc: jle 0x29b
fffff80002698ae2: mov eax, 0xc000001c
fffff80002698ae7: jmp 0x29b
fffff80002698aec: mov ecx, 0x4a
fffff80002698af1: xor r9d, r9d
fffff80002698af4: mov r8, cr8
fffff80002698af8: or r8d, r8d
fffff80002698afb: jne 0x4d1
fffff80002698afd: mov ecx, 1
fffff80002698b02: movzx r8d, byte ptr [r11 + 0x1f0]
fffff80002698b0a: mov r9d, dword ptr [r11 + 0x1c4]
fffff80002698b11: mov rdx, qword ptr [rbp + 0xe8]
fffff80002698b18: mov r10, rbp
fffff80002698b1b: call 0x540
fffff80002698b20: sub rsp, 0x50
fffff80002698b24: mov qword ptr [rsp + 0x20], rcx
fffff80002698b29: mov qword ptr [rsp + 0x28], rdx
fffff80002698b2e: mov qword ptr [rsp + 0x30], r8
fffff80002698b33: mov qword ptr [rsp + 0x38], r9
fffff80002698b38: mov qword ptr [rsp + 0x40], r10
fffff80002698b3d: mov rcx, r10
fffff80002698b40: call 0xe3670
fffff80002698b45: mov rcx, qword ptr [rsp + 0x20]
fffff80002698b4a: mov rdx, qword ptr [rsp + 0x28]
fffff80002698b4f: mov r8, qword ptr [rsp + 0x30]
fffff80002698b54: mov r9, qword ptr [rsp + 0x38]
fffff80002698b59: mov r10, qword ptr [rsp + 0x40]
fffff80002698b5e: add rsp, 0x50
fffff80002698b62: call r10
fffff80002698b65: mov qword ptr [rbp - 0x50], rax
fffff80002698b69: mov rcx, rax
fffff80002698b6c: call 0xe3610
fffff80002698b71: mov rax, qword ptr [rbp - 0x50]
fffff80002698b75: jmp 0x293
fffff80002698b7a: nop word ptr [rax + rax]
fffff80002698b80: sub rsp, 0x138
fffff80002698b87: lea rax, qword ptr [rsp + 0x100]
fffff80002698b8f: movaps xmmword ptr [rsp + 0x30], xmm6
fffff80002698b94: movaps xmmword ptr [rsp + 0x40], xmm7
fffff80002698b99: movaps xmmword ptr [rsp + 0x50], xmm8
fffff80002698b9f: movaps xmmword ptr [rsp + 0x60], xmm9
fffff80002698ba5: movaps xmmword ptr [rsp + 0x70], xmm10
fffff80002698bab: movaps xmmword ptr [rax - 0x80], xmm11
fffff80002698bb0: movaps xmmword ptr [rax - 0x70], xmm12
fffff80002698bb5: movaps xmmword ptr [rax - 0x60], xmm13
fffff80002698bba: movaps xmmword ptr [rax - 0x50], xmm14
fffff80002698bbf: movaps xmmword ptr [rax - 0x40], xmm15
fffff80002698bc4: mov qword ptr [rax], rbx
fffff80002698bc7: mov qword ptr [rax + 8], rdi
fffff80002698bcb: mov qword ptr [rax + 0x10], rsi
fffff80002698bcf: mov qword ptr [rax + 0x18], r12
fffff80002698bd3: mov qword ptr [rax + 0x20], r13
fffff80002698bd7: mov qword ptr [rax + 0x28], r14
fffff80002698bdb: mov qword ptr [rax + 0x30], r15
fffff80002698bdf: mov qword ptr [rsp + 0x20], r10
fffff80002698be4: call 0x1000
fffff80002698be9: nop 
fffff80002698bea: nop word ptr [rax + rax]
fffff80002698bf9: nop dword ptr [rax]
fffff80002698c00: sub rsp, 0x1d8
fffff80002698c07: lea rax, qword ptr [rsp + 0x100]
fffff80002698c0f: movaps xmmword ptr [rsp + 0x30], xmm6
fffff80002698c14: movaps xmmword ptr [rsp + 0x40], xmm7
fffff80002698c19: movaps xmmword ptr [rsp + 0x50], xmm8
fffff80002698c1f: movaps xmmword ptr [rsp + 0x60], xmm9
fffff80002698c25: movaps xmmword ptr [rsp + 0x70], xmm10
fffff80002698c2b: movaps xmmword ptr [rax - 0x80], xmm11
fffff80002698c30: movaps xmmword ptr [rax - 0x70], xmm12
fffff80002698c35: movaps xmmword ptr [rax - 0x60], xmm13
fffff80002698c3a: movaps xmmword ptr [rax - 0x50], xmm14
fffff80002698c3f: movaps xmmword ptr [rax - 0x40], xmm15
fffff80002698c44: mov qword ptr [rax], rbx
fffff80002698c47: mov qword ptr [rax + 8], rdi
fffff80002698c4b: mov qword ptr [rax + 0x10], rsi
fffff80002698c4f: mov qword ptr [rax + 0x18], r12
fffff80002698c53: mov qword ptr [rax + 0x20], r13
fffff80002698c57: mov qword ptr [rax + 0x28], r14
fffff80002698c5b: mov qword ptr [rax + 0x30], r15
fffff80002698c5f: mov rax, qword ptr gs:[0x188]
fffff80002698c68: bt dword ptr [rax + 0x4c], 0xb
fffff80002698c6d: jae 0x63d
fffff80002698c6f: test byte ptr [rbp + 0xf0], 1
fffff80002698c76: je 0x63d
fffff80002698c78: call 0xdc0
fffff80002698c7d: lea rax, qword ptr [rsp + 0x138]
fffff80002698c85: mov dword ptr [rax], ecx
fffff80002698c87: xor ecx, ecx
fffff80002698c89: mov dword ptr [rax + 4], ecx
fffff80002698c8c: mov qword ptr [rax + 8], rcx
fffff80002698c90: mov qword ptr [rax + 0x10], r8
fffff80002698c94: mov dword ptr [rax + 0x18], edx
fffff80002698c97: mov qword ptr [rax + 0x20], r9
fffff80002698c9b: mov qword ptr [rax + 0x28], r10
fffff80002698c9f: mov qword ptr [rax + 0x30], r11
fffff80002698ca3: mov r9b, byte ptr [rbp + 0xf0]
fffff80002698caa: and r9b, 1
fffff80002698cae: mov byte ptr [rsp + 0x20], 1
fffff80002698cb3: lea r8, qword ptr [rbp - 0x80]
fffff80002698cb7: mov rdx, rsp
fffff80002698cba: mov rcx, rax
fffff80002698cbd: call 0x3c64c
fffff80002698cc2: lea rcx, qword ptr [rsp + 0x100]
fffff80002698cca: movaps xmm6, xmmword ptr [rsp + 0x30]
fffff80002698ccf: movaps xmm7, xmmword ptr [rsp + 0x40]
fffff80002698cd4: movaps xmm8, xmmword ptr [rsp + 0x50]
fffff80002698cda: movaps xmm9, xmmword ptr [rsp + 0x60]
fffff80002698ce0: movaps xmm10, xmmword ptr [rsp + 0x70]
fffff80002698ce6: movaps xmm11, xmmword ptr [rcx - 0x80]
fffff80002698ceb: movaps xmm12, xmmword ptr [rcx - 0x70]
fffff80002698cf0: movaps xmm13, xmmword ptr [rcx - 0x60]
fffff80002698cf5: movaps xmm14, xmmword ptr [rcx - 0x50]
fffff80002698cfa: movaps xmm15, xmmword ptr [rcx - 0x40]
fffff80002698cff: mov rbx, qword ptr [rcx]
fffff80002698d02: mov rdi, qword ptr [rcx + 8]
fffff80002698d06: mov rsi, qword ptr [rcx + 0x10]
fffff80002698d0a: mov r12, qword ptr [rcx + 0x18]
fffff80002698d0e: mov r13, qword ptr [rcx + 0x20]
fffff80002698d12: mov r14, qword ptr [rcx + 0x28]
fffff80002698d16: mov r15, qword ptr [rcx + 0x30]
fffff80002698d1a: cli 
fffff80002698d1b: test byte ptr [rbp + 0xf0], 1
fffff80002698d22: je 0x7a3
fffff80002698d28: mov rcx, qword ptr gs:[0x188]
fffff80002698d31: cmp byte ptr [rcx + 0x7a], 0
fffff80002698d35: je 0x710
fffff80002698d37: mov ecx, 1
fffff80002698d3c: mov cr8, rcx
fffff80002698d40: sti 
fffff80002698d41: call 0xffffffffffff4a90
fffff80002698d46: cli 
fffff80002698d47: mov ecx, 0
fffff80002698d4c: mov cr8, rcx
fffff80002698d50: mov rcx, qword ptr gs:[0x188]
fffff80002698d59: test dword ptr [rcx], 0x40020000
fffff80002698d5f: je 0x746
fffff80002698d61: test byte ptr [rcx + 2], 2
fffff80002698d65: je 0x735
fffff80002698d67: call 0x9a2e0
fffff80002698d6c: mov rcx, qword ptr gs:[0x188]
fffff80002698d75: test byte ptr [rcx + 3], 0x40
fffff80002698d79: je 0x746
fffff80002698d7b: lea rsp, qword ptr [rbp - 0x80]
fffff80002698d7f: mov cl, 1
fffff80002698d81: call 0xe80
fffff80002698d86: ldmxcsr dword ptr [rbp - 0x54]
fffff80002698d8a: cmp word ptr [rbp + 0x80], 0
fffff80002698d92: je 0x759
fffff80002698d94: call 0x1440
fffff80002698d99: movaps xmm0, xmmword ptr [rbp - 0x10]
fffff80002698d9d: movaps xmm1, xmmword ptr [rbp]
fffff80002698da1: movaps xmm2, xmmword ptr [rbp + 0x10]
fffff80002698da5: movaps xmm3, xmmword ptr [rbp + 0x20]
fffff80002698da9: movaps xmm4, xmmword ptr [rbp + 0x30]
fffff80002698dad: movaps xmm5, xmmword ptr [rbp + 0x40]
fffff80002698db1: mov r11, qword ptr [rbp - 0x20]
fffff80002698db5: mov r10, qword ptr [rbp - 0x28]
fffff80002698db9: mov r9, qword ptr [rbp - 0x30]
fffff80002698dbd: mov r8, qword ptr [rbp - 0x38]
fffff80002698dc1: mov rdx, qword ptr [rbp - 0x40]
fffff80002698dc5: mov rcx, qword ptr [rbp - 0x48]
fffff80002698dc9: mov rax, qword ptr [rbp - 0x50]
fffff80002698dcd: mov rsp, rbp
fffff80002698dd0: mov rbp, qword ptr [rbp + 0xd8]
fffff80002698dd7: add rsp, 0xe8
fffff80002698dde: swapgs 
fffff80002698de1: iretq 
fffff80002698de3: ldmxcsr dword ptr [rbp - 0x54]
fffff80002698de7: movaps xmm0, xmmword ptr [rbp - 0x10]
fffff80002698deb: movaps xmm1, xmmword ptr [rbp]
fffff80002698def: movaps xmm2, xmmword ptr [rbp + 0x10]
fffff80002698df3: movaps xmm3, xmmword ptr [rbp + 0x20]
fffff80002698df7: movaps xmm4, xmmword ptr [rbp + 0x30]
fffff80002698dfb: movaps xmm5, xmmword ptr [rbp + 0x40]
fffff80002698dff: mov r11, qword ptr [rbp - 0x20]
fffff80002698e03: mov r10, qword ptr [rbp - 0x28]
fffff80002698e07: mov r9, qword ptr [rbp - 0x30]
fffff80002698e0b: mov r8, qword ptr [rbp - 0x38]
fffff80002698e0f: mov rdx, qword ptr [rbp - 0x40]
fffff80002698e13: mov rcx, qword ptr [rbp - 0x48]
fffff80002698e17: mov rax, qword ptr [rbp - 0x50]
fffff80002698e1b: mov rsp, rbp
fffff80002698e1e: mov rbp, qword ptr [rbp + 0xd8]
fffff80002698e25: add rsp, 0xe8
fffff80002698e2c: iretq 
fffff80002698e2e: nop word ptr [rax + rax]
fffff80002698e3d: nop dword ptr [rax]
fffff80002698e40: sub rsp, 0x28
fffff80002698e44: mov rbx, qword ptr gs:[0x188]
fffff80002698e4d: mov rcx, qword ptr [rbx + 0x1d8]
fffff80002698e54: lea rbp, qword ptr [rcx + 0x80]
fffff80002698e5b: mov rax, cr8
fffff80002698e5f: or al, byte ptr [rbx + 0x1f0]
fffff80002698e65: or eax, dword ptr [rbx + 0x1c4]
fffff80002698e6b: je 0x861
fffff80002698e6d: mov ecx, 0x4a
fffff80002698e72: xor r9d, r9d
fffff80002698e75: mov r8, cr8
fffff80002698e79: or r8d, r8d
fffff80002698e7c: jne 0x852
fffff80002698e7e: mov ecx, 1
fffff80002698e83: movzx r8d, byte ptr [rbx + 0x1f0]
fffff80002698e8b: mov r9d, dword ptr [rbx + 0x1c4]
fffff80002698e92: mov rdx, qword ptr [rbp + 0xe8]
fffff80002698e99: mov r10, rbp
fffff80002698e9c: call 0x540
fffff80002698ea1: cli 
fffff80002698ea2: mov rcx, qword ptr gs:[0x188]
fffff80002698eab: cmp byte ptr [rcx + 0x7a], 0
fffff80002698eaf: je 0x8c8
fffff80002698eb1: mov qword ptr [rbp - 0x50], rax
fffff80002698eb5: xor eax, eax
fffff80002698eb7: mov qword ptr [rbp - 0x48], rax
fffff80002698ebb: mov qword ptr [rbp - 0x40], rax
fffff80002698ebf: mov qword ptr [rbp - 0x38], rax
fffff80002698ec3: mov qword ptr [rbp - 0x30], rax
fffff80002698ec7: mov qword ptr [rbp - 0x28], rax
fffff80002698ecb: mov qword ptr [rbp - 0x20], rax
fffff80002698ecf: pxor xmm0, xmm0
fffff80002698ed3: movaps xmmword ptr [rbp - 0x10], xmm0
fffff80002698ed7: movaps xmmword ptr [rbp], xmm0
fffff80002698edb: movaps xmmword ptr [rbp + 0x10], xmm0
fffff80002698edf: movaps xmmword ptr [rbp + 0x20], xmm0
fffff80002698ee3: movaps xmmword ptr [rbp + 0x30], xmm0
fffff80002698ee7: movaps xmmword ptr [rbp + 0x40], xmm0
fffff80002698eeb: mov ecx, 1
fffff80002698ef0: mov cr8, rcx
fffff80002698ef4: sti 
fffff80002698ef5: call 0xffffffffffff4a90
fffff80002698efa: cli 
fffff80002698efb: mov ecx, 0
fffff80002698f00: mov cr8, rcx
fffff80002698f04: mov rax, qword ptr [rbp - 0x50]
fffff80002698f08: mov rcx, qword ptr gs:[0x188]
fffff80002698f11: test dword ptr [rcx], 0x40020000
fffff80002698f17: je 0x907
fffff80002698f19: mov qword ptr [rbp - 0x50], rax
fffff80002698f1d: test byte ptr [rcx + 2], 2
fffff80002698f21: je 0x8f1
fffff80002698f23: call 0x9a2e0
fffff80002698f28: mov rcx, qword ptr gs:[0x188]
fffff80002698f31: test byte ptr [rcx + 3], 0x40
fffff80002698f35: je 0x903
fffff80002698f37: lea rsp, qword ptr [rbp - 0x80]
fffff80002698f3b: xor rcx, rcx
fffff80002698f3e: call 0xe80
fffff80002698f43: mov rax, qword ptr [rbp - 0x50]
fffff80002698f47: ldmxcsr dword ptr [rbp - 0x54]
fffff80002698f4b: xor r10, r10
fffff80002698f4e: cmp word ptr [rbp + 0x80], 0
fffff80002698f56: je 0x956
fffff80002698f58: mov qword ptr [rbp - 0x50], rax
fffff80002698f5c: call 0x1440
fffff80002698f61: mov rax, qword ptr gs:[0x188]
fffff80002698f6a: mov rax, qword ptr [rax + 0x70]
fffff80002698f6e: mov rax, qword ptr [rax + 0x100]
fffff80002698f75: or rax, rax
fffff80002698f78: je 0x952
fffff80002698f7a: cmp word ptr [rbp + 0xf0], 0x33
fffff80002698f82: jne 0x952
fffff80002698f84: mov r10, qword ptr [rbp + 0xe8]
fffff80002698f8b: mov qword ptr [rbp + 0xe8], rax
fffff80002698f92: mov rax, qword ptr [rbp - 0x50]
fffff80002698f96: mov r8, qword ptr [rbp + 0x100]
fffff80002698f9d: mov r9, qword ptr [rbp + 0xd8]
fffff80002698fa4: xor edx, edx
fffff80002698fa6: pxor xmm0, xmm0
fffff80002698faa: pxor xmm1, xmm1
fffff80002698fae: pxor xmm2, xmm2
fffff80002698fb2: pxor xmm3, xmm3
fffff80002698fb6: pxor xmm4, xmm4
fffff80002698fba: pxor xmm5, xmm5
fffff80002698fbe: mov rcx, qword ptr [rbp + 0xe8]
fffff80002698fc5: mov r11, qword ptr [rbp + 0xf8]
fffff80002698fcc: mov rbp, r9
fffff80002698fcf: mov rsp, r8
fffff80002698fd2: swapgs 
fffff80002698fd5: sysret 
fffff80002698fd8: nop word ptr [rax + rax]
fffff80002698fe7: nop word ptr [rax + rax]
fffff80002698ff6: nop word ptr [rax + rax]
fffff80002699000: cli 
fffff80002699001: mov rdx, qword ptr gs:[0x188]
fffff8000269900a: mov rdi, qword ptr [rdx + 0x28]
fffff8000269900e: lea rbp, qword ptr [rdi - 0x110]
fffff80002699015: sub rdi, 8
fffff80002699019: mov rsi, qword ptr [rcx + 0x20]
fffff8000269901d: sub rsi, 8
fffff80002699021: mov rdx, rcx
fffff80002699024: mov rcx, qword ptr [rcx + 0x30]
fffff80002699028: shr rcx, 3
fffff8000269902c: std 
fffff8000269902d: rep movsq qword ptr [rdi], qword ptr [rsi]
fffff80002699030: cld 
fffff80002699031: lea rsp, qword ptr [rdi + 8]
fffff80002699035: mov rcx, rdx
fffff80002699038: mov rdx, qword ptr [rcx + 0x38]
fffff8000269903c: jmp rdx
fffff8000269903e: nop 
fffff80002699040: mov qword ptr [rbp - 0x80], rcx
fffff80002699044: mov qword ptr [rbp - 0x78], rax
fffff80002699048: sub rsp, 0x1a8
fffff8000269904f: movaps xmmword ptr [rsp + 0xa0], xmm6
fffff80002699057: movaps xmmword ptr [rsp + 0xb0], xmm7
fffff8000269905f: movaps xmmword ptr [rsp + 0xc0], xmm8
fffff80002699068: movaps xmmword ptr [rsp + 0xd0], xmm9
fffff80002699071: movaps xmmword ptr [rsp + 0xe0], xmm10
fffff8000269907a: movaps xmmword ptr [rsp + 0xf0], xmm11
fffff80002699083: movaps xmmword ptr [rsp + 0x100], xmm12
fffff8000269908c: movaps xmmword ptr [rsp + 0x110], xmm13
fffff80002699095: movaps xmmword ptr [rsp + 0x120], xmm14
fffff8000269909e: movaps xmmword ptr [rsp + 0x130], xmm15
fffff800026990a7: mov qword ptr [rsp + 0x188], r12
fffff800026990af: mov qword ptr [rsp + 0x190], r13
fffff800026990b7: mov qword ptr [rsp + 0x198], r14
fffff800026990bf: mov qword ptr [rsp + 0x1a0], r15
fffff800026990c7: mov qword ptr [rsp + 0x178], rdi
fffff800026990cf: mov qword ptr [rsp + 0x180], rsi
fffff800026990d7: mov qword ptr [rsp + 0x170], rbx
fffff800026990df: lea rax, qword ptr [rbp + 0x110]
fffff800026990e6: mov qword ptr [rsp + 0x20], rax
fffff800026990eb: sub rax, rsp
fffff800026990ee: mov qword ptr [rsp + 0x28], rax
fffff800026990f3: sub rax, 0x1a8
fffff800026990f9: mov qword ptr [rsp + 0x30], rax
fffff800026990fe: lea rax, qword ptr [rip + 0x7b]
fffff80002699105: mov qword ptr [rsp + 0x38], rax
fffff8000269910a: lea rdx, qword ptr [rsp + 0x70]
fffff8000269910f: mov qword ptr [rsp + 0x58], rdx
fffff80002699114: lea rdx, qword ptr [rbp - 0x80]
fffff80002699118: mov qword ptr [rsp + 0x50], rdx
fffff8000269911d: bts qword ptr [rsp + 0x48], 0
fffff80002699124: mov rcx, rsp
fffff80002699127: call 0x1180c0
fffff8000269912c: mov r12, qword ptr [rsp + 0x188]
fffff80002699134: mov r13, qword ptr [rsp + 0x190]
fffff8000269913c: mov r14, qword ptr [rsp + 0x198]
fffff80002699144: add rsp, 0x1a8
fffff8000269914b: jmp 0x800
fffff80002699150: nop word ptr [rax + rax]
fffff8000269915f: nop word ptr [rax + rax]
fffff8000269916e: nop word ptr [rax + rax]
fffff8000269917d: nop dword ptr [rax]
fffff80002699180: sub rsp, 0x28
fffff80002699184: mov rax, qword ptr [rcx + 0x58]
fffff80002699188: movdqa xmm6, xmmword ptr [rax + 0x30]
fffff8000269918d: movdqa xmm7, xmmword ptr [rax + 0x40]
fffff80002699192: movdqa xmm8, xmmword ptr [rax + 0x50]
fffff80002699198: movdqa xmm9, xmmword ptr [rax + 0x60]
fffff8000269919e: movdqa xmm10, xmmword ptr [rax + 0x70]
fffff800026991a4: movdqa xmm11, xmmword ptr [rax + 0x80]
fffff800026991ad: movdqa xmm12, xmmword ptr [rax + 0x90]
fffff800026991b6: movdqa xmm13, xmmword ptr [rax + 0xa0]
fffff800026991bf: movdqa xmm14, xmmword ptr [rax + 0xb0]
fffff800026991c8: movdqa xmm15, xmmword ptr [rax + 0xc0]
fffff800026991d1: mov r12, qword ptr [rax + 0x118]
fffff800026991d8: mov r13, qword ptr [rax + 0x120]
fffff800026991df: mov r14, qword ptr [rax + 0x128]
fffff800026991e6: mov r15, qword ptr [rax + 0x130]
fffff800026991ed: mov rdi, qword ptr [rax + 0x108]
fffff800026991f4: mov rsi, qword ptr [rax + 0x110]
fffff800026991fb: mov rbx, qword ptr [rax + 0x100]
fffff80002699202: sti 
fffff80002699203: ldmxcsr dword ptr gs:[0x180]
fffff8000269920c: call 0xb6c10
fffff80002699211: mov rcx, qword ptr [rbp - 0x80]
fffff80002699215: mov rax, qword ptr [rbp - 0x78]
fffff80002699219: add rsp, 0x28
fffff8000269921d: ret 
fffff8000269921e: nop word ptr [rax + rax]
fffff8000269922d: nop word ptr [rax + rax]
fffff8000269923c: nop dword ptr [rax]
fffff80002699240: sub rsp, 0x1a8
fffff80002699247: movaps xmmword ptr [rsp + 0xa0], xmm6
fffff8000269924f: movaps xmmword ptr [rsp + 0xb0], xmm7
fffff80002699257: movaps xmmword ptr [rsp + 0xc0], xmm8
fffff80002699260: movaps xmmword ptr [rsp + 0xd0], xmm9
fffff80002699269: movaps xmmword ptr [rsp + 0xe0], xmm10
fffff80002699272: movaps xmmword ptr [rsp + 0xf0], xmm11
fffff8000269927b: movaps xmmword ptr [rsp + 0x100], xmm12
fffff80002699284: movaps xmmword ptr [rsp + 0x110], xmm13
fffff8000269928d: movaps xmmword ptr [rsp + 0x120], xmm14
fffff80002699296: movaps xmmword ptr [rsp + 0x130], xmm15
fffff8000269929f: mov qword ptr [rsp + 0x188], r12
fffff800026992a7: mov qword ptr [rsp + 0x190], r13
fffff800026992af: mov qword ptr [rsp + 0x198], r14
fffff800026992b7: mov qword ptr [rsp + 0x1a0], r15
fffff800026992bf: lea rax, qword ptr [rbp + 0x110]
fffff800026992c6: mov qword ptr [rsp + 0x20], rax
fffff800026992cb: sub rax, rsp
fffff800026992ce: mov qword ptr [rsp + 0x28], rax
fffff800026992d3: sub rax, 0x1a8
fffff800026992d9: mov qword ptr [rsp + 0x30], rax
fffff800026992de: lea rax, qword ptr [rip + 0x5b]
fffff800026992e5: mov qword ptr [rsp + 0x38], rax
fffff800026992ea: lea rdx, qword ptr [rsp + 0x70]
fffff800026992ef: mov qword ptr [rsp + 0x58], rdx
fffff800026992f4: lea rdx, qword ptr [rbp - 0x80]
fffff800026992f8: mov qword ptr [rsp + 0x50], rdx
fffff800026992fd: btr qword ptr [rsp + 0x48], 0
fffff80002699304: mov rcx, rsp
fffff80002699307: call 0x1180c0
fffff8000269930c: mov r12, qword ptr [rsp + 0x188]
fffff80002699314: mov r13, qword ptr [rsp + 0x190]
fffff8000269931c: mov r14, qword ptr [rsp + 0x198]
fffff80002699324: add rsp, 0x1a8
fffff8000269932b: jmp 0x800
fffff80002699330: nop word ptr [rax + rax]
fffff8000269933f: nop 
fffff80002699340: sub rsp, 0x28
fffff80002699344: mov rax, qword ptr [rcx + 0x58]
fffff80002699348: movdqa xmm6, xmmword ptr [rax + 0x30]
fffff8000269934d: movdqa xmm7, xmmword ptr [rax + 0x40]
fffff80002699352: movdqa xmm8, xmmword ptr [rax + 0x50]
fffff80002699358: movdqa xmm9, xmmword ptr [rax + 0x60]
fffff8000269935e: movdqa xmm10, xmmword ptr [rax + 0x70]
fffff80002699364: movdqa xmm11, xmmword ptr [rax + 0x80]
fffff8000269936d: movdqa xmm12, xmmword ptr [rax + 0x90]
fffff80002699376: movdqa xmm13, xmmword ptr [rax + 0xa0]
fffff8000269937f: movdqa xmm14, xmmword ptr [rax + 0xb0]
fffff80002699388: movdqa xmm15, xmmword ptr [rax + 0xc0]
fffff80002699391: mov r12, qword ptr [rax + 0x118]
fffff80002699398: mov r13, qword ptr [rax + 0x120]
fffff8000269939f: mov r14, qword ptr [rax + 0x128]
fffff800026993a6: mov r15, qword ptr [rax + 0x130]
fffff800026993ad: sti 
fffff800026993ae: mov rbx, qword ptr gs:[0x188]
fffff800026993b7: ldmxcsr dword ptr gs:[0x180]
fffff800026993c0: call 0xb6c10
fffff800026993c5: add rsp, 0x28
fffff800026993c9: ret 
fffff800026993ca: nop word ptr [rax + rax]
fffff800026993d9: nop word ptr [rax + rax]
fffff800026993e8: nop word ptr [rax + rax]
fffff800026993f7: nop word ptr [rax + rax]
fffff80002699400: sub rsp, 0x68
fffff80002699404: mov qword ptr [rbp - 0x80], r8
fffff80002699408: mov qword ptr [rbp - 0x78], r9
fffff8000269940c: mov qword ptr [rbp - 0x70], r10
fffff80002699410: mov qword ptr [rbp - 0x68], r11
fffff80002699414: lea r8, qword ptr [rsp + 0x70]
fffff80002699419: mov qword ptr [r8], rcx
fffff8000269941c: mov qword ptr [r8 + 8], rdx
fffff80002699420: lea rax, qword ptr [rbp + 0x110]
fffff80002699427: mov qword ptr [rsp + 0x20], rax
fffff8000269942c: sub rax, rsp
fffff8000269942f: mov qword ptr [rsp + 0x28], rax
fffff80002699434: mov qword ptr [rsp + 0x30], rax
fffff80002699439: lea rax, qword ptr [rip + 0x43]
fffff80002699440: mov qword ptr [rsp + 0x38], rax
fffff80002699445: mov qword ptr [rsp + 0x58], r8
fffff8000269944a: lea rdx, qword ptr [rbp - 0x80]
fffff8000269944e: mov qword ptr [rsp + 0x50], rdx
fffff80002699453: bts qword ptr [rsp + 0x48], 0
fffff8000269945a: mov rcx, rsp
fffff8000269945d: call 0x1180c0
fffff80002699462: mov r12, qword ptr [rsp + 0x188]
fffff8000269946a: mov r13, qword ptr [rsp + 0x190]
fffff80002699472: mov r14, qword ptr [rsp + 0x198]
fffff8000269947a: add rsp, 0x68
fffff8000269947e: jmp 0x800
fffff80002699483: sti 
fffff80002699484: call 0xb6c10
fffff80002699489: ldmxcsr dword ptr gs:[0x180]
fffff80002699492: lea r8, qword ptr [rsp + 0x70]
fffff80002699497: mov rcx, qword ptr [r8]
fffff8000269949a: mov rdx, qword ptr [r8 + 8]
fffff8000269949e: mov r8, qword ptr [rbp - 0x80]
fffff800026994a2: mov r9, qword ptr [rbp - 0x78]
fffff800026994a6: mov r10, qword ptr [rbp - 0x70]
fffff800026994aa: mov r11, qword ptr [rbp - 0x68]
fffff800026994ae: add rsp, 0x68
fffff800026994b2: ret 
fffff800026994b3: nop word ptr [rax + rax]
fffff800026994c0: sub rsp, 0x1a8
fffff800026994c7: movaps xmmword ptr [rsp + 0xa0], xmm6
fffff800026994cf: movaps xmmword ptr [rsp + 0xb0], xmm7
fffff800026994d7: movaps xmmword ptr [rsp + 0xc0], xmm8
fffff800026994e0: movaps xmmword ptr [rsp + 0xd0], xmm9
fffff800026994e9: movaps xmmword ptr [rsp + 0xe0], xmm10
fffff800026994f2: movaps xmmword ptr [rsp + 0xf0], xmm11
fffff800026994fb: movaps xmmword ptr [rsp + 0x100], xmm12
fffff80002699504: movaps xmmword ptr [rsp + 0x110], xmm13
fffff8000269950d: movaps xmmword ptr [rsp + 0x120], xmm14
fffff80002699516: movaps xmmword ptr [rsp + 0x130], xmm15
fffff8000269951f: mov qword ptr [rsp + 0x188], r12
fffff80002699527: mov qword ptr [rsp + 0x190], r13
fffff8000269952f: mov qword ptr [rsp + 0x198], r14
fffff80002699537: mov qword ptr [rsp + 0x1a0], r15
fffff8000269953f: mov qword ptr [rsp + 0x178], rdi
fffff80002699547: mov qword ptr [rsp + 0x180], rsi
fffff8000269954f: mov qword ptr [rsp + 0x170], rbx
fffff80002699557: sti 
fffff80002699558: mov byte ptr [rsp + 0x48], cl
fffff8000269955c: lea rdx, qword ptr [rsp + 0x70]
fffff80002699561: mov qword ptr [rsp + 0x58], rdx
fffff80002699566: lea rdx, qword ptr [rbp - 0x80]
fffff8000269956a: mov qword ptr [rsp + 0x50], rdx
fffff8000269956f: mov rcx, rsp
fffff80002699572: call 0x117410
fffff80002699577: lea rax, qword ptr [rsp + 0x70]
fffff8000269957c: movdqa xmm6, xmmword ptr [rax + 0x30]
fffff80002699581: movdqa xmm7, xmmword ptr [rax + 0x40]
fffff80002699586: movdqa xmm8, xmmword ptr [rax + 0x50]
fffff8000269958c: movdqa xmm9, xmmword ptr [rax + 0x60]
fffff80002699592: movdqa xmm10, xmmword ptr [rax + 0x70]
fffff80002699598: movdqa xmm11, xmmword ptr [rax + 0x80]
fffff800026995a1: movdqa xmm12, xmmword ptr [rax + 0x90]
fffff800026995aa: movdqa xmm13, xmmword ptr [rax + 0xa0]
fffff800026995b3: movdqa xmm14, xmmword ptr [rax + 0xb0]
fffff800026995bc: movdqa xmm15, xmmword ptr [rax + 0xc0]
fffff800026995c5: mov r12, qword ptr [rax + 0x118]
fffff800026995cc: mov r13, qword ptr [rax + 0x120]
fffff800026995d3: mov r14, qword ptr [rax + 0x128]
fffff800026995da: mov r15, qword ptr [rax + 0x130]
fffff800026995e1: mov rdi, qword ptr [rax + 0x108]
fffff800026995e8: mov rsi, qword ptr [rax + 0x110]
fffff800026995ef: mov rbx, qword ptr [rax + 0x100]
fffff800026995f6: add rsp, 0x1a8
fffff800026995fd: ret 
fffff800026995fe: nop 
fffff800026995ff: nop 
fffff80002699600: int3 
fffff80002699601: int3 
fffff80002699602: int3 
fffff80002699603: int3 
fffff80002699604: int3 
fffff80002699605: int3 
fffff80002699606: nop word ptr [rax + rax]
fffff80002699610: sub rsp, 0x28
fffff80002699614: call 0x1000
fffff80002699619: nop 
fffff8000269961a: int3 
fffff8000269961b: int3 
fffff8000269961c: int3 
fffff8000269961d: int3 
fffff8000269961e: int3 
fffff8000269961f: int3 
fffff80002699620: sub rsp, 0x28
fffff80002699624: mov qword ptr [rsp + 0x20], 0
fffff8000269962d: call 0x1000
fffff80002699632: nop 
fffff80002699633: int3 
fffff80002699634: int3 
fffff80002699635: int3 
fffff80002699636: int3 
fffff80002699637: int3 
fffff80002699638: int3 
fffff80002699639: nop dword ptr [rax]
