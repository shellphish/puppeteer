;
; This is supposed to read out the memory. It reads addresses and length on
; INFD and writes addresses on OUTFD. It uses memory for storing the length and
; address. Dumps registers REG, esp, esi, and edi on start.
;
; nasm -o dumpmem.o dumpmem.asm -DINFD=0 -DOUTFD=1 -DADDR_MEM=0x804A500 -DLEN_MEM=0x804A504 -DREG=eax

USE32

_start:
	mov [ADDR_MEM], REG
	xor edx, edx
	mov dl, 4
	mov ecx, ADDR_MEM
	xor ebx, ebx
	inc ebx
	xor eax, eax
	mov al, 4
	int 80h

	mov [ADDR_MEM], esp
	xor eax, eax
	mov al, 4
	int 80h

	mov [ADDR_MEM], esi
	xor eax, eax
	mov al, 4
	int 80h

	mov [ADDR_MEM], edi
	xor eax, eax
	mov al, 4
	int 80h

;
; Command loop
;
read_cmd:
;	xor edx, edx
;	inc edx
;	mov [ADDR_MEM], edx
;	mov ecx, ADDR_MEM
;	xor ebx, ebx
;	xor eax, eax
;	mov al, 3
;	int 80h
;	mov edx, [ADDR_MEM]
;	cmp edx, 'M'
;	jz read_target
;

;
; This dumps memory
;
read_target:
	xor edx, edx
	mov dl, 4
	mov ecx, ADDR_MEM
	xor ebx, ebx
	xor eax, eax
	mov al, 3
	int 80h
	mov ecx, LEN_MEM
	mov eax, 0x3
	int 80h

dump_target:
	mov edx, [LEN_MEM]
	mov ecx, [ADDR_MEM]

	cmp ecx, 0
	je exit

	xor ebx, ebx
	inc ebx
	xor eax, eax
	mov al, 4
	int 80h

jump_back:
	jmp read_cmd

exit:
	mov eax, 1
	int 80h
