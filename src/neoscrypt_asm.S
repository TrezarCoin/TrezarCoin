/*
 * Copyright (c) 2014 John Doering <ghostlander@phoenixcoin.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if (ASM) && (__x86_64__)

/* neoscrypt_copy(dst, src, len)
 * AMD64 memcpy() */
.globl neoscrypt_copy
.globl _neoscrypt_copy
neoscrypt_copy:
_neoscrypt_copy:
#if (WIN64)
	movq	%rdi, %r10
	movq	%rsi, %r11
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#endif
	xorq	%rcx, %rcx
	movl	%edx, %ecx
	shrq	$4, %rcx
	xorq	%r9, %r9
	cmpq	%r9, %rcx
	jz	.4byte_copy_test
.16byte_copy:
	movq	0(%rsi), %rax
	movq	8(%rsi), %r8
	movq	%rax, 0(%rdi)
	movq	%r8, 8(%rdi)
	addq	$16, %rsi
	addq	$16, %rdi
	decq	%rcx
	jnz	.16byte_copy

.4byte_copy_test:
	movl	%edx, %ecx
	shrq	$2, %rcx
	andq	$0x3, %rcx
	cmpq	%r9, %rcx
	jz	.byte_copy_test
.4byte_copy:
	movl	0(%rsi), %eax
	movl	%eax, 0(%rdi)
	addq	$4, %rsi
	addq	$4, %rdi
	decq	%rcx
	jnz	.4byte_copy

.byte_copy_test:
	movl	%edx, %ecx
	andq	$0x3, %rcx
	cmpq	%r9, %rcx
	jz	.copy_finish
.byte_copy:
	movb	0(%rsi), %al
	movb	%al, 0(%rdi)
	incq	%rsi
	incq	%rdi
	decq	%rcx
	jnz	.byte_copy

.copy_finish:
#if (WIN64)
	movq	%r10, %rdi
	movq	%r11, %rsi
#endif
	ret


/* neoscrypt_erase(dst, len)
 * AMD64 memory eraser */
.globl neoscrypt_erase
.globl _neoscrypt_erase
neoscrypt_erase:
_neoscrypt_erase:
#if (WIN64)
	movq	%rdi, %r10
	movq	%rsi, %r11
	movq	%rcx, %rdi
	movq	%rdx, %rsi
#endif
	xorq	%rcx, %rcx
	movl	%esi, %ecx
	shrq	$4, %rcx
	xorq	%rax, %rax
	cmpq	%rax, %rcx
	jz	.4byte_erase_test
.16byte_erase:
	movq	%rax, 0(%rdi)
	movq	%rax, 8(%rdi)
	addq	$16, %rdi
	decq	%rcx
	jnz	.16byte_erase

.4byte_erase_test:
	movl	%esi, %ecx
	shrq	$2, %rcx
	andq	$0x3, %rcx
	cmpq	%rax, %rcx
	jz	.byte_erase_test
.4byte_erase:
	movl	%eax, 0(%rdi)
	addq	$4, %rdi
	decq	%rcx
	jnz	.4byte_erase

.byte_erase_test:
	movl	%esi, %ecx
	andq	$0x3, %rcx
	cmpq	%rax, %rcx
	jz	.erase_finish
.byte_erase:
	movb	%al, 0(%rdi)
	incq	%rdi
	decq	%rcx
	jnz	.byte_erase

.erase_finish:
#if (WIN64)
	movq	%r10, %rdi
	movq	%r11, %rsi
#endif
	ret


/* neoscrypt_xor(dst, src, len)
 * AMD64 XOR engine */
.globl neoscrypt_xor
.globl _neoscrypt_xor
neoscrypt_xor:
_neoscrypt_xor:
#if (WIN64)
	movq	%rdi, %r10
	movq	%rsi, %r11
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#endif
	xorq	%rcx, %rcx
	movl	%edx, %ecx
	shrq	$4, %rcx
	xorq	%r9, %r9
	cmpq	%r9, %rcx
	jz	.4byte_xor_test
.16byte_xor:
	movq	0(%rsi), %rax
	movq	8(%rsi), %r8
	xorq	0(%rdi), %rax
	xorq	8(%rdi), %r8
	movq	%rax, 0(%rdi)
	movq	%r8, 8(%rdi)
	addq	$16, %rsi
	addq	$16, %rdi
	decq	%rcx
	jnz	.16byte_xor

.4byte_xor_test:
	movl	%edx, %ecx
	shrq	$2, %rcx
	andq	$0x3, %rcx
	cmpq	%r9, %rcx
	jz	.byte_xor_test
.4byte_xor:
	movl	0(%rsi), %eax
	xorl	0(%rdi), %eax
	movl	%eax, 0(%rdi)
	addq	$4, %rsi
	addq	$4, %rdi
	decq	%rcx
	jnz	.4byte_xor

.byte_xor_test:
	movl	%edx, %ecx
	andq	$0x3, %rcx
	cmpq	%r9, %rcx
	jz	.xor_finish
.byte_xor:
	movb	0(%rsi), %al
	xorb	0(%rdi), %al
	movb	%al, 0(%rdi)
	incq	%rsi
	incq	%rdi
	decq	%rcx
	jnz	.byte_xor

.xor_finish:
#if (WIN64)
	movq	%r10, %rdi
	movq	%r11, %rsi
#endif
	ret


/* neoscrypt_salsa_tangle(mem, count)
 * AMD64 (SSE2) Salsa20 map switcher;
 * correct map:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
 * SSE2 map:     0   5  10  15  12   1   6  11   8  13   2   7   4   9  14   3
 * NOTE: arguments passed in %r8 and %r9; %rbx not preserved */
neoscrypt_salsa_tangle_sse2:
.salsa_tangle_sse2:
	movl	4(%r8), %eax
	movl	20(%r8), %ebx
	movl	8(%r8), %ecx
	movl	40(%r8), %edx
	movl	%eax, 20(%r8)
	movl	%ebx, 4(%r8)
	movl	%ecx, 40(%r8)
	movl	%edx, 8(%r8)
	movl	12(%r8), %eax
	movl	60(%r8), %ebx
	movl	16(%r8), %ecx
	movl	48(%r8), %edx
	movl	%eax, 60(%r8)
	movl	%ebx, 12(%r8)
	movl	%ecx, 48(%r8)
	movl	%edx, 16(%r8)
	movl	28(%r8), %eax
	movl	44(%r8), %ebx
	movl	36(%r8), %ecx
	movl	52(%r8), %edx
	movl	%eax, 44(%r8)
	movl	%ebx, 28(%r8)
	movl	%ecx, 52(%r8)
	movl	%edx, 36(%r8)
	addq	$64, %r8
	decq	%r9
	jnz	.salsa_tangle_sse2

	ret


/* neoscrypt_xor_salsa_sse2(mem, xormem, double_rounds)
 * AMD64 (SSE2) Salsa20 with XOR;
 * mem and xormem must be aligned properly;
 * NOTE: arguments passed in %r8, %r9, %r10 */
neoscrypt_xor_salsa_sse2:
	movdqa	0(%r8), %xmm0
	movdqa	16(%r8), %xmm1
	movdqa	32(%r8), %xmm2
	movdqa	48(%r8), %xmm3
	pxor	0(%r9), %xmm0
	pxor	16(%r9), %xmm1
	pxor	32(%r9), %xmm2
	pxor	48(%r9), %xmm3
	movdqa	%xmm0, %xmm12
	movdqa	%xmm1, %xmm13
	movdqa	%xmm2, %xmm14
	movdqa	%xmm3, %xmm15
.xor_salsa_sse2:
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4E, %xmm2, %xmm2
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4E, %xmm2, %xmm2
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	decq	%r10
	jnz	.xor_salsa_sse2

	paddd	%xmm12, %xmm0
	paddd	%xmm13, %xmm1
	paddd	%xmm14, %xmm2
	paddd	%xmm15, %xmm3
	movdqa	%xmm0, 0(%r8)
	movdqa	%xmm1, 16(%r8)
	movdqa	%xmm2, 32(%r8)
	movdqa	%xmm3, 48(%r8)

	ret


/* neoscrypt_xor_chacha_sse2(mem, xormem, double_rounds)
 * AMD64 (SSE2) ChaCha20 with XOR;
 * mem and xormem must be aligned properly;
 * NOTE: arguments passed in %r8, %r9, %r10 */
neoscrypt_xor_chacha_sse2:
	movdqa	0(%r8), %xmm0
	movdqa	16(%r8), %xmm1
	movdqa	32(%r8), %xmm2
	movdqa	48(%r8), %xmm3
	pxor	0(%r9), %xmm0
	pxor	16(%r9), %xmm1
	pxor	32(%r9), %xmm2
	pxor	48(%r9), %xmm3
	movdqa	%xmm0, %xmm12
	movdqa	%xmm1, %xmm13
	movdqa	%xmm2, %xmm14
	movdqa	%xmm3, %xmm15
.xor_chacha_sse2:
	paddd	%xmm1, %xmm0
	pxor 	%xmm0, %xmm3
	pshuflw	$0xB1, %xmm3, %xmm3
	pshufhw	$0xB1, %xmm3, %xmm3
	paddd	%xmm3, %xmm2
	pxor 	%xmm2, %xmm1
	movdqa	%xmm1, %xmm4
	pslld	$12, %xmm1
	psrld	$20, %xmm4
	pxor	%xmm4, %xmm1
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movdqa	%xmm3, %xmm4
	pslld	$8, %xmm3
	psrld	$24, %xmm4
	pxor	%xmm4, %xmm3
	pshufd	$0x93, %xmm0, %xmm0
	paddd	%xmm3, %xmm2
	pshufd	$0x4E, %xmm3, %xmm3
	pxor	%xmm2, %xmm1
	pshufd	$0x39, %xmm2, %xmm2
	movdqa	%xmm1, %xmm4
	pslld	$7, %xmm1
	psrld	$25, %xmm4
	pxor	%xmm4, %xmm1
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	pshuflw	$0xB1, %xmm3, %xmm3
	pshufhw $0xB1, %xmm3, %xmm3
	paddd	%xmm3, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm1, %xmm4
	pslld	$12, %xmm1
	psrld	$20, %xmm4
	pxor	%xmm4, %xmm1
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movdqa	%xmm3, %xmm4
	pslld	$8, %xmm3
	psrld	$24, %xmm4
	pxor	%xmm4, %xmm3
	pshufd	$0x39, %xmm0, %xmm0
	paddd	%xmm3, %xmm2
	pshufd	$0x4E, %xmm3, %xmm3
	pxor	%xmm2, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	movdqa	%xmm1, %xmm4
	pslld	$7, %xmm1
	psrld	$25, %xmm4
	pxor	%xmm4, %xmm1
	decq	%r10
	jnz	.xor_chacha_sse2

	paddd	%xmm12, %xmm0
	paddd	%xmm13, %xmm1
	paddd	%xmm14, %xmm2
	paddd	%xmm15, %xmm3
	movdqa	%xmm0, 0(%r8)
	movdqa	%xmm1, 16(%r8)
	movdqa	%xmm2, 32(%r8)
	movdqa	%xmm3, 48(%r8)

	ret


/* neoscrypt_xor_salsa(mem, xormem, tempmem, double_rounds)
 * AMD64 (INT) Salsa20 with XOR (SSE2 support required);
 * NOTE: arguments passed in %r8, %r9, %r10, %r11 */
neoscrypt_xor_salsa:
/* XOR and copy to temporary memory */
	movdqa	0(%r8), %xmm0
	movdqa	16(%r8), %xmm1
	movdqa	32(%r8), %xmm2
	movdqa	48(%r8), %xmm3
	pxor	0(%r9), %xmm0
	pxor	16(%r9), %xmm1
	pxor	32(%r9), %xmm2
	pxor	48(%r9), %xmm3
	movdqa	%xmm0, 0(%r10)
	movdqa	%xmm1, 16(%r10)
	movdqa	%xmm2, 32(%r10)
	movdqa	%xmm3, 48(%r10)
	movdqa	%xmm0, %xmm12
	movdqa	%xmm1, %xmm13
	movdqa	%xmm2, %xmm14
	movdqa	%xmm3, %xmm15
.xor_salsa:
/* quarters A and B */
	movl	0(%r10), %eax	/* A: load a */
	movl	20(%r10), %ebx	/* B: load a */
	addl	48(%r10), %eax	/* A: t = a + d */
	addl	4(%r10), %ebx	/* B: t = a + d */
	roll	$7, %eax	/* A: rotate t */
	roll	$7, %ebx	/* B: rotate t */
	xorl	16(%r10), %eax	/* A: b = b ^ t */
	xorl	36(%r10), %ebx	/* B: b = b ^ t */
	movl	%eax, %esi	/* A: copy b */
	movl	%ebx, %edi	/* B: copy b */
	movl	%esi, 16(%r10)	/* A: store b */
	movl	%edi, 36(%r10)	/* B: store b */
	addl	0(%r10), %eax	/* A: t = b + a */
	addl	20(%r10), %ebx	/* B: t = b + a */
	roll	$9, %eax	/* A: rotate t */
	roll	$9, %ebx	/* B: rotate t */
	xorl	32(%r10), %eax	/* A: c = c ^ t */
	xorl	52(%r10), %ebx	/* B: c = c ^ t */
	movl	%eax, %ecx	/* A: copy c */
	movl	%ebx, %edx	/* B: copy c */
	movl	%ecx, 32(%r10)	/* A: store c */
	movl	%edx, 52(%r10)	/* B: store c */
	addl	%esi, %eax	/* A: t = c + b */
	addl	%edi, %ebx	/* B: t = c + b */
	roll	$13, %eax	/* A: rotate t */
	roll	$13, %ebx	/* B: rotate t */
	xorl	48(%r10), %eax	/* A: d = d ^ t */
	xorl	4(%r10), %ebx	/* B: d = d ^ t */
	movl	%eax, 48(%r10)	/* A: store d */
	movl	%ebx, 4(%r10)	/* B: store d */
	addl	%eax, %ecx	/* A: t = d + c */
	movl	40(%r10), %eax	/* C: load a */
	addl	%ebx, %edx	/* B: t = d + c */
	movl	60(%r10), %ebx	/* D: load a */
	roll	$18, %ecx	/* A: rotate t */
	addl	24(%r10), %eax	/* C: t = a + d */
	roll	$18, %edx	/* B: rotate t */
	addl	44(%r10), %ebx	/* D: t = a + d */
	xorl	0(%r10), %ecx	/* A: a = a ^ t */
	roll	$7, %eax	/* C: rotate t */
	xorl	20(%r10), %edx	/* B: a = a ^ t */
	roll	$7, %ebx	/* D: rotate t */
	movl	%ecx, 0(%r10)	/* A: store a */
	movl	%edx, 20(%r10)	/* B: store a */
/* quarters C and D */
	xorl	56(%r10), %eax
	xorl	12(%r10), %ebx
	movl	%eax, %esi
	movl	%ebx, %edi
	movl	%esi, 56(%r10)
	movl	%edi, 12(%r10)
	addl	40(%r10), %eax
	addl	60(%r10), %ebx
	roll	$9, %eax
	roll	$9, %ebx
	xorl	8(%r10), %eax
	xorl	28(%r10), %ebx
	movl	%eax, %ecx
	movl	%ebx, %edx
	movl	%ecx, 8(%r10)
	movl	%edx, 28(%r10)
	addl	%esi, %eax
	addl	%edi, %ebx
	roll	$13, %eax
	roll	$13, %ebx
	xorl	24(%r10), %eax
	xorl	44(%r10), %ebx
	movl	%eax, 24(%r10)
	movl	%ebx, 44(%r10)
	addl	%eax, %ecx
	movl	0(%r10), %eax	/* E */
	addl	%ebx, %edx
	movl	20(%r10), %ebx	/* F */
	roll	$18, %ecx
	addl	12(%r10), %eax	/* E */
	roll	$18, %edx
	addl	16(%r10), %ebx	/* F */
	xorl	40(%r10), %ecx
	roll	$7, %eax	/* E */
	xorl	60(%r10), %edx
	roll	$7, %ebx	/* F */
	movl	%ecx, 40(%r10)
	movl	%edx, 60(%r10)
/* quarters E and F */
	xorl	4(%r10), %eax
	xorl	24(%r10), %ebx
	movl	%eax, %esi
	movl	%ebx, %edi
	movl	%esi, 4(%r10)
	movl	%edi, 24(%r10)
	addl	0(%r10), %eax
	addl	20(%r10), %ebx
	roll	$9, %eax
	roll	$9, %ebx
	xorl	8(%r10), %eax
	xorl	28(%r10), %ebx
	movl	%eax, %ecx
	movl	%ebx, %edx
	movl	%ecx, 8(%r10)
	movl	%edx, 28(%r10)
	addl	%esi, %eax
	addl	%edi, %ebx
	roll	$13, %eax
	roll	$13, %ebx
	xorl	12(%r10), %eax
	xorl	16(%r10), %ebx
	movl	%eax, 12(%r10)
	movl	%ebx, 16(%r10)
	addl	%eax, %ecx
	movl	40(%r10), %eax	/* G */
	addl	%ebx, %edx
	movl	60(%r10), %ebx	/* H */
	roll	$18, %ecx
	addl	36(%r10), %eax	/* G */
	roll	$18, %edx
	addl	56(%r10), %ebx	/* H */
	xorl	0(%r10), %ecx
	roll	$7, %eax	/* G */
	xorl	20(%r10), %edx
	roll	$7, %ebx	/* H */
	movl	%ecx, 0(%r10)
	movl	%edx, 20(%r10)
/* quarters G and H */
	xorl	44(%r10), %eax
	xorl	48(%r10), %ebx
	movl	%eax, %esi
	movl	%ebx, %edi
	movl	%esi, 44(%r10)
	movl	%edi, 48(%r10)
	addl	40(%r10), %eax
	addl	60(%r10), %ebx
	roll	$9, %eax
	roll	$9, %ebx
	xorl	32(%r10), %eax
	xorl	52(%r10), %ebx
	movl	%eax, %ecx
	movl	%ebx, %edx
	movl	%ecx, 32(%r10)
	movl	%edx, 52(%r10)
	addl	%esi, %eax
	addl	%edi, %ebx
	roll	$13, %eax
	roll	$13, %ebx
	xorl	36(%r10), %eax
	xorl	56(%r10), %ebx
	movl	%eax, 36(%r10)
	movl	%ebx, 56(%r10)
	addl	%eax, %ecx
	addl	%ebx, %edx
	roll	$18, %ecx
	roll	$18, %edx
	xorl	40(%r10), %ecx
	xorl	60(%r10), %edx
	movl	%ecx, 40(%r10)
	movl	%edx, 60(%r10)
	decq	%r11
	jnz	.xor_salsa

	movdqa	0(%r10), %xmm0
	movdqa	16(%r10), %xmm1
	movdqa	32(%r10), %xmm2
	movdqa	48(%r10), %xmm3
	paddd	%xmm12, %xmm0
	paddd	%xmm13, %xmm1
	paddd	%xmm14, %xmm2
	paddd	%xmm15, %xmm3
	movdqa	%xmm0, 0(%r8)
	movdqa	%xmm1, 16(%r8)
	movdqa	%xmm2, 32(%r8)
	movdqa	%xmm3, 48(%r8)

	ret


/* neoscrypt_xor_chacha(mem, xormem, tempmem, double_rounds)
 * AMD64 (INT) ChaCha20 with XOR (SSE2 support required);
 * NOTE: arguments passed in %r8, %r9, %r10, %r11 */
neoscrypt_xor_chacha:
/* XOR and copy to temporary memory */
	movdqa	0(%r8), %xmm0
	movdqa	16(%r8), %xmm1
	movdqa	32(%r8), %xmm2
	movdqa	48(%r8), %xmm3
	pxor	0(%r9), %xmm0
	pxor	16(%r9), %xmm1
	pxor	32(%r9), %xmm2
	pxor	48(%r9), %xmm3
	movdqa	%xmm0, 0(%r10)
	movdqa	%xmm1, 16(%r10)
	movdqa	%xmm2, 32(%r10)
	movdqa	%xmm3, 48(%r10)
	movdqa	%xmm0, %xmm12
	movdqa	%xmm1, %xmm13
	movdqa	%xmm2, %xmm14
	movdqa	%xmm3, %xmm15
.xor_chacha:
/* quarter A */
	movl	16(%r10), %ebx	/* load b */
	movl	0(%r10), %eax	/* load a */
	addl	%ebx, %eax	/* a = a + b */
	movl	48(%r10), %edx	/* load d */
	xorl	%eax, %edx	/* d = d ^ a */
	movl	32(%r10), %ecx	/* load c */
	roll	$16, %edx	/* rotate d */
	movl	20(%r10), %esi	/* B: load b */
	addl	%edx, %ecx	/* c = c + d */
	movl	4(%r10), %edi	/* B: load a */
	xorl	%ecx, %ebx	/* b = b ^ c */
	addl	%esi, %edi	/* B: a = a + b */
	roll	$12, %ebx	/* rotate b */
	addl	%ebx, %eax	/* a = a + b */
	movl	%eax, 0(%r10)	/* store a */
	xorl	%eax, %edx	/* d = d ^ a */
	movl	52(%r10), %eax	/* B: load d */
	roll	$8, %edx	/* rotate d */
	xorl	%edi, %eax	/* B: d = d ^ a */
	movl	%edx, 48(%r10)	/* store d */
	addl	%edx, %ecx	/* c = c + d */
	roll	$16, %eax	/* B: rotate d */
	movl	%ecx, 32(%r10)	/* store c */
	movl	36(%r10), %edx	/* B: load c */
	xorl	%ecx, %ebx	/* b = b ^ c */
	addl	%eax, %edx	/* B: c = c + d */
	roll	$7, %ebx	/* rotate b */
	movl	24(%r10), %ecx	/* C: load b */
	movl	%ebx, 16(%r10)	/* store b */
/* quarter B */
	xorl	%edx, %esi	/* b = b ^ c */
	movl	8(%r10), %ebx	/* C: load a */
	roll	$12, %esi	/* rotate b */
	addl	%esi, %edi	/* a = a + b */
	addl	%ecx, %ebx	/* C: a = a + b */
	movl	%edi, 4(%r10)	/* store a */
	xorl	%edi, %eax	/* d = d ^ a */
	movl	56(%r10), %edi	/* C: load d */
	roll	$8, %eax	/* rotate d */
	xorl	%ebx, %edi	/* C: d = d ^ a */
	movl	%eax, 52(%r10)	/* store d */
	addl	%eax, %edx	/* c = c + d */
	roll	$16, %edi	/* C: rotate d */
	movl	%edx, 36(%r10)	/* store c */
	xorl	%edx, %esi	/* b = b ^ c */
	movl	40(%r10), %eax	/* C: load c */
	roll	$7, %esi	/* rotate b */
	addl	%edi, %eax	/* C: c = c + d */
	movl	%esi, 20(%r10)	/* store b */
/* quarter C */
	movl	28(%r10), %edx	/* D: load b */
	xorl	%eax, %ecx	/* b = b ^ c */
	movl	12(%r10), %esi	/* D: load a */
	roll	$12, %ecx	/* rotate b */
	addl	%ecx, %ebx	/* a = a + b */
	addl	%edx, %esi	/* D: a = a + b */
	movl	%ebx, 8(%r10)	/* store a */
	xorl	%ebx, %edi	/* d = d ^ a */
	movl	60(%r10), %ebx	/* D: load d */
	roll	$8, %edi	/* rotate d */
	xorl	%esi, %ebx	/* D: d = d ^ a */
	movl	%edi, 56(%r10)	/* store d */
	addl	%edi, %eax	/* c = c + d */
	roll	$16, %ebx	/* D: rotate d */
	movl	%eax, 40(%r10)	/* store c */
	xorl	%eax, %ecx	/* b = b ^ c */
	movl	44(%r10), %edi	/* D: load c */
	roll	$7, %ecx	/* rotate b */
	addl	%ebx, %edi	/* D: c = c + d */
	movl	%ecx, 24(%r10)	/* store b */
/* quarter D */
	xorl	%edi, %edx	/* b = b ^ c */
	roll	$12, %edx	/* rotate b */
	addl	%edx, %esi	/* a = a + b */
	movl	%esi, 12(%r10)	/* store a */
	xorl	%esi, %ebx	/* d = d ^ a */
	roll	$8, %ebx	/* rotate d */
	movl	%ebx, 60(%r10)	/* store d */
	addl	%ebx, %edi	/* c = c + d */
	movl	%edi, 44(%r10)	/* store c */
	xorl	%edi, %edx	/* b = b ^ c */
	roll	$7, %edx	/* rotate b */
	movl	%edx, 28(%r10)	/* store b */
/* quarter E */
	movl	0(%r10), %eax
	movl	20(%r10), %ebx
	addl	%ebx, %eax
	movl	60(%r10), %edx
	xorl	%eax, %edx
	movl	40(%r10), %ecx
	roll	$16, %edx
	movl	24(%r10), %esi
	addl	%edx, %ecx
	movl	4(%r10), %edi
	xorl	%ecx, %ebx
	addl	%esi, %edi
	roll	$12, %ebx
	addl	%ebx, %eax
	movl	%eax, 0(%r10)
	xorl	%eax, %edx
	movl	48(%r10), %eax
	roll	$8, %edx
	xorl	%edi, %eax
	movl	%edx, 60(%r10)
	addl	%edx, %ecx
	roll	$16, %eax
	movl	%ecx, 40(%r10)
	movl	44(%r10), %edx
	xorl	%ecx, %ebx
	addl	%eax, %edx
	roll	$7, %ebx
	movl	28(%r10), %ecx
	movl	%ebx, 20(%r10)
/* quarter F */
	xorl	%edx, %esi
	movl	8(%r10), %ebx
	roll	$12, %esi
	addl	%esi, %edi
	addl	%ecx, %ebx
	movl	%edi, 4(%r10)
	xorl	%edi, %eax
	movl	52(%r10), %edi
	roll	$8, %eax
	xorl	%ebx, %edi
	movl	%eax, 48(%r10)
	addl	%eax, %edx
	roll	$16, %edi
	movl	%edx, 44(%r10)
	xorl	%edx, %esi
	movl	32(%r10), %eax
	roll	$7, %esi
	addl	%edi, %eax
	movl	%esi, 24(%r10)
/* quarter G */
	movl	16(%r10), %edx
	xorl	%eax, %ecx
	movl	12(%r10), %esi
	roll	$12, %ecx
	addl	%ecx, %ebx
	addl	%edx, %esi
	movl	%ebx, 8(%r10)
	xorl	%ebx, %edi
	movl	56(%r10), %ebx
	roll	$8, %edi
	xorl	%esi, %ebx
	movl	%edi, 52(%r10)
	addl	%edi, %eax
	roll	$16, %ebx
	movl	%eax, 32(%r10)
	xorl	%eax, %ecx
	movl	36(%r10), %edi
	roll	$7, %ecx
	addl	%ebx, %edi
	movl	%ecx, 28(%r10)
/* quarter H */
	xorl	%edi, %edx
	roll	$12, %edx
	addl	%edx, %esi
	movl	%esi, 12(%r10)
	xorl	%esi, %ebx
	roll	$8, %ebx
	movl	%ebx, 56(%r10)
	addl	%ebx, %edi
	movl	%edi, 36(%r10)
	xorl	%edi, %edx
	roll	$7, %edx
	movl	%edx, 16(%r10)
	decq	%r11
	jnz	.xor_chacha

	movdqa	0(%r10), %xmm0
	movdqa	16(%r10), %xmm1
	movdqa	32(%r10), %xmm2
	movdqa	48(%r10), %xmm3
	paddd	%xmm12, %xmm0
	paddd	%xmm13, %xmm1
	paddd	%xmm14, %xmm2
	paddd	%xmm15, %xmm3
	movdqa	%xmm0, 0(%r8)
	movdqa	%xmm1, 16(%r8)
	movdqa	%xmm2, 32(%r8)
	movdqa	%xmm3, 48(%r8)

	ret


/* neoscrypt(input, output, profile)
 * AMD64 (INT, SSE2) NeoScrypt engine (SSE2 required for INT);
 * supports NeoScrypt and Scrypt only */
.globl neoscrypt
.globl _neoscrypt
neoscrypt:
_neoscrypt:
#if (WIN64)
	pushq	%rdi
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
	movq	%r8, %rdx
#endif
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
/* save input, output and profile */
	movq	%rdi, %r14
	movq	%rsi, %r15
	movq	%rdx, %rbx
	
#if (SHA256)
/* Scrypt mode */
	testl	$0x01, %ebx
	jnz	.scrypt
#endif

#if (WIN64)
/* attempt to allocate 33280 + 128 bytes of stack space fails miserably;
 * have to use malloc() and free() instead */
	subq	$128, %rsp
/* allocate memory (9 pages of 4Kb each) */
	movq	$0x9000, %rcx
	call	malloc
/* save memory address */
	movq	%rax, 64(%rsp)
/* align memory */
	addq	$64, %rax
	andq	$0xFFFFFFFFFFFFFFC0, %rax
/* memory base: X, Z, V */
	leaq	64(%rax), %rbp
#else
/* align stack */
	movq	%rsp, %rax
	andq	$0xFFFFFFFFFFFFFFC0, %rsp
	subq	$0x8280, %rsp
/* save unaligned stack */
	movq	%rax, 32(%rsp)
/* memory base: X, Z, V */
	leaq	128(%rsp), %rbp
#endif /* WIN64 */

/* FastKDF */
#if (WIN64)
#if (OPT)
	movq	%r14, %rcx
	movq	%r14, %rdx
	movq	%rbp, %r8
	xorq	%r9, %r9
	call	neoscrypt_fastkdf_opt
#else
	movq	$80, %rax
	movq	%r14, %rcx
	movq	%rax, %rdx
	movq	%r14, %r8
	movq	%rax, %r9
	movq	$32, 32(%rsp)
	movq	%rbp, 40(%rsp)
	movq	$256, 48(%rsp)
	call	neoscrypt_fastkdf
#endif /* OPT */
#else
#if (OPT)
	movq	%r14, %rdi
	movq	%r14, %rsi
	movq	%rbp, %rdx
	xorq	%rcx, %rcx
#if (__APPLE__)
	call	_neoscrypt_fastkdf_opt
#else
	call	neoscrypt_fastkdf_opt
#endif /* __APPLE__ */
#else
	movq	$80, %rax
	movq	%r14, %rdi
	movq	%rax, %rsi
	movq	%r14, %rdx
	movq	%rax, %rcx
	movq	$32, %r8
	movq	%rbp, %r9
	movq	$256, 0(%rsp)
#if (__APPLE__)
	call	_neoscrypt_fastkdf
#else
	call	neoscrypt_fastkdf
#endif /* __APPLE__ */
#endif /* OPT */
#endif /* WIN64 */

/* blkcpy(Z, X) */
	leaq	256(%rbp), %rax
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	128(%rbp), %xmm8
	movdqa	144(%rbp), %xmm9
	movdqa	160(%rbp), %xmm10
	movdqa	176(%rbp), %xmm11
	movdqa	192(%rbp), %xmm12
	movdqa	208(%rbp), %xmm13
	movdqa	224(%rbp), %xmm14
	movdqa	240(%rbp), %xmm15
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
	movdqa	%xmm8, 128(%rax)
	movdqa	%xmm9, 144(%rax)
	movdqa	%xmm10, 160(%rax)
	movdqa	%xmm11, 176(%rax)
	movdqa	%xmm12, 192(%rax)
	movdqa	%xmm13, 208(%rax)
	movdqa	%xmm14, 224(%rax)
	movdqa	%xmm15, 240(%rax)

/* SSE2 switch */
	testl	$0x1000, %ebx
	jnz	.neoscrypt_sse2

/* tempmem and double rounds */
	leaq	-64(%rbp), %r10
	movq	$10, %r12

	xorq	%r13, %r13
.chacha_ns1:
/* blkcpy(V, Z) */
	leaq	512(%rbp), %rax
	movq	%r13, %rdx
	movb	$8, %cl
	shlq	%cl, %rdx
	leaq	256(%rbp), %rcx
	addq	%rdx, %rax
	movdqa	0(%rcx), %xmm0
	movdqa	16(%rcx), %xmm1
	movdqa	32(%rcx), %xmm2
	movdqa	48(%rcx), %xmm3
	movdqa	64(%rcx), %xmm4
	movdqa	80(%rcx), %xmm5
	movdqa	96(%rcx), %xmm6
	movdqa	112(%rcx), %xmm7
	movdqa	128(%rcx), %xmm8
	movdqa	144(%rcx), %xmm9
	movdqa	160(%rcx), %xmm10
	movdqa	176(%rcx), %xmm11
	movdqa	192(%rcx), %xmm12
	movdqa	208(%rcx), %xmm13
	movdqa	224(%rcx), %xmm14
	movdqa	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
	movdqa	%xmm8, 128(%rax)
	movdqa	%xmm9, 144(%rax)
	movdqa	%xmm10, 160(%rax)
	movdqa	%xmm11, 176(%rax)
	movdqa	%xmm12, 192(%rax)
	movdqa	%xmm13, 208(%rax)
	movdqa	%xmm14, 224(%rax)
	movdqa	%xmm15, 240(%rax)
/* blkmix(Z) */
	leaq	256(%rbp), %r8
	leaq	448(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	320(%rbp), %r8
	leaq	256(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	384(%rbp), %r8
	leaq	320(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	448(%rbp), %r8
	leaq	384(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	320(%rbp), %rax
	leaq	384(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.chacha_ns1

	xorq	%r13, %r13
.chacha_ns2:
/* integerify(Z) mod 128 */
	leaq	256(%rbp), %rax
	leaq	512(%rbp), %rcx
	xorq	%rdx, %rdx
	movl	448(%rbp), %edx
	andl	$0x7F, %edx
	shlq	$8, %rdx
	addq	%rdx, %rcx
/* blkxor(Z, V) */
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	64(%rax), %xmm4
	movdqa	80(%rax), %xmm5
	movdqa	96(%rax), %xmm6
	movdqa	112(%rax), %xmm7
	movdqa	128(%rax), %xmm8
	movdqa	144(%rax), %xmm9
	movdqa	160(%rax), %xmm10
	movdqa	176(%rax), %xmm11
	movdqa	192(%rax), %xmm12
	movdqa	208(%rax), %xmm13
	movdqa	224(%rax), %xmm14
	movdqa	240(%rax), %xmm15
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	pxor	128(%rcx), %xmm8
	pxor	144(%rcx), %xmm9
	pxor	160(%rcx), %xmm10
	pxor	176(%rcx), %xmm11
	pxor	192(%rcx), %xmm12
	pxor	208(%rcx), %xmm13
	pxor	224(%rcx), %xmm14
	pxor	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
	movdqa	%xmm8, 128(%rax)
	movdqa	%xmm9, 144(%rax)
	movdqa	%xmm10, 160(%rax)
	movdqa	%xmm11, 176(%rax)
	movdqa	%xmm12, 192(%rax)
	movdqa	%xmm13, 208(%rax)
	movdqa	%xmm14, 224(%rax)
	movdqa	%xmm15, 240(%rax)
/* blkmix(Z) */
	leaq	256(%rbp), %r8
	leaq	448(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	320(%rbp), %r8
	leaq	256(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	384(%rbp), %r8
	leaq	320(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	448(%rbp), %r8
	leaq	384(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_chacha
	leaq	320(%rbp), %rax
	leaq	384(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.chacha_ns2

	xorq	%r13, %r13
.salsa_ns1:
/* blkcpy(V, X) */
	leaq	512(%rbp), %rax
	movq	%r13, %rdx
	movb	$8, %cl
	shlq	%cl, %rdx
	addq	%rdx, %rax
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	128(%rbp), %xmm8
	movdqa	144(%rbp), %xmm9
	movdqa	160(%rbp), %xmm10
	movdqa	176(%rbp), %xmm11
	movdqa	192(%rbp), %xmm12
	movdqa	208(%rbp), %xmm13
	movdqa	224(%rbp), %xmm14
	movdqa	240(%rbp), %xmm15
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
	movdqa	%xmm8, 128(%rax)
	movdqa	%xmm9, 144(%rax)
	movdqa	%xmm10, 160(%rax)
	movdqa	%xmm11, 176(%rax)
	movdqa	%xmm12, 192(%rax)
	movdqa	%xmm13, 208(%rax)
	movdqa	%xmm14, 224(%rax)
	movdqa	%xmm15, 240(%rax)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	192(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	128(%rbp), %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	192(%rbp), %r8
	leaq	128(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	64(%rbp), %rax
	leaq	128(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.salsa_ns1

	xorq	%r13, %r13
.salsa_ns2:
/* integerify(X) mod 128 */
	leaq	512(%rbp), %rcx
	xorq	%rdx, %rdx
	movl	192(%rbp), %edx
	andl	$0x7F, %edx
	shlq	$8, %rdx
	addq	%rdx, %rcx
/* blkxor(X, V) */
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	128(%rbp), %xmm8
	movdqa	144(%rbp), %xmm9
	movdqa	160(%rbp), %xmm10
	movdqa	176(%rbp), %xmm11
	movdqa	192(%rbp), %xmm12
	movdqa	208(%rbp), %xmm13
	movdqa	224(%rbp), %xmm14
	movdqa	240(%rbp), %xmm15
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	pxor	128(%rcx), %xmm8
	pxor	144(%rcx), %xmm9
	pxor	160(%rcx), %xmm10
	pxor	176(%rcx), %xmm11
	pxor	192(%rcx), %xmm12
	pxor	208(%rcx), %xmm13
	pxor	224(%rcx), %xmm14
	pxor	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rbp)
	movdqa	%xmm1, 16(%rbp)
	movdqa	%xmm2, 32(%rbp)
	movdqa	%xmm3, 48(%rbp)
	movdqa	%xmm4, 64(%rbp)
	movdqa	%xmm5, 80(%rbp)
	movdqa	%xmm6, 96(%rbp)
	movdqa	%xmm7, 112(%rbp)
	movdqa	%xmm8, 128(%rbp)
	movdqa	%xmm9, 144(%rbp)
	movdqa	%xmm10, 160(%rbp)
	movdqa	%xmm11, 176(%rbp)
	movdqa	%xmm12, 192(%rbp)
	movdqa	%xmm13, 208(%rbp)
	movdqa	%xmm14, 224(%rbp)
	movdqa	%xmm15, 240(%rbp)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	192(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	128(%rbp), %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	192(%rbp), %r8
	leaq	128(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	64(%rbp), %rax
	leaq	128(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.salsa_ns2

/* blkxor(X, Z) */
	leaq	256(%rbp), %rcx
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	128(%rbp), %xmm8
	movdqa	144(%rbp), %xmm9
	movdqa	160(%rbp), %xmm10
	movdqa	176(%rbp), %xmm11
	movdqa	192(%rbp), %xmm12
	movdqa	208(%rbp), %xmm13
	movdqa	224(%rbp), %xmm14
	movdqa	240(%rbp), %xmm15
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	pxor	128(%rcx), %xmm8
	pxor	144(%rcx), %xmm9
	pxor	160(%rcx), %xmm10
	pxor	176(%rcx), %xmm11
	pxor	192(%rcx), %xmm12
	pxor	208(%rcx), %xmm13
	pxor	224(%rcx), %xmm14
	pxor	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rbp)
	movdqa	%xmm1, 16(%rbp)
	movdqa	%xmm2, 32(%rbp)
	movdqa	%xmm3, 48(%rbp)
	movdqa	%xmm4, 64(%rbp)
	movdqa	%xmm5, 80(%rbp)
	movdqa	%xmm6, 96(%rbp)
	movdqa	%xmm7, 112(%rbp)
	movdqa	%xmm8, 128(%rbp)
	movdqa	%xmm9, 144(%rbp)
	movdqa	%xmm10, 160(%rbp)
	movdqa	%xmm11, 176(%rbp)
	movdqa	%xmm12, 192(%rbp)
	movdqa	%xmm13, 208(%rbp)
	movdqa	%xmm14, 224(%rbp)
	movdqa	%xmm15, 240(%rbp)

/* FastKDF */
#if (WIN64)
#if (OPT)
	movq	%r14, %rcx
	movq	%rbp, %rdx
	movq	%r15, %r8
	xorq	%r9, %r9
	incq	%r9
	call	neoscrypt_fastkdf_opt
#else
	movq	%r14, %rcx
	movq	$80, %rdx
	movq	%rbp, %r8
	movq	$256, %r9
	movq	$32, %rax
	movq	%rax, 32(%rsp)
	movq	%r15, 40(%rsp)
	movq	%rax, 48(%rsp)
	call	neoscrypt_fastkdf
#endif /* OPT */
#else
#if (OPT)
	movq	%r14, %rdi
	movq	%rbp, %rsi
	movq	%r15, %rdx
	xorq	%rcx, %rcx
	incq	%rcx
#if (__APPLE__)
	call	_neoscrypt_fastkdf_opt
#else
	call	neoscrypt_fastkdf_opt
#endif /* __APPLE__ */
#else
	movq	%r14, %rdi
	movq	$80, %rsi
	movq	%rbp, %rdx
	movq	$256, %rcx
	movq	$32, %r8
	movq	%r15, %r9
	movq	$32, 0(%rsp)
#if (__APPLE__)
	call	_neoscrypt_fastkdf
#else
	call	neoscrypt_fastkdf
#endif /* __APPLE__ */
#endif /* OPT */
#endif /* WIN64 */

#if (WIN64)
/* free memory */
	movq	64(%rsp), %rcx
	call	free
/* restore stack */
	addq	$128, %rsp
#else
/* restore stack */
	movq	32(%rsp), %rsp
#endif
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
#if (WIN64)
	popq	%rsi
	popq	%rdi
#endif
	ret

.neoscrypt_sse2:
	movq	$10, %r12

	xorq	%r13, %r13
.chacha_ns1_sse2:
/* blkcpy(V, Z) */
	leaq	512(%rbp), %rax
	movq	%r13, %rdx
	movb	$8, %cl
	shlq	%cl, %rdx
	leaq	256(%rbp), %rcx
	addq	%rdx, %rax
	movdqa	0(%rcx), %xmm0
	movdqa	16(%rcx), %xmm1
	movdqa	32(%rcx), %xmm2
	movdqa	48(%rcx), %xmm3
	movdqa	64(%rcx), %xmm4
	movdqa	80(%rcx), %xmm5
	movdqa	96(%rcx), %xmm6
	movdqa	112(%rcx), %xmm7
	movdqa	128(%rcx), %xmm8
	movdqa	144(%rcx), %xmm9
	movdqa	160(%rcx), %xmm10
	movdqa	176(%rcx), %xmm11
	movdqa	192(%rcx), %xmm12
	movdqa	208(%rcx), %xmm13
	movdqa	224(%rcx), %xmm14
	movdqa	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
	movdqa	%xmm8, 128(%rax)
	movdqa	%xmm9, 144(%rax)
	movdqa	%xmm10, 160(%rax)
	movdqa	%xmm11, 176(%rax)
	movdqa	%xmm12, 192(%rax)
	movdqa	%xmm13, 208(%rax)
	movdqa	%xmm14, 224(%rax)
	movdqa	%xmm15, 240(%rax)
/* blkmix(Z) */
	leaq	256(%rbp), %r8
	leaq	448(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	320(%rbp), %r8
	leaq	256(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	384(%rbp), %r8
	leaq	320(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	448(%rbp), %r8
	leaq	384(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	320(%rbp), %rax
	leaq	384(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.chacha_ns1_sse2

	xorq	%r13, %r13
.chacha_ns2_sse2:
/* integerify(Z) mod 128 */
	leaq	256(%rbp), %rax
	leaq	512(%rbp), %rcx
	xorq	%rdx, %rdx
	movl	448(%rbp), %edx
	andl	$0x7F, %edx
	shlq	$8, %rdx
	addq	%rdx, %rcx
/* blkxor(Z, V) */
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	64(%rax), %xmm4
	movdqa	80(%rax), %xmm5
	movdqa	96(%rax), %xmm6
	movdqa	112(%rax), %xmm7
	movdqa	128(%rax), %xmm8
	movdqa	144(%rax), %xmm9
	movdqa	160(%rax), %xmm10
	movdqa	176(%rax), %xmm11
	movdqa	192(%rax), %xmm12
	movdqa	208(%rax), %xmm13
	movdqa	224(%rax), %xmm14
	movdqa	240(%rax), %xmm15
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	pxor	128(%rcx), %xmm8
	pxor	144(%rcx), %xmm9
	pxor	160(%rcx), %xmm10
	pxor	176(%rcx), %xmm11
	pxor	192(%rcx), %xmm12
	pxor	208(%rcx), %xmm13
	pxor	224(%rcx), %xmm14
	pxor	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
	movdqa	%xmm8, 128(%rax)
	movdqa	%xmm9, 144(%rax)
	movdqa	%xmm10, 160(%rax)
	movdqa	%xmm11, 176(%rax)
	movdqa	%xmm12, 192(%rax)
	movdqa	%xmm13, 208(%rax)
	movdqa	%xmm14, 224(%rax)
	movdqa	%xmm15, 240(%rax)
/* blkmix(Z) */
	leaq	256(%rbp), %r8
	leaq	448(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	320(%rbp), %r8
	leaq	256(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	384(%rbp), %r8
	leaq	320(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	448(%rbp), %r8
	leaq	384(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_chacha_sse2
	leaq	320(%rbp), %rax
	leaq	384(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.chacha_ns2_sse2

	movq	%rbp, %r8
	movq	$4, %r9
	call	neoscrypt_salsa_tangle_sse2

	xorq	%r13, %r13
.salsa_ns1_sse2:
/* blkcpy(V, X) */
	leaq	512(%rbp), %rax
	movq	%r13, %rdx
	movb	$8, %cl
	shlq	%cl, %rdx
	addq	%rdx, %rax
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	128(%rbp), %xmm8
	movdqa	144(%rbp), %xmm9
	movdqa	160(%rbp), %xmm10
	movdqa	176(%rbp), %xmm11
	movdqa	192(%rbp), %xmm12
	movdqa	208(%rbp), %xmm13
	movdqa	224(%rbp), %xmm14
	movdqa	240(%rbp), %xmm15
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
	movdqa	%xmm8, 128(%rax)
	movdqa	%xmm9, 144(%rax)
	movdqa	%xmm10, 160(%rax)
	movdqa	%xmm11, 176(%rax)
	movdqa	%xmm12, 192(%rax)
	movdqa	%xmm13, 208(%rax)
	movdqa	%xmm14, 224(%rax)
	movdqa	%xmm15, 240(%rax)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	192(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	128(%rbp), %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	192(%rbp), %r8
	leaq	128(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	64(%rbp), %rax
	leaq	128(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.salsa_ns1_sse2

	xorq	%r13, %r13
.salsa_ns2_sse2:
/* integerify(X) mod 128 */
	leaq	512(%rbp), %rcx
	xorq	%rdx, %rdx
	movl	192(%rbp), %edx
	andl	$0x7F, %edx
	shlq	$8, %rdx
	addq	%rdx, %rcx
/* blkxor(X, V) */
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	128(%rbp), %xmm8
	movdqa	144(%rbp), %xmm9
	movdqa	160(%rbp), %xmm10
	movdqa	176(%rbp), %xmm11
	movdqa	192(%rbp), %xmm12
	movdqa	208(%rbp), %xmm13
	movdqa	224(%rbp), %xmm14
	movdqa	240(%rbp), %xmm15
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	pxor	128(%rcx), %xmm8
	pxor	144(%rcx), %xmm9
	pxor	160(%rcx), %xmm10
	pxor	176(%rcx), %xmm11
	pxor	192(%rcx), %xmm12
	pxor	208(%rcx), %xmm13
	pxor	224(%rcx), %xmm14
	pxor	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rbp)
	movdqa	%xmm1, 16(%rbp)
	movdqa	%xmm2, 32(%rbp)
	movdqa	%xmm3, 48(%rbp)
	movdqa	%xmm4, 64(%rbp)
	movdqa	%xmm5, 80(%rbp)
	movdqa	%xmm6, 96(%rbp)
	movdqa	%xmm7, 112(%rbp)
	movdqa	%xmm8, 128(%rbp)
	movdqa	%xmm9, 144(%rbp)
	movdqa	%xmm10, 160(%rbp)
	movdqa	%xmm11, 176(%rbp)
	movdqa	%xmm12, 192(%rbp)
	movdqa	%xmm13, 208(%rbp)
	movdqa	%xmm14, 224(%rbp)
	movdqa	%xmm15, 240(%rbp)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	192(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	128(%rbp), %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	192(%rbp), %r8
	leaq	128(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	64(%rbp), %rax
	leaq	128(%rbp), %rdx
	movdqa	0(%rax), %xmm0
	movdqa	16(%rax), %xmm1
	movdqa	32(%rax), %xmm2
	movdqa	48(%rax), %xmm3
	movdqa	0(%rdx), %xmm4
	movdqa	16(%rdx), %xmm5
	movdqa	32(%rdx), %xmm6
	movdqa	48(%rdx), %xmm7
	movdqa	%xmm0, 0(%rdx)
	movdqa	%xmm1, 16(%rdx)
	movdqa	%xmm2, 32(%rdx)
	movdqa	%xmm3, 48(%rdx)
	movdqa	%xmm4, 0(%rax)
	movdqa	%xmm5, 16(%rax)
	movdqa	%xmm6, 32(%rax)
	movdqa	%xmm7, 48(%rax)
	incq	%r13
	cmpq	$128, %r13
	jnz	.salsa_ns2_sse2

	movq	%rbp, %r8
	movq	$4, %r9
	call	neoscrypt_salsa_tangle_sse2

/* blkxor(X, Z) */
	leaq	256(%rbp), %rcx
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	128(%rbp), %xmm8
	movdqa	144(%rbp), %xmm9
	movdqa	160(%rbp), %xmm10
	movdqa	176(%rbp), %xmm11
	movdqa	192(%rbp), %xmm12
	movdqa	208(%rbp), %xmm13
	movdqa	224(%rbp), %xmm14
	movdqa	240(%rbp), %xmm15
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	pxor	128(%rcx), %xmm8
	pxor	144(%rcx), %xmm9
	pxor	160(%rcx), %xmm10
	pxor	176(%rcx), %xmm11
	pxor	192(%rcx), %xmm12
	pxor	208(%rcx), %xmm13
	pxor	224(%rcx), %xmm14
	pxor	240(%rcx), %xmm15
	movdqa	%xmm0, 0(%rbp)
	movdqa	%xmm1, 16(%rbp)
	movdqa	%xmm2, 32(%rbp)
	movdqa	%xmm3, 48(%rbp)
	movdqa	%xmm4, 64(%rbp)
	movdqa	%xmm5, 80(%rbp)
	movdqa	%xmm6, 96(%rbp)
	movdqa	%xmm7, 112(%rbp)
	movdqa	%xmm8, 128(%rbp)
	movdqa	%xmm9, 144(%rbp)
	movdqa	%xmm10, 160(%rbp)
	movdqa	%xmm11, 176(%rbp)
	movdqa	%xmm12, 192(%rbp)
	movdqa	%xmm13, 208(%rbp)
	movdqa	%xmm14, 224(%rbp)
	movdqa	%xmm15, 240(%rbp)

/* FastKDF */
#if (WIN64)
#if (OPT)
	movq	%r14, %rcx
	movq	%rbp, %rdx
	movq	%r15, %r8
	xorq	%r9, %r9
	incq	%r9
	call	neoscrypt_fastkdf_opt
#else
	movq	%r14, %rcx
	movq	$80, %rdx
	movq	%rbp, %r8
	movq	$256, %r9
	movq	$32, %rax
	movq	%rax, 32(%rsp)
	movq	%r15, 40(%rsp)
	movq	%rax, 48(%rsp)
#endif /* OPT */
#else
#if (OPT)
	movq	%r14, %rdi
	movq	%rbp, %rsi
	movq	%r15, %rdx
	xorq	%rcx, %rcx
	incq	%rcx
#if (__APPLE__)
	call	_neoscrypt_fastkdf_opt
#else
	call	neoscrypt_fastkdf_opt
#endif /* __APPLE__ */
#else
	movq	%r14, %rdi
	movq	$80, %rsi
	movq	%rbp, %rdx
	movq	$256, %rcx
	movq	$32, %rax
	movq	%rax, %r8
	movq	%r15, %r9
	movq	%rax, 0(%rsp)
#if (__APPLE__)
	call	_neoscrypt_fastkdf
#else
	call	neoscrypt_fastkdf
#endif /* __APPLE__ */
#endif /* OPT */
#endif /* WIN64 */

#if (WIN64)
/* free memory */
	movq	64(%rsp), %rcx
	call	free
/* restore stack */
	addq	$128, %rsp
#else
/* restore stack */
	movq	32(%rsp), %rsp
#endif
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
#if (WIN64)
	popq	%rsi
	popq	%rdi
#endif
	ret

#if (SHA256)

.scrypt:
#if (WIN64)
/* attempt to allocate 131200 + 128 bytes of stack space fails miserably;
 * have to use malloc() and free() instead */
	subq	$128, %rsp
/* allocate memory (33 pages of 4Kb each) */
	movq	$0x21000, %rcx
	call	malloc
/* save memory address */
	movq	%rax, 64(%rsp)
/* align memory */
	addq	$64, %rax
	andq	$0xFFFFFFFFFFFFFFC0, %rax
/* memory base: X, Z, V */
	leaq	64(%rax), %rbp
#else
/* align stack */
	movq	%rsp, %rax
	andq	$0xFFFFFFFFFFFFFFC0, %rsp
	subq	$0x20100, %rsp
/* save unaligned stack */
	movq	%rax, 32(%rsp)
/* memory base: X, Z, V */
	leaq	128(%rsp), %rbp
#endif /* WIN64 */

/* PBKDF2-HMAC-SHA256 */
#if (WIN64)
	movq	$80, %rax
	movq	%r14, %rcx
	movq	%rax, %rdx
	movq	%r14, %r8
	movq	%rax, %r9
	movq	$1, 32(%rsp)
	movq	%rbp, 40(%rsp)
	movq	$128, 48(%rsp)
	call	neoscrypt_pbkdf2_sha256
#else
	movq	$80, %rax
	movq	%r14, %rdi
	movq	%rax, %rsi
	movq	%r14, %rdx
	movq	%rax, %rcx
	movq	$1, %r8
	movq	%rbp, %r9
	movq	$128, 0(%rsp)
#if (__APPLE__)
	call	_neoscrypt_pbkdf2_sha256
#else
	call	neoscrypt_pbkdf2_sha256
#endif /* __APPLE__ */
#endif /* WIN64 */

/* SSE2 switch */
	testl	$0x1000, %ebx
	jnz	.scrypt_sse2

/* tempmem and double rounds */
	leaq	-64(%rbp), %r10
	movq	$4, %r12

	xorq	%r13, %r13
.salsa_s1:
/* blkcpy(V, X) */
	leaq	128(%rbp), %rax
	movq	%r13, %rdx
	movb	$7, %cl
	shlq	%cl, %rdx
	addq	%rdx, %rax
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	incq	%r13
	cmpq	$1024, %r13
	jnz	.salsa_s1

	xorq	%r13, %r13
.salsa_s2:
/* integerify(X) mod 1024 */
	leaq	128(%rbp), %rcx
	xorq	%rdx, %rdx
	movl	64(%rbp), %edx
	andl	$0x03FF, %edx
	shlq	$7, %rdx
	addq	%rdx, %rcx
/* blkxor(X, V) */
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	movdqa	%xmm0, 0(%rbp)
	movdqa	%xmm1, 16(%rbp)
	movdqa	%xmm2, 32(%rbp)
	movdqa	%xmm3, 48(%rbp)
	movdqa	%xmm4, 64(%rbp)
	movdqa	%xmm5, 80(%rbp)
	movdqa	%xmm6, 96(%rbp)
	movdqa	%xmm7, 112(%rbp)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r11
	call	neoscrypt_xor_salsa
	incq	%r13
	cmpq	$1024, %r13
	jnz	.salsa_s2

/* PBKDF2-HMAC-SHA256 */
#if (WIN64)
	movq	%r14, %rcx
	movq	$80, %rdx
	movq	%rbp, %r8
	movq	$128, %r9
	movq	$1, 32(%rsp)
	movq	%r15, 40(%rsp)
	movq	$32, 48(%rsp)
	call	neoscrypt_pbkdf2_sha256
#else
	movq	%r14, %rdi
	movq	$80, %rsi
	movq	%rbp, %rdx
	movq	$128, %rcx
	movq	$1, %r8
	movq	%r15, %r9
	movq	$32, 0(%rsp)
#if (__APPLE__)
	call	_neoscrypt_pbkdf2_sha256
#else
	call	neoscrypt_pbkdf2_sha256
#endif /* __APPLE__ */
#endif /* WIN64 */

#if (WIN64)
/* free memory */
	movq	64(%rsp), %rcx
	call	free
/* restore stack */
	addq	$128, %rsp
#else
/* restore stack */
	movq	32(%rsp), %rsp
#endif
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
#if (WIN64)
	popq	%rsi
	popq	%rdi
#endif
	ret

.scrypt_sse2:
	movq	%rbp, %r8
	movq	$2, %r9
	call	neoscrypt_salsa_tangle_sse2

	movq	$4, %r12

	xorq	%r13, %r13
.salsa_s1_sse2:
/* blkcpy(V, X) */
	leaq	128(%rbp), %rax
	movq	%r13, %rdx
	movb	$7, %cl
	shlq	%cl, %rdx
	addq	%rdx, %rax
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	movdqa	%xmm0, 0(%rax)
	movdqa	%xmm1, 16(%rax)
	movdqa	%xmm2, 32(%rax)
	movdqa	%xmm3, 48(%rax)
	movdqa	%xmm4, 64(%rax)
	movdqa	%xmm5, 80(%rax)
	movdqa	%xmm6, 96(%rax)
	movdqa	%xmm7, 112(%rax)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	incq	%r13
	cmpq	$1024, %r13
	jnz	.salsa_s1_sse2

	xorq	%r13, %r13
.salsa_s2_sse2:
/* integerify(X) mod 1024 */
	leaq	128(%rbp), %rcx
	xorq	%rdx, %rdx
	movl	64(%rbp), %edx
	andl	$0x03FF, %edx
	shlq	$7, %rdx
	addq	%rdx, %rcx
/* blkxor(X, V) */
	movdqa	0(%rbp), %xmm0
	movdqa	16(%rbp), %xmm1
	movdqa	32(%rbp), %xmm2
	movdqa	48(%rbp), %xmm3
	movdqa	64(%rbp), %xmm4
	movdqa	80(%rbp), %xmm5
	movdqa	96(%rbp), %xmm6
	movdqa	112(%rbp), %xmm7
	pxor	0(%rcx), %xmm0
	pxor	16(%rcx), %xmm1
	pxor	32(%rcx), %xmm2
	pxor	48(%rcx), %xmm3
	pxor	64(%rcx), %xmm4
	pxor	80(%rcx), %xmm5
	pxor	96(%rcx), %xmm6
	pxor	112(%rcx), %xmm7
	movdqa	%xmm0, 0(%rbp)
	movdqa	%xmm1, 16(%rbp)
	movdqa	%xmm2, 32(%rbp)
	movdqa	%xmm3, 48(%rbp)
	movdqa	%xmm4, 64(%rbp)
	movdqa	%xmm5, 80(%rbp)
	movdqa	%xmm6, 96(%rbp)
	movdqa	%xmm7, 112(%rbp)
/* blkmix(X) */
	movq	%rbp, %r8
	leaq	64(%rbp), %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	leaq	64(%rbp), %r8
	movq	%rbp, %r9
	movq	%r12, %r10
	call	neoscrypt_xor_salsa_sse2
	incq	%r13
	cmpq	$1024, %r13
	jnz	.salsa_s2_sse2

	movq	%rbp, %r8
	movq	$2, %r9
	call	neoscrypt_salsa_tangle_sse2

/* PBKDF2-HMAC-SHA256 */
#if (WIN64)
	movq	%r14, %rcx
	movq	$80, %rdx
	movq	%rbp, %r8
	movq	$128, %r9
	movq	$1, 32(%rsp)
	movq	%r15, 40(%rsp)
	movq	$32, 48(%rsp)
	call	neoscrypt_pbkdf2_sha256
#else
	movq	%r14, %rdi
	movq	$80, %rsi
	movq	%rbp, %rdx
	movq	$128, %rcx
	movq	$1, %r8
	movq	%r15, %r9
	movq	$32, 0(%rsp)
#if (__APPLE__)
	call	_neoscrypt_pbkdf2_sha256
#else
	call	neoscrypt_pbkdf2_sha256
#endif /* __APPLE__ */
#endif /* WIN64 */

#if (WIN64)
/* free memory */
	movq	64(%rsp), %rcx
	call	free
/* restore stack */
	addq	$128, %rsp
#else
/* restore stack */
	movq	32(%rsp), %rsp
#endif
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
#if (WIN64)
	popq	%rsi
	popq	%rdi
#endif
	ret

#endif /* (SHA256) */

#endif /* (ASM) && (__x86_64__) */


#if (ASM) && (__i386__)

/* neoscrypt_copy(dst, src, len)
 * i386 memcpy() */
.globl neoscrypt_copy
.globl _neoscrypt_copy
neoscrypt_copy:
_neoscrypt_copy:
	pushl	%ebx
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	movl	20(%esp), %edi
	movl	24(%esp), %esi
	movl	28(%esp), %ecx
	shrl	$4, %ecx
	xorl	%eax, %eax
	cmpl	%eax, %ecx
	jz	.copy_tail
.copy_16b:
	movl	0(%esi), %eax
	movl	4(%esi), %edx
	movl	8(%esi), %ebx
	movl	12(%esi), %ebp
	movl	%eax, 0(%edi)
	movl	%edx, 4(%edi)
	movl	%ebx, 8(%edi)
	movl	%ebp, 12(%edi)
	addl	$16, %esi
	addl	$16, %edi
	decl	%ecx
	jnz	.copy_16b

.copy_tail:
	xorl	%eax, %eax
	movl	28(%esp), %ecx
	andl	$0xF, %ecx
	cmpl	%eax, %ecx
	jz	.copy_finish
	movb	%cl, %ch
	andb	$0x3, %cl
	shrb	$2, %ch
	cmpb	%ah, %ch
	jz	.copy_1b
.copy_4b:
	movl	0(%esi), %edx
	movl	%edx, 0(%edi)
	addl	$4, %esi
	addl	$4, %edi
	decb	%ch
	jnz	.copy_4b

	cmpb	%al, %cl
	jz	.copy_finish
.copy_1b:
	movb	0(%esi), %dl
	movb	%dl, 0(%edi)
	incl	%esi
	incl	%edi
	decb	%cl
	jnz	.copy_1b

.copy_finish:
	popl	%esi
	popl	%edi
	popl	%ebp
	popl	%ebx
	ret


/* neoscrypt_erase(dst, len)
 * i386 memory eraser */
.globl neoscrypt_erase
.globl _neoscrypt_erase
neoscrypt_erase:
_neoscrypt_erase:
	movl	4(%esp), %edx
	movl	8(%esp), %ecx
	shrl	$4, %ecx
	xorl	%eax, %eax
	cmpl	%eax, %ecx
	jz	.erase_tail
.erase_16b:
	movl	%eax, 0(%edx)
	movl	%eax, 4(%edx)
	movl	%eax, 8(%edx)
	movl	%eax, 12(%edx)
	addl	$16, %edx
	decl	%ecx
	jnz	.erase_16b

.erase_tail:
	movl	8(%esp), %ecx
	andl	$0xF, %ecx
	cmpl	%eax, %ecx
	jz	.erase_finish
	movb	%cl, %ch
	andb	$0x3, %cl
	shrb	$2, %ch
	cmpb	%ah, %ch
	jz	.erase_1b
.erase_4b:
	movl	%eax, 0(%edx)
	addl	$4, %edx
	decb	%ch
	jnz	.erase_4b

	cmpb	%al, %cl
	jz	.erase_finish
.erase_1b:
	movb	%al, 0(%edx)
	incl	%edx
	decb	%cl
	jnz	.erase_1b

.erase_finish:
	ret


/* neoscrypt_xor(dst, src, len)
 * i386 XOR engine */
.globl neoscrypt_xor
.globl _neoscrypt_xor
neoscrypt_xor:
_neoscrypt_xor:
	pushl	%ebx
	pushl	%ebp
	pushl	%edi
	pushl	%esi
	movl	20(%esp), %edi
	movl	24(%esp), %esi
	movl	28(%esp), %ecx
	shrl	$4, %ecx
	xorl	%eax, %eax
	cmpl	%eax, %ecx
	jz	.xor_tail
.xor_16b:
	movl	0(%edi), %eax
	movl	4(%edi), %edx
	movl	8(%edi), %ebx
	movl	12(%edi), %ebp
	xorl	0(%esi), %eax
	xorl	4(%esi), %edx
	xorl	8(%esi), %ebx
	xorl	12(%esi), %ebp
	movl	%eax, 0(%edi)
	movl	%edx, 4(%edi)
	movl	%ebx, 8(%edi)
	movl	%ebp, 12(%edi)
	addl	$16, %esi
	addl	$16, %edi
	decl	%ecx
	jnz	.xor_16b

.xor_tail:
	xorl	%eax, %eax
	movl	28(%esp), %ecx
	andl	$0xF, %ecx
	cmpl	%eax, %ecx
	jz	.xor_finish
	movb	%cl, %ch
	andb	$0x3, %cl
	shrb	$2, %ch
	cmpb	%ah, %ch
	jz	.xor_1b
.xor_4b:
	movl	0(%edi), %edx
	xorl	0(%esi), %edx
	movl	%edx, 0(%edi)
	addl	$4, %esi
	addl	$4, %edi
	decb	%ch
	jnz	.xor_4b

	cmpb	%al, %cl
	jz	.xor_finish
.xor_1b:
	movb	0(%edi), %dl
	xorb	0(%esi), %dl
	movb	%dl, 0(%edi)
	incl	%esi
	incl	%edi
	decb	%cl
	jnz	.xor_1b

.xor_finish:
	popl	%esi
	popl	%edi
	popl	%ebp
	popl	%ebx
	ret


/* neoscrypt_xor_salsa(mem, xormem, workmem, double_rounds)
 * i386 (INT) Salsa20 with XOR (MMX support required) */
neoscrypt_xor_salsa:
	pushl	%ebx
	pushl	%ebp
	pushl	%esi
	pushl	%edi
/* XOR and copy to temporary memory */
	movl	20(%esp), %ebx
	movl	24(%esp), %ecx
	movl	28(%esp), %ebp
	movq	0(%ebx), %mm0
	movq	8(%ebx), %mm1
	movq	16(%ebx), %mm2
	movq	24(%ebx), %mm3
	movq	32(%ebx), %mm4
	movq	40(%ebx), %mm5
	movq	48(%ebx), %mm6
	movq	56(%ebx), %mm7
	pxor	0(%ecx), %mm0
	pxor	8(%ecx), %mm1
	pxor	16(%ecx), %mm2
	pxor	24(%ecx), %mm3
	pxor	32(%ecx), %mm4
	pxor	40(%ecx), %mm5
	pxor	48(%ecx), %mm6
	pxor	56(%ecx), %mm7
	movq	%mm0, 0(%ebx)
	movq	%mm1, 8(%ebx)
	movq	%mm2, 16(%ebx)
	movq	%mm3, 24(%ebx)
	movq	%mm4, 32(%ebx)
	movq	%mm5, 40(%ebx)
	movq	%mm6, 48(%ebx)
	movq	%mm7, 56(%ebx)
	movq	%mm0, 0(%ebp)
	movq	%mm1, 8(%ebp)
	movq	%mm2, 16(%ebp)
	movq	%mm3, 24(%ebp)
	movq	%mm4, 32(%ebp)
	movq	%mm5, 40(%ebp)
	movq	%mm6, 48(%ebp)
	movq	%mm7, 56(%ebp)
/* number of double rounds */
	movl	32(%esp), %eax
	movl	%eax, -4(%esp)
.xor_salsa:
/* quarters A and B */
	movl	0(%ebp), %eax	/* A: load a */
	movl	20(%ebp), %ebx	/* B: load a */
	addl	48(%ebp), %eax	/* A: t = a + d */
	addl	4(%ebp), %ebx	/* B: t = a + d */
	roll	$7, %eax	/* A: rotate t */
	roll	$7, %ebx	/* B: rotate t */
	xorl	16(%ebp), %eax	/* A: b = b ^ t */
	xorl	36(%ebp), %ebx	/* B: b = b ^ t */
	movl	%eax, %esi	/* A: copy b */
	movl	%ebx, %edi	/* B: copy b */
	movl	%esi, 16(%ebp)	/* A: store b */
	movl	%edi, 36(%ebp)	/* B: store b */
	addl	0(%ebp), %eax	/* A: t = b + a */
	addl	20(%ebp), %ebx	/* B: t = b + a */
	roll	$9, %eax	/* A: rotate t */
	roll	$9, %ebx	/* B: rotate t */
	xorl	32(%ebp), %eax	/* A: c = c ^ t */
	xorl	52(%ebp), %ebx	/* B: c = c ^ t */
	movl	%eax, %ecx	/* A: copy c */
	movl	%ebx, %edx	/* B: copy c */
	movl	%ecx, 32(%ebp)	/* A: store c */
	movl	%edx, 52(%ebp)	/* B: store c */
	addl	%esi, %eax	/* A: t = c + b */
	addl	%edi, %ebx	/* B: t = c + b */
	roll	$13, %eax	/* A: rotate t */
	roll	$13, %ebx	/* B: rotate t */
	xorl	48(%ebp), %eax	/* A: d = d ^ t */
	xorl	4(%ebp), %ebx	/* B: d = d ^ t */
	movl	%eax, 48(%ebp)	/* A: store d */
	movl	%ebx, 4(%ebp)	/* B: store d */
	addl	%eax, %ecx	/* A: t = d + c */
	movl	40(%ebp), %eax	/* C: load a */
	addl	%ebx, %edx	/* B: t = d + c */
	movl	60(%ebp), %ebx	/* D: load a */
	roll	$18, %ecx	/* A: rotate t */
	addl	24(%ebp), %eax	/* C: t = a + d */
	roll	$18, %edx	/* B: rotate t */
	addl	44(%ebp), %ebx	/* D: t = a + d */
	xorl	0(%ebp), %ecx	/* A: a = a ^ t */
	roll	$7, %eax	/* C: rotate t */
	xorl	20(%ebp), %edx	/* B: a = a ^ t */
	roll	$7, %ebx	/* D: rotate t */
	movl	%ecx, 0(%ebp)	/* A: store a */
	movl	%edx, 20(%ebp)	/* B: store a */
/* quarters C and D */
	xorl	56(%ebp), %eax
	xorl	12(%ebp), %ebx
	movl	%eax, %esi
	movl	%ebx, %edi
	movl	%esi, 56(%ebp)
	movl	%edi, 12(%ebp)
	addl	40(%ebp), %eax
	addl	60(%ebp), %ebx
	roll	$9, %eax
	roll	$9, %ebx
	xorl	8(%ebp), %eax
	xorl	28(%ebp), %ebx
	movl	%eax, %ecx
	movl	%ebx, %edx
	movl	%ecx, 8(%ebp)
	movl	%edx, 28(%ebp)
	addl	%esi, %eax
	addl	%edi, %ebx
	roll	$13, %eax
	roll	$13, %ebx
	xorl	24(%ebp), %eax
	xorl	44(%ebp), %ebx
	movl	%eax, 24(%ebp)
	movl	%ebx, 44(%ebp)
	addl	%eax, %ecx
	movl	0(%ebp), %eax	/* E */
	addl	%ebx, %edx
	movl	20(%ebp), %ebx	/* F */
	roll	$18, %ecx
	addl	12(%ebp), %eax	/* E */
	roll	$18, %edx
	addl	16(%ebp), %ebx	/* F */
	xorl	40(%ebp), %ecx
	roll	$7, %eax	/* E */
	xorl	60(%ebp), %edx
	roll	$7, %ebx	/* F */
	movl	%ecx, 40(%ebp)
	movl	%edx, 60(%ebp)
/* quarters E and F */
	xorl	4(%ebp), %eax
	xorl	24(%ebp), %ebx
	movl	%eax, %esi
	movl	%ebx, %edi
	movl	%esi, 4(%ebp)
	movl	%edi, 24(%ebp)
	addl	0(%ebp), %eax
	addl	20(%ebp), %ebx
	roll	$9, %eax
	roll	$9, %ebx
	xorl	8(%ebp), %eax
	xorl	28(%ebp), %ebx
	movl	%eax, %ecx
	movl	%ebx, %edx
	movl	%ecx, 8(%ebp)
	movl	%edx, 28(%ebp)
	addl	%esi, %eax
	addl	%edi, %ebx
	roll	$13, %eax
	roll	$13, %ebx
	xorl	12(%ebp), %eax
	xorl	16(%ebp), %ebx
	movl	%eax, 12(%ebp)
	movl	%ebx, 16(%ebp)
	addl	%eax, %ecx
	movl	40(%ebp), %eax	/* G */
	addl	%ebx, %edx
	movl	60(%ebp), %ebx	/* H */
	roll	$18, %ecx
	addl	36(%ebp), %eax	/* G */
	roll	$18, %edx
	addl	56(%ebp), %ebx	/* H */
	xorl	0(%ebp), %ecx
	roll	$7, %eax	/* G */
	xorl	20(%ebp), %edx
	roll	$7, %ebx	/* H */
	movl	%ecx, 0(%ebp)
	movl	%edx, 20(%ebp)
/* quarters G and H */
	xorl	44(%ebp), %eax
	xorl	48(%ebp), %ebx
	movl	%eax, %esi
	movl	%ebx, %edi
	movl	%esi, 44(%ebp)
	movl	%edi, 48(%ebp)
	addl	40(%ebp), %eax
	addl	60(%ebp), %ebx
	roll	$9, %eax
	roll	$9, %ebx
	xorl	32(%ebp), %eax
	xorl	52(%ebp), %ebx
	movl	%eax, %ecx
	movl	%ebx, %edx
	movl	%ecx, 32(%ebp)
	movl	%edx, 52(%ebp)
	addl	%esi, %eax
	addl	%edi, %ebx
	roll	$13, %eax
	roll	$13, %ebx
	xorl	36(%ebp), %eax
	xorl	56(%ebp), %ebx
	movl	%eax, 36(%ebp)
	movl	%ebx, 56(%ebp)
	addl	%eax, %ecx
	addl	%ebx, %edx
	roll	$18, %ecx
	roll	$18, %edx
	xorl	40(%ebp), %ecx
	xorl	60(%ebp), %edx
	movl	%ecx, 40(%ebp)
	movl	%edx, 60(%ebp)
	decl	-4(%esp)
	jnz	.xor_salsa

/* write back data */
	movl	20(%esp), %ebx
	movq	0(%ebx), %mm0
	movq	8(%ebx), %mm1
	movq	16(%ebx), %mm2
	movq	24(%ebx), %mm3
	movq	32(%ebx), %mm4
	movq	40(%ebx), %mm5
	movq	48(%ebx), %mm6
	movq	56(%ebx), %mm7
	paddd	0(%ebp), %mm0
	paddd	8(%ebp), %mm1
	paddd	16(%ebp), %mm2
	paddd	24(%ebp), %mm3
	paddd	32(%ebp), %mm4
	paddd	40(%ebp), %mm5
	paddd	48(%ebp), %mm6
	paddd	56(%ebp), %mm7
	movq	%mm0, 0(%ebx)
	movq	%mm1, 8(%ebx)
	movq	%mm2, 16(%ebx)
	movq	%mm3, 24(%ebx)
	movq	%mm4, 32(%ebx)
	movq	%mm5, 40(%ebx)
	movq	%mm6, 48(%ebx)
	movq	%mm7, 56(%ebx)

	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret


/* neoscrypt_xor_chacha(mem, xormem, tempmem, double_rounds)
 * i386 (INT) ChaCha20 with XOR (MMX support required) */
neoscrypt_xor_chacha:
	pushl	%ebx
	pushl	%ebp
	pushl	%esi
	pushl	%edi
/* XOR and copy to temporary memory */
	movl	20(%esp), %ebx
	movl	24(%esp), %ecx
	movl	28(%esp), %ebp
	movq	0(%ebx), %mm0
	movq	8(%ebx), %mm1
	movq	16(%ebx), %mm2
	movq	24(%ebx), %mm3
	movq	32(%ebx), %mm4
	movq	40(%ebx), %mm5
	movq	48(%ebx), %mm6
	movq	56(%ebx), %mm7
	pxor	0(%ecx), %mm0
	pxor	8(%ecx), %mm1
	pxor	16(%ecx), %mm2
	pxor	24(%ecx), %mm3
	pxor	32(%ecx), %mm4
	pxor	40(%ecx), %mm5
	pxor	48(%ecx), %mm6
	pxor	56(%ecx), %mm7
	movq	%mm0, 0(%ebx)
	movq	%mm1, 8(%ebx)
	movq	%mm2, 16(%ebx)
	movq	%mm3, 24(%ebx)
	movq	%mm4, 32(%ebx)
	movq	%mm5, 40(%ebx)
	movq	%mm6, 48(%ebx)
	movq	%mm7, 56(%ebx)
	movq	%mm0, 0(%ebp)
	movq	%mm1, 8(%ebp)
	movq	%mm2, 16(%ebp)
	movq	%mm3, 24(%ebp)
	movq	%mm4, 32(%ebp)
	movq	%mm5, 40(%ebp)
	movq	%mm6, 48(%ebp)
	movq	%mm7, 56(%ebp)
/* number of double rounds */
	movl	32(%esp), %eax
	movl	%eax, -4(%esp)
.xor_chacha:
/* quarter A */
	movl	16(%ebp), %ebx	/* load b */
	movl	0(%ebp), %eax	/* load a */
	addl	%ebx, %eax	/* a = a + b */
	movl	48(%ebp), %edx	/* load d */
	xorl	%eax, %edx	/* d = d ^ a */
	movl	32(%ebp), %ecx	/* load c */
	roll	$16, %edx	/* rotate d */
	movl	20(%ebp), %esi	/* B: load b */
	addl	%edx, %ecx	/* c = c + d */
	movl	4(%ebp), %edi	/* B: load a */
	xorl	%ecx, %ebx	/* b = b ^ c */
	addl	%esi, %edi	/* B: a = a + b */
	roll	$12, %ebx	/* rotate b */
	addl	%ebx, %eax	/* a = a + b */
	movl	%eax, 0(%ebp)	/* store a */
	xorl	%eax, %edx	/* d = d ^ a */
	movl	52(%ebp), %eax	/* B: load d */
	roll	$8, %edx	/* rotate d */
	xorl	%edi, %eax	/* B: d = d ^ a */
	movl	%edx, 48(%ebp)	/* store d */
	addl	%edx, %ecx	/* c = c + d */
	roll	$16, %eax	/* B: rotate d */
	movl	%ecx, 32(%ebp)	/* store c */
	movl	36(%ebp), %edx	/* B: load c */
	xorl	%ecx, %ebx	/* b = b ^ c */
	addl	%eax, %edx	/* B: c = c + d */
	roll	$7, %ebx	/* rotate b */
	movl	24(%ebp), %ecx	/* C: load b */
	movl	%ebx, 16(%ebp)	/* store b */
/* quarter B */
	xorl	%edx, %esi	/* b = b ^ c */
	movl	8(%ebp), %ebx	/* C: load a */
	roll	$12, %esi	/* rotate b */
	addl	%esi, %edi	/* a = a + b */
	addl	%ecx, %ebx	/* C: a = a + b */
	movl	%edi, 4(%ebp)	/* store a */
	xorl	%edi, %eax	/* d = d ^ a */
	movl	56(%ebp), %edi	/* C: load d */
	roll	$8, %eax	/* rotate d */
	xorl	%ebx, %edi	/* C: d = d ^ a */
	movl	%eax, 52(%ebp)	/* store d */
	addl	%eax, %edx	/* c = c + d */
	roll	$16, %edi	/* C: rotate d */
	movl	%edx, 36(%ebp)	/* store c */
	xorl	%edx, %esi	/* b = b ^ c */
	movl	40(%ebp), %eax	/* C: load c */
	roll	$7, %esi	/* rotate b */
	addl	%edi, %eax	/* C: c = c + d */
	movl	%esi, 20(%ebp)	/* store b */
/* quarter C */
	movl	28(%ebp), %edx	/* D: load b */
	xorl	%eax, %ecx	/* b = b ^ c */
	movl	12(%ebp), %esi	/* D: load a */
	roll	$12, %ecx	/* rotate b */
	addl	%ecx, %ebx	/* a = a + b */
	addl	%edx, %esi	/* D: a = a + b */
	movl	%ebx, 8(%ebp)	/* store a */
	xorl	%ebx, %edi	/* d = d ^ a */
	movl	60(%ebp), %ebx	/* D: load d */
	roll	$8, %edi	/* rotate d */
	xorl	%esi, %ebx	/* D: d = d ^ a */
	movl	%edi, 56(%ebp)	/* store d */
	addl	%edi, %eax	/* c = c + d */
	roll	$16, %ebx	/* D: rotate d */
	movl	%eax, 40(%ebp)	/* store c */
	xorl	%eax, %ecx	/* b = b ^ c */
	movl	44(%ebp), %edi	/* D: load c */
	roll	$7, %ecx	/* rotate b */
	addl	%ebx, %edi	/* D: c = c + d */
	movl	%ecx, 24(%ebp)	/* store b */
/* quarter D */
	xorl	%edi, %edx	/* b = b ^ c */
	roll	$12, %edx	/* rotate b */
	addl	%edx, %esi	/* a = a + b */
	movl	%esi, 12(%ebp)	/* store a */
	xorl	%esi, %ebx	/* d = d ^ a */
	roll	$8, %ebx	/* rotate d */
	movl	%ebx, 60(%ebp)	/* store d */
	addl	%ebx, %edi	/* c = c + d */
	movl	%edi, 44(%ebp)	/* store c */
	xorl	%edi, %edx	/* b = b ^ c */
	roll	$7, %edx	/* rotate b */
	movl	%edx, 28(%ebp)	/* store b */
/* quarter E */
	movl	0(%ebp), %eax
	movl	20(%ebp), %ebx
	addl	%ebx, %eax
	movl	60(%ebp), %edx
	xorl	%eax, %edx
	movl	40(%ebp), %ecx
	roll	$16, %edx
	movl	24(%ebp), %esi
	addl	%edx, %ecx
	movl	4(%ebp), %edi
	xorl	%ecx, %ebx
	addl	%esi, %edi
	roll	$12, %ebx
	addl	%ebx, %eax
	movl	%eax, 0(%ebp)
	xorl	%eax, %edx
	movl	48(%ebp), %eax
	roll	$8, %edx
	xorl	%edi, %eax
	movl	%edx, 60(%ebp)
	addl	%edx, %ecx
	roll	$16, %eax
	movl	%ecx, 40(%ebp)
	movl	44(%ebp), %edx
	xorl	%ecx, %ebx
	addl	%eax, %edx
	roll	$7, %ebx
	movl	28(%ebp), %ecx
	movl	%ebx, 20(%ebp)
/* quarter F */
	xorl	%edx, %esi
	movl	8(%ebp), %ebx
	roll	$12, %esi
	addl	%esi, %edi
	addl	%ecx, %ebx
	movl	%edi, 4(%ebp)
	xorl	%edi, %eax
	movl	52(%ebp), %edi
	roll	$8, %eax
	xorl	%ebx, %edi
	movl	%eax, 48(%ebp)
	addl	%eax, %edx
	roll	$16, %edi
	movl	%edx, 44(%ebp)
	xorl	%edx, %esi
	movl	32(%ebp), %eax
	roll	$7, %esi
	addl	%edi, %eax
	movl	%esi, 24(%ebp)
/* quarter G */
	movl	16(%ebp), %edx
	xorl	%eax, %ecx
	movl	12(%ebp), %esi
	roll	$12, %ecx
	addl	%ecx, %ebx
	addl	%edx, %esi
	movl	%ebx, 8(%ebp)
	xorl	%ebx, %edi
	movl	56(%ebp), %ebx
	roll	$8, %edi
	xorl	%esi, %ebx
	movl	%edi, 52(%ebp)
	addl	%edi, %eax
	roll	$16, %ebx
	movl	%eax, 32(%ebp)
	xorl	%eax, %ecx
	movl	36(%ebp), %edi
	roll	$7, %ecx
	addl	%ebx, %edi
	movl	%ecx, 28(%ebp)
/* quarter H */
	xorl	%edi, %edx
	roll	$12, %edx
	addl	%edx, %esi
	movl	%esi, 12(%ebp)
	xorl	%esi, %ebx
	roll	$8, %ebx
	movl	%ebx, 56(%ebp)
	addl	%ebx, %edi
	movl	%edi, 36(%ebp)
	xorl	%edi, %edx
	roll	$7, %edx
	movl	%edx, 16(%ebp)
	decl	-4(%esp)
	jnz	.xor_chacha

/* write back data */
	movl	20(%esp), %ebx
	movq	0(%ebx), %mm0
	movq	8(%ebx), %mm1
	movq	16(%ebx), %mm2
	movq	24(%ebx), %mm3
	movq	32(%ebx), %mm4
	movq	40(%ebx), %mm5
	movq	48(%ebx), %mm6
	movq	56(%ebx), %mm7
	paddd	0(%ebp), %mm0
	paddd	8(%ebp), %mm1
	paddd	16(%ebp), %mm2
	paddd	24(%ebp), %mm3
	paddd	32(%ebp), %mm4
	paddd	40(%ebp), %mm5
	paddd	48(%ebp), %mm6
	paddd	56(%ebp), %mm7
	movq	%mm0, 0(%ebx)
	movq	%mm1, 8(%ebx)
	movq	%mm2, 16(%ebx)
	movq	%mm3, 24(%ebx)
	movq	%mm4, 32(%ebx)
	movq	%mm5, 40(%ebx)
	movq	%mm6, 48(%ebx)
	movq	%mm7, 56(%ebx)

	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret


/* neoscrypt_salsa_tangle_sse2(mem, count)
 * i386 (SSE2) Salsa20 map switcher;
 * correct map:  0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
 * SSE2 map:     0   5  10  15  12   1   6  11   8  13   2   7   4   9  14   3 */
neoscrypt_salsa_tangle_sse2:
	pushl	%ebx
	movl	8(%esp), %ebx
	movl	12(%esp), %ecx
.salsa_tangle_sse2:
	movl	4(%ebx), %eax
	movl	20(%ebx), %edx
	movl	%eax, 20(%ebx)
	movl	%edx, 4(%ebx)
	movl	8(%ebx), %eax
	movl	40(%ebx), %edx
	movl	%eax, 40(%ebx)
	movl	%edx, 8(%ebx)
	movl	12(%ebx), %eax
	movl	60(%ebx), %edx
	movl	%eax, 60(%ebx)
	movl	%edx, 12(%ebx)
	movl	16(%ebx), %eax
	movl	48(%ebx), %edx
	movl	%eax, 48(%ebx)
	movl	%edx, 16(%ebx)
	movl	28(%ebx), %eax
	movl	44(%ebx), %edx
	movl	%eax, 44(%ebx)
	movl	%edx, 28(%ebx)
	movl	36(%ebx), %eax
	movl	52(%ebx), %edx
	movl	%eax, 52(%ebx)
	movl	%edx, 36(%ebx)
	addl	$64, %ebx
	decl	%ecx
	jnz	.salsa_tangle_sse2

	popl	%ebx
	ret


/* neoscrypt_xor_salsa_sse2(mem, xormem, double_rounds)
 * i386 (SSE2) Salsa20 with XOR;
 * mem and xormem must be aligned properly */
neoscrypt_xor_salsa_sse2:
	movl	4(%esp), %edx
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movdqa	0(%edx), %xmm0
	movdqa	16(%edx), %xmm1
	movdqa	32(%edx), %xmm2
	movdqa	48(%edx), %xmm3
	pxor	0(%eax), %xmm0
	pxor	16(%eax), %xmm1
	pxor	32(%eax), %xmm2
	pxor	48(%eax), %xmm3
	movdqa	%xmm0, %xmm6
	movdqa	%xmm1, %xmm7
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)
.xor_salsa_sse2:
	movdqa	%xmm1, %xmm4
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm3
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm1
	pshufd	$0x4E, %xmm2, %xmm2
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	movdqa	%xmm3, %xmm4
	pxor	%xmm5, %xmm0
	pshufd	$0x39, %xmm1, %xmm1
	paddd	%xmm0, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$7, %xmm4
	psrld	$25, %xmm5
	pxor	%xmm4, %xmm1
	movdqa	%xmm0, %xmm4
	pxor	%xmm5, %xmm1
	paddd	%xmm1, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$9, %xmm4
	psrld	$23, %xmm5
	pxor	%xmm4, %xmm2
	movdqa	%xmm1, %xmm4
	pxor	%xmm5, %xmm2
	pshufd	$0x93, %xmm1, %xmm1
	paddd	%xmm2, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$13, %xmm4
	psrld	$19, %xmm5
	pxor	%xmm4, %xmm3
	movdqa	%xmm2, %xmm4
	pxor	%xmm5, %xmm3
	pshufd	$0x4E, %xmm2, %xmm2
	paddd	%xmm3, %xmm4
	movdqa	%xmm4, %xmm5
	pslld	$18, %xmm4
	psrld	$14, %xmm5
	pxor	%xmm4, %xmm0
	pshufd	$0x39, %xmm3, %xmm3
	pxor	%xmm5, %xmm0
	decl	%ecx
	jnz	.xor_salsa_sse2

	paddd	%xmm6, %xmm0
	paddd	%xmm7, %xmm1
	paddd	32(%edx), %xmm2
	paddd	48(%edx), %xmm3
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)

	ret


/* neoscrypt_xor_chacha_sse2(mem, xormem, double_rounds)
 * i386 (SSE2) ChaCha20 with XOR;
 * mem and xormem must be aligned properly */
neoscrypt_xor_chacha_sse2:
	movl	4(%esp), %edx
	movl	8(%esp), %eax
	movl	12(%esp), %ecx
	movdqa	0(%edx), %xmm0
	movdqa	16(%edx), %xmm1
	movdqa	32(%edx), %xmm2
	movdqa	48(%edx), %xmm3
	pxor	0(%eax), %xmm0
	pxor	16(%eax), %xmm1
	pxor	32(%eax), %xmm2
	pxor	48(%eax), %xmm3
	movdqa	%xmm0, %xmm5
	movdqa	%xmm1, %xmm6
	movdqa	%xmm2, %xmm7
	movdqa	%xmm3, 48(%edx)
.xor_chacha_sse2:
	paddd	%xmm1, %xmm0
	pxor 	%xmm0, %xmm3
	pshuflw	$0xB1, %xmm3, %xmm3
	pshufhw	$0xB1, %xmm3, %xmm3
	paddd	%xmm3, %xmm2
	pxor 	%xmm2, %xmm1
	movdqa	%xmm1, %xmm4
	pslld	$12, %xmm1
	psrld	$20, %xmm4
	pxor	%xmm4, %xmm1
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movdqa	%xmm3, %xmm4
	pslld	$8, %xmm3
	psrld	$24, %xmm4
	pxor	%xmm4, %xmm3
	pshufd	$0x93, %xmm0, %xmm0
	paddd	%xmm3, %xmm2
	pshufd	$0x4E, %xmm3, %xmm3
	pxor	%xmm2, %xmm1
	pshufd	$0x39, %xmm2, %xmm2
	movdqa	%xmm1, %xmm4
	pslld	$7, %xmm1
	psrld	$25, %xmm4
	pxor	%xmm4, %xmm1
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	pshuflw	$0xB1, %xmm3, %xmm3
	pshufhw $0xB1, %xmm3, %xmm3
	paddd	%xmm3, %xmm2
	pxor	%xmm2, %xmm1
	movdqa	%xmm1, %xmm4
	pslld	$12, %xmm1
	psrld	$20, %xmm4
	pxor	%xmm4, %xmm1
	paddd	%xmm1, %xmm0
	pxor	%xmm0, %xmm3
	movdqa	%xmm3, %xmm4
	pslld	$8, %xmm3
	psrld	$24, %xmm4
	pxor	%xmm4, %xmm3
	pshufd	$0x39, %xmm0, %xmm0
	paddd	%xmm3, %xmm2
	pshufd	$0x4E, %xmm3, %xmm3
	pxor	%xmm2, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	movdqa	%xmm1, %xmm4
	pslld	$7, %xmm1
	psrld	$25, %xmm4
	pxor	%xmm4, %xmm1
	decl	%ecx
	jnz	.xor_chacha_sse2

	paddd	%xmm5, %xmm0
	paddd	%xmm6, %xmm1
	paddd	%xmm7, %xmm2
	paddd	48(%edx), %xmm3
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)

	ret


/* neoscrypt(input, output, profile)
 * i386 (INT, SSE2) NeoScrypt engine (MMX required for INT);
 * supports NeoScrypt and Scrypt only */
.globl neoscrypt
.globl _neoscrypt
neoscrypt:
_neoscrypt:
	pushl	%ebx
	pushl	%ebp
	pushl	%esi
	pushl	%edi
	movl	20(%esp), %esi
	movl	24(%esp), %edi
	movl	28(%esp), %ebx
	
#if (SHA256)
/* Scrypt mode */
	testl	$0x01, %ebx
	jnz	.scrypt
#endif

#if (WIN32)
/* attempt to allocate 33280 + 128 bytes of stack space fails miserably;
 * have to use malloc() and free() instead */
	subl	$64, %esp
/* allocate memory (9 pages of 4Kb each) */
	movl	$0x9000, 0(%esp)
	call	_malloc
/* save memory address */
	movl	%eax, 32(%esp)
/* align memory */
	addl	$64, %eax
	andl	$0xFFFFFFC0, %eax
/* memory base: X, Z, V */
	leal	64(%eax), %ebp
#else
/* align stack */
	movl	%esp, %eax
	andl	$0xFFFFFFC0, %esp
	subl	$0x8280, %esp
/* save unaligned stack */
	movl	%eax, 32(%esp)
/* memory base: X, Z, V */
	leal	128(%esp), %ebp
#endif /* WIN32 */

/* FastKDF */
#if (OPT)
	movl	%esi, 0(%esp)
	movl	%esi, 4(%esp)
	movl	%ebp, 8(%esp)
	xorl	%eax, %eax
	movl	%eax, 12(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_fastkdf_opt
#else
	call	neoscrypt_fastkdf_opt
#endif /* WIN32 || __APPLE__ */
#else
	movl	$80, %eax
	movl	%esi, 0(%esp)
	movl	%eax, 4(%esp)
	movl	%esi, 8(%esp)
	movl	%eax, 12(%esp)
	movl	$32, 16(%esp)
	movl	%ebp, 20(%esp)
	movl	$256, 24(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_fastkdf
#else
	call	neoscrypt_fastkdf
#endif /* WIN32  || __APPLE__ */
#endif /* OPT */

/* SSE2 switch */
	testl	$0x1000, %ebx
	jnz	.neoscrypt_sse2

/* blkcpy(Z, X) */
	leal	256(%ebp), %eax
	movq	0(%ebp), %mm0
	movq	8(%ebp), %mm1
	movq	16(%ebp), %mm2
	movq	24(%ebp), %mm3
	movq	32(%ebp), %mm4
	movq	40(%ebp), %mm5
	movq	48(%ebp), %mm6
	movq	56(%ebp), %mm7
	movq	%mm0, 0(%eax)
	movq	%mm1, 8(%eax)
	movq	%mm2, 16(%eax)
	movq	%mm3, 24(%eax)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	movq	64(%ebp), %mm0
	movq	72(%ebp), %mm1
	movq	80(%ebp), %mm2
	movq	88(%ebp), %mm3
	movq	96(%ebp), %mm4
	movq	104(%ebp), %mm5
	movq	112(%ebp), %mm6
	movq	120(%ebp), %mm7
	movq	%mm0, 64(%eax)
	movq	%mm1, 72(%eax)
	movq	%mm2, 80(%eax)
	movq	%mm3, 88(%eax)
	movq	%mm4, 96(%eax)
	movq	%mm5, 104(%eax)
	movq	%mm6, 112(%eax)
	movq	%mm7, 120(%eax)
	movq	128(%ebp), %mm0
	movq	136(%ebp), %mm1
	movq	144(%ebp), %mm2
	movq	152(%ebp), %mm3
	movq	160(%ebp), %mm4
	movq	168(%ebp), %mm5
	movq	176(%ebp), %mm6
	movq	184(%ebp), %mm7
	movq	%mm0, 128(%eax)
	movq	%mm1, 136(%eax)
	movq	%mm2, 144(%eax)
	movq	%mm3, 152(%eax)
	movq	%mm4, 160(%eax)
	movq	%mm5, 168(%eax)
	movq	%mm6, 176(%eax)
	movq	%mm7, 184(%eax)
	movq	192(%ebp), %mm0
	movq	200(%ebp), %mm1
	movq	208(%ebp), %mm2
	movq	216(%ebp), %mm3
	movq	224(%ebp), %mm4
	movq	232(%ebp), %mm5
	movq	240(%ebp), %mm6
	movq	248(%ebp), %mm7
	movq	%mm0, 192(%eax)
	movq	%mm1, 200(%eax)
	movq	%mm2, 208(%eax)
	movq	%mm3, 216(%eax)
	movq	%mm4, 224(%eax)
	movq	%mm5, 232(%eax)
	movq	%mm6, 240(%eax)
	movq	%mm7, 248(%eax)

	leal	-64(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	$10, 12(%esp)

	xorl	%ebx, %ebx
.chacha_ns1:
/* blkcpy(V, Z) */
	leal	512(%ebp), %eax
	movl	%ebx, %edx
	movb	$8, %cl
	shll	%cl, %edx
	leal	256(%ebp), %ecx
	addl	%edx, %eax
	movq	0(%ecx), %mm0
	movq	8(%ecx), %mm1
	movq	16(%ecx), %mm2
	movq	24(%ecx), %mm3
	movq	32(%ecx), %mm4
	movq	40(%ecx), %mm5
	movq	48(%ecx), %mm6
	movq	56(%ecx), %mm7
	movq	%mm0, 0(%eax)
	movq	%mm1, 8(%eax)
	movq	%mm2, 16(%eax)
	movq	%mm3, 24(%eax)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	movq	64(%ecx), %mm0
	movq	72(%ecx), %mm1
	movq	80(%ecx), %mm2
	movq	88(%ecx), %mm3
	movq	96(%ecx), %mm4
	movq	104(%ecx), %mm5
	movq	112(%ecx), %mm6
	movq	120(%ecx), %mm7
	movq	%mm0, 64(%eax)
	movq	%mm1, 72(%eax)
	movq	%mm2, 80(%eax)
	movq	%mm3, 88(%eax)
	movq	%mm4, 96(%eax)
	movq	%mm5, 104(%eax)
	movq	%mm6, 112(%eax)
	movq	%mm7, 120(%eax)
	movq	128(%ecx), %mm0
	movq	136(%ecx), %mm1
	movq	144(%ecx), %mm2
	movq	152(%ecx), %mm3
	movq	160(%ecx), %mm4
	movq	168(%ecx), %mm5
	movq	176(%ecx), %mm6
	movq	184(%ecx), %mm7
	movq	%mm0, 128(%eax)
	movq	%mm1, 136(%eax)
	movq	%mm2, 144(%eax)
	movq	%mm3, 152(%eax)
	movq	%mm4, 160(%eax)
	movq	%mm5, 168(%eax)
	movq	%mm6, 176(%eax)
	movq	%mm7, 184(%eax)
	movq	192(%ecx), %mm0
	movq	200(%ecx), %mm1
	movq	208(%ecx), %mm2
	movq	216(%ecx), %mm3
	movq	224(%ecx), %mm4
	movq	232(%ecx), %mm5
	movq	240(%ecx), %mm6
	movq	248(%ecx), %mm7
	movq	%mm0, 192(%eax)
	movq	%mm1, 200(%eax)
	movq	%mm2, 208(%eax)
	movq	%mm3, 216(%eax)
	movq	%mm4, 224(%eax)
	movq	%mm5, 232(%eax)
	movq	%mm6, 240(%eax)
	movq	%mm7, 248(%eax)
/* blkmix(Z) */
	leal	256(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	448(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	320(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	256(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	384(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	320(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	448(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	384(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	320(%ebp), %eax
	leal	384(%ebp), %edx
	movq	0(%eax), %mm0
	movq	8(%eax), %mm1
	movq	16(%eax), %mm2
	movq	24(%eax), %mm3
	movq	0(%edx), %mm4
	movq	8(%edx), %mm5
	movq	16(%edx), %mm6
	movq	24(%edx), %mm7
	movq	%mm0, 0(%edx)
	movq	%mm1, 8(%edx)
	movq	%mm2, 16(%edx)
	movq	%mm3, 24(%edx)
	movq	%mm4, 0(%eax)
	movq	%mm5, 8(%eax)
	movq	%mm6, 16(%eax)
	movq	%mm7, 24(%eax)
	movq	32(%eax), %mm0
	movq	40(%eax), %mm1
	movq	48(%eax), %mm2
	movq	56(%eax), %mm3
	movq	32(%edx), %mm4
	movq	40(%edx), %mm5
	movq	48(%edx), %mm6
	movq	56(%edx), %mm7
	movq	%mm0, 32(%edx)
	movq	%mm1, 40(%edx)
	movq	%mm2, 48(%edx)
	movq	%mm3, 56(%edx)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.chacha_ns1

	xorl	%ebx, %ebx
.chacha_ns2:
/* integerify(Z) mod 128 */
	leal	256(%ebp), %eax
	leal	512(%ebp), %ecx
	movl	448(%ebp), %edx
	andl	$0x7F, %edx
	shll	$8, %edx
	addl	%edx, %ecx
/* blkxor(Z, V) */
	movq	0(%eax), %mm0
	movq	8(%eax), %mm1
	movq	16(%eax), %mm2
	movq	24(%eax), %mm3
	movq	32(%eax), %mm4
	movq	40(%eax), %mm5
	movq	48(%eax), %mm6
	movq	56(%eax), %mm7
	pxor	0(%ecx), %mm0
	pxor	8(%ecx), %mm1
	pxor	16(%ecx), %mm2
	pxor	24(%ecx), %mm3
	pxor	32(%ecx), %mm4
	pxor	40(%ecx), %mm5
	pxor	48(%ecx), %mm6
	pxor	56(%ecx), %mm7
	movq	%mm0, 0(%eax)
	movq	%mm1, 8(%eax)
	movq	%mm2, 16(%eax)
	movq	%mm3, 24(%eax)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	movq	64(%eax), %mm0
	movq	72(%eax), %mm1
	movq	80(%eax), %mm2
	movq	88(%eax), %mm3
	movq	96(%eax), %mm4
	movq	104(%eax), %mm5
	movq	112(%eax), %mm6
	movq	120(%eax), %mm7
	pxor	64(%ecx), %mm0
	pxor	72(%ecx), %mm1
	pxor	80(%ecx), %mm2
	pxor	88(%ecx), %mm3
	pxor	96(%ecx), %mm4
	pxor	104(%ecx), %mm5
	pxor	112(%ecx), %mm6
	pxor	120(%ecx), %mm7
	movq	%mm0, 64(%eax)
	movq	%mm1, 72(%eax)
	movq	%mm2, 80(%eax)
	movq	%mm3, 88(%eax)
	movq	%mm4, 96(%eax)
	movq	%mm5, 104(%eax)
	movq	%mm6, 112(%eax)
	movq	%mm7, 120(%eax)
	movq	128(%eax), %mm0
	movq	136(%eax), %mm1
	movq	144(%eax), %mm2
	movq	152(%eax), %mm3
	movq	160(%eax), %mm4
	movq	168(%eax), %mm5
	movq	176(%eax), %mm6
	movq	184(%eax), %mm7
	pxor	128(%ecx), %mm0
	pxor	136(%ecx), %mm1
	pxor	144(%ecx), %mm2
	pxor	152(%ecx), %mm3
	pxor	160(%ecx), %mm4
	pxor	168(%ecx), %mm5
	pxor	176(%ecx), %mm6
	pxor	184(%ecx), %mm7
	movq	%mm0, 128(%eax)
	movq	%mm1, 136(%eax)
	movq	%mm2, 144(%eax)
	movq	%mm3, 152(%eax)
	movq	%mm4, 160(%eax)
	movq	%mm5, 168(%eax)
	movq	%mm6, 176(%eax)
	movq	%mm7, 184(%eax)
	movq	192(%eax), %mm0
	movq	200(%eax), %mm1
	movq	208(%eax), %mm2
	movq	216(%eax), %mm3
	movq	224(%eax), %mm4
	movq	232(%eax), %mm5
	movq	240(%eax), %mm6
	movq	248(%eax), %mm7
	pxor	192(%ecx), %mm0
	pxor	200(%ecx), %mm1
	pxor	208(%ecx), %mm2
	pxor	216(%ecx), %mm3
	pxor	224(%ecx), %mm4
	pxor	232(%ecx), %mm5
	pxor	240(%ecx), %mm6
	pxor	248(%ecx), %mm7
	movq	%mm0, 192(%eax)
	movq	%mm1, 200(%eax)
	movq	%mm2, 208(%eax)
	movq	%mm3, 216(%eax)
	movq	%mm4, 224(%eax)
	movq	%mm5, 232(%eax)
	movq	%mm6, 240(%eax)
	movq	%mm7, 248(%eax)
/* blkmix(Z) */
	leal	256(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	448(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	320(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	256(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	384(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	320(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	448(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	384(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha
	leal	320(%ebp), %eax
	leal	384(%ebp), %edx
	movq	0(%eax), %mm0
	movq	8(%eax), %mm1
	movq	16(%eax), %mm2
	movq	24(%eax), %mm3
	movq	0(%edx), %mm4
	movq	8(%edx), %mm5
	movq	16(%edx), %mm6
	movq	24(%edx), %mm7
	movq	%mm0, 0(%edx)
	movq	%mm1, 8(%edx)
	movq	%mm2, 16(%edx)
	movq	%mm3, 24(%edx)
	movq	%mm4, 0(%eax)
	movq	%mm5, 8(%eax)
	movq	%mm6, 16(%eax)
	movq	%mm7, 24(%eax)
	movq	32(%eax), %mm0
	movq	40(%eax), %mm1
	movq	48(%eax), %mm2
	movq	56(%eax), %mm3
	movq	32(%edx), %mm4
	movq	40(%edx), %mm5
	movq	48(%edx), %mm6
	movq	56(%edx), %mm7
	movq	%mm0, 32(%edx)
	movq	%mm1, 40(%edx)
	movq	%mm2, 48(%edx)
	movq	%mm3, 56(%edx)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.chacha_ns2

	xorl	%ebx, %ebx
.salsa_ns1:
/* blkcpy(V, X) */
	leal	512(%ebp), %eax
	movl	%ebx, %edx
	movl	$8, %ecx
	shll	%cl, %edx
	addl	%edx, %eax
	movq	0(%ebp), %mm0
	movq	8(%ebp), %mm1
	movq	16(%ebp), %mm2
	movq	24(%ebp), %mm3
	movq	32(%ebp), %mm4
	movq	40(%ebp), %mm5
	movq	48(%ebp), %mm6
	movq	56(%ebp), %mm7
	movq	%mm0, 0(%eax)
	movq	%mm1, 8(%eax)
	movq	%mm2, 16(%eax)
	movq	%mm3, 24(%eax)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	movq	64(%ebp), %mm0
	movq	72(%ebp), %mm1
	movq	80(%ebp), %mm2
	movq	88(%ebp), %mm3
	movq	96(%ebp), %mm4
	movq	104(%ebp), %mm5
	movq	112(%ebp), %mm6
	movq	120(%ebp), %mm7
	movq	%mm0, 64(%eax)
	movq	%mm1, 72(%eax)
	movq	%mm2, 80(%eax)
	movq	%mm3, 88(%eax)
	movq	%mm4, 96(%eax)
	movq	%mm5, 104(%eax)
	movq	%mm6, 112(%eax)
	movq	%mm7, 120(%eax)
	movq	128(%ebp), %mm0
	movq	136(%ebp), %mm1
	movq	144(%ebp), %mm2
	movq	152(%ebp), %mm3
	movq	160(%ebp), %mm4
	movq	168(%ebp), %mm5
	movq	176(%ebp), %mm6
	movq	184(%ebp), %mm7
	movq	%mm0, 128(%eax)
	movq	%mm1, 136(%eax)
	movq	%mm2, 144(%eax)
	movq	%mm3, 152(%eax)
	movq	%mm4, 160(%eax)
	movq	%mm5, 168(%eax)
	movq	%mm6, 176(%eax)
	movq	%mm7, 184(%eax)
	movq	192(%ebp), %mm0
	movq	200(%ebp), %mm1
	movq	208(%ebp), %mm2
	movq	216(%ebp), %mm3
	movq	224(%ebp), %mm4
	movq	232(%ebp), %mm5
	movq	240(%ebp), %mm6
	movq	248(%ebp), %mm7
	movq	%mm0, 192(%eax)
	movq	%mm1, 200(%eax)
	movq	%mm2, 208(%eax)
	movq	%mm3, 216(%eax)
	movq	%mm4, 224(%eax)
	movq	%mm5, 232(%eax)
	movq	%mm6, 240(%eax)
	movq	%mm7, 248(%eax)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	192(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	128(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	192(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	128(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	64(%ebp), %eax
	leal	128(%ebp), %edx
	movq	0(%eax), %mm0
	movq	8(%eax), %mm1
	movq	16(%eax), %mm2
	movq	24(%eax), %mm3
	movq	0(%edx), %mm4
	movq	8(%edx), %mm5
	movq	16(%edx), %mm6
	movq	24(%edx), %mm7
	movq	%mm0, 0(%edx)
	movq	%mm1, 8(%edx)
	movq	%mm2, 16(%edx)
	movq	%mm3, 24(%edx)
	movq	%mm4, 0(%eax)
	movq	%mm5, 8(%eax)
	movq	%mm6, 16(%eax)
	movq	%mm7, 24(%eax)
	movq	32(%eax), %mm0
	movq	40(%eax), %mm1
	movq	48(%eax), %mm2
	movq	56(%eax), %mm3
	movq	32(%edx), %mm4
	movq	40(%edx), %mm5
	movq	48(%edx), %mm6
	movq	56(%edx), %mm7
	movq	%mm0, 32(%edx)
	movq	%mm1, 40(%edx)
	movq	%mm2, 48(%edx)
	movq	%mm3, 56(%edx)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.salsa_ns1

	xorl	%ebx, %ebx
.salsa_ns2:
/* integerify(X) mod 128 */
	leal	512(%ebp), %ecx
	movl	192(%ebp), %edx
	andl	$0x7F, %edx
	shll	$8, %edx
	addl	%edx, %ecx
/* blkxor(X, V) */
	movq	0(%ebp), %mm0
	movq	8(%ebp), %mm1
	movq	16(%ebp), %mm2
	movq	24(%ebp), %mm3
	movq	32(%ebp), %mm4
	movq	40(%ebp), %mm5
	movq	48(%ebp), %mm6
	movq	56(%ebp), %mm7
	pxor	0(%ecx), %mm0
	pxor	8(%ecx), %mm1
	pxor	16(%ecx), %mm2
	pxor	24(%ecx), %mm3
	pxor	32(%ecx), %mm4
	pxor	40(%ecx), %mm5
	pxor	48(%ecx), %mm6
	pxor	56(%ecx), %mm7
	movq	%mm0, 0(%ebp)
	movq	%mm1, 8(%ebp)
	movq	%mm2, 16(%ebp)
	movq	%mm3, 24(%ebp)
	movq	%mm4, 32(%ebp)
	movq	%mm5, 40(%ebp)
	movq	%mm6, 48(%ebp)
	movq	%mm7, 56(%ebp)
	movq	64(%ebp), %mm0
	movq	72(%ebp), %mm1
	movq	80(%ebp), %mm2
	movq	88(%ebp), %mm3
	movq	96(%ebp), %mm4
	movq	104(%ebp), %mm5
	movq	112(%ebp), %mm6
	movq	120(%ebp), %mm7
	pxor	64(%ecx), %mm0
	pxor	72(%ecx), %mm1
	pxor	80(%ecx), %mm2
	pxor	88(%ecx), %mm3
	pxor	96(%ecx), %mm4
	pxor	104(%ecx), %mm5
	pxor	112(%ecx), %mm6
	pxor	120(%ecx), %mm7
	movq	%mm0, 64(%ebp)
	movq	%mm1, 72(%ebp)
	movq	%mm2, 80(%ebp)
	movq	%mm3, 88(%ebp)
	movq	%mm4, 96(%ebp)
	movq	%mm5, 104(%ebp)
	movq	%mm6, 112(%ebp)
	movq	%mm7, 120(%ebp)
	movq	128(%ebp), %mm0
	movq	136(%ebp), %mm1
	movq	144(%ebp), %mm2
	movq	152(%ebp), %mm3
	movq	160(%ebp), %mm4
	movq	168(%ebp), %mm5
	movq	176(%ebp), %mm6
	movq	184(%ebp), %mm7
	pxor	128(%ecx), %mm0
	pxor	136(%ecx), %mm1
	pxor	144(%ecx), %mm2
	pxor	152(%ecx), %mm3
	pxor	160(%ecx), %mm4
	pxor	168(%ecx), %mm5
	pxor	176(%ecx), %mm6
	pxor	184(%ecx), %mm7
	movq	%mm0, 128(%ebp)
	movq	%mm1, 136(%ebp)
	movq	%mm2, 144(%ebp)
	movq	%mm3, 152(%ebp)
	movq	%mm4, 160(%ebp)
	movq	%mm5, 168(%ebp)
	movq	%mm6, 176(%ebp)
	movq	%mm7, 184(%ebp)
	movq	192(%ebp), %mm0
	movq	200(%ebp), %mm1
	movq	208(%ebp), %mm2
	movq	216(%ebp), %mm3
	movq	224(%ebp), %mm4
	movq	232(%ebp), %mm5
	movq	240(%ebp), %mm6
	movq	248(%ebp), %mm7
	pxor	192(%ecx), %mm0
	pxor	200(%ecx), %mm1
	pxor	208(%ecx), %mm2
	pxor	216(%ecx), %mm3
	pxor	224(%ecx), %mm4
	pxor	232(%ecx), %mm5
	pxor	240(%ecx), %mm6
	pxor	248(%ecx), %mm7
	movq	%mm0, 192(%ebp)
	movq	%mm1, 200(%ebp)
	movq	%mm2, 208(%ebp)
	movq	%mm3, 216(%ebp)
	movq	%mm4, 224(%ebp)
	movq	%mm5, 232(%ebp)
	movq	%mm6, 240(%ebp)
	movq	%mm7, 248(%ebp)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	192(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	128(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	192(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	128(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	64(%ebp), %eax
	leal	128(%ebp), %edx
	movq	0(%eax), %mm0
	movq	8(%eax), %mm1
	movq	16(%eax), %mm2
	movq	24(%eax), %mm3
	movq	0(%edx), %mm4
	movq	8(%edx), %mm5
	movq	16(%edx), %mm6
	movq	24(%edx), %mm7
	movq	%mm0, 0(%edx)
	movq	%mm1, 8(%edx)
	movq	%mm2, 16(%edx)
	movq	%mm3, 24(%edx)
	movq	%mm4, 0(%eax)
	movq	%mm5, 8(%eax)
	movq	%mm6, 16(%eax)
	movq	%mm7, 24(%eax)
	movq	32(%eax), %mm0
	movq	40(%eax), %mm1
	movq	48(%eax), %mm2
	movq	56(%eax), %mm3
	movq	32(%edx), %mm4
	movq	40(%edx), %mm5
	movq	48(%edx), %mm6
	movq	56(%edx), %mm7
	movq	%mm0, 32(%edx)
	movq	%mm1, 40(%edx)
	movq	%mm2, 48(%edx)
	movq	%mm3, 56(%edx)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.salsa_ns2

/* blkxor(X, Z) */
	leal	256(%ebp), %ecx
	movq	0(%ebp), %mm0
	movq	8(%ebp), %mm1
	movq	16(%ebp), %mm2
	movq	24(%ebp), %mm3
	movq	32(%ebp), %mm4
	movq	40(%ebp), %mm5
	movq	48(%ebp), %mm6
	movq	56(%ebp), %mm7
	pxor	0(%ecx), %mm0
	pxor	8(%ecx), %mm1
	pxor	16(%ecx), %mm2
	pxor	24(%ecx), %mm3
	pxor	32(%ecx), %mm4
	pxor	40(%ecx), %mm5
	pxor	48(%ecx), %mm6
	pxor	56(%ecx), %mm7
	movq	%mm0, 0(%ebp)
	movq	%mm1, 8(%ebp)
	movq	%mm2, 16(%ebp)
	movq	%mm3, 24(%ebp)
	movq	%mm4, 32(%ebp)
	movq	%mm5, 40(%ebp)
	movq	%mm6, 48(%ebp)
	movq	%mm7, 56(%ebp)
	movq	64(%ebp), %mm0
	movq	72(%ebp), %mm1
	movq	80(%ebp), %mm2
	movq	88(%ebp), %mm3
	movq	96(%ebp), %mm4
	movq	104(%ebp), %mm5
	movq	112(%ebp), %mm6
	movq	120(%ebp), %mm7
	pxor	64(%ecx), %mm0
	pxor	72(%ecx), %mm1
	pxor	80(%ecx), %mm2
	pxor	88(%ecx), %mm3
	pxor	96(%ecx), %mm4
	pxor	104(%ecx), %mm5
	pxor	112(%ecx), %mm6
	pxor	120(%ecx), %mm7
	movq	%mm0, 64(%ebp)
	movq	%mm1, 72(%ebp)
	movq	%mm2, 80(%ebp)
	movq	%mm3, 88(%ebp)
	movq	%mm4, 96(%ebp)
	movq	%mm5, 104(%ebp)
	movq	%mm6, 112(%ebp)
	movq	%mm7, 120(%ebp)
	movq	128(%ebp), %mm0
	movq	136(%ebp), %mm1
	movq	144(%ebp), %mm2
	movq	152(%ebp), %mm3
	movq	160(%ebp), %mm4
	movq	168(%ebp), %mm5
	movq	176(%ebp), %mm6
	movq	184(%ebp), %mm7
	pxor	128(%ecx), %mm0
	pxor	136(%ecx), %mm1
	pxor	144(%ecx), %mm2
	pxor	152(%ecx), %mm3
	pxor	160(%ecx), %mm4
	pxor	168(%ecx), %mm5
	pxor	176(%ecx), %mm6
	pxor	184(%ecx), %mm7
	movq	%mm0, 128(%ebp)
	movq	%mm1, 136(%ebp)
	movq	%mm2, 144(%ebp)
	movq	%mm3, 152(%ebp)
	movq	%mm4, 160(%ebp)
	movq	%mm5, 168(%ebp)
	movq	%mm6, 176(%ebp)
	movq	%mm7, 184(%ebp)
	movq	192(%ebp), %mm0
	movq	200(%ebp), %mm1
	movq	208(%ebp), %mm2
	movq	216(%ebp), %mm3
	movq	224(%ebp), %mm4
	movq	232(%ebp), %mm5
	movq	240(%ebp), %mm6
	movq	248(%ebp), %mm7
	pxor	192(%ecx), %mm0
	pxor	200(%ecx), %mm1
	pxor	208(%ecx), %mm2
	pxor	216(%ecx), %mm3
	pxor	224(%ecx), %mm4
	pxor	232(%ecx), %mm5
	pxor	240(%ecx), %mm6
	pxor	248(%ecx), %mm7
	movq	%mm0, 192(%ebp)
	movq	%mm1, 200(%ebp)
	movq	%mm2, 208(%ebp)
	movq	%mm3, 216(%ebp)
	movq	%mm4, 224(%ebp)
	movq	%mm5, 232(%ebp)
	movq	%mm6, 240(%ebp)
	movq	%mm7, 248(%ebp)

/* FastKDF */
#if (OPT)
	movl	%esi, 0(%esp)
	movl	%ebp, 4(%esp)
	movl	%edi, 8(%esp)
	movl	$1, 12(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_fastkdf_opt
#else
	call	neoscrypt_fastkdf_opt
#endif /* WIN32 || __APPLE__ */
#else
	movl	%esi, 0(%esp)
	movl	$80, 4(%esp)
	movl	%ebp, 8(%esp)
	movl	$256, 12(%esp)
	movl	$32, 16(%esp)
	movl	%edi, 20(%esp)
	movl	$32, 24(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_fastkdf
#else
	call	neoscrypt_fastkdf
#endif /* WIN32 || __APPLE__ */
#endif /* OPT */

#if (WIN32)
/* free memory */
	movl	32(%esp), %eax
	movl	%eax, 0(%esp)
	call	_free
/* restore stack */
	addl	$64, %esp
#else
/* restore stack */
	movl	32(%esp), %esp
#endif
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	emms
	ret

.neoscrypt_sse2:
/* blkcpy(Z, X) */
	leal	256(%ebp), %eax
	movdqa	0(%ebp), %xmm0
	movdqa	16(%ebp), %xmm1
	movdqa	32(%ebp), %xmm2
	movdqa	48(%ebp), %xmm3
	movdqa	64(%ebp), %xmm4
	movdqa	80(%ebp), %xmm5
	movdqa	96(%ebp), %xmm6
	movdqa	112(%ebp), %xmm7
	movdqa	%xmm0, 0(%eax)
	movdqa	%xmm1, 16(%eax)
	movdqa	%xmm2, 32(%eax)
	movdqa	%xmm3, 48(%eax)
	movdqa	%xmm4, 64(%eax)
	movdqa	%xmm5, 80(%eax)
	movdqa	%xmm6, 96(%eax)
	movdqa	%xmm7, 112(%eax)
	movdqa	128(%ebp), %xmm0
	movdqa	144(%ebp), %xmm1
	movdqa	160(%ebp), %xmm2
	movdqa	176(%ebp), %xmm3
	movdqa	192(%ebp), %xmm4
	movdqa	208(%ebp), %xmm5
	movdqa	224(%ebp), %xmm6
	movdqa	240(%ebp), %xmm7
	movdqa	%xmm0, 128(%eax)
	movdqa	%xmm1, 144(%eax)
	movdqa	%xmm2, 160(%eax)
	movdqa	%xmm3, 176(%eax)
	movdqa	%xmm4, 192(%eax)
	movdqa	%xmm5, 208(%eax)
	movdqa	%xmm6, 224(%eax)
	movdqa	%xmm7, 240(%eax)

	movl	$10, 8(%esp)

	xorl	%ebx, %ebx
.chacha_ns1_sse2:
/* blkcpy(V, Z) */
	leal	512(%ebp), %eax
	movl	%ebx, %edx
	movb	$8, %cl
	shll	%cl, %edx
	leal	256(%ebp), %ecx
	addl	%edx, %eax
	movdqa	0(%ecx), %xmm0
	movdqa	16(%ecx), %xmm1
	movdqa	32(%ecx), %xmm2
	movdqa	48(%ecx), %xmm3
	movdqa	64(%ecx), %xmm4
	movdqa	80(%ecx), %xmm5
	movdqa	96(%ecx), %xmm6
	movdqa	112(%ecx), %xmm7
	movdqa	%xmm0, 0(%eax)
	movdqa	%xmm1, 16(%eax)
	movdqa	%xmm2, 32(%eax)
	movdqa	%xmm3, 48(%eax)
	movdqa	%xmm4, 64(%eax)
	movdqa	%xmm5, 80(%eax)
	movdqa	%xmm6, 96(%eax)
	movdqa	%xmm7, 112(%eax)
	movdqa	128(%ecx), %xmm0
	movdqa	144(%ecx), %xmm1
	movdqa	160(%ecx), %xmm2
	movdqa	176(%ecx), %xmm3
	movdqa	192(%ecx), %xmm4
	movdqa	208(%ecx), %xmm5
	movdqa	224(%ecx), %xmm6
	movdqa	240(%ecx), %xmm7
	movdqa	%xmm0, 128(%eax)
	movdqa	%xmm1, 144(%eax)
	movdqa	%xmm2, 160(%eax)
	movdqa	%xmm3, 176(%eax)
	movdqa	%xmm4, 192(%eax)
	movdqa	%xmm5, 208(%eax)
	movdqa	%xmm6, 224(%eax)
	movdqa	%xmm7, 240(%eax)
/* blkmix(Z) */
	leal	256(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	448(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	320(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	256(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	384(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	320(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	448(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	384(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	320(%ebp), %eax
	leal	384(%ebp), %edx
	movdqa	0(%eax), %xmm0
	movdqa	16(%eax), %xmm1
	movdqa	32(%eax), %xmm2
	movdqa	48(%eax), %xmm3
	movdqa	0(%edx), %xmm4
	movdqa	16(%edx), %xmm5
	movdqa	32(%edx), %xmm6
	movdqa	48(%edx), %xmm7
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)
	movdqa	%xmm4, 0(%eax)
	movdqa	%xmm5, 16(%eax)
	movdqa	%xmm6, 32(%eax)
	movdqa	%xmm7, 48(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.chacha_ns1_sse2

	xorl	%ebx, %ebx
.chacha_ns2_sse2:
/* integerify(Z) mod 128 */
	leal	256(%ebp), %eax
	leal	512(%ebp), %ecx
	movl	448(%ebp), %edx
	andl	$0x7F, %edx
	shll	$8, %edx
	addl	%edx, %ecx
/* blkxor(Z, V) */
	movdqa	0(%eax), %xmm0
	movdqa	16(%eax), %xmm1
	movdqa	32(%eax), %xmm2
	movdqa	48(%eax), %xmm3
	movdqa	64(%eax), %xmm4
	movdqa	80(%eax), %xmm5
	movdqa	96(%eax), %xmm6
	movdqa	112(%eax), %xmm7
	pxor	0(%ecx), %xmm0
	pxor	16(%ecx), %xmm1
	pxor	32(%ecx), %xmm2
	pxor	48(%ecx), %xmm3
	pxor	64(%ecx), %xmm4
	pxor	80(%ecx), %xmm5
	pxor	96(%ecx), %xmm6
	pxor	112(%ecx), %xmm7
	movdqa	%xmm0, 0(%eax)
	movdqa	%xmm1, 16(%eax)
	movdqa	%xmm2, 32(%eax)
	movdqa	%xmm3, 48(%eax)
	movdqa	%xmm4, 64(%eax)
	movdqa	%xmm5, 80(%eax)
	movdqa	%xmm6, 96(%eax)
	movdqa	%xmm7, 112(%eax)
	movdqa	128(%eax), %xmm0
	movdqa	144(%eax), %xmm1
	movdqa	160(%eax), %xmm2
	movdqa	176(%eax), %xmm3
	movdqa	192(%eax), %xmm4
	movdqa	208(%eax), %xmm5
	movdqa	224(%eax), %xmm6
	movdqa	240(%eax), %xmm7
	pxor	128(%ecx), %xmm0
	pxor	144(%ecx), %xmm1
	pxor	160(%ecx), %xmm2
	pxor	176(%ecx), %xmm3
	pxor	192(%ecx), %xmm4
	pxor	208(%ecx), %xmm5
	pxor	224(%ecx), %xmm6
	pxor	240(%ecx), %xmm7
	movdqa	%xmm0, 128(%eax)
	movdqa	%xmm1, 144(%eax)
	movdqa	%xmm2, 160(%eax)
	movdqa	%xmm3, 176(%eax)
	movdqa	%xmm4, 192(%eax)
	movdqa	%xmm5, 208(%eax)
	movdqa	%xmm6, 224(%eax)
	movdqa	%xmm7, 240(%eax)
/* blkmix(Z) */
	leal	256(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	448(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	320(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	256(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	384(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	320(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	448(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	384(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_chacha_sse2
	leal	320(%ebp), %eax
	leal	384(%ebp), %edx
	movdqa	0(%eax), %xmm0
	movdqa	16(%eax), %xmm1
	movdqa	32(%eax), %xmm2
	movdqa	48(%eax), %xmm3
	movdqa	0(%edx), %xmm4
	movdqa	16(%edx), %xmm5
	movdqa	32(%edx), %xmm6
	movdqa	48(%edx), %xmm7
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)
	movdqa	%xmm4, 0(%eax)
	movdqa	%xmm5, 16(%eax)
	movdqa	%xmm6, 32(%eax)
	movdqa	%xmm7, 48(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.chacha_ns2_sse2

	movl	%ebp, 0(%esp)
	movl	$4, 4(%esp)
	call	neoscrypt_salsa_tangle_sse2

	xorl	%ebx, %ebx
.salsa_ns1_sse2:
/* blkcpy(V, X) */
	leal	512(%ebp), %eax
	movl	%ebx, %edx
	movl	$8, %ecx
	shll	%cl, %edx
	addl	%edx, %eax
	movdqa	0(%ebp), %xmm0
	movdqa	16(%ebp), %xmm1
	movdqa	32(%ebp), %xmm2
	movdqa	48(%ebp), %xmm3
	movdqa	64(%ebp), %xmm4
	movdqa	80(%ebp), %xmm5
	movdqa	96(%ebp), %xmm6
	movdqa	112(%ebp), %xmm7
	movdqa	%xmm0, 0(%eax)
	movdqa	%xmm1, 16(%eax)
	movdqa	%xmm2, 32(%eax)
	movdqa	%xmm3, 48(%eax)
	movdqa	%xmm4, 64(%eax)
	movdqa	%xmm5, 80(%eax)
	movdqa	%xmm6, 96(%eax)
	movdqa	%xmm7, 112(%eax)
	movdqa	128(%ebp), %xmm0
	movdqa	144(%ebp), %xmm1
	movdqa	160(%ebp), %xmm2
	movdqa	176(%ebp), %xmm3
	movdqa	192(%ebp), %xmm4
	movdqa	208(%ebp), %xmm5
	movdqa	224(%ebp), %xmm6
	movdqa	240(%ebp), %xmm7
	movdqa	%xmm0, 128(%eax)
	movdqa	%xmm1, 144(%eax)
	movdqa	%xmm2, 160(%eax)
	movdqa	%xmm3, 176(%eax)
	movdqa	%xmm4, 192(%eax)
	movdqa	%xmm5, 208(%eax)
	movdqa	%xmm6, 224(%eax)
	movdqa	%xmm7, 240(%eax)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	192(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	128(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	192(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	128(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	64(%ebp), %eax
	leal	128(%ebp), %edx
	movdqa	0(%eax), %xmm0
	movdqa	16(%eax), %xmm1
	movdqa	32(%eax), %xmm2
	movdqa	48(%eax), %xmm3
	movdqa	0(%edx), %xmm4
	movdqa	16(%edx), %xmm5
	movdqa	32(%edx), %xmm6
	movdqa	48(%edx), %xmm7
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)
	movdqa	%xmm4, 0(%eax)
	movdqa	%xmm5, 16(%eax)
	movdqa	%xmm6, 32(%eax)
	movdqa	%xmm7, 48(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.salsa_ns1_sse2

	xorl	%ebx, %ebx
.salsa_ns2_sse2:
/* integerify(X) mod 128 */
	leal	512(%ebp), %ecx
	movl	192(%ebp), %edx
	andl	$0x7F, %edx
	shll	$8, %edx
	addl	%edx, %ecx
/* blkxor(X, V) */
	movdqa	0(%ebp), %xmm0
	movdqa	16(%ebp), %xmm1
	movdqa	32(%ebp), %xmm2
	movdqa	48(%ebp), %xmm3
	movdqa	64(%ebp), %xmm4
	movdqa	80(%ebp), %xmm5
	movdqa	96(%ebp), %xmm6
	movdqa	112(%ebp), %xmm7
	pxor	0(%ecx), %xmm0
	pxor	16(%ecx), %xmm1
	pxor	32(%ecx), %xmm2
	pxor	48(%ecx), %xmm3
	pxor	64(%ecx), %xmm4
	pxor	80(%ecx), %xmm5
	pxor	96(%ecx), %xmm6
	pxor	112(%ecx), %xmm7
	movdqa	%xmm0, 0(%ebp)
	movdqa	%xmm1, 16(%ebp)
	movdqa	%xmm2, 32(%ebp)
	movdqa	%xmm3, 48(%ebp)
	movdqa	%xmm4, 64(%ebp)
	movdqa	%xmm5, 80(%ebp)
	movdqa	%xmm6, 96(%ebp)
	movdqa	%xmm7, 112(%ebp)
	movdqa	128(%ebp), %xmm0
	movdqa	144(%ebp), %xmm1
	movdqa	160(%ebp), %xmm2
	movdqa	176(%ebp), %xmm3
	movdqa	192(%ebp), %xmm4
	movdqa	208(%ebp), %xmm5
	movdqa	224(%ebp), %xmm6
	movdqa	240(%ebp), %xmm7
	pxor	128(%ecx), %xmm0
	pxor	144(%ecx), %xmm1
	pxor	160(%ecx), %xmm2
	pxor	176(%ecx), %xmm3
	pxor	192(%ecx), %xmm4
	pxor	208(%ecx), %xmm5
	pxor	224(%ecx), %xmm6
	pxor	240(%ecx), %xmm7
	movdqa	%xmm0, 128(%ebp)
	movdqa	%xmm1, 144(%ebp)
	movdqa	%xmm2, 160(%ebp)
	movdqa	%xmm3, 176(%ebp)
	movdqa	%xmm4, 192(%ebp)
	movdqa	%xmm5, 208(%ebp)
	movdqa	%xmm6, 224(%ebp)
	movdqa	%xmm7, 240(%ebp)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	192(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	128(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	192(%ebp), %eax
	movl	%eax, 0(%esp)
	leal	128(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	64(%ebp), %eax
	leal	128(%ebp), %edx
	movdqa	0(%eax), %xmm0
	movdqa	16(%eax), %xmm1
	movdqa	32(%eax), %xmm2
	movdqa	48(%eax), %xmm3
	movdqa	0(%edx), %xmm4
	movdqa	16(%edx), %xmm5
	movdqa	32(%edx), %xmm6
	movdqa	48(%edx), %xmm7
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)
	movdqa	%xmm4, 0(%eax)
	movdqa	%xmm5, 16(%eax)
	movdqa	%xmm6, 32(%eax)
	movdqa	%xmm7, 48(%eax)
	incl	%ebx
	cmpl	$128, %ebx
	jnz	.salsa_ns2_sse2

	movl	%ebp, 0(%esp)
	movl	$4, 4(%esp)
	call	neoscrypt_salsa_tangle_sse2

/* blkxor(X, Z) */
	leal	256(%ebp), %ecx
	movdqa	0(%ebp), %xmm0
	movdqa	16(%ebp), %xmm1
	movdqa	32(%ebp), %xmm2
	movdqa	48(%ebp), %xmm3
	movdqa	64(%ebp), %xmm4
	movdqa	80(%ebp), %xmm5
	movdqa	96(%ebp), %xmm6
	movdqa	112(%ebp), %xmm7
	pxor	0(%ecx), %xmm0
	pxor	16(%ecx), %xmm1
	pxor	32(%ecx), %xmm2
	pxor	48(%ecx), %xmm3
	pxor	64(%ecx), %xmm4
	pxor	80(%ecx), %xmm5
	pxor	96(%ecx), %xmm6
	pxor	112(%ecx), %xmm7
	movdqa	%xmm0, 0(%ebp)
	movdqa	%xmm1, 16(%ebp)
	movdqa	%xmm2, 32(%ebp)
	movdqa	%xmm3, 48(%ebp)
	movdqa	%xmm4, 64(%ebp)
	movdqa	%xmm5, 80(%ebp)
	movdqa	%xmm6, 96(%ebp)
	movdqa	%xmm7, 112(%ebp)
	movdqa	128(%ebp), %xmm0
	movdqa	144(%ebp), %xmm1
	movdqa	160(%ebp), %xmm2
	movdqa	176(%ebp), %xmm3
	movdqa	192(%ebp), %xmm4
	movdqa	208(%ebp), %xmm5
	movdqa	224(%ebp), %xmm6
	movdqa	240(%ebp), %xmm7
	pxor	128(%ecx), %xmm0
	pxor	144(%ecx), %xmm1
	pxor	160(%ecx), %xmm2
	pxor	176(%ecx), %xmm3
	pxor	192(%ecx), %xmm4
	pxor	208(%ecx), %xmm5
	pxor	224(%ecx), %xmm6
	pxor	240(%ecx), %xmm7
	movdqa	%xmm0, 128(%ebp)
	movdqa	%xmm1, 144(%ebp)
	movdqa	%xmm2, 160(%ebp)
	movdqa	%xmm3, 176(%ebp)
	movdqa	%xmm4, 192(%ebp)
	movdqa	%xmm5, 208(%ebp)
	movdqa	%xmm6, 224(%ebp)
	movdqa	%xmm7, 240(%ebp)

/* FastKDF */
#if (OPT)
	movl	%esi, 0(%esp)
	movl	%ebp, 4(%esp)
	movl	%edi, 8(%esp)
	movl	$1, 12(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_fastkdf_opt
#else
	call	neoscrypt_fastkdf_opt
#endif /* WIN32 || __APPLE__ */
#else
	movl	%esi, 0(%esp)
	movl	$80, 4(%esp)
	movl	%ebp, 8(%esp)
	movl	$256, 12(%esp)
	movl	$32, 16(%esp)
	movl	%edi, 20(%esp)
	movl	$32, 24(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_fastkdf
#else
	call	neoscrypt_fastkdf
#endif /* WIN32 || __APPLE__ */
#endif /* OPT */

#if (WIN32)
/* free memory */
	movl	32(%esp), %eax
	movl	%eax, 0(%esp)
	call	_free
/* restore stack */
	addl	$64, %esp
#else
/* restore stack */
	movl	32(%esp), %esp
#endif
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret

#if (SHA256)

.scrypt:
#if (WIN32)
/* attempt to allocate 131200 + 128 bytes of stack space fails miserably;
 * have to use malloc() and free() instead */
	subl	$64, %esp
/* allocate memory (33 pages of 4Kb each) */
	movl	$0x21000, 0(%esp)
	call	_malloc
/* save memory address */
	movl	%eax, 32(%esp)
/* align memory */
	addl	$64, %eax
	andl	$0xFFFFFFC0, %eax
/* memory base: X, Z, V */
	leal	64(%eax), %ebp
#else
/* align stack */
	movl	%esp, %eax
	andl	$0xFFFFFFC0, %esp
	subl	$0x20100, %esp
/* save unaligned stack */
	movl	%eax, 32(%esp)
/* memory base: X, Z, V */
	leal	128(%esp), %ebp
#endif /* WIN32 */

/* PBKDF2-HMAC-SHA256 */
	movl	$80, %eax
	movl	%esi, 0(%esp)
	movl	%eax, 4(%esp)
	movl	%esi, 8(%esp)
	movl	%eax, 12(%esp)
	movl	$1, 16(%esp)
	movl	%ebp, 20(%esp)
	movl	$128, 24(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_pbkdf2_sha256
#else
	call	neoscrypt_pbkdf2_sha256
#endif

/* SSE2 switch */
	testl	$0x1000, %ebx
	jnz	.scrypt_sse2

	leal	-64(%ebp), %edx
	movl	%edx, 8(%esp)
	movl	$4, 12(%esp)

	xorl	%ebx, %ebx
.salsa_s1:
/* blkcpy(V, X) */
	leal	128(%ebp), %eax
	movl	%ebx, %edx
	movl	$7, %ecx
	shll	%cl, %edx
	addl	%edx, %eax
	movq	0(%ebp), %mm0
	movq	8(%ebp), %mm1
	movq	16(%ebp), %mm2
	movq	24(%ebp), %mm3
	movq	32(%ebp), %mm4
	movq	40(%ebp), %mm5
	movq	48(%ebp), %mm6
	movq	56(%ebp), %mm7
	movq	%mm0, 0(%eax)
	movq	%mm1, 8(%eax)
	movq	%mm2, 16(%eax)
	movq	%mm3, 24(%eax)
	movq	%mm4, 32(%eax)
	movq	%mm5, 40(%eax)
	movq	%mm6, 48(%eax)
	movq	%mm7, 56(%eax)
	movq	64(%ebp), %mm0
	movq	72(%ebp), %mm1
	movq	80(%ebp), %mm2
	movq	88(%ebp), %mm3
	movq	96(%ebp), %mm4
	movq	104(%ebp), %mm5
	movq	112(%ebp), %mm6
	movq	120(%ebp), %mm7
	movq	%mm0, 64(%eax)
	movq	%mm1, 72(%eax)
	movq	%mm2, 80(%eax)
	movq	%mm3, 88(%eax)
	movq	%mm4, 96(%eax)
	movq	%mm5, 104(%eax)
	movq	%mm6, 112(%eax)
	movq	%mm7, 120(%eax)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa
	incl	%ebx
	cmpl	$1024, %ebx
	jnz	.salsa_s1

	xorl	%ebx, %ebx
.salsa_s2:
/* integerify(X) mod 1024 */
	leal	128(%ebp), %eax
	movl	64(%ebp), %edx
	andl	$0x03FF, %edx
	shll	$7, %edx
	addl	%edx, %eax
/* blkxor(X, V) */
	movq	0(%ebp), %mm0
	movq	8(%ebp), %mm1
	movq	16(%ebp), %mm2
	movq	24(%ebp), %mm3
	movq	32(%ebp), %mm4
	movq	40(%ebp), %mm5
	movq	48(%ebp), %mm6
	movq	56(%ebp), %mm7
	pxor	0(%eax), %mm0
	pxor	8(%eax), %mm1
	pxor	16(%eax), %mm2
	pxor	24(%eax), %mm3
	pxor	32(%eax), %mm4
	pxor	40(%eax), %mm5
	pxor	48(%eax), %mm6
	pxor	56(%eax), %mm7
	movq	%mm0, 0(%ebp)
	movq	%mm1, 8(%ebp)
	movq	%mm2, 16(%ebp)
	movq	%mm3, 24(%ebp)
	movq	%mm4, 32(%ebp)
	movq	%mm5, 40(%ebp)
	movq	%mm6, 48(%ebp)
	movq	%mm7, 56(%ebp)
	movq	64(%ebp), %mm0
	movq	72(%ebp), %mm1
	movq	80(%ebp), %mm2
	movq	88(%ebp), %mm3
	movq	96(%ebp), %mm4
	movq	104(%ebp), %mm5
	movq	112(%ebp), %mm6
	movq	120(%ebp), %mm7
	pxor	64(%eax), %mm0
	pxor	72(%eax), %mm1
	pxor	80(%eax), %mm2
	pxor	88(%eax), %mm3
	pxor	96(%eax), %mm4
	pxor	104(%eax), %mm5
	pxor	112(%eax), %mm6
	pxor	120(%eax), %mm7
	movq	%mm0, 64(%ebp)
	movq	%mm1, 72(%ebp)
	movq	%mm2, 80(%ebp)
	movq	%mm3, 88(%ebp)
	movq	%mm4, 96(%ebp)
	movq	%mm5, 104(%ebp)
	movq	%mm6, 112(%ebp)
	movq	%mm7, 120(%ebp)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa
	incl	%ebx
	cmpl	$1024, %ebx
	jnz	.salsa_s2

/* PBKDF2-HMAC-SHA256 */
	movl	%esi, 0(%esp)
	movl	$80, 4(%esp)
	movl	%ebp, 8(%esp)
	movl	$128, 12(%esp)
	movl	$1, 16(%esp)
	movl	%edi, 20(%esp)
	movl	$32, 24(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_pbkdf2_sha256
#else
	call	neoscrypt_pbkdf2_sha256
#endif

#if (WIN32)
/* free memory */
	movl	32(%esp), %eax
	movl	%eax, 0(%esp)
	call	_free
/* restore stack */
	addl	$64, %esp
#else
/* restore stack */
	movl	32(%esp), %esp
#endif
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	emms
	ret

.scrypt_sse2:
	movl	%ebp, 0(%esp)
	movl	$2, 4(%esp)
	call	neoscrypt_salsa_tangle_sse2

	movl	$4, 8(%esp)

	xorl	%ebx, %ebx
.salsa_s1_sse2:
/* blkcpy(V, X) */
	leal	128(%ebp), %eax
	movl	%ebx, %edx
	movl	$7, %ecx
	shll	%cl, %edx
	addl	%edx, %eax
	movdqa	0(%ebp), %xmm0
	movdqa	16(%ebp), %xmm1
	movdqa	32(%ebp), %xmm2
	movdqa	48(%ebp), %xmm3
	movdqa	64(%ebp), %xmm4
	movdqa	80(%ebp), %xmm5
	movdqa	96(%ebp), %xmm6
	movdqa	112(%ebp), %xmm7
	movdqa	%xmm0, 0(%eax)
	movdqa	%xmm1, 16(%eax)
	movdqa	%xmm2, 32(%eax)
	movdqa	%xmm3, 48(%eax)
	movdqa	%xmm4, 64(%eax)
	movdqa	%xmm5, 80(%eax)
	movdqa	%xmm6, 96(%eax)
	movdqa	%xmm7, 112(%eax)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	incl	%ebx
	cmpl	$1024, %ebx
	jnz	.salsa_s1_sse2

	xorl	%ebx, %ebx
.salsa_s2_sse2:
/* integerify(X) mod 1024 */
	leal	128(%ebp), %eax
	movl	64(%ebp), %edx
	andl	$0x03FF, %edx
	shll	$7, %edx
	addl	%edx, %eax
/* blkxor(X, V) */
	movdqa	0(%ebp), %xmm0
	movdqa	16(%ebp), %xmm1
	movdqa	32(%ebp), %xmm2
	movdqa	48(%ebp), %xmm3
	movdqa	64(%ebp), %xmm4
	movdqa	80(%ebp), %xmm5
	movdqa	96(%ebp), %xmm6
	movdqa	112(%ebp), %xmm7
	pxor	0(%eax), %xmm0
	pxor	16(%eax), %xmm1
	pxor	32(%eax), %xmm2
	pxor	48(%eax), %xmm3
	pxor	64(%eax), %xmm4
	pxor	80(%eax), %xmm5
	pxor	96(%eax), %xmm6
	pxor	112(%eax), %xmm7
	movdqa	%xmm0, 0(%ebp)
	movdqa	%xmm1, 16(%ebp)
	movdqa	%xmm2, 32(%ebp)
	movdqa	%xmm3, 48(%ebp)
	movdqa	%xmm4, 64(%ebp)
	movdqa	%xmm5, 80(%ebp)
	movdqa	%xmm6, 96(%ebp)
	movdqa	%xmm7, 112(%ebp)
/* blkmix(X) */
	movl	%ebp, 0(%esp)
	leal	64(%ebp), %edx
	movl	%edx, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	leal	64(%ebp), %eax
	movl	%eax, 0(%esp)
	movl	%ebp, 4(%esp)
	call	neoscrypt_xor_salsa_sse2
	incl	%ebx
	cmpl	$1024, %ebx
	jnz	.salsa_s2_sse2

	movl	%ebp, 0(%esp)
	movl	$2, 4(%esp)
	call	neoscrypt_salsa_tangle_sse2

/* PBKDF2-HMAC-SHA256 */
	movl	%esi, 0(%esp)
	movl	$80, 4(%esp)
	movl	%ebp, 8(%esp)
	movl	$128, 12(%esp)
	movl	$1, 16(%esp)
	movl	%edi, 20(%esp)
	movl	$32, 24(%esp)
#if (WIN32) || (__APPLE__)
	call	_neoscrypt_pbkdf2_sha256
#else
	call	neoscrypt_pbkdf2_sha256
#endif

#if (WIN32)
/* free memory */
	movl	32(%esp), %eax
	movl	%eax, 0(%esp)
	call	_free
/* restore stack */
	addl	$64, %esp
#else
/* restore stack */
	movl	32(%esp), %esp
#endif
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret

#endif /* (SHA256) */

#endif /* (ASM) && (__i386__) */
