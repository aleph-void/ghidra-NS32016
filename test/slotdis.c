/* Disassemble the first instruction of every fixed-size slot of a file with GNU libopcodes
   (ns32k), one line per slot:  "<slot> <length> <text>".  Length 1 with a text starting with a
   digit is binutils' "undefined opcode" output.
     slotdis <file> <slot-size> [mach]
   Built by build-slotdis.sh against an installed binutils (libopcodes.a) and its headers. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#define PACKAGE "x"
#define PACKAGE_VERSION "x"
#include "bfd.h"
#include "dis-asm.h"

static char outbuf[4096];
static int outlen;

static int cap(void *s, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	outlen += vsnprintf(outbuf + outlen, sizeof(outbuf) - outlen, fmt, ap);
	va_end(ap);
	return 0;
}

static int cap_styled(void *s, enum disassembler_style st, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	outlen += vsnprintf(outbuf + outlen, sizeof(outbuf) - outlen, fmt, ap);
	va_end(ap);
	return 0;
}

static void print_addr(bfd_vma addr, struct disassemble_info *info)
{
	outlen += snprintf(outbuf + outlen, sizeof(outbuf) - outlen, "0x%llx", (unsigned long long)addr);
}

/* slotdis <file> list <base-address> <addresses.txt> [mach]: decode one instruction at each hex
   address of the list; the file is mapped at <base-address>.  Output: "<address> <length> <text>". */
static int list_mode(int argc, char **argv)
{
	FILE *f = fopen(argv[1], "rb");
	unsigned long long base = strtoull(argv[3], NULL, 16);
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	unsigned char *buf = malloc(sz);
	if (fread(buf, 1, sz, f) != (size_t)sz)
		return 1;
	FILE *al = fopen(argv[4], "r");
	unsigned long long a;
	while (fscanf(al, "%llx", &a) == 1) {
		struct disassemble_info info;
		init_disassemble_info(&info, NULL, cap, cap_styled);
		info.arch = bfd_arch_ns32k;
		info.mach = argc > 5 ? atoi(argv[5]) : 0;
		long off = (long)(a - base);
		info.buffer = buf + off;
		info.buffer_vma = a;
		info.buffer_length = sz - off > 64 ? 64 : sz - off;
		info.print_address_func = print_addr;
		disassemble_init_for_target(&info);
		disassembler_ftype d = disassembler(bfd_arch_ns32k, 0, info.mach, NULL);
		outlen = 0;
		outbuf[0] = 0;
		int len = d(a, &info);
		for (char *c = outbuf; *c; c++)
			if (*c == '\t')
				*c = ' ';
		printf("%llx %d %s\n", a, len, outbuf);
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc > 4 && !strcmp(argv[2], "list"))
		return list_mode(argc, argv);
	FILE *f = fopen(argv[1], "rb");
	int slot = atoi(argv[2]);
	fseek(f, 0, SEEK_END);
	long sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	unsigned char *buf = malloc(sz);
	if (fread(buf, 1, sz, f) != (size_t)sz)
		return 1;
	for (long i = 0; i < sz / slot; i++) {
		struct disassemble_info info;
		init_disassemble_info(&info, NULL, cap, cap_styled);
		info.arch = bfd_arch_ns32k;
		info.mach = argc > 3 ? atoi(argv[3]) : 0;
		info.buffer = buf + i * slot;
		info.buffer_vma = i * slot;
		info.buffer_length = slot;
		info.print_address_func = print_addr;
		disassemble_init_for_target(&info);
		disassembler_ftype d = disassembler(bfd_arch_ns32k, 0, info.mach, NULL);
		outlen = 0;
		outbuf[0] = 0;
		int len = d(i * slot, &info);
		for (char *c = outbuf; *c; c++)
			if (*c == '\t')
				*c = ' ';
		printf("%ld %d %s\n", i, len, outbuf);
	}
	return 0;
}
