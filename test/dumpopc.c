/* Dump GNU binutils' NS32000 opcode table (include/opcode/ns32k.h) as text for the test corpora:
   one line per entry: name id_bits total_bits seed-hex operand-string
   Built by build-dumpopc.sh against a binutils source tree; the output is generated at test time and
   not committed (binutils is GPL). */
#include <stdio.h>
#include "opcode/ns32k.h"
int main(void)
{
	unsigned n = sizeof(ns32k_opcodes) / sizeof(ns32k_opcodes[0]);
	for (unsigned i = 0; i < n; i++) {
		const struct ns32k_opcode *o = &ns32k_opcodes[i];
		printf("%s %u %u %lx %s\n", o->name, o->opcode_id_size, o->opcode_size, o->opcode_seed,
		       o->operands[0] ? o->operands : "-");
	}
	return 0;
}
