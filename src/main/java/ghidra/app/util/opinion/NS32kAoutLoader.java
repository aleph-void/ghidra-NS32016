/* ###
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.opinion;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for linked National Semiconductor 32000-series BSD a.out executables (NetBSD/pc532, machine
 * id 137). The 32-byte header has the magic number and machine id stored most significant byte first
 * and the sizes least significant byte first. OMAGIC, NMAGIC, ZMAGIC and QMAGIC executables are
 * loaded; the symbol table (struct nlist) supplies labels and function entry points. Relocation
 * records of unlinked objects are not applied.
 */
public class NS32kAoutLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "NetBSD ns32k a.out";

	private static final int HEADER_SIZE = 32;
	private static final int OMAGIC = 0407;
	private static final int NMAGIC = 0410;
	private static final int ZMAGIC = 0413;
	private static final int QMAGIC = 0314;
	private static final int MID_PC532 = 137;
	private static final int PAGE = 0x1000;

	private static final int N_EXT = 1;
	private static final int N_TEXT = 4;
	private static final int N_DATA = 6;
	private static final int N_BSS = 8;
	private static final int N_ABS = 2;
	private static final int N_STAB = 0xe0;

	private static final String LANGUAGE = "NS32016:LE:32:NS32532";

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public int getTierPriority() {
		return 50;
	}

	private static boolean isMagic(int magic) {
		return magic == OMAGIC || magic == NMAGIC || magic == ZMAGIC || magic == QMAGIC;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < HEADER_SIZE) {
			return specs;
		}
		BinaryReader be = new BinaryReader(provider, false);
		int mid = be.readUnsignedShort(0) & 0x3ff;
		int magic = be.readUnsignedShort(2);
		if (mid != MID_PC532 || !isMagic(magic)) {
			return specs;
		}
		BinaryReader le = new BinaryReader(provider, true);
		long text = le.readUnsignedInt(4);
		long data = le.readUnsignedInt(8);
		if (text + data > provider.length() + PAGE) {
			return specs;
		}
		specs.add(new LoadSpec(this, textBase(magic), new LanguageCompilerSpecPair(LANGUAGE, "default"),
			true));
		return specs;
	}

	private static long textBase(int magic) {
		return (magic == ZMAGIC || magic == QMAGIC) ? PAGE : 0;
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws CancelledException, IOException {
		ByteProvider provider = settings.provider();
		TaskMonitor monitor = settings.monitor();
		BinaryReader be = new BinaryReader(provider, false);
		BinaryReader le = new BinaryReader(provider, true);
		int magic = be.readUnsignedShort(2);
		long text = le.readUnsignedInt(4);
		long data = le.readUnsignedInt(8);
		long bss = le.readUnsignedInt(12);
		long syms = le.readUnsignedInt(16);
		long entry = le.readUnsignedInt(20);
		long trsize = le.readUnsignedInt(24);
		long drsize = le.readUnsignedInt(28);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Memory mem = program.getMemory();
		boolean paged = magic == ZMAGIC || magic == QMAGIC;
		long textAddr = textBase(magic);
		// ZMAGIC/QMAGIC: the text segment includes the header, from file offset 0
		long textOff = paged ? 0 : HEADER_SIZE;
		long textLen = paged ? text : text;
		long dataOff = textOff + text;
		long dataAddr = paged ? alignUp(textAddr + text, PAGE) : alignUp(textAddr + text, 4);
		if (magic == NMAGIC) {
			dataAddr = alignUp(textAddr + text, PAGE);
		}
		try {
			if (text > 0) {
				createBlock(mem, provider, space, ".text", textAddr, textOff, textLen, true, monitor);
			}
			if (data > 0) {
				createBlock(mem, provider, space, ".data", dataAddr, dataOff, data, false, monitor);
			}
			if (bss > 0) {
				MemoryBlock b = mem.createUninitializedBlock(".bss", space.getAddress(dataAddr + data),
					bss, false);
				b.setRead(true);
				b.setWrite(true);
			}
			SymbolTable symtab = program.getSymbolTable();
			Address entryAddr = space.getAddress(entry);
			symtab.createLabel(entryAddr, "entry", SourceType.IMPORTED);
			symtab.addExternalEntryPoint(entryAddr);
			if (syms > 0) {
				long symOff = dataOff + data + trsize + drsize;
				applySymbols(program, provider, le, symOff, syms, space, textAddr, dataAddr, data);
			}
		}
		catch (Exception e) {
			throw new IOException("cannot load a.out image: " + e.getMessage(), e);
		}
	}

	private static long alignUp(long v, long a) {
		return (v + a - 1) / a * a;
	}

	private void createBlock(Memory mem, ByteProvider provider, AddressSpace space, String name,
			long addr, long fileOff, long len, boolean exec, TaskMonitor monitor) throws Exception {
		long avail = Math.max(0, Math.min(len, provider.length() - fileOff));
		try (InputStream in = provider.getInputStream(fileOff)) {
			MemoryBlock b = mem.createInitializedBlock(name, space.getAddress(addr), in, avail, monitor,
				false);
			b.setRead(true);
			b.setWrite(!exec);
			b.setExecute(exec);
		}
	}

	/** struct nlist: n_strx(4) n_type(1) n_other(1) n_desc(2) n_value(4); the string table follows. */
	private void applySymbols(Program program, ByteProvider provider, BinaryReader le, long symOff,
			long symBytes, AddressSpace space, long textAddr, long dataAddr, long dataLen)
			throws IOException {
		long count = symBytes / 12;
		long strBase = symOff + symBytes;
		if (strBase + 4 > provider.length()) {
			return;
		}
		SymbolTable symtab = program.getSymbolTable();
		for (long i = 0; i < count; i++) {
			long p = symOff + i * 12;
			long strx = le.readUnsignedInt(p);
			int type = le.readUnsignedByte(p + 4);
			long value = le.readUnsignedInt(p + 8);
			if ((type & N_STAB) != 0 || strx == 0) {
				continue;
			}
			int kind = type & ~N_EXT & 0x1f;
			if (kind != N_TEXT && kind != N_DATA && kind != N_BSS) {
				continue;
			}
			String name = le.readAsciiString(strBase + strx);
			if (name.isEmpty()) {
				continue;
			}
			try {
				Address a = space.getAddress(value);
				if (!program.getMemory().contains(a)) {
					continue;
				}
				symtab.createLabel(a, name, SourceType.IMPORTED);
				if (kind == N_TEXT) {
					AbstractProgramLoader.markAsFunction(program, name, a);
				}
			}
			catch (Exception e) {
				// ignore symbols that cannot be placed
			}
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			ghidra.framework.model.DomainObject domainObject, boolean isLoadIntoProgram,
			boolean mirrorFsLayout) {
		return new ArrayList<>();
	}
}
