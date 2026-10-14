"""Dump class vtables out of an MSVC-built PE, using its RTTI.

The Linux dumps in mvm-reversed/Useful/vtable carry a name per slot because
server_srv.so keeps its symbols. server.dll does not, so the only thing that
still names a class on the Windows side is RTTI: MSVC emits a Complete Object
Locator immediately before every vtable, and the locator points at a type
descriptor holding the decorated class name.

That is enough to produce the same shape of dump, one file per class, minus the
per-slot names. Matching a slot to a Linux signature is a separate problem and
a separate tool; this one only has to be exhaustive and honest about what it
found.

Layout, from the documented MSVC ABI. 32-bit, where the fields are absolute
addresses:

    RTTICompleteObjectLocator        TypeDescriptor
      +0x00 signature (0)              +0x00 vftable of type_info
      +0x04 offset                     +0x04 spare
      +0x08 cdOffset                   +0x08 name, ".?AVCTFPlayer@@"
      +0x0c pTypeDescriptor
      +0x10 pClassDescriptor

64-bit uses the same order but stores RVAs and adds a self RVA at +0x14.

    python3 dumpvtables.py server.dll out_dir/
"""
import struct, sys, re
from pathlib import Path

IMAGE_SCN_MEM_EXECUTE = 0x20000000


class PE:
    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a PE: no MZ")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE: no PE signature")
        coff = pe + 4
        machine, sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        self.pe32_plus = magic == 0x20B
        self.base = (struct.unpack_from("<Q", data, opt + 24)[0] if self.pe32_plus
                     else struct.unpack_from("<I", data, opt + 28)[0])
        self.ptr = 8 if self.pe32_plus else 4
        self.sections = []
        table = opt + opt_size
        for i in range(sections):
            off = table + i * 40
            name = data[off:off + 8].rstrip(b"\0").decode("latin-1")
            vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
            flags = struct.unpack_from("<I", data, off + 36)[0]
            self.sections.append({
                "name": name, "va": self.base + va, "vsize": vsize or rawsize,
                "raw": rawptr, "rawsize": rawsize,
                "exec": bool(flags & IMAGE_SCN_MEM_EXECUTE),
            })

    def section_of(self, va):
        for s in self.sections:
            if s["va"] <= va < s["va"] + s["vsize"]:
                return s
        return None

    def read(self, va, n):
        s = self.section_of(va)
        if s is None:
            return None
        off = s["raw"] + (va - s["va"])
        if off + n > s["raw"] + s["rawsize"]:
            return None
        return self.data[off:off + n]

    def word(self, va):
        """One pointer-sized value, or None if va is not backed by file bytes."""
        raw = self.read(va, self.ptr)
        if raw is None or len(raw) < self.ptr:
            return None
        return struct.unpack("<Q" if self.pe32_plus else "<I", raw)[0]

    def dword(self, va):
        raw = self.read(va, 4)
        return None if raw is None or len(raw) < 4 else struct.unpack("<I", raw)[0]

    def is_code(self, va):
        s = self.section_of(va)
        return s is not None and s["exec"]


def type_descriptors(pe):
    """address -> decorated class name, for every ".?AV"/".?AU" descriptor."""
    out = {}
    name_at = pe.ptr * 2
    for s in pe.sections:
        blob = pe.data[s["raw"]:s["raw"] + s["rawsize"]]
        for m in re.finditer(rb"\.\?A[VU][^\x00]{0,510}\x00", blob):
            name_va = s["va"] + m.start()
            out[name_va - name_at] = m.group(0).rstrip(b"\0").decode("latin-1")
    return out


def locators(pe, descriptors):
    """address -> (class name, offset), for every Complete Object Locator we can believe.

    The offset is where in the complete object this vtable's subobject sits, and
    it is what tells a class's own table from the ones it carries for the bases
    it multiply inherits: the primary table is the one at offset 0. Without it a
    class with several tables is unmatchable, which is the largest refusal
    bucket in matchvtables.py.
    """
    found = {}
    for s in pe.sections:
        if s["exec"]:
            continue
        for va in range(s["va"], s["va"] + s["vsize"] - 20, 4):
            if pe.dword(va) != 0 and not pe.pe32_plus:
                continue
            td = pe.dword(va + 12)
            if td is None:
                continue
            addr = td if not pe.pe32_plus else pe.base + td
            name = descriptors.get(addr)
            if name is None:
                continue
            cd = pe.dword(va + 16)
            target = cd if not pe.pe32_plus else pe.base + (cd or 0)
            if cd and pe.section_of(target) is not None:
                found[va] = (name, pe.dword(va + 4) or 0)
    return found


def vtables(pe, cols):
    """class name -> [(slot index, function address)], from the slot after each locator.

    Walking forward until the first non-code pointer runs straight into the next
    class, because .rdata packs the tables together and the neighbour's first
    slot is a code pointer too. Every table is preceded by its own locator, so
    the locator addresses are the boundaries: a table ends before the next one.
    """
    starts = []
    for s in pe.sections:
        if s["exec"]:
            continue
        for va in range(s["va"], s["va"] + s["vsize"] - pe.ptr, pe.ptr):
            pointed = pe.word(va)
            if pointed is not None and pointed in cols:
                name, offset = cols[pointed]
                starts.append((va + pe.ptr, name, offset))

    boundaries = sorted(cols)
    out = {}
    for start, name, offset in starts:
        limit = next((b for b in boundaries if b > start), None)
        slots, at = [], start
        while limit is None or at < limit:
            fn = pe.word(at)
            if fn is None or not pe.is_code(fn):
                break
            slots.append((len(slots), fn))
            at += pe.ptr
        if slots:
            out.setdefault(name, []).append((start, offset, slots))
    return out


def undecorate(name):
    """.?AVCTFPlayer@@ -> CTFPlayer. Nested names come back outermost last."""
    body = name[4:]
    if body.endswith("@@"):
        body = body[:-2]
    parts = [p for p in body.split("@") if p]
    return "::".join(reversed(parts)) if parts else name


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        raise SystemExit(2)
    binary, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    pe = PE(binary.read_bytes())
    print(f"{binary.name}: {'x64' if pe.pe32_plus else 'x86'}, base 0x{pe.base:x}, "
          f"{len(pe.sections)} sections")

    descriptors = type_descriptors(pe)
    print(f"type descriptors : {len(descriptors)}")
    cols = locators(pe, descriptors)
    print(f"object locators  : {len(cols)}")
    tables = vtables(pe, cols)
    print(f"vtables          : {sum(len(v) for v in tables.values())} "
          f"across {len(tables)} classes")

    outdir.mkdir(parents=True, exist_ok=True)
    for decorated, instances in sorted(tables.items()):
        pretty = undecorate(decorated)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", pretty)
        lines = [pretty, ""]
        for start, offset, slots in sorted(instances):
            # The offset is always written, not only when a class has several
            # tables: a reader should not have to know how many there were to
            # know whether this is the class's own table or a base's.
            lines.append(f"// vtable at 0x{start:08x} offset 0x{offset:04x}")
            for index, fn in slots:
                lines.append(f"+0x{index * pe.ptr:04x}:  {fn:08x}")
            lines.append("")
        (outdir / f"{safe}.txt").write_text("\n".join(lines))
    print(f"wrote {len(tables)} files to {outdir}")


main()
