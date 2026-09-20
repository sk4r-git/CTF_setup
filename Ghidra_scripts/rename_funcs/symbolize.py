#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#@author sk4r
#@runtime Jython
#@category Symbol
#@keybinding
#@menupath Tools.Symbolize
#@toolbar
"""
symbolize.py -- renomme les fonctions Ghidra et reinjecte les symboles dans l'ELF.

Un seul fichier, trois facons de le lancer :

1. Headless, tout en un coup (pas besoin d'ouvrir Ghidra) :

       python3 symbolize.py ./prog

   -> lance analyzeHeadless, renomme les FUN_*, exporte le JSON,
      reconstruit les sections si besoin et ecrit ./prog_with_symbols

2. Depuis Ghidra (Script Manager ou Tools > Symbolize), apres ton analyse :

   -> renomme les FUN_* restants (tes noms a toi sont conserves),
      exporte le JSON, puis relance automatiquement ce meme fichier
      avec le python3 du systeme pour patcher le binaire. Un seul clic.

   Ghidra tourne en Jython : il ne peut pas importer lief. Le script se
   re-execute donc lui-meme via subprocess dans un CPython qui, lui, a lief.

3. Patch seul (c'est ce que Ghidra appelle en interne, utile pour rejouer) :

       python3 symbolize.py --patch-only ./prog --json /tmp/symbols.json

Arguments -postScript acceptes (headless) :
    prefix=my_fn_   json=/tmp/symbols.json   patch=0|1   binary=./prog   out=./prog.sym
"""
from __future__ import print_function

import json
import os
import sys

# --------------------------------------------------------------------------
# Configuration -- adapte ces valeurs a ta machine si besoin.
# GHIDRA_HOME et SYMBOLIZE_PYTHON sont aussi lisibles depuis l'environnement.
# --------------------------------------------------------------------------
GHIDRA_CANDIDATES = [
    "/usr/share/ghidra",
    os.path.expanduser("~/GHIDRA_SCRIPT/ghidra_11.4.2_PUBLIC"),
    os.path.expanduser("~/Tools/ghidra"),
    "/opt/ghidra",
]


def detect_ghidra_home():
    """GHIDRA_HOME, sinon la premiere install qui a un analyzeHeadless."""
    env = os.environ.get("GHIDRA_HOME")
    if env:
        return env
    for cand in GHIDRA_CANDIDATES:
        if os.path.isfile(os.path.join(cand, "support", "analyzeHeadless")):
            return cand
    return GHIDRA_CANDIDATES[0]


GHIDRA_HOME = detect_ghidra_home()
DEFAULT_PREFIX = "my_fn_"
DEFAULT_JSON = "/tmp/symbols.json"
OUTPUT_SUFFIX = "_with_symbols"
PROJECT_NAME = "SymbolizeProj"

# Prefixes Ghidra consideres comme "pas encore renommes par l'utilisateur".
AUTO_PREFIXES = ("FUN_", "thunk_FUN_")


def log(msg):
    print("[symbolize] %s" % msg)


def warn(msg):
    print("[symbolize][!] %s" % msg)


# ==========================================================================
#  Detection du mode d'execution
# ==========================================================================
def running_in_ghidra():
    """Vrai si on tourne dans l'interpreteur embarque de Ghidra (Jython ou PyGhidra)."""
    try:
        currentProgram  # noqa: F821  -- injecte par Ghidra
    except NameError:
        return False
    return True


def self_path():
    """Chemin absolu de CE fichier, y compris sous Jython ou __file__ manque."""
    try:
        return os.path.abspath(str(getSourceFile().getAbsolutePath()))  # noqa: F821
    except Exception:
        pass
    try:
        return os.path.abspath(__file__)
    except NameError:
        return os.path.abspath(sys.argv[0])


# ==========================================================================
#  PARTIE GHIDRA (Jython) -- renommage + export JSON + appel du patcher
# ==========================================================================
def ghidra_collect(prefix):
    """Renomme les fonctions auto-nommees et collecte fonctions + globales."""
    from ghidra.program.model.symbol import SourceType

    fm = currentProgram.getFunctionManager()          # noqa: F821
    st = currentProgram.getSymbolTable()              # noqa: F821
    listing = currentProgram.getListing()             # noqa: F821
    memory = currentProgram.getMemory()               # noqa: F821
    base = currentProgram.getImageBase().getOffset()  # noqa: F821

    functions = []
    renamed = 0

    for f in fm.getFunctions(True):
        if f.isExternal():
            continue
        entry_block = memory.getBlock(f.getEntryPoint())
        # Le bloc EXTERNAL de Ghidra est synthetique : il n'existe pas dans le fichier.
        if entry_block is None or entry_block.getName() == "EXTERNAL":
            continue
        name = f.getName()
        if name.startswith(AUTO_PREFIXES):
            name = prefix + f.getEntryPoint().toString()
            f.setName(name, SourceType.USER_DEFINED)
            renamed += 1
        entry = f.getEntryPoint()
        functions.append({
            "name": name,
            "va": entry.getOffset(),
            "offset": entry.getOffset() - base,
            "size": int(f.getBody().getNumAddresses()),
        })

    globals_ = []
    for sym in st.getAllSymbols(True):
        # On n'exporte que ce que TU as nomme a la main.
        if sym.getSource() != SourceType.USER_DEFINED:
            continue
        if not sym.getParentNamespace().isGlobal():
            continue
        if sym.isExternal():
            continue
        addr = sym.getAddress()
        if addr is None or not addr.isMemoryAddress():
            continue
        # Les fonctions sont deja sorties au-dessus.
        if fm.getFunctionAt(addr) is not None:
            continue
        block = memory.getBlock(addr)
        if block is None or block.getName() == "EXTERNAL":
            continue

        size = 0
        data = listing.getDataAt(addr)
        if data is not None:
            size = int(data.getLength())

        globals_.append({
            "name": sym.getName(),
            "va": addr.getOffset(),
            "offset": addr.getOffset() - base,
            "size": size,
        })

    return {
        "image_base": base,
        "functions": functions,
        "globals": globals_,
    }, renamed


def ghidra_binary_path():
    """Retrouve le fichier d'origine importe dans Ghidra."""
    try:
        path = currentProgram.getExecutablePath()  # noqa: F821
    except Exception:
        path = None
    if path:
        path = str(path)
        # Ghidra prefixe parfois les chemins Windows d'un '/'.
        if os.path.exists(path):
            return os.path.abspath(path)
        if len(path) > 2 and path[0] == "/" and path[2] == ":" and os.path.exists(path[1:]):
            return os.path.abspath(path[1:])
    return None


def find_cpython():
    """Trouve un CPython qui sait importer lief (Jython ne peut pas)."""
    import subprocess

    candidates = []
    forced = os.environ.get("SYMBOLIZE_PYTHON")
    if forced:
        candidates.append(forced)

    dirs = os.environ.get("PATH", "").split(os.pathsep)
    # Ghidra lance depuis un raccourci graphique a souvent un PATH minimal.
    dirs += ["/usr/local/bin", "/usr/bin", "/bin", os.path.expanduser("~/.local/bin")]
    for d in dirs:
        if not d:
            continue
        for name in ("python3", "python"):
            p = os.path.join(d, name)
            if os.path.isfile(p) and os.access(p, os.X_OK) and p not in candidates:
                candidates.append(p)

    for p in candidates:
        try:
            proc = subprocess.Popen(
                [p, "-c", "import lief"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            proc.communicate()
            if proc.returncode == 0:
                return p
        except Exception:
            continue
    return None


def run_subprocess(cmd, tag):
    """Lance une commande et recopie sa sortie dans la console (Ghidra incluse)."""
    import subprocess

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        print("%s %s" % (tag, line.rstrip()))
    proc.stdout.close()
    return proc.wait()


def ghidra_main():
    args = {}
    try:
        for a in getScriptArgs():  # noqa: F821
            if "=" in a:
                k, v = str(a).split("=", 1)
                args[k] = v
    except Exception:
        pass

    prefix = args.get("prefix", DEFAULT_PREFIX)
    json_path = args.get("json", args.get("output", DEFAULT_JSON))
    out_path = args.get("out")
    do_patch = args.get("patch", "1").lower() not in ("0", "no", "false", "off")

    data, renamed = ghidra_collect(prefix)

    json_dir = os.path.dirname(os.path.abspath(json_path))
    if json_dir and not os.path.isdir(json_dir):
        os.makedirs(json_dir)
    fd = open(json_path, "w")
    try:
        json.dump(data, fd, indent=2)
    finally:
        fd.close()

    log("%d fonction(s) auto-renommee(s) avec le prefixe '%s'" % (renamed, prefix))
    log("%d fonction(s) et %d globale(s) exportee(s) vers %s"
        % (len(data["functions"]), len(data["globals"]), json_path))

    if not do_patch:
        # Le driver headless (etape 1) patchera lui-meme apres la fermeture du projet.
        return

    binary = args.get("binary") or ghidra_binary_path()
    if binary is None:
        warn("binaire d'origine introuvable (getExecutablePath). Patch manuel :")
        warn("    python3 %s --patch-only <binaire> --json %s" % (self_path(), json_path))
        return

    try:
        import lief  # noqa: F401
    except ImportError:
        pass
    else:
        # PyGhidra : on tourne deja dans un CPython qui a lief, pas de subprocess.
        log("lief disponible dans l'interpreteur courant, patch direct")
        patch_binary(binary, json_path, out_path)
        return

    python = find_cpython()
    if python is None:
        warn("aucun python3 avec lief trouve. Installe-le (pip install lief) ou pose")
        warn("SYMBOLIZE_PYTHON=/chemin/vers/python3 dans l'environnement de Ghidra.")
        warn("Patch manuel : python3 %s --patch-only %s --json %s"
             % (self_path(), binary, json_path))
        return

    cmd = [python, self_path(), "--patch-only", binary, "--json", json_path]
    if out_path:
        cmd += ["-o", out_path]

    log("patch via %s ..." % python)
    rc = run_subprocess(cmd, "  |")
    if rc != 0:
        warn("le patch lief a echoue (code %d)" % rc)


# ==========================================================================
#  PARTIE CPYTHON -- reconstruction des sections + injection des symboles
# ==========================================================================
def elf_link_base(elf):
    """Adresse de chargement de l'ELF tel qu'il est lie (0 pour un PIE)."""
    import lief

    bases = [s.virtual_address for s in elf.segments
             if s.type == lief.ELF.Segment.TYPE.LOAD]
    return min(bases) if bases else 0


def rebuild_sections(elf):
    """Recree une table de sections a partir des PT_LOAD (binaire sstrip-e)."""
    import lief

    if len(elf.sections) > 0:
        return 0

    S = lief.ELF.Section
    SEG = lief.ELF.Segment

    def add(name, stype, flags=0):
        sec = S()
        sec.name = name
        sec.type = stype
        sec.flags = int(flags)
        # loaded=False : on decrit du contenu deja present, pas de nouveau segment.
        return elf.add(sec, False)

    used = {}

    def uniq(name):
        n = used.get(name, 0)
        used[name] = n + 1
        return name if n == 0 else "%s.%d" % (name, n)

    # L'index 0 est reserve par l'ABI ELF : sans lui, shndx=0 veut dire SHN_UNDEF.
    add("", S.TYPE.SHT_NULL_)

    added = 0
    for seg in elf.segments:
        if seg.type != SEG.TYPE.LOAD or seg.physical_size == 0:
            continue

        flags = int(S.FLAGS.ALLOC.value)
        if seg.has(SEG.FLAGS.X):
            name = ".text"
            flags |= int(S.FLAGS.EXECINSTR.value)
        elif seg.has(SEG.FLAGS.W):
            name = ".data"
            flags |= int(S.FLAGS.WRITE.value)
        else:
            name = ".rodata"

        sec = add(uniq(name), S.TYPE.PROGBITS, flags)
        # La geometrie se pose APRES add() : LIEF recalcule size depuis le content.
        sec.virtual_address = seg.virtual_address
        sec.offset = seg.file_offset
        sec.size = seg.physical_size
        sec.alignment = seg.alignment or 1
        added += 1

        # Queue non mappee du segment inscriptible = .bss
        bss = seg.virtual_size - seg.physical_size
        if bss > 0 and seg.has(SEG.FLAGS.W):
            sec = add(uniq(".bss"), S.TYPE.NOBITS,
                      int(S.FLAGS.ALLOC.value) | int(S.FLAGS.WRITE.value))
            sec.virtual_address = seg.virtual_address + seg.physical_size
            sec.offset = seg.file_offset + seg.physical_size
            sec.size = bss
            sec.alignment = 1
            added += 1

    # Sans .shstrtab, LIEF ne sait pas ou ecrire les noms de sections.
    shstrtab_name = ".shstrtab"
    add(shstrtab_name, S.TYPE.STRTAB)
    for idx, sec in enumerate(elf.sections):
        if sec.name == shstrtab_name:
            elf.header.section_name_table_idx = idx
            break

    # sstrip met e_shentsize a 0 ; il faut le restaurer sinon readelf/gdb decrochent.
    is64 = elf.header.identity_class == lief.ELF.Header.CLASS.ELF64
    elf.header.section_header_size = 64 if is64 else 40

    return added


def alloc_sections(elf):
    """Liste (index, section) des sections reellement mappees en memoire."""
    import lief

    out = []
    for idx, sec in enumerate(elf.sections):
        if sec.virtual_address == 0 or sec.size == 0:
            continue
        if not sec.has(lief.ELF.Section.FLAGS.ALLOC):
            continue
        out.append((idx, sec))
    return out


def section_index_for(sections, va):
    for idx, sec in sections:
        if sec.virtual_address <= va < sec.virtual_address + sec.size:
            return idx
    return None


def patch_binary(binary, json_path, output=None):
    import lief

    with open(json_path) as fd:
        data = json.load(fd)

    elf = lief.ELF.parse(binary)
    if elf is None:
        raise SystemExit("[symbolize][!] %s n'est pas un ELF lisible" % binary)

    ghidra_base = data.get("image_base", 0)
    link_base = elf_link_base(elf)

    def to_file_va(entry):
        # 'offset' est relatif a l'image base de Ghidra : robuste meme si tu as rebase.
        off = entry.get("offset")
        if off is None:
            off = entry["va"] - ghidra_base
        return off + link_base

    added_sections = rebuild_sections(elf)
    if added_sections:
        log("table de sections absente : %d section(s) reconstruite(s) depuis les PT_LOAD"
            % added_sections)

    sections = alloc_sections(elf)
    if not sections:
        raise SystemExit("[symbolize][!] aucune section mappable, impossible de placer les symboles")

    existing = set(s.name for s in elf.symtab_symbols)

    if len(elf.symtab_symbols) == 0:
        # BFD (gdb, nm, objdump) considere symtab[0] comme l'entree nulle reservee
        # et l'ignore : sans ce placeholder on perd le premier vrai symbole.
        null = lief.ELF.Symbol()
        null.name = ""
        null.value = 0
        null.size = 0
        null.type = lief.ELF.Symbol.TYPE.NOTYPE
        null.binding = lief.ELF.Symbol.BINDING.LOCAL
        null.shndx = 0
        elf.add_symtab_symbol(null)

    def inject(entries, sym_type, kind):
        ok = skipped = dup = 0
        for e in entries:
            if e["name"] in existing:
                dup += 1
                continue
            va = to_file_va(e)
            idx = section_index_for(sections, va)
            if idx is None:
                warn("%s %s @ 0x%x hors de toute section, ignore" % (kind, e["name"], va))
                skipped += 1
                continue
            sym = lief.ELF.Symbol()
            sym.name = e["name"]
            sym.value = va
            sym.size = e.get("size", 0) or 0
            sym.type = sym_type
            sym.binding = lief.ELF.Symbol.BINDING.GLOBAL
            sym.visibility = lief.ELF.Symbol.VISIBILITY.DEFAULT
            sym.shndx = idx
            elf.add_symtab_symbol(sym)
            existing.add(e["name"])
            ok += 1
        return ok, skipped, dup

    f_ok, f_skip, f_dup = inject(
        data.get("functions", []), lief.ELF.Symbol.TYPE.FUNC, "fonction")
    g_ok, g_skip, g_dup = inject(
        data.get("globals", []), lief.ELF.Symbol.TYPE.OBJECT, "globale")

    if output is None:
        output = binary + OUTPUT_SUFFIX
    elf.write(output)
    try:
        os.chmod(output, 0o755)
    except OSError:
        pass

    log("%d fonction(s) + %d globale(s) injectee(s)  (ignorees: %d, deja presentes: %d)"
        % (f_ok, g_ok, f_skip + g_skip, f_dup + g_dup))
    log("ecrit -> %s" % output)
    return output


# ==========================================================================
#  PARTIE HEADLESS -- pilote analyzeHeadless puis patche, en un seul appel
# ==========================================================================
def headless_main(opts):
    import shutil
    import tempfile

    binary = os.path.abspath(opts.binary)
    if not os.path.isfile(binary):
        raise SystemExit("[symbolize][!] fichier introuvable : %s" % binary)

    analyze = os.path.join(opts.ghidra, "support", "analyzeHeadless")
    if not os.path.isfile(analyze):
        raise SystemExit(
            "[symbolize][!] analyzeHeadless introuvable dans %s\n"
            "                pose GHIDRA_HOME=... ou utilise --ghidra" % opts.ghidra)

    me = self_path()
    project_dir = opts.project or tempfile.mkdtemp(prefix="symbolize-")
    cleanup = opts.project is None

    cmd = [
        analyze, project_dir, PROJECT_NAME,
        "-import", binary,
        "-scriptPath", os.path.dirname(me),
        "-postScript", os.path.basename(me),
        "prefix=" + opts.prefix,
        "json=" + opts.json,
        "patch=0",  # le patch se fait ici, apres fermeture propre du projet
        "-deleteProject",
    ]

    log("analyse headless de %s ..." % binary)
    rc = run_subprocess(cmd, "  |")
    if rc != 0:
        if cleanup:
            shutil.rmtree(project_dir, ignore_errors=True)
        raise SystemExit("[symbolize][!] analyzeHeadless a echoue (code %d)" % rc)
    if cleanup:
        shutil.rmtree(project_dir, ignore_errors=True)

    if not os.path.isfile(opts.json):
        raise SystemExit("[symbolize][!] %s n'a pas ete produit par Ghidra" % opts.json)

    patch_binary(binary, opts.json, opts.out)


def cpython_main(argv):
    import argparse

    p = argparse.ArgumentParser(
        prog="symbolize.py",
        description="Renomme les fonctions via Ghidra et reinjecte les symboles dans l'ELF.",
    )
    p.add_argument("binary", help="binaire ELF a symboliser")
    p.add_argument("-o", "--out", default=None,
                   help="fichier de sortie (defaut: <binaire>%s)" % OUTPUT_SUFFIX)
    p.add_argument("-p", "--prefix", default=DEFAULT_PREFIX,
                   help="prefixe des fonctions auto-renommees (defaut: %s)" % DEFAULT_PREFIX)
    p.add_argument("-j", "--json", default=DEFAULT_JSON,
                   help="chemin du JSON intermediaire (defaut: %s)" % DEFAULT_JSON)
    p.add_argument("--patch-only", action="store_true",
                   help="ne relance pas Ghidra, patche a partir du JSON existant")
    p.add_argument("--ghidra", default=GHIDRA_HOME,
                   help="racine de l'installation Ghidra (defaut: %s)" % GHIDRA_HOME)
    p.add_argument("--project", default=None,
                   help="dossier de projet Ghidra a conserver (defaut: temporaire, supprime)")
    opts = p.parse_args(argv)

    if opts.patch_only:
        patch_binary(opts.binary, opts.json, opts.out)
    else:
        headless_main(opts)


# ==========================================================================
if running_in_ghidra():
    ghidra_main()
elif __name__ == "__main__":
    cpython_main(sys.argv[1:])
