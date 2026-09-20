# symbolize.py

Un seul fichier qui renomme les fonctions dans Ghidra **et** reinjecte les
symboles dans l'ELF. Plus besoin d'enchainer deux scripts a la main.

Le fichier est a la fois un script Ghidra (Jython) et un script CPython : il
detecte tout seul dans quel interpreteur il tourne.

## 1. Passe rapide, sans ouvrir Ghidra

```sh
python3 symbolize.py ./prog
```

Lance `analyzeHeadless`, renomme les `FUN_*`, exporte le JSON, reconstruit la
table de sections si elle manque, injecte les symboles et ecrit
`./prog_with_symbols`. Tout en une commande.

Options : `-o SORTIE`, `-p PREFIXE` (defaut `my_fn_`), `-j CHEMIN_JSON`,
`--ghidra /chemin/ghidra`, `--project DIR` (garde le projet au lieu d'un temporaire).

## 2. Depuis Ghidra, apres ton analyse

Script Manager > `symbolize.py`, ou le menu `Tools > Symbolize`.

Les fonctions que tu as deja renommees sont conservees, seules les `FUN_*`
restantes sont nommees automatiquement. Tes labels globaux (`USER_DEFINED`)
sont exportes aussi. Le binaire d'origine est patche dans la foulee vers
`<binaire>_with_symbols` : un seul clic, rien a relancer derriere.

Ghidra tourne en Jython et ne peut pas importer `lief`. Le script se relance
donc lui-meme via `subprocess` dans le `python3` du systeme. Il cherche un
interpreteur qui sait faire `import lief` dans `$PATH`, `/usr/bin`,
`/usr/local/bin` et `~/.local/bin`. Si Ghidra est lance depuis un raccourci
graphique avec un `PATH` minimal, force-le :

```sh
export SYMBOLIZE_PYTHON=/usr/bin/python3
```

## 3. Rejouer juste le patch

```sh
python3 symbolize.py --patch-only ./prog --json /tmp/symbols.json
```

## Ghidra 12.x : l'extension Jython est obligatoire

Depuis Ghidra 12, Jython n'est plus integre : c'est une extension optionnelle,
et les `.py` sans en-tete `@runtime` partent par defaut sur PyGhidra. D'ou
l'erreur :

    Unable to load script: xxx.py
      detail: Ghidra was not started with PyGhidra. Python is not available

Deux choses reglent ca, les deux sont deja en place ici :

1. Le script declare `#@runtime Jython` dans son en-tete. A remettre dans tous
   tes anciens scripts Jython, sinon ils tombent sur PyGhidra.
2. L'extension Jython doit etre installee : `File > Install Extensions`,
   cocher `Jython`, redemarrer. En ligne de commande :

   ```sh
   unzip /usr/share/ghidra/Extensions/Ghidra/*_Jython.zip \
         -d ~/.config/ghidra/ghidra_<version>/Extensions/
   ```

Si tu preferes PyGhidra, lance Ghidra avec `support/pyghidraRun` et enleve la
ligne `#@runtime Jython`. Le script detecte alors qu'il peut importer `lief`
directement et patche sans passer par un subprocess -- a condition que `lief`
soit installe dans le venv de PyGhidra.

## Configuration

L'install Ghidra utilisee en headless est auto-detectee : `$GHIDRA_HOME`, puis
la premiere de `/usr/share/ghidra`, `~/GHIDRA_SCRIPT/ghidra_11.4.2_PUBLIC`,
`~/Tools/ghidra`, `/opt/ghidra` qui possede un `support/analyzeHeadless`.
`--ghidra` force le choix. Prends la meme version que ton GUI, sinon l'analyse
headless et l'analyse interactive ne donnent pas les memes resultats.

`SYMBOLIZE_PYTHON` force l'interpreteur CPython utilise pour la partie lief.

## Details qui evitent les surprises

- Les adresses passent par `offset = va - image_base`, donc ca marche en PIE
  comme en non-PIE, et meme si tu as rebase le programme dans Ghidra.
- Un binaire dont les en-tetes de sections ont ete supprimes (`sstrip`) voit sa
  table reconstruite depuis les `PT_LOAD` (`.text` / `.rodata` / `.data` /
  `.bss`, plus `.shstrtab` et l'entree nulle).
- Une entree nulle est placee en tete de `.symtab` : `gdb`, `nm` et `objdump`
  ignorent l'index 0, sans elle le premier symbole est perdu.
- Les tailles de fonctions sont exportees, donc `disassemble ma_fonction`
  marche dans gdb.
- Le bloc `EXTERNAL` synthetique de Ghidra est filtre (il n'existe pas dans le
  fichier), et les symboles deja presents ne sont pas dupliques.

## Dependances

`pip install lief` (teste avec lief 0.16.1, Ghidra 11.4.2, Jython 2.7.4).
