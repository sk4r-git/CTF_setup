# Usage

2 options:

## passe rapide

Voulez faire une premiere passe rapide sans avoir à ouvrir ghidra
et simplement avoir des symboles nommables
alors lancez le script en headless, il faut juste decommenter la ligne
subprocess.run(cmd, check=True)

## après analyse et avant gdb
Une fois l'analyse faite avec ghidra et les fonction renommées,
lancer le script rename.py avec le script manager
ça va écrire le json dans /tmp

ensuite avec la ligne copmmentée, lancer le refind_symbols.py