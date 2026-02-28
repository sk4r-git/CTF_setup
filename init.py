#!/usr/bin/python

import subprocess
import os
import json


print("sources are supposed to be already curled")
print("and under the following architecture :")
print("./pwn_xxx")
print("./pwn_yyy")
print("./re_xxx")
print("./re_yyy")
print("./cry_xxx")
print("./cry_yyy")

print("for pwn chall, dir contains either:")
print("  a zip file")
print("  a binary with libc")
print("  a tar file")
print("  a tar.gz file")

json_path = "./CTF_setup/state_dir.json"
if os.path.exists(json_path):
    with open(json_path, "r") as f:
        try:
            dir_state = json.load(f)
        except json.JSONDecodeError:
            print("JSON invalide, création d'un nouveau dictionnaire")
            dir_state = {"directories processed": []}
else:
    print("Fichier JSON inexistant, création")
    dir_state = {"directories processed": []}

print(dir_state)

state_lookup = {d["dir"]: d["processed"] for d in dir_state["directories processed"]}

for dirs in os.listdir("."):
    if dirs.startswith("pwn") and (state_lookup.get(dirs) == False or not dirs in state_lookup):
        try:
            subprocess.run(f"./CTF_setup/Utils/pwninit.py {dirs}", shell=True)
            success = True
        except:
            success = False

        exists = any(d["dir"] == dirs for d in dir_state["directories processed"])
        if not exists:
            dir_state["directories processed"].append({
                "dir": dirs,
                "processed": success,
            })


with open(json_path, "w") as fd:
    json.dump(dir_state, fd, indent=2)

