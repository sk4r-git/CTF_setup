#!/usr/bin/python

import subprocess
import os
import sys

os.chdir(sys.argv[1])
print("################")
print(os.getcwd())

#backup okazou
os.mkdir("backup.bck.bak")
for file_name in os.listdir("."):
    if file_name != "backup.bck.bak":
        subprocess.run("cp -r " + file_name + " " + "backup.bck.bak/", shell=True)

def restore_backup():
    for file_name in os.listdir("."):
        if file_name != "backup.bck.bak":
            os.remove(file_name)
    subprocess.run("mv backup.bck.bak/* .", shell=True)
    os.remove("backup.bck.bak")

# all unzipping and depth 0
for file_name in os.listdir("."):
    error = 0
    print(file_name)
    is_zip = False
    if "Zip archive data" in subprocess.run("file " + file_name, shell=True, capture_output=True, text=True).stdout:
        is_zip = True
    if is_zip:
        arch_content = subprocess.run("unzip -l " + file_name + " | tail -n+4 | head -n-2", shell=True, capture_output=True, text=True)
        for files in arch_content.stdout.splitlines():
            fname = files.split(" ")[-1]
            if fname.endswith("/"):
                continue
            if "/" in fname:
                fname = fname.split("/")[-1]
            idx = 0
            new_fname = fname
            while new_fname in os.listdir("."):
                new_fname = fname + "." + str(idx)
                idx += 1
            path = files.split(" ")[-1]
            uz = subprocess.run("unzip -p " + file_name + " " + path + " > " + new_fname, shell=True, capture_output=True, text=True)
            if uz.returncode != 0:
                error = 1
    if error == 1:
        print("error on unzipping file ", file_name)
        print("you should do it by hand")
        restore_backup()
        exit(1)
    if error == 0 and is_zip:
        os.remove(file_name)
try:
    subprocess.run("pwninit --template-path=../CTF_setup/Utils/template.py", shell=True)
except:
    restore_backup()