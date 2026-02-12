#!/bin/sh

echo "sources are supposed to be already curled"
echo "and under the following architecture :"
echo "./pwn_xxx"
echo "./pwn_yyy"
echo "./re_xxx"
echo "./re_yyy"
echo "./cry_xxx"
echo "./cry_yyy"

echo "for pwn chall, dir contains either:"
echo "  a zip file"
echo "  a binary with libc"
echo "  a binary with docker"

# need
# patchelf
# pwninit
# one_gadget
# elfutils
# binutils

# sh=$SHELL
# sh2=$(basename $sh)
# pwd=$PWD
# rc="~/.${sh2}rc"
# echo "export PATH=\$PATH:$pwd/Utils" >> $rc
# rm -rf ./.git*
# rm gitp