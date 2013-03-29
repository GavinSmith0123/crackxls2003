#!/bin/sh

echo Testing key searching
./crackxls2003 -t -s "00 00 28 05 8f" protected_document.xls
cd test-files
../crackxls2003 -t -s "75 61 25 d0 6d" 4qwer.xls
../crackxls2003 -t -s "00 00 00 9c de" ape\$dog.xls

echo Testing decryption
rm testout.xls
../crackxls2003 -d  "9c a7 4a 7b 84" testdoc.xls testout.xls
poledump testout.xls
cmp testout.xls test-target.xls
