#!/bin/sh

echo Testing key searching
./crackxls2003 -t -s "00 00 28 05 8f" protected_document.xls
cd test-files
../crackxls2003 -t -s "75 61 25 d0 6d" 4qwer.xls
../crackxls2003 -t -s "00 00 00 9c de" ape\$dog.xls

../crackxls2003 -t -s '00 00 20 b1 b5' 4qwer.doc
../crackxls2003 -t -s '00 00 88 20 23' monkey-2.doc

echo Testing decryption

rm -f testout.xls
../crackxls2003 -d  "9c a7 4a 7b 84" testdoc.xls testout.xls
poledump testout.xls
cmp testout.xls test-target.xls

rm -f 4qwer-out.doc
../crackxls2003 -d 'E6 8B 26 B1 B5' 4qwer.doc 4qwer-out.doc
poledump 4qwer-out.doc
cmp 4qwer-out.doc 4qwer-target.doc

rm -f monkey-2-out.doc
../crackxls2003 -d 'ea 65 8d 20 23' monkey-2.doc monkey-2-out.doc
poledump monkey-2-out.doc
cmp monkey-2-out.doc monkey-2-target.doc





