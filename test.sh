#!/bin/sh

./crackxls2003 -t -s "00 00 28 05 8f" protected_document.xls
cd test-files
../crackxls2003 -t -s "75 61 25 d0 6d" 4qwer.xls
../crackxls2003 -t -s "00 00 00 9c de" ape\$dog.xls
