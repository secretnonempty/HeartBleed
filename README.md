Compile:


perl Configure VC-WIN32<br>
set path=d:\nasm;%path%<br>
ms\do_nasm<br>
nmake -f ms\nt.mak<br>
set include=%~dp0inc32;%include%<br>
set lib=%~dp0out32;%lib%<br> 
cl /EHsc /MT /Zi heartbleed.c getopt_long.c /link /subsystem:console /machine:x86 /OPT:REF /PDB:heartbleed.pdb<br>
cl /EHsc /MT /Zi heartleech.c /link /subsystem:console /machine:x86 /OPT:REF /PDB:heartleech.pdb<br>

