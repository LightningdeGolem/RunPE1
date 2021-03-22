nasm -f win64 injected_asm.asm
link /ENTRY:main /MACHINE:X64 /NODEFAULTLIB /SUBSYSTEM:CONSOLE injected_asm.obj