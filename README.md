# File Infector
A simple program written in C for injecting shellcode into ELF binaries

Usage:
  ./infector \<filename\>

Info:<br>
  Currently it doesn't support big-endian
  It only works on executable ELF binaries
  
How it works:<br>
  It gets the EPA (Entery Point Address) and puts it in the shellcode in order to jump to it after executing the shellcode then it
  looks for a codecave large enough for the shellcode. After finding one it places the shellcode there and deletes the null bytes
  there so the filesize will not change then it calculates the address of the shellcode in the file and replaces EPA with it.
  This causes the program to first jump to our shellcode execute it and then jump back to where the original EPA was and run the
  program normally.

If you found any bugs please report them to me<br>
Contact: nullbyteprivilege@gmail.com

******** I AM NOT RESPONSIBLE FOR ANY MISUSE OF THIS PROGRAM ********
