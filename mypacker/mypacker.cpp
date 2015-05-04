// mypacker.cpp : definisce il punto di ingresso dell'applicazione console.
//

#include "stdafx.h"
#include "pe.h"
#include "debug.h"



PE pe;

void encrypt(isections *section, int val);
int load_stub(PE *pe);
int write_stub_file(char stub[],int size,char *temp_asm_path );
int read_stub_file(char *filename,char **buffer);

int _tmain(int argc, _TCHAR* argv[])
{
	char *input_path ="C:\\Users\\phate\\Desktop\\mypacker\\compiled.exe";
	char *output_path ="C:\\Users\\phate\\Desktop\\mypacker\\mypacked.exe";

	
	printf("loaded path %s\n",input_path);
	if (!pe_read(input_path, &pe)) {
		printf("Wrong PE format\n");
		return -1;
	}
	printf("PE has been read\n");

	DWORD oep = pe.EntryPoint;
	printf("OEP is %x",oep);
	//get the section containing the entry point
	int ep_section_number = getEntryPointSection(&pe);
	isections  *ep_section = &pe.m_sections[ep_section_number];
	//set the section writable	
	DEBUG(("old Entry Point Section Characteristics %x\n",ep_section->header.Characteristics));
	ep_section->header.Characteristics |= IMAGE_SCN_MEM_WRITE;
	DEBUG(("new Entry Point Section Characteristics %x\n",pe.m_sections[0].header.Characteristics));
	//Encrypting data
	DEBUG(("Entry Point Section before encrypting "));
	printSectionInfo(ep_section);
	encrypt(ep_section,0x01);
	DEBUG(("Entry Point Section after encrypting "));
	printSectionInfo(ep_section);

	//reading decrypted hex from file
	load_stub(&pe);
/*
	if (!pe_write(output_path, &pe)) {
		printf("Error in writing PE \n");
		return 0;
	}
	printf("Encrypted PE successfully written in %s \n",output_path);
*/
	return 0;
}

void encrypt(isections *section, int val){
	
	DEBUG(("Section EP has Data\n"));
	for (unsigned int i=0;i< section->header.SizeOfRawData;i++){
		section->data[i] = section->data[i] ^ val;
		}
	
	}

int load_stub(PE *pe){
	//writing the stub in a temporary file
	
	char *yasm_path="C:\\Users\\phate\\Desktop\\mypacker\\yasm.exe";
	char *temp_asm_path="C:\\Users\\phate\\Desktop\\mypacker\\temp_decrypter.asm";
	char *hex_decrypter_path="C:\\Users\\phate\\Desktop\\mypacker\\decrypter";
	char stub[] ="bits 32\n"
				"	pushad       ; save registers\n"
				"	mov esi, 000401000h  ; set up registers for decryption loop\n"
				"	mov edi, esi\n"
				"	mov ecx, 0000001e6h\n"
				"_loop:\n"
				"    lodsb\n"
				"    xor al, 042h\n"
				"    stosb\n"
				"    loop _loop\n"
				"    popad\n"
				"    push 000401000h\n"
				"    retn\n";
	//writing the asm file
	write_stub_file(stub,sizeof(stub),temp_asm_path);


	//creating the assebled file
	char cmd[512];
	sprintf(cmd,"%s %s -o %s",yasm_path,temp_asm_path,hex_decrypter_path);
	system((char *)cmd);

	//read assembled file
	char *stub_buffer=NULL;
	int stub_size = read_stub_file(hex_decrypter_path,&stub_buffer);
	printf("stub buffer %x , ",stub_buffer);
	if(stub_size < 0 ){DEBUG(("Problem in reading the hexadecimal decrypter")); return -1;}
	
	for (int i=0;i< stub_size;i++){
		printf("ar address %x value %d ",stub_buffer+i,*(stub_buffer+i));
		}

		

	
}

int write_stub_file(char stub[],int size,char *temp_asm_path ){
	FILE *asmFile = fopen(temp_asm_path, "w");
    if(!asmFile){
		DEBUG(("Can't write temporary asm file %s\n",temp_asm_path));
        return -1;
	}
	fwrite(stub,size,1,asmFile );
	fclose(asmFile);
	return 0;
}

int read_stub_file(char *filename,char **buffer){
	FILE *decrypterFile = fopen(filename,"r");
	 if(!decrypterFile){
		DEBUG(("Can't read hexadecial decrypter file created by yasm %s\n",filename));
        return -1;
	}
	//get file size
	fseek(decrypterFile,0,SEEK_END);
	long size =  ftell (decrypterFile);
	rewind (decrypterFile);

	*buffer = (char*) malloc (sizeof(char)*size); 

	// copy the file into the buffer:
	int result = fread (*buffer,1,size,decrypterFile);
	

	if (result != size) {DEBUG(("Reading error %s\n",filename));return -1;}
	/*
	for (int i=0;i< size;i++){
		printf("at address %x value  ",*buffer[i]);
		}
		*/
	// terminate
	fclose (decrypterFile);
	return size;


}


