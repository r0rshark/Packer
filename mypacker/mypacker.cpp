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
int insert_stub_section(char *stub,int stub_size, PE *pe);

int _tmain(int argc, _TCHAR* argv[])
{
	char *input_path ="C:\\Users\\phate\\Desktop\\mypacker\\compiled.exe";
	char *output_path ="C:\\Users\\phate\\Desktop\\mypacker\\mypacked.exe";

	
	printf("loaded path %s\n",input_path);
	if (!pe_read(input_path, &pe)) {
		printf("Wrong PE format\n");
		return -1;
	}
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
	DEBUG(("Entry Point Section before encrypting \n"));
	printSectionInfo(ep_section);
	encrypt(ep_section,0x01);
	DEBUG(("Entry Point Section after encrypting \n"));
	printSectionInfo(ep_section);

	//reading decrypted hex from file
	int new_ep = load_stub(&pe);
	if(new_ep<0){DEBUG(("There was a problem in loading the stub into the PE"));return -1;}

	//Changing program entry point
	DEBUG(("aOld entry point %x\n",pe.int_headers.OptionalHeader.AddressOfEntryPoint));
	pe.int_headers.OptionalHeader.AddressOfEntryPoint = new_ep;
	DEBUG(("aNew entry point %x\n",pe.int_headers.OptionalHeader.AddressOfEntryPoint));
	

	if (!pe_write(output_path, &pe)) {
		printf("Error in writing PE \n");
		return 0;
	}
	printf("Encrypted PE successfully written in %s \n",output_path);

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
	
	//put stub inside .text section
	int new_ep = insert_stub_section(stub_buffer,stub_size, pe);
	return new_ep;
	
	
	/*for (int i=0;i< stub_size;i++){
		printf("%hx ",*(stub_buffer+i));
		}
		*/

		

	
}

int write_stub_file(char stub[],int size,char *temp_asm_path ){
	FILE *asmFile = fopen(temp_asm_path, "wb");
    if(!asmFile){
		DEBUG(("Can't write temporary asm file %s\n",temp_asm_path));
        return -1;
	}
	fwrite(stub,size,1,asmFile );
	fclose(asmFile);
	return 0;
}

int read_stub_file(char *filename,char **buffer){
	FILE *decrypterFile = fopen(filename,"rb");
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
	// terminate
	fclose (decrypterFile);
	return size;
}

int insert_stub_section(char * buffer,int stub_size, PE *pe){
	
	AddSection(".newtext",buffer,stub_size,NULL,pe);

	int number_of_sections=pe->int_headers.FileHeader.NumberOfSections;
	for(int i=0;i<number_of_sections;i++){
		DEBUG(("\n----------SECTION %d-------------\n",i));
		DEBUG(("Section name %s\n",pe->m_sections[i].header.Name));
		printSectionInfo(&pe->m_sections[i]);
	}

	//get the RVA of the section
	for(int i=number_of_sections-1;i>=0;i--) {//start from the last because the inserted one will be placed as last
		if(strcmp((const char *)pe->m_sections[i].header.Name,".newtext")==0){
			DEBUG(("Found inserted section named %s at rva %x\n",pe->m_sections[i].header.Name, pe->m_sections[i].header.VirtualAddress));
			return pe->m_sections[i].header.VirtualAddress;
		}
	}
	return -1;

}


