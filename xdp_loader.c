#include <gelf.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <unistd.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <asm/unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <net/if.h>
#include <linux/if_link.h>

int get_elf_section(Elf *elf, int sectionIndex, GElf_Ehdr *elfHeader, 
	char **sectionName, GElf_Shdr *sectionHeader, Elf_Data **sectionData)
{
	Elf_Scn *scn = elf_getscn(elf, sectionIndex);
	
	if (!scn) {
		return 1;
	}

	if (gelf_getshdr(scn, sectionHeader) != sectionHeader) {
		return 2;
	}

	*sectionName = elf_strptr(elf, elfHeader->e_shstrndx, sectionHeader->sh_name);
	
	if (!*sectionName || !sectionHeader->sh_size) {
		return 3;
	}

	*sectionData = elf_getdata(scn, 0);
	
	if (!*sectionData || elf_getdata(scn, *sectionData) != NULL) {
		return 4;
	}

	return 0;
}

int readFile(char* path) {
	int fd = open(path, O_RDONLY, 0);
	
	if (fd < 0) {
		printf("Error openning %s for read: %s\n", path, strerror(errno));
		return 1;
	}
	
	char buffer[1024];
	int err = read(fd, buffer, sizeof(buffer));
	
	close(fd);
	
	if (err < 0 || err >= sizeof(buffer)) {
		printf("Error reading from %s: %s\n", path, strerror(errno));
		return 1;
	}
	
	buffer[err] = 0;
	return atoi(buffer);
}

// Kept in a single long method for simplicity, avoid pointers, structs etc..
//
//	1. Read the xdp_program.o program and find its code section
//	2. Load the xdp code into the kernel
//
int main(int argc, char *argv[]) {
	char* xdpProgramFilename = "xdp_program.o";
	
	int xdpProgramFileDescriptor = open(xdpProgramFilename, O_RDONLY, 0);
	
	if (xdpProgramFileDescriptor < 0) {
		printf("Error openning xdp_program.o for read: %s\n", strerror(errno));
		return 1;
	}
	
	printf("Opened file descriptor to xdp.o, fd: %d\n", xdpProgramFileDescriptor);
	printf("About to initialize libelf library\n");
	
	if (elf_version(EV_CURRENT) == EV_NONE) {
		printf("Error initializing elf library: %s\n", strerror(errno));
		return 1;
	}
	
	printf("Reading xdp_program.o as an Elf file\n");
	
	Elf *elf = elf_begin(xdpProgramFileDescriptor, ELF_C_READ, NULL);

	if (!elf) {
		printf("Error reading %s as elf file %s\n", xdpProgramFilename, strerror(errno));
		return 1;
	}
	
	printf("Successfully read xdp_program.o as an Elf file\n");
	
	GElf_Ehdr elfHeader;
	
	if (gelf_getehdr(elf, &elfHeader) != &elfHeader) {
		printf("Error reading elf headers\n");
		return 1;
	}
	
	printf("Elf file contains %d section, looking for the xdp code section\n", elfHeader.e_shnum);
	
	struct bpf_insn *xdpProgramInstuctions = NULL;
	size_t xdpProgramInstuctionsCount;
	
	for (int sectionIndex = 1; sectionIndex < elfHeader.e_shnum; sectionIndex++) {
		char *sectionName;
		GElf_Shdr sectionHeader;
		Elf_Data *sectionData;
		
		if (get_elf_section(elf, sectionIndex, &elfHeader, &sectionName, &sectionHeader, &sectionData)) {
			continue;
		}
		
		if (strcmp(sectionName, ".text") != 0) {
			continue;
		}
		
		xdpProgramInstuctions = sectionData->d_buf;
		xdpProgramInstuctionsCount = sectionData->d_size / sizeof(struct bpf_insn);
		break;
	}
	
	if (xdpProgramInstuctions == NULL) {
		printf("Unable to find .text section in xdp_program.o\n");
		return 1;
	}
	
	printf("Successfully read xdp code with %zd instuctions\n", xdpProgramInstuctionsCount);
		
	char log_buffer[1024] = {0};
	int loadedXdpDescriptor = bpf_load_program(BPF_PROG_TYPE_XDP, xdpProgramInstuctions, 
			xdpProgramInstuctionsCount, "GPL", 0, log_buffer, sizeof(log_buffer));
	
	if (loadedXdpDescriptor < 0) {
		printf("Error loading bpf program into the kernel %d %s %s\n", loadedXdpDescriptor, strerror(errno), log_buffer);
		return 1;
	}
	
	printf("Successfully loaded xdp program into the kernel, fd: %d\n", loadedXdpDescriptor);
	
	
	unsigned int index = if_nametoindex("lo");
	
	if (index <= 0) {
		printf("Error getting interface index %d %s\n", index, strerror(errno));
		return 1;
	}
	
	printf("Network interface is %d\n", index);
	
	bpf_set_link_xdp_fd(index, -1, 0);
	int err = bpf_set_link_xdp_fd(index, loadedXdpDescriptor, XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST);
	if (err < 0) {
		printf("Failed attaching %d %s\n", err, strerror(-err));
		return err;
	}
	
	printf("Successfully attached link to xdp\n");
	
	getchar();
	
	printf("Detaching\n");
	bpf_set_link_xdp_fd(index, -1, 0);
	return 0;
}
