EBPF_OBJ = hellobpf.o
VMLINUX_H = vmlinux.h
SKEL = loader.skel.h
LOADER_OBJ = loader.o

.PHONY: ebpf vmlinux skeleton loader clean

ebpf: vmlinux $(EBPF_OBJ) 

$(EBPF_OBJ): hellobpf.c
	sudo clang -O2 -target bpf -c hellobpf.c -o hellobpf.o

vmlinux: $(VMLINUX_H) # Check whether the file exists, and create the file if not exists.

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

skeleton: vmlinux $(EBPF_OBJ) # Create skeleton header file (for Interface)
	sudo bpftool gen skeleton hellobpf.o name loader > loader.skel.h

loader: vmlinux skeleton loader.c $(SKEL)
	clang loader.c -lbpf -o loader.o

clean:
	rm -f $(EBPF_OBJ) $(VMLINUX_H) $(SKEL) $(LOADER_OBJ)