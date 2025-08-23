EBPF_SOURCE = detect_systemCall.c
EBPF_OBJ = detect_systemCall.o
LOADER_SOURCE = loader.c
LOADER_OBJ = loader.o
VMLINUX_H = vmlinux.h
SKEL = loader.skel.h

.PHONY: ebpf vmlinux skeleton loader clean

ebpf: vmlinux $(EBPF_OBJ) 

$(EBPF_OBJ): ${EBPF_SOURCE}
	sudo clang -O2 -target bpf -g -c ${EBPF_SOURCE} -o ${EBPF_OBJ}

vmlinux: $(VMLINUX_H) # Check whether the file exists, and create the file if not exists.

$(VMLINUX_H):
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

skeleton: vmlinux $(EBPF_OBJ) # Create skeleton header file (for Interface)
	sudo bpftool gen skeleton ${EBPF_OBJ} name loader > loader.skel.h

loader: vmlinux skeleton ${LOADER_SOURCE} $(SKEL)
	clang ${LOADER_SOURCE} -lbpf -o ${LOADER_OBJ}

clean:
	rm -f $(EBPF_OBJ) $(VMLINUX_H) $(SKEL) $(LOADER_OBJ)