XDP_TARGETS = xdp_redirect xdp_sni

LLC ?= llc
CLANG ?= clang
CC ?= gcc

CFLAGS := -g -Wall -Iheaders

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}

all: $(XDP_OBJ)

clean:
	rm *.o *.ll

$(XDP_OBJ): %.o: %.c  Makefile
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
