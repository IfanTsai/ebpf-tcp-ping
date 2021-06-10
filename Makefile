.PHONY: all clean install uninstall

CLANG ?= clang
LLC   ?= llc
NIC   ?= eth0
XDP_OBJ ?= xdp_ping
XDP_SEC ?= xdp-ping

INCLUDES ?= -I./include -I./lib -I./
CLANG_FLAGS ?= -D__NR_CPUS__=4 -O2 -target bpf -nostdinc -emit-llvm
CLANF_FLAGS += -Wall -Wextra -Wshadow -Wno-address-of-packed-member -Wno-unknown-warning-option -Wno-gnu-variable-sized-type-not-at-end -Wdeclaration-after-statement
LLC_FLAGS ?= -march=bpf -mcpu=probe -mattr=dwarfris -filetype=obj

all: $(XDP_OBJ)

$(XDP_OBJ): $(XDP_OBJ).ll
	$(LLC) $(LLC_FLAGS) -o $@.o $^

%.ll: %.c
	$(CLANG) $(INCLUDES) $(CLANG_FLAGS) -c $^ -o $@

clean:
	-rm -rf *.ll *.o

install: $(XDP_OBJ)
	sudo ip link set dev $(NIC) xdpgeneric off
	sudo ip link set dev $(NIC) xdpgeneric obj $^.o sec $(XDP_SEC)

uninstall:
	sudo ip link set dev $(NIC) xdpgeneric off
