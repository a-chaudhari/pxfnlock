BPF_OBJ = bpf/hid_modify.bpf.o
SKEL_H = bpf/hid_modify.skel.h
TARGET = pxFnLock

all: $(TARGET)

$(BPF_OBJ): bpf/hid_modify.bpf.c
	clang -target bpf -O2 -g -c $< -o $@

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(TARGET): pxFnLock.c $(SKEL_H)
	gcc -O2 -o $@ $< -lbpf

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET)

run: $(TARGET)
	./$(TARGET)

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	cp pxfnlock.service /etc/systemd/system/
	cp pxfnlock-restore.service /etc/systemd/system/
	systemctl daemon-reload

.PHONY: all clean run
