WLA=wla-gb
WLALINK=wlalink

pwn.gb: pwn.linkfile pwn.o
	$(WLALINK) pwn.linkfile $@

pwn.o: pwn.s
	$(WLA) -o $@ $<

.PHONY: clean
clean:
	rm -f pwn.gb pwn.o
