.PHONY: all
all: flag_program.txt

.PHONY: clean
clean:
	rm -vf *.bin *.txt .tmp_*

flag_program.txt: flag_program.bin
	cat flag_program.bin | xxd -p -c30 > $@
	printf "EOF" >> $@

flag_program.bin: flag_program.s
	@echo "kstool -b x16 ... 7c00 > .tmp_$@"
	@kstool -b x16 "$(shell grep -o '^[^#]*' $< | tr '\n' ';')" 7c00 > .tmp_$@
	go run ../crypto.go -bootloader=../test_bootloader.bin -key=4100410041004100 -target=".tmp_$@" -patch
	#fallocate -l 520 $@
	mv .tmp_$@ $@
