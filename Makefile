all: subdirs

subdirs: kernel_module library benchmark

kernel_module:
	sudo make -C $@
	sudo make install -C $@

library:
	sudo make -C $@
	sudo make install -C $@

benchmark:
	make -C $@

clean:
	make clean -C benchmark
	sudo make clean -C kernel_module
	sudo make clean -C library

# has to add directory as PHONY or it can not compile the second time
.PHONY: kernel_module library benchmark clean 