SRC := main parser test_case_entry sandbox

all: adapter install

%.o: %.c
	gcc -c -o $@ $< -ggdb

adapter: $(addsuffix .o, $(SRC))
	gcc -o adapter -I./ $^ -lrt -ggdb

install:
	cp adapter $(HOME)/.local/dynamorio/adapter

# test_case_entry.o: test_case_entry.c
# gcc -o test_case_entry.o -c test_case_entry.c -masm=intel -lrt -ggdb
