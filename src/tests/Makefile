# cd .. && ./cli.py fuzz -s x86/isa_spec/base.json -n 1  -i 0 && cd - && make wrapper && ./test

wrapper:
	sed '1s:^:.globl test_case_main\n:' ../generated.asm > generated.asm
	as generated.asm -o generated.o
	gcc wrapper.c -c -o wrapper.o
	gcc wrapper.o generated.o -o test