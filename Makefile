all : main

main: main.o
	gcc -o main main.o -lnetfilter_queue

main.o: main.c netfilter_block.h
	gcc -c -o main.o main.c

clean:
	rm main *.o
