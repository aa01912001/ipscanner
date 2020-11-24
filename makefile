ipscanner: main.o  fill_packet.o
	gcc -o ipscanner main.o fill_packet.o
main.o: main.c fill_packet.h
	gcc -c main.c
fill_packet.o: fill_packet.c
	gcc -c fill_packet.c
clean:
	rm -f *.o 

