all : netfilter_test

netfilter_test: nfTest.o
	g++ -g -o netfilter_test nfTest.o -lnetfilter_queue

main.o:
	g++ -g -c -o nfTest.o nfTest.c

clean:
	rm -f netfilter_test
	rm -f *.o

