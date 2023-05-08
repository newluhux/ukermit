CFLAGS += -Wall -Wextra -O3 -g3

all:	ukermit

ukermit:
	$(CC) $(CFLAGS) ukermit.c -o ukermit

clean:
	rm -vf *~ *.o *.out ukermit
