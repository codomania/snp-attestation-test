all:
	$(CC) -Wall -o snp-guest-request snp-guest-request.c

clean:
	$(RM) snp-guest-request
