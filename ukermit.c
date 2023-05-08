#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

#define CHAR_SOH 0x1

#define ktochar(x) ((x) + 32)
#define kunchar(x) ((x)-32)
#define kctl(x) ((x) ^ 64)
#define ksum(x) (ktochar(((x) + (((x) & 192) >> 6)) & 63))
#define kseqadd(x, n) (((x) + (n)) & 0x3F)

static inline int kisqbin(char c)
{
	return (((c >= '!') && (c <= '>')) || ((c >= '`') && (c <= '~')));
}

static inline int kisqctl(char c)
{
	return ((c >= ' ') && (c <= '~'));
}

enum {
	KHDR_MARK = 0,
	KHDR_LEN = 1,
	KHDR_SEQ = 2,
	KHDR_TYPE = 3,

	/* kermit header size */
	KHDR_SIZE = 4,
};

enum {
	KTYPE_ACK = 'Y',
	KTYPE_NACK = 'N',
	KTYPE_SINIT = 'S',
	KTYPE_FHDR = 'F',
	KTYPE_DATA = 'D',
	KTYPE_EOF = 'Z',
	KTYPE_BREAK = 'B',
	KTYPE_ERROR = 'E',
};

enum {
	KPARAM_MAXLEN = 0,
	KPARAM_TIME = 1,
	KPARAM_NPAD = 2,
	KPARAM_PADC = 3,
	KPARAM_EOL = 4,
	KPARAM_QCTL = 5,
	KPARAM_QBIN = 6,
	KPARAM_CHKT = 7,
	KPARAM_REPT = 8,
	KPARAM_CAPAS = 9,
	KPARAM_WINDO = 10,
	KPARAM_MAXLX1 = 11,
	KPARAM_MAXLX2 = 12,

	/* kermit param size */
	KPARAM_SIZE = 13,
};

/* 4 bytes is [qbin] [qctl] [char], then leave a byte for check*/
#define KENCODE_MAXSIZE 4

#define KBUFMAX 96

struct kstate {
	uint8_t seq;
	uint8_t type;
	uint8_t txbuf[KBUFMAX];
	uint8_t rxbuf[KBUFMAX];
	uint8_t param[KPARAM_SIZE];
};

uint8_t kmksum(const uint8_t * buf)
{
	uint8_t len = kunchar(buf[KHDR_LEN]) + 2;
	uint8_t sum = 0;
	uint8_t i;
	for (i = KHDR_LEN; i < (len - 1); i++) {
		sum += buf[i];
	}
	return ksum(sum);
}

uint8_t kmkpkt(struct kstate *k, uint8_t * in, int insize)
{
	uint8_t pktmaxlen = kunchar(k->param[KPARAM_MAXLEN]);
	uint8_t buflen = 0;
	int inused = 0;
	uint8_t c;

	uint8_t qbin;
	uint8_t qctl;

	qbin = k->param[KPARAM_QBIN];
	qctl = k->param[KPARAM_QCTL];

	k->txbuf[KHDR_MARK] = CHAR_SOH;
	k->txbuf[KHDR_LEN] = ktochar(0);
	k->txbuf[KHDR_SEQ] = ktochar(k->seq);
	k->txbuf[KHDR_TYPE] = k->type;
	buflen += KHDR_SIZE;

	if (k->txbuf[KHDR_TYPE] == KTYPE_SINIT) {
		memcpy(k->txbuf + buflen, k->param, KPARAM_SIZE);
		buflen += KPARAM_SIZE;
		inused += KPARAM_SIZE;
	} else {
		while (((pktmaxlen - buflen) > KENCODE_MAXSIZE)
		       && (inused < insize)) {
			c = in[inused];
			inused++;
			if (kisqbin(qbin) && (c > 0x7F)) {
				k->txbuf[buflen] = qbin;
				buflen++;
				c &= 0x7F;
			}
			if (kisqctl(qctl)) {
				if (c < 0x20 || c == 0x7F || c == qctl ||
				    ((kisqbin(qbin)) && (c == qbin))) {
					k->txbuf[buflen] = qctl;
					buflen++;
					if ((c == qctl) || (c == qbin)) {
						// nop
					} else {
						c = kctl(c);
					}
				}
			}
			k->txbuf[buflen] = c;
			buflen++;
		}
	}
	/* don't include MARK, LEN, but include CHECK */
	buflen++;
	k->txbuf[KHDR_LEN] = ktochar(buflen - 2);

	/* checksum */
	k->txbuf[buflen - 1] = kmksum(k->txbuf);

	/* eol */
	k->txbuf[buflen] = kunchar(k->param[KPARAM_EOL]);
	buflen++;

	/* end with '\0', easy for look length */
	k->txbuf[buflen] = '\0';

	return inused;
}

int ksend(struct kstate *k)
{
	uint8_t len;
	len = strnlen((char *)k->txbuf, kunchar(k->param[KPARAM_MAXLEN]));
	fprintf(stderr, "tx: send %d bytes to remote\n", len);
	return write(STDOUT_FILENO, k->txbuf, len);
}

int krecv(struct kstate *k)
{
	uint8_t *rxbuf;
	rxbuf = k->rxbuf;
	uint8_t rxbuf_len = 0;
	uint8_t temp;

	/* wait [MARK] */
	do {
		read(STDIN_FILENO, &rxbuf[KHDR_MARK], 1);
	} while (rxbuf[KHDR_MARK] != CHAR_SOH);
	rxbuf_len++;

	/* recv [LEN] */
	read(STDIN_FILENO, &rxbuf[KHDR_LEN], 1);
	temp = kunchar(rxbuf[KHDR_LEN]);
	/* min pkt layout is [MARK] [LEN] [SEQ] [TYPE] [CHECK] */
	if (temp > (kunchar(k->param[KPARAM_MAXLEN]))) {
		fprintf(stderr, "rx: bad len\n");
		return -1;
	}
	rxbuf_len++;

	/* recv [SEQ] [TYPE] [DATA] [CHECK] */
	read(STDIN_FILENO, &rxbuf[KHDR_SEQ], temp);
	rxbuf_len += temp;
	rxbuf[rxbuf_len] = '\0';

	temp = kmksum(rxbuf);	/* compute local checksum */
	if (temp != rxbuf[rxbuf_len - 1]) {
		fprintf(stderr, "rx: package checksum failed\n");
		return -1;
	}

	return rxbuf_len;
}

struct kstate *kused = NULL;

void timer_handle(int i)
{
	(void)i;
	if (kused != NULL) {
		fprintf(stderr, "timer: timeout, retrans\n");
		ksend(kused);
	}
	alarm(kunchar(kused->param[KPARAM_TIME]));
}

void kloop(struct kstate *k)
{
	uint8_t temp;
	uint8_t *rxbuf;
	rxbuf = k->rxbuf;
	while (1) {
		/* send buf */
		ksend(k);
		/* update timer */
		alarm(kunchar(k->param[KPARAM_TIME]));
		/* recv ack */
		if (krecv(k) < 0) {
			continue;
		}
		temp = k->rxbuf[KHDR_TYPE];
		if (temp == KTYPE_ACK) {
			fprintf(stderr, "local: recv ack\n");
			break;
		}
		switch (temp) {
		case KTYPE_NACK:
			fprintf(stderr, "local: recv nack\n");
			break;
		case KTYPE_ERROR:
			fprintf(stderr, "remote: %s\n", &rxbuf[KHDR_SIZE]);
			break;
		default:
			fprintf(stderr, "local: unimplement type: %c\n", temp);
			break;
		}
	}
}

void help(void)
{
	char helpmsg[] =
	    "usage: ukermit [option] -s filename\n"
	    "\n"
	    "-l number      max package length\n"
	    "-b char        8bit prefix char\n"
	    "-e char        end of line char\n"
	    "-t number      timeout seconds\n";
	fprintf(stderr, "%s", helpmsg);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		help();
		exit(EXIT_FAILURE);
	}

	struct kstate ks;
	memset(&ks, 0x0, sizeof(ks));
	kused = &ks;

	/* set default value */
	ks.seq = 0;
	ks.type = KTYPE_SINIT;
	ks.param[KPARAM_MAXLEN] = ktochar(80);
	ks.param[KPARAM_TIME] = ktochar(5);
	ks.param[KPARAM_NPAD] = ktochar(0);
	ks.param[KPARAM_PADC] = kctl('\0');
	ks.param[KPARAM_EOL] = ktochar('\r');
	ks.param[KPARAM_QCTL] = '#';
	ks.param[KPARAM_QBIN] = 'N';
	ks.param[KPARAM_CHKT] = '1';
	ks.param[KPARAM_REPT] = ' ';
	ks.param[KPARAM_CAPAS] = ktochar(0);
	ks.param[KPARAM_WINDO] = ktochar(0);
	ks.param[KPARAM_MAXLX1] = ktochar(0);
	ks.param[KPARAM_MAXLX2] = ktochar(0);

	char *filename = NULL;
	int i;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0) {
			help();
			exit(EXIT_FAILURE);
		} else if (strcmp(argv[i], "-l") == 0) {
			i++;
			ks.param[KPARAM_MAXLEN] = ktochar(atoi(argv[i]));
		} else if (strcmp(argv[i], "-b") == 0) {
			i++;
			ks.param[KPARAM_QBIN] = argv[i][0];
		} else if (strcmp(argv[i], "-t") == 0) {
			i++;
			ks.param[KPARAM_TIME] = ktochar(atoi(argv[i]));
		} else if (strcmp(argv[i], "-e") == 0) {
			i++;
			ks.param[KPARAM_EOL] = ktochar(argv[i][0]);
		} else if (strcmp(argv[i], "-s") == 0) {
			i++;
			filename = argv[i];
		}
	}
	if (filename == NULL) {
		help();
		exit(EXIT_FAILURE);
	}
	int fd;
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("can't open file");
		exit(EXIT_FAILURE);
	}

	/* timer */
	signal(SIGALRM, timer_handle);

	ks.type = KTYPE_SINIT;
	if (kmkpkt(&ks, ks.param, KPARAM_SIZE) != KPARAM_SIZE) {
		fprintf(stderr, "buffer too small\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "local: send init param to remote\n");
	kloop(&ks);
	ks.seq = kseqadd(ks.seq, 1);

	ks.type = KTYPE_FHDR;
	if (kmkpkt(&ks, (uint8_t *) filename, strlen(filename))
	    != strlen(filename)) {
		fprintf(stderr, "filename too long\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stderr, "local: send filename to remote\n");
	kloop(&ks);
	ks.seq = kseqadd(ks.seq, 1);

	ssize_t nr;
	ssize_t temp;
	ssize_t bufused;
	ssize_t readed = 0;
	uint8_t buf[BUFSIZ];

	ssize_t filesize;
	filesize = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	ks.type = KTYPE_DATA;
	fprintf(stderr, "local: send file data to remote\n");
	while (readed < filesize) {
		nr = read(fd, buf, BUFSIZ);
		if (nr < 0) {
			perror("can't read file");
			exit(EXIT_FAILURE);
		}
		bufused = 0;
		while (bufused < nr) {
			temp = kmkpkt(&ks, buf + bufused, nr - bufused);
			kloop(&ks);
			bufused += temp;
			readed += temp;
			fprintf(stderr, "progress: %ld/%ld\n", readed,
				filesize);
			ks.seq = kseqadd(ks.seq, 1);
		}
	}
	fprintf(stderr, "local: file send done\n");

	ks.type = KTYPE_EOF;
	kmkpkt(&ks, NULL, 0);
	fprintf(stderr, "local: send EOF to remote\n");
	kloop(&ks);
	ks.seq = kseqadd(ks.seq, 1);

	ks.type = KTYPE_BREAK;
	kmkpkt(&ks, NULL, 0);
	fprintf(stderr, "local: send break to remote\n");
	kloop(&ks);
	ks.seq = kseqadd(ks.seq, 1);

	fprintf(stderr, "local: close kermit\n");
	exit(EXIT_SUCCESS);
}
