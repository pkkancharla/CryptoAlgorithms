#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>

char *pubkeyfile=NULL;
char *prtkeyfile=NULL;
BIO  *bio_log=NULL;
unsigned int print;

void usage(void){
	printf("\n rsa -i <private key file> -o <public key file> -p ");
	printf("\n rsa -h  -- For help");
	printf("\n");
}
	

void getrsa(void){

	BIO *prtbio, *pubbio;
	EVP_PKEY *pkey;

	if (prtkeyfile) {
		if ((prtbio = BIO_new_file(prtkeyfile, "r")) == NULL) {
			BIO_printf(bio_log, "\n BIO_new_file %s failed\n", prtkeyfile);
			goto end;
		}
	}
	else {
		BIO_printf(bio_log, "\n Private key file not provided\n");
		goto end;
	}

	if (pubkeyfile) {
		if ((pubbio = BIO_new_file(pubkeyfile, "w")) == NULL) {
			BIO_printf(bio_log, "\n BIO_new_file %s failed\n", pubkeyfile);
			goto end;
		}
	}
	else {
		pubbio = bio_log;
	}

	if ((pkey = PEM_read_bio_PrivateKey(prtbio, NULL, NULL, NULL)) == NULL) {
		BIO_printf(bio_log, "\n Unable to load\n");
		goto end;
	}

	if( !PEM_write_bio_PUBKEY(pubbio, pkey)) {
		BIO_printf(bio_log, "\n Public key extract failed\n");
		goto end;
	}

	if (print) {
		EVP_PKEY_print_private(pubbio, pkey, 0, NULL);
	}
		
	end:
		if(prtbio) {
			BIO_free(prtbio);
		}

		if(pubkeyfile && pubbio) {
			BIO_free(pubbio);
		}
	
		if(pkey) {
			EVP_PKEY_free(pkey);
		}

	return;
}

int main(int argc, char **argv) {

	unsigned int opt;

	while( (opt=getopt(argc, argv, "i:o:hp")) != -1) {
		switch(opt) {
			case 'i':
				if((prtkeyfile = (char *) OPENSSL_malloc(strlen(optarg)+1)) == NULL) {
					printf("\n %s: OPENSSL_malloc failed. \n", optarg);
				}

				memset(prtkeyfile, 0, strlen(optarg)+1);
				memcpy(prtkeyfile, optarg, strlen(optarg));
				break;

			case 'o':
				if((pubkeyfile = (char *) OPENSSL_malloc(strlen(optarg)+1)) == NULL) {
					printf("\n %s: OPENSSL_malloc failed. \n", optarg);
				}

				memset(pubkeyfile, 0, strlen(optarg)+1);
				memcpy(pubkeyfile, optarg, strlen(optarg));
				break;

			case 'p':
				print = 1;
				break;
			case 'h':
				usage();
				goto end;
				break;

			case '?':
				printf("\n Invalid parameter passed\n");
				break;
		}		
	}

	bio_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	if(bio_log == NULL) {
		printf("BIO_new_fp failed\n");
		goto end;
	}

	getrsa();	


end:

	if(pubkeyfile) {
		OPENSSL_free(pubkeyfile);
	}

	if(prtkeyfile) {
		OPENSSL_free(prtkeyfile);
	}

	if(bio_log) {
		BIO_free_all(bio_log);
	}
	
	return 0;
}
