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
char *signfile=NULL;
char *msgfile=NULL;
BIO *bio_log=NULL;
char *message = "RSA signing message";

void usage(void){
	printf("\n rsaverify -i <public key file>  -m <message file> -d <digest type> -s <sign filename>");
	printf("\n rsaverify -h  -- For help");
	printf("\n");
}
	

void rsa_verify(void){

	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY *pkey=NULL;
	BIO *pubbio = NULL, *signbio=NULL;
	char *msg = NULL, *signbuf = NULL;
	unsigned int msglen;
	size_t signlen;
	int ret;
	

	if( (mdctx = EVP_MD_CTX_new()) == NULL) {
		BIO_printf(bio_log, "\nMD ctx create failed\n");
		return ;

	}

	if (pubkeyfile) {
		if ((pubbio = BIO_new_file(pubkeyfile, "r")) == NULL) {
			BIO_printf(bio_log, "\nBIO_new_file %s failed\n", pubkeyfile);
			goto end;
		}
	}
	else {
		BIO_printf(bio_log, "\nPublic key file not provided\n");
		goto end;
	}

	if ((pkey = PEM_read_bio_PUBKEY(pubbio, NULL, NULL, NULL)) == NULL) {
		BIO_printf(bio_log, "\nUnable to load PUBKEY\n");
		goto end;
	}

	ret = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey );
	if(!ret) {
		BIO_printf(bio_log, "\nMD ctx sign init  failed\n");
		goto end;

	}

	if(msgfile){
		FILE *fp = fopen(msgfile, "r");
		if (fp) {
			fseek(fp, 0L, SEEK_END);
			msglen = ftell(fp);
			fseek(fp, 0L, SEEK_SET);
			if((msg = OPENSSL_malloc(msglen)) == NULL) {
				BIO_printf(bio_log, "\nMem alloc  failed\n");
				goto end;

			}
			msglen = fread(msg, 1, msglen, fp);
		}
		else{
			BIO_printf(bio_log, "\nMessage file open  failed\n");
			goto end;
		}
	}
	else {
		msg = message;
		msglen = strlen(msg);
	}

	if( (signbio = BIO_new_file(signfile, "rb")) == NULL) {
		BIO_printf(bio_log, "\nSign file open  failed\n");
		goto end;
	}

	signlen = EVP_PKEY_size(pkey); 

	signbuf = OPENSSL_malloc(signlen);
	if (signbuf == NULL) {
		BIO_printf(bio_log, "\nMalloc failed\n");
		BIO_free(signbio);
		goto end;
	}

	signlen = BIO_read(signbio, signbuf, signlen);
	BIO_free(signbio);
	if (signlen < 0 ) {
		BIO_printf(bio_log, "\nError in reading sign file\n");
		goto end;
	}

	if(EVP_DigestVerifyUpdate(mdctx, msg, msglen) <= 0){
		BIO_printf(bio_log, "\nMD ctx sign update  failed\n");
		goto end;
	}

	if(EVP_DigestVerifyFinal(mdctx, signbuf, signlen) == 1){
		BIO_printf(bio_log, "\nSignature verification SUCCESS\n");
	}
	else {
		BIO_printf(bio_log, "\nSignature verification FAILED\n");
	}

	

	end:

		if(msgfile && msg) {
			OPENSSL_free(msg);
		}

		if(signbuf) {
			OPENSSL_free(signbuf);
		}

		if(mdctx) {
			EVP_MD_CTX_free(mdctx);
		}	

		if(pubbio) {
			BIO_free(pubbio);
		}

		if(pkey) {
			EVP_PKEY_free(pkey);
		}

	return;
}

int main(int argc, char **argv) {

	unsigned int opt;

	while( (opt=getopt(argc, argv, "i:s:d:m:h")) != -1) {
		switch(opt) {
			case 'i':
				if((pubkeyfile = (char *) OPENSSL_malloc(strlen(optarg)+1)) == NULL) {
					printf("\n %s: OPENSSL_malloc failed. \n", optarg);
				}

				memset(pubkeyfile, 0, strlen(optarg)+1);
				memcpy(pubkeyfile, optarg, strlen(optarg));
				break;

			case 'm':
				if((msgfile = (char *) OPENSSL_malloc(strlen(optarg)+1)) == NULL) {
					printf("\n %s: OPENSSL_malloc failed. \n", optarg);
				}

				memset(msgfile, 0, strlen(optarg)+1);
				memcpy(msgfile, optarg, strlen(optarg));
				break;

			case 's':
				if((signfile = (char *) OPENSSL_malloc(strlen(optarg)+1)) == NULL) {
					printf("\n %s: OPENSSL_malloc failed. \n", optarg);
				}

				memset(signfile, 0, strlen(optarg)+1);
				memcpy(signfile, optarg, strlen(optarg));
				break;

			case 'd':
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

	rsa_verify();	


end:
	if(pubkeyfile) {
		OPENSSL_free(pubkeyfile);
	}

	if(signfile) {
		OPENSSL_free(signfile);
	}

	if(msgfile) {
		OPENSSL_free(msgfile);
	}

	if(bio_log) {
		BIO_free_all(bio_log);
	}
	
	return 0;
}
