#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>

char *prtkeyfile=NULL;
char *signfile=NULL;
char *msgfile=NULL;
BIO  *bio_log=NULL;
char *message = "RSA signing message";

void usage(void){
	printf("\n rsasign -i <private key file>  -m <message file> -d <digest type> -s <sign output filename>");
	printf("\n rsasign -h  -- For help");
	printf("\n");
}
	

void rsa_sign(void){

	EVP_MD_CTX *mdctx = NULL;
	EVP_PKEY *pkey=NULL;
	BIO *prtbio = NULL, *signbio=NULL;
	char *msg = NULL, *signbuf = NULL;
	unsigned int msglen;
	size_t signlen;
	int ret;
	

	if( (mdctx = EVP_MD_CTX_new()) == NULL) {
		BIO_printf(bio_log, "\n MD ctx create failed\n");
		return ;

	}

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

	if (signfile) {
		if ((signbio = BIO_new_file(signfile, "w")) == NULL) {
			BIO_printf(bio_log, "\n BIO_new_file %s failed\n", signfile);
			goto end;
		}
	}
	else {
		signbio = bio_log;
	}

	if ((pkey = PEM_read_bio_PrivateKey(prtbio, NULL, NULL, NULL)) == NULL) {
		BIO_printf(bio_log, "\n Unable to load\n");
		goto end;
	}

	ret = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey );
	if(!ret) {
		BIO_printf(bio_log, "\n MD ctx sign init  failed\n");
		goto end;

	}

	if(msgfile){
		FILE *fp = fopen(msgfile, "r");
		if (fp) {
			fseek(fp, 0L, SEEK_END);
			msglen = ftell(fp);
			fseek(fp, 0L, SEEK_SET);
			if((msg = OPENSSL_malloc(msglen)) == NULL) {
				BIO_printf(bio_log, "\n Mem alloc  failed\n");
				goto end;

			}
			msglen = fread(msg, 1, msglen, fp);
		}
		else{
			BIO_printf(bio_log, "\n Message file open  failed\n");
			goto end;
		}
	}
	else {
		msg = message;
		msglen = strlen(msg);
	}

	if(EVP_DigestSignUpdate(mdctx, msg, msglen) <= 0){
		BIO_printf(bio_log, "\n MD ctx sign update  failed\n");
		goto end;
	}

	if(EVP_DigestSignFinal(mdctx, NULL, &signlen) <= 0){
		BIO_printf(bio_log, "\n Sign len get failed\n");
		goto end;
	}

	if( (signbuf = OPENSSL_malloc(signlen)) == NULL) {
		BIO_printf(bio_log, "\n Mem alloc failed\n");
		goto end;
	}

	if(EVP_DigestSignFinal(mdctx, signbuf, &signlen) <= 0){
		BIO_printf(bio_log, "\n Signature getting failed\n");
		goto end;
	}

	BIO_write(signbio, signbuf, signlen);
	

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

		if(prtbio) {
			BIO_free(prtbio);
		}

		if(signfile && signbio) {
			BIO_free(signbio);
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
				if((prtkeyfile = (char *) OPENSSL_malloc(strlen(optarg)+1)) == NULL) {
					printf("\n %s: OPENSSL_malloc failed. \n", optarg);
				}

				memset(prtkeyfile, 0, strlen(optarg)+1);
				memcpy(prtkeyfile, optarg, strlen(optarg));
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

	rsa_sign();	


end:
	if(prtkeyfile) {
		OPENSSL_free(prtkeyfile);
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
