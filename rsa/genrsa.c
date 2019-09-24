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
BIO  *bio_log=NULL;
unsigned int rsabits = 2048;

void usage(void){
	printf("\n rsagen -s <rsa size in bits> -o <private key file>");
	printf("\n rsagen -h  -- For help");
	printf("\n");
}
	

void generate_rsa(void){
	BIGNUM *bn=NULL;
 	RSA *rsa=NULL;
	EVP_PKEY *pkey=NULL;
	BIO *prtbio;

	if((bn = BN_new()) == NULL) {
		BIO_printf(bio_log, "Failed to allocate BN\n");
		goto end;
	} 
	BN_set_word(bn, RSA_F4);

	rsa = RSA_new();	
	RSA_generate_key_ex(rsa, rsabits, bn, NULL);

	if((pkey = EVP_PKEY_new()) == NULL) {
		BIO_printf(bio_log, "EVP_PKEY_New failed\n");
		goto end;
	}
	EVP_PKEY_assign_RSA(pkey, rsa);

	if (prtkeyfile) {
		if ((prtbio = BIO_new_file(prtkeyfile, "w")) == NULL) {
			BIO_printf(bio_log, "\n BIO_new_file %s failed\n", prtkeyfile);
			goto end;
		}
	}
	else {
		if ((prtbio = BIO_new_fp(stdout, BIO_NOCLOSE)) == NULL) {
			BIO_printf(bio_log, "\n BIO_new_file  failed\n");
			goto end;
		}
	}

	if (!PEM_write_bio_PrivateKey(prtbio, pkey, NULL, NULL, 0, NULL, NULL)) {
		BIO_printf(bio_log, "PEM_write_bio_PrivateKey failed\n");
		goto end;
	}
		
	end:
		if (bn) {
			BN_free(bn);
		}

		if(pkey) {
			EVP_PKEY_free(pkey);
		}


	return;
}

int main(int argc, char **argv) {

	unsigned int opt;

	while( (opt=getopt(argc, argv, "o:s:h")) != -1) {
		switch(opt) {
			case 's':
				rsabits = atoi(optarg);
				break;

			case 'o':
				if((prtkeyfile = (char *) OPENSSL_malloc(strlen(optarg)+1)) == NULL) {
					printf("\n %s: OPENSSL_malloc failed. \n", optarg);
				}

				memset(prtkeyfile, 0, strlen(optarg)+1);
				memcpy(prtkeyfile, optarg, strlen(optarg));
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

	generate_rsa();	


end:

	if(prtkeyfile) {
		OPENSSL_free(prtkeyfile);
	}

	if(bio_log) {
		BIO_free_all(bio_log);
	}
	
	return 0;
}
