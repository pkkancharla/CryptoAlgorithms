all:
	gcc genrsa.c  -L/opt/openssl/lib -lcrypto -o genrsa
	gcc rsa.c  -L/opt/openssl/lib -lcrypto -o rsa
	gcc rsasign.c  -L/opt/openssl/lib -lcrypto -o rsasign
	gcc rsaverify.c  -L/opt/openssl/lib -lcrypto -o rsaverify


clean:
	rm genrsa -rf
	rm rsa -rf
	rm rsasign -rf
	rm rsaverify -rf
	
