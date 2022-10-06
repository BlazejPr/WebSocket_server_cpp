

XCC     = g++
LD      = g++


 
 

CFLAGS  = -std=c++17   -m64    -c -Wall -g3  -fPIC  -fpermissive -Wwrite-strings 

LDFLAGS = -g -ldl  -m64     -lpthread -I. -L. -lresolv  -lssl  -lcrypto -lboost_locale -lmysqlcppconn8  -lmysqlclient   -o
 
 


all: bk_server_sll2




	
main.o: main.cpp 
	$(XCC) $(CFLAGS) main.cpp -o $@	 
	
	

bk_server_sll2: main.o
	@echo "Link..................................." $@
	
	 
	$(LD) $(LDFLAGS) $@ main.o     CryptoNew/libcryptopp.a 
	#$(LD) $(LDFLAGS) $@ main.o   CryptoNew/libcryptopp.a 
	
	 
	@echo  "\033[0;31m"
	@echo  "Link................................ 100%" $@
	@echo  "\033[0m"	 	
 
	@echo  "...................................."
	@echo  ".                                  ."
	@echo  ".            bk_server             ."
	@echo  ".          Progress Plus           ." 
	@echo  ".         auth. Błażej Kita        ."
	@echo  ".                                  ."
	@echo  "...................................."
  

clean:
	-rm -f *.map main.o bk_server_sll2

 
.PHONY: all celan	

