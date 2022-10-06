

//

//https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers

//https://stackoverflow.com/questions/17915098/openssl-ssl-h-no-such-file-or-directory-during-installation-of-git

//https://dev.mysql.com/doc/connector-cpp/8.0/en/connector-cpp-apps-general-considerations.html

//#include </usr/include/openssl/applink.c>
#include </usr/include/openssl/bio.h>
#include </usr/include/openssl/ssl.h>
#include </usr/include/openssl/err.h>


#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <sys/time.h>
#include <dlfcn.h> 
#include <stdlib.h>
#include <iomanip>
#include <cmath>
#include <fstream>

#include <stdio.h>

//dla sieci

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/ioctl.h>

#include <netdb.h>



#include <fcntl.h>    /* For O_RDWR */
#include <unistd.h> 



#include "./CryptoNew/sha.h"
#include "./CryptoNew/base64.h"


#include "/usr/include/mysql/mysql.h";

 

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

 

 

 

using namespace std;
 
 


std::string IntToString(int value)
{
     std::string Result;         
     std::ostringstream convert;   
     convert << value; 
     Result = convert.str(); 
    
     char * data = new char[Result.size() + 1];
     std::copy(Result.begin(), Result.end(), data);
     data[Result.size()] = '\0'; 
     
     std::string ret = std::string(data);
     delete[] data;
     
     return ret;
};


 
long int getTimestamp() {
    
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    return ms;
};



void SHA1(char* input, unsigned int sizeInput, char* output, int* sizeOutput)
{
  CryptoPP::byte const* pbData = input; //(CryptoPP::byte*)data.data();
  unsigned int nDataLen =  sizeInput; //data.length();
  CryptoPP::byte abDigest[CryptoPP::SHA1::DIGESTSIZE];

  CryptoPP::SHA1().CalculateDigest(abDigest, pbData, nDataLen);

  // return string((char*)abDigest);  -- BAD!!!
  //return std::string((char*)abDigest, CryptoPP::SHA256::DIGESTSIZE);
  
  memcpy(output, (char*)abDigest, CryptoPP::SHA1::DIGESTSIZE );
  *sizeOutput = CryptoPP::SHA1::DIGESTSIZE;
  
}


bool getHeader(char* output, int maxBuff, const char* header, const char* input, int sizeInput)
{
   // std::cout<<"\n-> "<<strlen(input)<<" | "<<strlen(header);
 
    
    if(strlen(input) <= strlen(header)) return false;
    
    char headers[100][1000];  //10 lines x 1000 znaków
    int actLines = 0;
    int actChar = 0;
    
    for(int c=0; c< sizeInput-1; c++)
    {
        if(actLines >= 100) break;
        
        if( input[c] == '\r' && input[c+1] == '\n' ) { c++; actLines++;  actChar = 0; continue; }
                
        headers[actLines][actChar] = input[c];
        actChar++;                
    } 
    
    //headers
    for(int L = 0; L<actLines; L++)
    {
    
        //std::cout<< "\n ["<< headers[L]<<"]\r\n";
 
        
        int countCorrect = 0;
        
       // std::cout<<" , Length:  "<<strlen(headers[L]);
        
        for(int m=0; m<strlen(header);m++)
        {
            if(m >= strlen(headers[L]) ) break;
            if(header[m] != headers[L][m] ) { break; } else countCorrect++;        
        }
        
     //   std::cout<<", countCorrect: "<<countCorrect<<" --> "<<strlen(header);
        
        if(countCorrect > 0 &&  countCorrect == strlen(header))
        {
         //   std::cout<<"\nZnaleziono: "<<headers[L]<<"\r\n";
            bool startC = false;
            int lx = 0;
            for(int p=0; p<strlen(headers[L]);p++)
            {
                if(headers[L][p] == ':') { p++; startC=true; continue;  }
                if(startC)
                {
                  output[lx] = headers[L][p];                 
                  lx++;
                }
            }
        
            return true;
        }
    }
    
  return false;  
    
}


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
#define MAX_THREADS  100

int actualThread = 0;

pthread_attr_t attrX;


SSL_CTX *sslctxG;

struct thread_info
{
    pthread_t thread;
    long int created_at;    //TimeStamp
    long int first_ts;    //TimeStamp
    


    int socket;
    SSL *cSSL;  
    SSL_CTX *sslctx;
    
    char user[200];         //nazwa podłączonego usera
    char clientToken[200];  //unique token in system defined
    char system[400];       //system
    char url_status[400];   //url for notice, connect disconnect client..
    
    char threadName[100];
    short int status;       // 0 - free, 1 - prepre, 2 -busy...
    
    bool success;
};
thread_info threads[MAX_THREADS];


/**
 * Clear information about thread...
 * @param index
 */
void clearRow(int index)
{
    if(index > MAX_THREADS)
    {
        return;
    }
    
  //  std::cout<<"\nClear Row: "<<index<<", Name: "<<threads[index].threadName<<", Token: "<<threads[index].clientToken<<", System: "<<threads[index].system;
    
    //threads[index].thread = NULL;
    threads[index].created_at = -1;
    threads[index].first_ts = -1;
    threads[index].socket = -1;
    threads[index].cSSL = NULL;
    threads[index].sslctx = NULL;
    memset(threads[index].user,0,200);
    memset(threads[index].clientToken,0,200);
    memset(threads[index].system,0,400);
    memset(threads[index].url_status,0,400);
    memset(threads[index].threadName,0,100);
    threads[index].status = 0; //free..
}

//------------------------------------------------------------------------------

int getFreeIndex()
{
    for(int i=0; i<MAX_THREADS;i++)
    {
       if(threads[i].status == 0) return i;
    }
    
    return -1;
}

//------------------------------------------------------------------------------
/**
 * 
 */
void clearAllRow()
{
    for(int i=0; i<MAX_THREADS;i++)
    {
       clearRow(i);
    }
}


//------------------------------------------------------------------------------

void disconnect(int index)
{
    if(threads[index].cSSL != NULL)
    {
      SSL_shutdown(threads[index].cSSL);
      SSL_free(threads[index].cSSL);
      threads[index].cSSL = NULL;
    }
              
    if(threads[index].socket > 0)
    {
      shutdown(threads[index].socket, SHUT_RDWR);
      close(threads[index].socket); 
      threads[index].socket = -1;
    }
}

//------------------------------------------------------------------------------
/**
 * 
 */
void showInfo()
{
    for(int i=0; i<MAX_THREADS;i++)
    {
        if(  threads[i].status == 2) //Only Busy..
        {            
            std::cout<<"\nThread: "<<i<<", Name: "<< threads[i].threadName<<", Token: "<< threads[i].clientToken<<", System: "<< threads[i].system;  
            
            long int ts = getTimestamp();
            long int diff = 0;
            
            if(threads[i].created_at > 0)
            {
                diff = ts - threads[i].created_at;
                std::cout<<", Ts: "<<diff;
            }
            
            if(strlen(threads[i].user) > 2 )
            {
                std::cout<<", User: "<<threads[i].user;
            }
        }
    }
}

//------------------------------------------------------------------------------


int sendData( SSL *cSSL,  char* data, int socket, int size)
{
 try{    
    std::cout<<"\033[1;34m";
    std::cout<<"\nSendData "<<data;
    std::cout<<"\033[0m\n";
    
    if(cSSL == NULL)
    {
        std::cout<<"\nCannot send data :( ";
        return -2;
    }
    
    if(size <= 125)
    {
        char frame[1024];
        memset(frame,0,1024);

        frame[0] = 0b10000001; //fin 1, opcode 1
        frame[1] = 0b00000000; //maska = 0

        char length = (char)size;
        frame[1] += length;

        memcpy(frame+2, data,  size );

        // write( socket , frame , 2 + size );  
         
        int s = SSL_write(cSSL, frame,   2 + size);
               
       
        std::cout<<"\033[1;34m";
        std::cout<<"\nSendDataCout "<<s;
        std::cout<<"\033[0m\n";
        
        if(s < 0 )
        {
             int nError = SSL_get_error(cSSL, s);
             if (SSL_ERROR_WANT_WRITE == nError || SSL_ERROR_WANT_READ == nError)
               {
                   std::cout<<"\nSend ssl data, buffer is blocking, errno: %d";
               }else {  std::cout<<"\nSend ssl data, inny blad: "<<nError; }                             
        }
        
        return s;
    }
 
    if(size > 125 && size < 65535 )
    {
        char frame[1024];
        memset(frame,0,1024);

        frame[0] = 0b10000001; //fin 1, opcode 1
        frame[1] = 0b01111110; //maska = 0 + 126
 

        unsigned short length = (unsigned short)size;
        frame[2] = 0;
        frame[3] = 0;
        
       // memcpy(frame+3, &length, 1);
        
        frame[3] = length & 0xff;
        frame[2] = (length >> 8) & 0xff;
        
       // std::cout<<"\nSS: "<<length<<" | "<<sizeof(length)<<" "<<(unsigned int)frame[2]<<"+"<<(unsigned int)frame[3];
       

        memcpy(frame+4, data,  size );

         //write( socket , frame , 4 + size );  
            int s = SSL_write(cSSL, frame,   4 + size);
            std::cout<<"\033[1;34m";
            std::cout<<"\nSendDataCout "<<s;
            std::cout<<"\033[0m\n";
            
                if(s < 0 )
                {
                     int nError = SSL_get_error(cSSL, s);
                     if (SSL_ERROR_WANT_WRITE == nError || SSL_ERROR_WANT_READ == nError)
                       {
                           std::cout<<"\nSend ssl data, buffer is blocking, errno: %d";
                     }else {  std::cout<<"\nSend ssl data, inny blad: "<<nError; }                                          

                }            
            
            return s;
    }
 
   }
      catch (...)
     {
        std::exception_ptr p = std::current_exception();
        std::cerr <<(p ? p.__cxa_exception_type()->name() : "null") << std::endl;
     }
  
 return -1;
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

void* runThreadDBFinal(void* portHandle)
{
      
     std::cout<<"Watek utworzony final...";
          
     try
     {    
         MYSQL_RES *result;

         MYSQL_ROW row;

         MYSQL *connection, mysql;

         int state;
         
         mysql_init(&mysql);

         connection = mysql_real_connect(&mysql,"*****","**********","********","*****",0,0,0);
         
         
         if (connection == NULL)
            {
               std::cout<<"\nblad polaczenia...";
               printf(mysql_error(&mysql));
               return NULL;
            }else
            {
               std::cout<<"\nPolaczono final DB...";
            }
         
  
         sleep(2);
         while(1)
         {
                state = mysql_query(connection, "SELECT id, token, json_data FROM notices WHERE token IS NOT NULL AND json_data IS NOT NULL AND  success='0' AND created_at>DATE_SUB(CURDATE(), INTERVAL 1 HOUR) ORDER BY id DESC LIMIT 100;" );
                if (state !=0)
                {
                        printf(mysql_error(connection));
                        return 1;
                }

                result = mysql_store_result(connection);

                while ( ( row=mysql_fetch_row(result)) != NULL )
                {
                //   printf("\n %s, %s, %s \n", (row[0] ? row[0] : "NULL"), (row[1] ? row[1] : "NULL" ),  (row[2] ? row[2] : "NULL" )  );
                   
                   //wyślij.....................................................
                   //-----------------------------------------------------------
                   const char* idX = row[0] ? row[0] : "-100";
                   
                   const char* token = row[1] ? row[1] : "NULLXXXXX";
                   const char* sys = "www.example...pl";
                   char* res = "";
                   std::string raport = "";
                   
                   const char* message = row[2] ? row[2] : "NULLx";
                   
                
                   
                   
                   if(strlen(token) > 0 && token[0] =='@' )
                   {
                       
                         for(int c=0; c<MAX_THREADS; c++)
                                    {
                             
                                        if(  threads[c].status != 2) continue;

                                    
                                        if( strlen( threads[c].system ) !=  strlen(sys) ) continue;                               

                                        if( strcmp(   threads[c].system, sys ) == 0 )
                                        {
                                            //  if( strcmp(  nt_clients[c].clientToken, token ) == 0 )
                                            //  {
                                                  // jest lilent..
                                                    raport.append( threads[c].clientToken);
                                                  
                                                    threads[c].success =  false;
                                         
                                                    sendData( threads[c].cSSL ,message,  threads[c].socket, strlen(message));


                                                    usleep(200000); //czekaj az watek klienta odbierz odpowiedz... i ustawi true/false..
                                                    if( threads[c].success)  raport.append( " {\"status\":\"OK\",\"info\":\"Msg has been sent\"}" );
                                                    if(!threads[c].success) raport.append(" {\"status\":\"ERROR\",\"info\":\"Cannot send data\"}");
                                                 
                                                    raport.append(" | ");
                                             // };
                                        };
                                    };
                       
                        res = raport.c_str();
                       
                        std::string query = "";
                        
                        query.append("UPDATE notices SET success='1', response='");
                        query.append(res);
                        query.append("' WHERE id='");
                        query.append(idX);
                        query.append("';");
                       
                        mysql_query(connection, query.c_str() );
                     //  printf("\nQUERY: %s", query.c_str()  );
                       
                   }else
                   {
                       //sprawdz czy klient o podanym tokenie jest podlaczony...
                                    int inxClient = -1;
                                    for(int c=0; c<MAX_THREADS; c++)
                                    {
                                        if(  threads[c].status != 2) continue;

                                       // std::cout<<"\nSearch "<<sys <<" @ "<<token <<" --> "<<nt_clients[c].system  <<" @ " << nt_clients[c].clientToken ;

                                        if( strlen(threads[c].system ) !=  strlen(sys) ) continue;
                                        if( strlen( threads[c].clientToken ) !=  strlen(token) ) continue;

                                        if( strcmp( threads[c].system, sys ) == 0 )
                                        {
                                              if( strcmp(  threads[c].clientToken, token ) == 0 )
                                              {
                                                  inxClient = c; 
                                                  
                                                  //----------------------------------------------------------------------------------------
                                                  //----------------------------------------------------------------------------------------
                                                            char toSend[65000];
                                                            memset(toSend,0,65000);
                                                            memcpy(toSend, message, strlen(message) ); 


                                                           threads[c].success =  false;


                                                            sendData(threads[c].cSSL ,toSend, threads[c].socket, strlen(toSend));



                                                            usleep(200000); //czekaj az watek klienta odbierz odpowiedz... i ustawi true/false..
                                                            if(threads[c].success) res = "{\"status\":\"OK\",\"info\":\"Msg has been sent\"}";
                                                            if(!threads[c].success) res = "{\"status\":\"ERROR\",\"info\":\"Cannot send data\"}";

                                                            std::string queryx = "";

                                                            if( threads[c].success)
                                                            {
                                                                queryx.append("UPDATE notices SET success='1', response='");
                                                                queryx.append(res);
                                                                queryx.append("' WHERE id='");
                                                                queryx.append(idX);
                                                                queryx.append("';");
                                                            }else
                                                            {
                                                                queryx.append("UPDATE notices SET success='0', response='");
                                                                queryx.append(res);
                                                                queryx.append("' WHERE id='");
                                                                queryx.append(idX);
                                                                queryx.append("';");
                                                            }
                                                            
                                                            mysql_query(connection, queryx.c_str() );
                                                         //   printf("\nQUERY: %s", queryx.c_str()  );

                                                  //----------------------------------------------------------------------------------------
                                                  //----------------------------------------------------------------------------------------
                                              };
                                        };
                                    };

                                    if(inxClient == -1 )
                                    {
                                        std::string query = "";
                                        
                                        res = "{\"status\":\"ERROR\",\"info\":\"Not found client for token.\"}";
                                        
                                        query.append("UPDATE notices SET success='0', response='");
                                        query.append(res);
                                        query.append("' WHERE id='");
                                        query.append(idX);
                                        query.append("';");
                                        
                                       mysql_query(connection, query.c_str() );
                                     //  printf("\nQUERY: %s", query.c_str()  );
                                            
                                    } else
                                    {
                                    }
                   
                                    
                   }       
                                    
                                    
                                    
           
                }


                mysql_free_result(result);
                
                sleep(6);
         }
         
        
        
        mysql_close(connection);
         
       
     }catch(const std::exception& ex)
     {
          std::cerr << "Error occurred 1: " << ex.what() << std::endl;
     } 
     catch (...)
     {
        std::exception_ptr p = std::current_exception();
        std::cerr <<(p ? p.__cxa_exception_type()->name() : "null") << std::endl;
     }
    
    return NULL;
}

void* runThreadDBTest(void* portHandle)
{
      
     std::cout<<"Watek utworzony test...";
          
     try
     {    
         MYSQL_RES *result;

         MYSQL_ROW row;

         MYSQL *connection, mysql;

         int state;
         
         mysql_init(&mysql);

      connection = mysql_real_connect(&mysql,"******","*********","********","********",0,0,0);
         
         
         if (connection == NULL)
            {
               std::cout<<"\nblad polaczenia...";
               printf(mysql_error(&mysql));
               return NULL;
            }else
            {
               std::cout<<"\nPolaczono test DB...";
            }
         
       
         sleep(2);
         while(1)
         {
                state = mysql_query(connection, "SELECT id, token, json_data FROM notices WHERE token IS NOT NULL AND json_data IS NOT NULL AND  success='0' AND created_at>DATE_SUB(CURDATE(), INTERVAL 1 HOUR) ORDER BY id DESC LIMIT 100;" );
                if (state !=0)
                {
                        printf(mysql_error(connection));
                        return 1;
                }

                result = mysql_store_result(connection);

                while ( ( row=mysql_fetch_row(result)) != NULL )
                {
                //   printf("\n %s, %s, %s \n", (row[0] ? row[0] : "NULL"), (row[1] ? row[1] : "NULL" ),  (row[2] ? row[2] : "NULL" )  );
                   
                   //wyślij.....................................................
                   //-----------------------------------------------------------
                   const char* idX = row[0] ? row[0] : "-100";
                   
                   const char* token = row[1] ? row[1] : "NULLXXXXX";
                   const char* sys = "test2.example....pl";
                   char* res = "";
                   std::string raport = "";
                   
                   const char* message = row[2] ? row[2] : "NULLx";
                   
                
                   
                   
                   if(strlen(token) > 0 && token[0] =='@' )
                   {
                       
                         for(int c=0; c<MAX_THREADS; c++)
                                    {
                             
                                        if(  threads[c].status != 2) continue;

                                    
                                        if( strlen( threads[c].system ) !=  strlen(sys) ) continue;                               

                                        if( strcmp(   threads[c].system, sys ) == 0 )
                                        {
                                            //  if( strcmp(  nt_clients[c].clientToken, token ) == 0 )
                                            //  {
                                                  // jest lilent..
                                                    raport.append( threads[c].clientToken);
                                                  
                                                    threads[c].success =  false;
                                         
                                                    sendData( threads[c].cSSL ,message,  threads[c].socket, strlen(message));


                                                    usleep(200000); //czekaj az watek klienta odbierz odpowiedz... i ustawi true/false..
                                                    if( threads[c].success)  raport.append( " {\"status\":\"OK\",\"info\":\"Msg has been sent\"}" );
                                                    if(!threads[c].success) raport.append(" {\"status\":\"ERROR\",\"info\":\"Cannot send data\"}");
                                                 
                                                    raport.append(" | ");
                                             // };
                                        };
                                    };
                       
                        res = raport.c_str();
                       
                        std::string query = "";
                        
                        query.append("UPDATE notices SET success='1', response='");
                        query.append(res);
                        query.append("' WHERE id='");
                        query.append(idX);
                        query.append("';");
                       
                        mysql_query(connection, query.c_str() );
                     //  printf("\nQUERY: %s", query.c_str()  );
                       
                   }else
                   {
                       //sprawdz czy klient o podanym tokenie jest podlaczony...
                                    int inxClient = -1;
                                    for(int c=0; c<MAX_THREADS; c++)
                                    {
                                        if(  threads[c].status != 2) continue;

                                       // std::cout<<"\nSearch "<<sys <<" @ "<<token <<" --> "<<nt_clients[c].system  <<" @ " << nt_clients[c].clientToken ;

                                        if( strlen(threads[c].system ) !=  strlen(sys) ) continue;
                                        if( strlen( threads[c].clientToken ) !=  strlen(token) ) continue;

                                        if( strcmp( threads[c].system, sys ) == 0 )
                                        {
                                              if( strcmp(  threads[c].clientToken, token ) == 0 )
                                              {
                                                  inxClient = c; 
                                                  
                                                  //----------------------------------------------------------------------------------------
                                                  //----------------------------------------------------------------------------------------
                                                            char toSend[65000];
                                                            memset(toSend,0,65000);
                                                            memcpy(toSend, message, strlen(message) ); 


                                                           threads[c].success =  false;


                                                            sendData(threads[c].cSSL ,toSend, threads[c].socket, strlen(toSend));



                                                            usleep(200000); //czekaj az watek klienta odbierz odpowiedz... i ustawi true/false..
                                                            if(threads[c].success) res = "{\"status\":\"OK\",\"info\":\"Msg has been sent\"}";
                                                            if(!threads[c].success) res = "{\"status\":\"ERROR\",\"info\":\"Cannot send data\"}";

                                                            std::string queryx = "";

                                                            if( threads[c].success)
                                                            {
                                                                queryx.append("UPDATE notices SET success='1', response='");
                                                                queryx.append(res);
                                                                queryx.append("' WHERE id='");
                                                                queryx.append(idX);
                                                                queryx.append("';");
                                                            }else
                                                            {
                                                                queryx.append("UPDATE notices SET success='0', response='");
                                                                queryx.append(res);
                                                                queryx.append("' WHERE id='");
                                                                queryx.append(idX);
                                                                queryx.append("';");
                                                            }
                                                            
                                                            mysql_query(connection, queryx.c_str() );
                                                         //   printf("\nQUERY: %s", queryx.c_str()  );

                                                  //----------------------------------------------------------------------------------------
                                                  //----------------------------------------------------------------------------------------
                                              };
                                        };
                                    };

                                    if(inxClient == -1 )
                                    {
                                        std::string query = "";
                                        
                                        res = "{\"status\":\"ERROR\",\"info\":\"Not found client for token.\"}";
                                        
                                        query.append("UPDATE notices SET success='0', response='");
                                        query.append(res);
                                        query.append("' WHERE id='");
                                        query.append(idX);
                                        query.append("';");
                                        
                                       mysql_query(connection, query.c_str() );
                                     //  printf("\nQUERY: %s", query.c_str()  );
                                            
                                    } else
                                    {
                                    }
                   
                                    
                   }       
                                    
                                    
                                    
           
                }


                mysql_free_result(result);
                
                sleep(6);
         }
         
        
        
        mysql_close(connection);
         
       
     }catch(const std::exception& ex)
     {
          std::cerr << "Error occurred 1: " << ex.what() << std::endl;
     } 
     catch (...)
     {
        std::exception_ptr p = std::current_exception();
        std::cerr <<(p ? p.__cxa_exception_type()->name() : "null") << std::endl;
     }
    
    return NULL;
}



//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

void* runThreadPortEthernetForSender(int indexClient)
{     
    std::cout<<"\nNew sender: "<<indexClient;
    actualThread++;
    std::cout<<"\nActual Thread: "<<actualThread; 
   // showInfo(); 
    
    
   threads[indexClient].status = 2; //Running...
        
    
    const char* res = "{\"status\":\"SUCCESS\"}";
    std::string raport = "{";
    
         
                  char received[1000]; 
                  memset(received,0,1000);                                  
                   int size = SSL_read( threads[indexClient].cSSL, (char *)received, 1000);     
            
                  
                  //znajdz nazwe systemu i token....
                  int splitPos[10];
                  int splitInx = -1;
                  
                  char sys[150];
                  char token[500];
                  memset(sys,0,50);
                  memset(token,0,500);
                  
                  char message[1024];
                  memset(message,0,1024);
                  
                  for(int c=0;c<size;c++)
                  {
                      if(received[c] == '/' || received[c] == ' ')
                      {
                         splitInx++;
                         if(splitInx > 9) break;
                         splitPos[splitInx] = c;
                      }
                  }                                                            
                  
                  if(splitInx > 2)
                  {
                      int sizeSys = splitPos[1]-1;
                      if(sizeSys > 100) sizeSys = 100;
                      memcpy(sys, received + splitPos[0] + 1,sizeSys  );
                      
                      int sizeToken =  splitPos[2]-1 - splitPos[1];
                      if(sizeToken > 500) sizeToken = 500;
                      memcpy(token, received + splitPos[1] + 1, sizeToken );    
                  }

                
                  
                   for(int c=0;c<size;c++)
                  {
                      if(received[c] == '\r' &&  received[c+1] == '\n' && received[c+2] == '\r' &&  received[c+3] == '\n')
                      {         
                          int maxSize = size - c;
                          if (maxSize > 1000) maxSize = 1000;
                          memcpy(message, &received[c+4], maxSize)    ;                      
                          break;
                      }
                  }                  
                  
                  std::cout<<"\033[1;33m";
                  std::cout<<"\n*****************************\n";
                  std::cout<<"\nSender:";                  
                  std::cout<<"\nSystem: ["<<sys<<"]";
                  std::cout<<"\nToken: ["<<token<<"]";              
                  std::cout<<"\nMessage: ["<<message<<"]";
                  std::cout<<"\n*****************************\n";
                  std::cout<<"\033[0m\n";
                  
                  if( strlen(sys) > 3 && strlen( token) == 1 &&  token[0] == '@' ) // wysli wiadomość rozgloszeionową.. do wszystkich z tego systemu..
                  {
                    
                                     for(int c=0; c<MAX_THREADS; c++)
                                    {
                                        if(threads[c].status != 2) continue;
                           

                                        std::cout<<"\nS: "<<threads[c].system <<"|"<<sys<<"|";
                                        std::cout<<"\nX: "<<strlen(threads[c].system) <<"|"<<strlen(sys)<<"|";
                                        
                                 
                                        if( strcmp( threads[c].system, sys ) == 0 )
                                        {
                                                raport.append("[\"token\":\"");
                                                raport.append(threads[c].clientToken);                                                                                                
                                                raport.append("\",\"name\":\"");
                                                raport.append(threads[c].user);   
                                                raport.append("\"],");
                                                
                                                 char toSend[65000];
                                                 memset(toSend,0,65000);
                                                 memcpy(toSend, message, strlen(message) ); 
                                                 sendData( threads[c].cSSL ,toSend, threads[c].socket, strlen(message));                                            
                                                
                                        };
                                    };
                                    
                          raport.append("}");
                          res = raport.c_str();
                          
                          std::cout<<"\n\nRaport: "<<res;
                      
                  }
                  else{                                 
                  
                                    //sprawdz czy klient o podanym tokenie jest podlaczony...
                                    int inxClient = -1;
                                    for(int c=0; c<MAX_THREADS; c++)
                                    {
                                        if(threads[c].status != 2) continue;

                                     
                                        if( strlen(threads[c].system ) !=  strlen(sys) ) continue;
                                        if( strlen( threads[c].clientToken ) !=  strlen(token) ) continue;

                                        if( strcmp( threads[c].system, sys ) == 0 )
                                        {
                                              if( strcmp( threads[c].clientToken, token ) == 0 )
                                              {
                                                  inxClient = c; 
                                              };
                                        };
                                    };

                                    if(inxClient == -1 )
                                    {
                                        res = "{\"status\":\"ERROR\",\"info\":\"Not found client for token.\"}";
                                    }else
                                    {
                                        
                                        for(int c=0; c<MAX_THREADS; c++)
                                        {
                                            if(threads[c].status != 2) continue;


                                            if( strlen(threads[c].system ) !=  strlen(sys) ) continue;
                                            if( strlen( threads[c].clientToken ) !=  strlen(token) ) continue;

                                            if( strcmp( threads[c].system, sys ) == 0 )
                                            {
                                                  if( strcmp( threads[c].clientToken, token ) == 0 )
                                                  {
                                                      //token..
                                                      
                                                            char toSend[65000];
                                                            memset(toSend,0,65000);
                                                            memcpy(toSend, message, strlen(message) ); 

                                                            threads[c].success =  false;

                                                            sendData(threads[c].cSSL ,toSend, threads[c].socket, strlen(toSend));

 
                                                            usleep(200000); //czekaj az watek klienta odbierz odpowiedz... i ustawi true/false..
                                                            if( threads[c].success) res = "{\"status\":\"OK\",\"info\":\"Msg has been sent\"}";
                                                            if(!threads[c].success) res = "{\"status\":\"ERROR\",\"info\":\"Cannot send data\"}";


                                                      
                                                      //token..                                                                                                            
                                                  };
                                            };
                                        };                                       
                                    };
                  }                             
                                    
                  
                  const char* responseJSON = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type:text/xml; charset=UTF-8\r\nCache-Control: no-cache\r\n";
                // write( eth->socket , responseJSON , strlen( responseJSON));  
                  SSL_write(threads[indexClient].cSSL, responseJSON,  strlen( responseJSON));
                                                                                       
                  const char* length = "Content-Length:";
                  //write( eth->socket , length , strlen( length));  
                  SSL_write(threads[indexClient].cSSL, length,  strlen( length));
                                         
                  std::string msg = IntToString( strlen( res)  );
                  const char* res2 = msg.c_str();
                  //write( eth->socket , res2 , strlen( res2));  
                   SSL_write(threads[indexClient].cSSL, res2,  strlen( res2));
                                       
                  const char* enter  = "\r\n\r\n";
                  //write( eth->socket , enter , strlen( enter));
                     SSL_write(threads[indexClient].cSSL, enter,  strlen( enter));
                  
                  //write( eth->socket , res , strlen( res));
                    SSL_write(threads[indexClient].cSSL, res,  strlen( res));
                                               
                                 
                
    
    
    disconnect(indexClient);
    clearRow(indexClient);
    actualThread--;
    return NULL;
}

//------------------------------------------------------------------------------
void* runThreadPortEthernetForReceiver(int indexClient)
{
 
    std::cout<<"\nNew receiver: "<<indexClient;
    actualThread++;
    std::cout<<"\nActual Thread: "<<actualThread; 
    //showInfo(); 
    
    if(1==2)
    {
       disconnect(indexClient); 
       clearRow(indexClient);
       actualThread--;
       return NULL;
    }
    
    
    threads[indexClient].status = 2; //Running...
    
    //WS
       usleep(100);
    
                  unsigned char ready[2000];                                     
                  memset(ready,0,1000);                                
                  int sizeInput = SSL_read(threads[indexClient].cSSL, (char *)ready, 1000);
             
                  
                  char webSocketKey[1000];
                  bool isKey =  getHeader(webSocketKey,1000, "Sec-WebSocket-Key", ready, sizeInput);
                  
                  if(!isKey )
                  {
                      std::cout<<"\nSec-WebSocket-Key not found!\n";                                            
                      disconnect(indexClient); 
                      clearRow(indexClient);
                      actualThread--;
                      return NULL;                   
                  }
                  
                  //sleep(10);
                  std::string key = std::string(webSocketKey);
                  key.append("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
                  
                  const char* keyGuide = key.c_str();
              
                   char sha1Key[1000];
                   int sizeSh1 = 0;
                   SHA1(keyGuide, strlen(keyGuide), sha1Key, &sizeSh1);
                                 
                    CryptoPP::Base64Encoder encoder;
                    char keyB64[3000];
         
                    memset(keyB64,0,3000);
                    encoder.Put(sha1Key, strlen(sha1Key) );
                    encoder.MessageEnd();

                    long int size = encoder.MaxRetrievable();                  
                    if(size)
                     {                         
                            encoder.Get( keyB64, size );
                     };                
                  
                  std::string xdH = "HTTP/1.1 101 Switching Protocols\r\n";
                  xdH.append("Upgrade: websocket\r\n");
                  xdH.append("Connection: Upgrade\r\n");
                  xdH.append("Sec-WebSocket-Accept: ");
                  xdH.append(keyB64);
                  xdH.append("\r\n");
                                    
                  const char* responseJSON = xdH.c_str();
                  //write( eth.socket , responseJSON , strlen( responseJSON));  
                  SSL_write(threads[indexClient].cSSL,responseJSON, strlen( responseJSON));
                         
                
                 //Read normal..
                       for(int r=0; r<500; r++ ) //max time...
                            {                                                                     
                                    memset(ready,0,1000);                 
                                    int size = 0;
                                                                                                                                                
                                     size = SSL_read(threads[indexClient].cSSL, (char *)ready, 1000);
                                      
                                     
                                      switch (SSL_get_error(threads[indexClient].cSSL, size))
                                      {
                                            case SSL_ERROR_NONE:                                                
                                                break;

                                            case SSL_ERROR_WANT_WRITE:
                                                //ssl_wait_write();
                                                std::cout<<"\nSSL wait write...";
                                                break;

                                            case SSL_ERROR_WANT_READ:
                                                std::cout<<"\nSSL wait read...";
                                                break;
                                                
                                            case SSL_ERROR_SYSCALL:
                                                {
                                                   std::cout<<"\nSSL error syscall";
                                                       const auto ssl_err = ERR_get_error();
                                                        if (ssl_err == 0)
                                                        {
                                                            if (size == 0)
                                                                std::cout<<"\nSSL socket was closed unexpectedly" ;
                                                        }
                                                        else
                                                        {
                                                            std::cout<<"\nRuntime error :( ";
                                                        }
                                                }
                                                break;                                                
                                      }
                                     
                                     
                                    if(size == -1) //timeOut
                                    {                      
                                        std::cout<<"\nTimeOut";
                                       // sleep(1);
                                        break;                                  
                                    }else if (size == 0) //
                                    {
                                        //disconnect                
                                        std::cout<<"\nDisconnect :( ";
                                      //  sleep(1);
                                        break;
                                    }                                   
                                    
                                    threads[indexClient].created_at = getTimestamp();     //refres
                                  
                                                                                                                               
                                    int fin = 0;
                                    int rsv1 = 0;
                                    int rsv2 = 0;
                                    int rsv3 = 0;
                                    unsigned int opcode= 0;
                                    int mask = 0;
                                    unsigned int payLoadLength = 0; 
                                    
                                    if( (ready[0] & 0b10000000) == 0b10000000 ) { fin = 1; }
                                    if( (ready[0] & 0b01000000) == 0b01000000 ) { rsv1 = 1; }
                                    if( (ready[0] & 0b00100000) == 0b00100000 ) { rsv2 = 1; }
                                    if( (ready[0] & 0b00010000) == 0b00010000 ) { rsv3 = 1; }
                                     
           
                                    
                                    memcpy(&opcode, ready, 1 );
                                    opcode = ((char)(opcode * 8)) / 8;
                                    
                                    if( (ready[1] & 0b10000000) == 0b10000000 ) { mask = 1; }
                                    
 
                                    
                                    memcpy(&payLoadLength, ready+1,1);                                                                                                                                          
                                    payLoadLength = payLoadLength ^ 0b10000000;
                                                                        
                               
                                    
                                    char encodedPayData[1024];
                                    memset(encodedPayData,0,1024);
                                    
                                    
                                    char maskKey[32];
                                    memset(maskKey,0, 32);
                                    
                                    char decoded[1024];
                                    memset(decoded, 0, 1024);
                                    
                                  
         
                                    
                                    if(payLoadLength <= 125) //odebrano wszystkie dane...
                                    { 
                                           memcpy(&maskKey, ready+2,32);  
                                         //  std::cout<<"\nMaksKey: "<<maskKey;
                                                                                    
                                           memcpy(&encodedPayData, ready+6,payLoadLength);                                
                                          // std::cout<<"\nPayLoadData: "<<encodedPayData;                                                                                                                                
                                           
                                           for(int s=0; s<payLoadLength; s++)
                                           {
                                               decoded[s] = encodedPayData[s] ^ maskKey[s % 4];
                                           }                                           
                                           //std::cout<<"\nDecoded: "<<decoded;
                                           //std::cout<<"\n";                                                                                      
                                    }
                                    
                                    if(payLoadLength == 126 ) //Read the next 16 bits and interpret those as an unsigned integer. You're done.
                                    {
                                        
                                    }
                                    
                                    if(payLoadLength == 127 ) //read the next 64 bits and interpret those as an unsigned integer. (The most significant bit must be 0.) You're done.
                                    {
                                        
                                    }
                                    
                                    /*
                                    std::cout<<"\033[1;32m";
                                    std::cout<<"\n-------------------------";
                                    std::cout<<"\nData from: "<<threads[indexClient].clientToken<<", "<<threads[indexClient].user;
                                    std::cout<<"\n"<<decoded;
                                    std::cout<<"\n-------------------------";
                                    std::cout<<"\033[0m\n";
                                     */
                                    
                                    if(decoded[0] == '_' && decoded[1] == 'U' && decoded[2] == 'S' && decoded[3] == 'R' && decoded[4] == '_' && decoded[5] == ':')
                                    {                                                                                             
                                              int sizeX = strlen(decoded) - 5;
                                              if(sizeX < 200)
                                              {
                                                 memcpy( threads[indexClient].user , decoded+5, strlen(decoded) - 5 );
                                              }else   memcpy( threads[indexClient].user , decoded+5, 100 );
                                              
                                              sendData(threads[indexClient].cSSL, "_USR_SAVED_",   threads[indexClient].socket , strlen("_USR_SAVED_")  );                                                                                                    
                                    }
                                    
                                   
                                      
                                     
                                    //register new client..
                                    if(decoded[0] == '_' && decoded[1] == 'R' && decoded[2] == 'E' && decoded[3] == 'G' && decoded[4] == '_' && decoded[5] == ':')
                                    {
                                      
                                        int AtSign = -1;
                                        for(int sx=0; sx<strlen(decoded); sx++)
                                        {
                                            if(decoded[sx] == '@') { AtSign = sx; break; }
                                        }
                                        
                                        if(AtSign > 0 )
                                        {
                                             
                                            char systemX[200];
                                            char tokenX[200];
                                            memcpy(tokenX, decoded+5+1, AtSign-5-1);
                                            memcpy(systemX, decoded + AtSign + 1 , strlen(decoded) - AtSign );
                                            
                                            std::cout<<"\nRegister: ["<<systemX<<"] ["<< tokenX<<"]";
                                                                                                                                                   
                                            memcpy(threads[indexClient].system, systemX, strlen(systemX) );
                                            memcpy(threads[indexClient].clientToken, tokenX, strlen(tokenX) );             
                                                                                                                                                                                      
                                            sendData(threads[indexClient].cSSL, "_HELLO_",  threads[indexClient].socket , strlen("_HELLO_")  );                                                                                                                                                                
                                        }
                                       
                                    }
                                    
                                    if(decoded[0] == '_' && decoded[1] == 'R' && decoded[2] == 'E' && decoded[3] == 'F' && decoded[4] == '_')
                                    {
                                         // sendData("_REF_OK_",   eth.socket , strlen("_REF_OK_")  );                                       
                                    }
                                    
                                    if(decoded[0] == '_' && decoded[1] == 'O' && decoded[2] == 'K' && decoded[3] == '_' )
                                    {
                                         threads[indexClient].success = true;
                                    }
                                   
                                    
                               
                                   
                                      
                            };
                            
                       
    
    
    
    
    
 
    disconnect(indexClient); 
    clearRow(indexClient);
    actualThread--;
    return NULL;
}
//------------------------------------------------------------------------------

void* runThreadPortEthernet(void* portHandle)
{
    
    while(1)
    {        
   
        int indexClient = getFreeIndex();        
          
               
        
        sockaddr_in client;                      
        int c = sizeof(struct sockaddr_in);
        int newSocket = accept(  threads[0].socket , (struct sockaddr *)&client , (socklen_t*)&c);
        
        
         if(indexClient < 0)
        {
            close(  newSocket ); 
            std::cout<<"\nNo space for new thread!";;
            exit( 0 );
            continue;
        }
       
     
        threads[indexClient].socket = newSocket;
        threads[indexClient].thread = NULL; 
        threads[indexClient].status = 3; //Starting....
        threads[indexClient].created_at = getTimestamp();
        threads[indexClient].first_ts = getTimestamp();
        
        //---------------------------------------------------
       

        
        threads[indexClient].sslctx = sslctxG;
        threads[indexClient].cSSL  = SSL_new(threads[indexClient].sslctx);
        SSL_set_fd( threads[indexClient].cSSL,  threads[indexClient].socket );
        //Here is the SSL Accept portion.  Now all reads and writes must use SSL
        int ssl_err = SSL_accept( threads[indexClient].cSSL);
        if(ssl_err <= 0)
        {
            //Error occurred, log and close down ssl
            std::cout<<"\nShutdown SSL :( ";
            sleep(1);
            disconnect(indexClient); 
            clearRow(indexClient);
            continue;
        }
              
        //---------------------------------------------------
        //---------------------------------------------------
       
        
        
              char ready[200]; 
              memset(ready,0,200);                
             // recv(new_socket, ready, 4, 0);  //pierwsze znaki to klucz...
              int err = -1;
              
              for(int y=0; y<10; y++)
              {
                 usleep(1000 * y);
                 err =   SSL_read(threads[indexClient].cSSL, (char *)ready, 4);     
                 if(err>0) break;
              }
              
              if(err <= 0 ) //disconnect lub timeOUt..
              {
                     std::cout<<"\nSocket disconnect (0x02AAA) "<<err;                                                         
                     disconnect(indexClient);                     
                     clearRow(indexClient);  
                     continue;
              }
            
            
              std::cout<<"\nOdczytano: "<<ready<<"\r\n";
       
              memcpy(threads[indexClient].threadName,"GCL",strlen("-?-"));
              
        
            
              threads[0].created_at = getTimestamp();  //zaktualizuj czas pracy serwera..
              
              
              if ( (ready[0] == 'P' && ready[1] == 'O' && ready[2] == 'S'   && ready[3] == 'T'   ) )
              { 
                                memset(ready,0,10);                                             
                                SSL_read(threads[indexClient].cSSL, (char *)ready, 4);                  
                                
 
                  
                                  if ( (ready[0] == ' ' && ready[1] == '/' && ready[2] == 's'  && ready[3] == 'x' ))
                                  {                                  
                                    
                                       int rc = pthread_create(&threads[indexClient].thread, &attrX,  &runThreadPortEthernetForSender, (int)indexClient );
                                       if (rc)
                                       {

                                       } else
                                       {
                                            pthread_detach( threads[indexClient].thread );
                                            pthread_setname_np(threads[indexClient].thread,"CL");
                                            memcpy(threads[indexClient].threadName,"PCL",strlen("CL"));
                                         
                                       }
 
                                  }
                  
                  
              }else
              if ( (ready[0] == 'G' && ready[1] == 'E' && ready[2] == 'T'   && ready[3] == ' ' ) )                  
              {
                    
                              
                                int rc = pthread_create(&threads[indexClient].thread, &attrX,  &runThreadPortEthernetForReceiver, (int)indexClient );
                                if (rc)
                                {
                                            
                                } else
                                {
                                     pthread_detach( threads[indexClient].thread );
                                     pthread_setname_np(threads[indexClient].thread,"GCL");      
                                     memcpy(threads[indexClient].threadName,"GCL",strlen("GCL"));
                                     
                                }
                            
                  
                  
              }else
              {
                     std::cout<<"\nSocket disconnect (0x02AFB) "<<err;                                                         
                     disconnect(indexClient);                     
                     clearRow(indexClient);  
                     continue; 
              }
              
        
    }
    
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

void* checker(void* portHandle)
{
    int showX = 0;          
    while(1)
    {
        sleep(1);      
        showX++;
        
        
        if(showX >= 10 )
        {
          std::cout<<"\nActual Thread: "<<actualThread;  
          showInfo();   
          showX = 0;
        }               
             
        
        
        //sprawdz timeoty..
        long int ts = getTimestamp();
        long int max = 1000 * 60  * 1;     
                   
        //actualThread
        
        const char* toSend = "_TIMEOUT_";
        const char* toSend2 = "_NO_HELLO_";

        //wątek serwera..
        long int diffSerwer =  ts - threads[0].created_at;
        
        if( threads[0].created_at > 0 && diffSerwer > 20000 )  //20 sek..  serwer nie otrzymał żadnego połączenia przez 20 sekund :(
        {
            std::cout<<"\n\n------------- Brak nowych klientow --------- \n\n";
            close( threads[0].socket); //zamknij port serwera..
            exit(0);
        }
        

        // wątki klientów....        
        for(int i=1; i<MAX_THREADS;i++) //bez serwera..
          {              
              if(  threads[i].status == 2) //Only Busy..
              {                                            
                  long int diff =  ts - threads[i].created_at;
                  long int diff2 =  ts - threads[i].first_ts;

                  if(  threads[i].first_ts > 0 &&  threads[i].first_ts == threads[i].created_at &&  diff2 > 2000 ) //timeOut
                  {
                     int sended = sendData(threads[i].cSSL ,toSend2, threads[i].socket, strlen(toSend2));                                                              
                     if(  sended > 0 &&  threads[i].cSSL  != NULL)  SSL_shutdown( threads[i].cSSL );    //metoda Read powinno zwrocić -1 i tym samym zakonczyć wątek..                   
                     
                     if(sended < 0)
                     {
                        std::cout<<"\nForce cancel thread..." ;
                        if( threads[i].thread != NULL) {pthread_cancel( threads[i].thread );  actualThread--; }
                        clearRow(i);                   
                     }                                          
                  }
                  
                  if( diff > max   )
                  {                                            
                      int sended =  sendData(threads[i].cSSL ,toSend, threads[i].socket, strlen(toSend));                                                              
                      if( sended > 0 &&  threads[i].cSSL  != NULL ) SSL_shutdown( threads[i].cSSL );    //metoda Read powinno zwrocić -1 i tym samym zakonczyć wątek..                                              
                      if(sended < 0)
                      {
                        std::cout<<"\nForce cancel thread..." ;
                        if( threads[i].thread != NULL) {pthread_cancel( threads[i].thread );  actualThread--; }
                        clearRow(i);                   
                      }                      
                  }                                                                    
              }                                        
              
          }
        
         
        
    }
       
       return NULL;
}

//------------------------------------------------------------------------------


int main(int argc, char** argv) 
{
                   
    std::cout<<"\nBK Notice Server Started....\n";          
   
    
    
          pthread_attr_t attrX;
          pthread_attr_init(&attrX);
         // pthread_attr_setdetachstate(&attrX, PTHREAD_CREATE_JOINABLE); //po zakonczeniu zwolni sie od razu pamiec...
          pthread_attr_setdetachstate(&attrX, PTHREAD_CREATE_DETACHED); //po zakonczeniu zwolni sie od razu pamiec...
          
          //watek Bazy danych......
      //------------------------------------------------------------------------
         pthread_t mainThreadDB;  
         pthread_t mainThreadDB2;  
          
          
        //-------------------
          
 
          int rc3 = pthread_create(&mainThreadDB2, &attrX,  &runThreadDBFinal, (void*)NULL );
          if (rc3)
           {
                 std::cout<<"\nNie można stworzyc watku dla DB\n";                      
           }else
           {
             pthread_setname_np(mainThreadDB2,"D2");
           }
 
          
          //-------
          sleep(3); //dodaj opóznienie czasowe pomiedzy dwoma polaczeniami
          
 
          int rc2 = pthread_create(&mainThreadDB, &attrX,  &runThreadDBTest, (void*)NULL );
          if (rc2)
           {
                 std::cout<<"\nNie można stworzyc watku dla DB\n";                      
           }else
           {
             pthread_setname_np(mainThreadDB,"D1");
           }
 
          
    
      //------------------------------------------------------------------------
      //------------------------------------------------------------------------                                    
      //---------------------------------
        
        //https://stackoverflow.com/questions/10175812/how-to-generate-a-self-signed-ssl-certificate-using-openssl/10176685#10176685
        
            
        sslctxG = SSL_CTX_new( SSLv23_server_method());
        
        if(sslctxG == NULL)
        {
            std::cout<<"\nShutdown SSL_CTX :( ";           
            return 0;
        }
        
        //sslctx = SSL_CTX_new( TLSv1_1_client_method());
        SSL_CTX_set_options(sslctxG, SSL_OP_SINGLE_DH_USE);
                
        // SSL_CTX_set_default_passwd_cb_userdata(sslctx,"!");
                
        int use_cert = SSL_CTX_use_certificate_file(sslctxG, "/etc/ssl/apache2/STAR_XXXXXXX_pl.crt" , SSL_FILETYPE_PEM);
        //int use_cert = SSL_CTX_use_certificate_file(sslctx, "./cert.pem" , SSL_FILETYPE_PEM);
        //int use_prv = SSL_CTX_use_PrivateKey_file(sslctx, "./key.pem", SSL_FILETYPE_PEM);
        int use_prv = SSL_CTX_use_PrivateKey_file(sslctxG, "/etc/ssl/apache2/server.key", SSL_FILETYPE_PEM);          
          
    //---------------------------------
          
    usleep(100);
    
    
    clearAllRow();
    
    //Run Server...
    //---------------------------------
    //---------------------------------
  
                 struct sockaddr_in server;  

                 //inicjalize SSL
                 SSL_load_error_strings();
                 SSL_library_init();
                 OpenSSL_add_all_algorithms();
              
                 
                 int socket_desc  = socket(AF_INET , SOCK_STREAM , 0);

                 if(socket_desc == -1)
                 {
                     std::cout<<"\nBlad, nie mozna utworzyc socketu! \n";
                     return 0;
                 }


                 //dont block port... close imediatelly      
                 int yes=1;     
                 if (setsockopt( socket_desc , SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) 
                 {
                    std::cout<<"\nNie mozna ustawic opcji socketu!\n";    
                    return 0; 
                 }

                 server.sin_family = AF_INET;
                 server.sin_addr.s_addr = INADDR_ANY;
                 server.sin_port = htons( 7043 );  //prod: 7043,  /dev: 7042

                 if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0)
                 {
                   std::cout<<"\nBind failed!\n";
                   close(socket_desc);
                   return 0;
                 }





                 std::cout<<"\nListen on the port: ssl: 7043\n";
                 listen(socket_desc ,  MAX_THREADS - 10 );   

                 
                 threads[0].status = 2; //busy..
                 threads[0].created_at = getTimestamp();
                 threads[0].socket = socket_desc;

                 //new thread to read
               

                 int rc = pthread_create(&threads[0].thread, &attrX,  &runThreadPortEthernet, (void*)NULL );
                 if (rc)
                  {
                        std::cout<<"\nNie można stworzyc watku dla serwera\n";
                        close(socket_desc);
                        return 0 ;
                  }else
                  {
                     pthread_setname_np(threads[0].thread,"SRV");                                      
                     memcpy(threads[0].threadName,"SRV",strlen("SRV"));
                     memcpy(threads[0].clientToken,"SERVER", strlen("SERVER") );
                  }
 
    
    //End server
    //---------------------------------
    //---------------------------------
    //---------------------------------
              
       
           pthread_t mainThreadCK;     
           int rc5 = pthread_create(&mainThreadCK, &attrX,  &checker, (void*)NULL );
          if (rc5)
           {
                 std::cout<<"\nNie można stworzyc watku dla CC\n";                      
           }else
           {
             pthread_setname_np(mainThreadCK,"CC");
           }

           
           //.........
           while(1)
           {
               std::cout<<"\nWorking........................\n";                                             
               sleep( 3 );                            
             
           }
                 
                 
    //--------------------------------- 
 
      
    close( threads[0].socket); //zamknij port serwera..
    
    std::cout<<"\nBK Notice Server Stoped\n";
    return 0;
}
