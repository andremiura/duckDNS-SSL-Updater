#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/ssl.h>
 int socket_connect(char *host, in_port_t port){
         struct hostent *hp;
         struct sockaddr_in addr;
         int on = 1, sock;     

         if((hp = gethostbyname(host)) == NULL){
                 herror("gethostbyname");
                 exit(1);
         }
         bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
         addr.sin_port = htons(port);
         addr.sin_family = AF_INET;
         sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
         setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
         if(sock == -1){
                 perror("setsockopt");
                 exit(1);
         }
         if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
                 perror("connect");
                 exit(1);
         }
         return sock;
 }

 #define BUFFER_SIZE 1024

 int main(int argc, char *argv[]){
        int fd;
        char buffer[BUFFER_SIZE];

	char *hostname="www.duckdns.org";

        char getCommand[1024]="";

        if(argc < 3){

                printf("\n use: %s subdomain token \n\n",argv[0]);
                exit(1);
        }

        if( (strlen(argv[1]) > 40) || (strlen(argv[2]) > 36) ){

                printf("\nSize error!\n\n");
                exit(1);
        }

        fd = socket_connect(hostname,443); 

	SSL_load_error_strings ();
	SSL_library_init ();
	SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method ());	
		
	SSL *conn = SSL_new(ssl_ctx);
	SSL_set_fd(conn, fd );	

	int connected = SSL_connect(conn);
	if ( connected != 1)
   	        exit(1);

        strcpy(getCommand,"GET /update?domains=");
        strcat(getCommand,argv[1]);
        strcat(getCommand,"&token=");
        strcat(getCommand,argv[2]);
        strcat(getCommand,"\r\n");
     	
	SSL_write(conn, getCommand , strlen(getCommand));  

        bzero(buffer, BUFFER_SIZE);

        while(SSL_read(conn, buffer, BUFFER_SIZE - 1) != 0){
                 fprintf(stderr, "%s", buffer);
                 bzero(buffer, BUFFER_SIZE);
        }
	printf("\n");

        SSL_shutdown(conn); 
        close(fd);
         
        return 0;




 }

