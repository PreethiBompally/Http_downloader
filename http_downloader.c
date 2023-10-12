#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// resolve the IP address of the web server based on its hostname. executed first to obtain the IP address
char* getRequestIp(char* host_name, char* result_ip_address)
{
  struct addrinfo *dns_names;
  struct addrinfo *interim;
  char interim_ip_address[NI_MAXHOST];
  int output_of_dns;
  output_of_dns = getaddrinfo(host_name, "80", NULL, &dns_names );
  if( output_of_dns != 0)
  {
    fprintf(stderr,"DNS error due to - %s", gai_strerror(output_of_dns));
  }
  for( interim=dns_names ; interim != NULL; interim = interim->ai_next)
  {
    int flag = getnameinfo(interim->ai_addr , interim->ai_addrlen , interim_ip_address , NI_MAXHOST ,NULL , 0 , NI_NUMERICHOST );
    if( flag )
    {
      fprintf(stderr, "getnameinfo() error due to - %s \n", gai_strerror(flag));
    }
    if( interim->ai_family == AF_INET )
    {
      strcpy( result_ip_address , interim_ip_address );
      break;
    }
  }
  return result_ip_address;
} // getRequestIp

// create a TCP socket and establish a tcp_conn to the web server
int establishTcpSocket(char* result_ip_address)
{
  int sckt_val;
  sckt_val = socket(AF_INET , SOCK_STREAM , 0);
  struct sockaddr_in sockaddr_out;
  sockaddr_out.sin_family = AF_INET;
  sockaddr_out.sin_port = htons(443);
  sockaddr_out.sin_addr.s_addr = inet_addr(result_ip_address);
  int tcp_conn = connect(sckt_val, (struct sockaddr *) &sockaddr_out, sizeof(sockaddr_out));
  if( tcp_conn == -1)
  {
    fprintf(stderr, "tcp_conn failed %s \n", gai_strerror(tcp_conn));
  }
  return sckt_val;
} //establishTcpSocket

// initialize an SSL/TLS session and bind it to the established TCP socket
SSL* bindSocketWithTLSSession(char* host_name , int sckt_val , SSL_CTX* ssl_ctx)
{
  SSL *connection = SSL_new(ssl_ctx);
  SSL_set_tlsext_host_name(connection, host_name);
  SSL_set_fd(connection,sckt_val);
  int err = SSL_connect(connection);
  if (err != 1)
  {
    printf("SSL Error");
    abort();
  }
  return connection;
} //bindSocketWithTLSSession

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void writeFiles(char *ext, char* buffer , int part , int length)
{
  pthread_mutex_lock(&mutex);
  if( strstr(buffer , "HTTP/1.1 206 Partial Content") == NULL)
  {
    char parts[20];
    sprintf(parts , "part_%d." , part);
    FILE *fptr = fopen(strcat(parts ,ext ) , "ab" );
    fwrite(buffer ,  1, length , fptr);
    fclose(fptr);
  }
  pthread_mutex_unlock(&mutex);
}// writeFiles

struct Arguments_for_thread_function
{
    char* host_name ;
    char* result_ip_address ;
    char* output_file_name ;
    SSL_CTX* ssl_ctx ;
    int i ;
    char* transitional_get;
    int last_part_length ;
    int file_length;
}; //Arguments_for_thread_function

char* getFileExtension(char* filename){
    char* ext = strrchr(filename, '.');
    if (ext && ext != filename) {
        return ext + 1; 
    }
    return NULL;
}

void* creating_thread(void* arguments)
{
    struct Arguments_for_thread_function* args = (struct Arguments_for_thread_function*) arguments;
    char* host_name = args->host_name;
    char* result_ip_address = args->result_ip_address ;
    char* output_file_name = args->output_file_name ;
    int i  = args->i;
    char* transitional_get = args->transitional_get;
    int last_part_length = args->last_part_length;
    SSL_library_init ();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method());
    int resp = 0;
    int prev = 0;
    char recur_buffer[last_part_length*2];
    char perm_buffer[args->file_length];
    int sckt_val = establishTcpSocket(result_ip_address);
    SSL *connection = bindSocketWithTLSSession(host_name , sckt_val , ssl_ctx);
    if( resp = SSL_write(connection , transitional_get , strlen(transitional_get)) < 0){
      perror("ERROR writing to ssl socket");
    }

    int k = 0;
    while(1) {      
          explicit_bzero(recur_buffer, last_part_length);
          if ((resp = SSL_read(connection, recur_buffer, last_part_length*2)) < 0) {
            perror("ERROR reading from socket.");
            break;
          }
          if (!resp){
            break;
          }
          else{
            if( strstr(recur_buffer , "HTTP/1.1 206 Partial Content") == NULL){
                k += resp;
                writeFiles(getFileExtension(output_file_name), recur_buffer , i+1 , resp);
            }
            else
            {
              char* offset = strstr(recur_buffer , "/r/n/r/n");
              if( offset != NULL)
              {
                offset = offset+4;
                k += strlen(offset);
                writeFiles(getFileExtension(output_file_name), recur_buffer + (resp-strlen(offset)), i, strlen(offset));
              }
            }
            if( k == last_part_length){
              SSL_free(connection);
              close(sckt_val);
              break;
            }
          }
    }
} //creating_thread

// parsing command-line arguments, initializing variables, and setting up the necessary data structures
void main(int argc, char **argv)
{
  char* link_address = NULL;
  char* output_file_name = NULL;
  char* tcp_count = NULL;
  char host_name[64];
  char result_ip_address[NI_MAXHOST];
  char path[1024];
  int sckt_val;
  char transitional_get[2048];
  char buffer[4096];
  char perm_buffer[4096];
  int content_length;
  for(int i = 0 ; i < argc ; i++)
  {
    if( strcmp(*(argv+i) , "-u") == 0)
    {
      link_address = *(argv+i+1);
    }
    if( strcmp(*(argv+i) , "-o") == 0)
    {
      output_file_name = *(argv+i+1);
    }
     if( strcmp(*(argv+i) , "-n") == 0)
    {
      tcp_count = *(argv+i+1);
    }
  }
  
  sscanf(link_address , "%*[^:]%*[:/]%[^/]%s", host_name, path);
  strcpy(result_ip_address , getRequestIp(host_name , result_ip_address));
  sckt_val = establishTcpSocket(result_ip_address);
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  SSL *connection = bindSocketWithTLSSession(host_name , sckt_val , ssl_ctx);
  
  sprintf(transitional_get , "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: PostmanRuntime/7.29.2\r\n\r\n" , path , host_name);

  char* request = transitional_get;
  int resp = 0;
  if( resp = SSL_write(connection , request , strlen(request)) < 0)
  {
    perror("ERROR writing to ssl socket");
  }

  while(1)
  {
    explicit_bzero(buffer, 4096);
    if ((resp = SSL_read(connection, buffer, 4095)) < 0) {
      perror("ERROR reading from socket.");
      break;
    }
    if (!resp) break;

    int Accept_ranges = 0;
    char* ac_flag = strstr(buffer , "Accept-Ranges: bytes");
    char* cl_flag = strstr(buffer , "Content-Length: ");
    if( cl_flag == NULL)
    {
      cl_flag = strstr(buffer , "Content-length");
    }
    if( cl_flag == NULL)
    {
      cl_flag = strstr(buffer , "content-length");
    }
    if( cl_flag == NULL)
    {
      cl_flag = strstr(buffer , "content-Length");
    }
    if( ac_flag != NULL)
    {
      Accept_ranges = 1;
    }
    if(cl_flag != NULL)
    {
      int i = 0;
      char content[20];
      cl_flag = cl_flag+16;
      char* end_flag = strstr(cl_flag , "\r\n");
      if( end_flag != NULL)
      {
        i = strlen(cl_flag) - strlen(end_flag);
      }
      strncpy(content , cl_flag , i);
      content_length = atoi(content);
    }
  }
  int no_of_tcp_conn_int = atoi(tcp_count);
  int part_length = content_length/(no_of_tcp_conn_int);
  int last_part_length = part_length+content_length-(no_of_tcp_conn_int)*part_length;
  unsigned char recur_buffer[last_part_length];
  pthread_t threads[no_of_tcp_conn_int];
  char* user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
  for(int i = 0 ; i < no_of_tcp_conn_int ; i++ )
  {
    if( i != no_of_tcp_conn_int-1)
    {
      sprintf(transitional_get , "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%d-%d\r\nUser-Agent: %s\r\n\r\n" , path , host_name , i*part_length , (i+1)*part_length-1 ,user_agent) ;
    }
    else
    {
      sprintf(transitional_get , "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%d-%d\r\nUser-Agent: %s\r\n\r\n" , path , host_name , i*part_length , i*part_length + last_part_length-1 ,user_agent) ;
    }
    struct Arguments_for_thread_function arguments;
    arguments.host_name = host_name;
    arguments.output_file_name = output_file_name;
    arguments.i = i;
    arguments.result_ip_address = result_ip_address;
    arguments.transitional_get = transitional_get;
    arguments.last_part_length = part_length;
    if( i == no_of_tcp_conn_int-1)
    {
      arguments.last_part_length = last_part_length;
    }
    arguments.ssl_ctx = ssl_ctx;
    arguments.file_length = content_length;
    pthread_create(&threads[i] , NULL , creating_thread ,(void *) &arguments);
    pthread_join(threads[i] , NULL);
  }
  
  FILE *fptr = fopen(output_file_name, "ab");
  for(int i = 0 ; i < no_of_tcp_conn_int; i++)
  {
    char file_no[20];
      sprintf(file_no , "part_%d." , i+1);
      FILE *intermediate_file = fopen(strcat(file_no ,getFileExtension(output_file_name)) , "rb" );
      fseek(intermediate_file , 0 , SEEK_END);
      int size = ftell(intermediate_file);
      rewind(intermediate_file);
      char bytes[size];
      fread(bytes , sizeof(bytes) , 1 , intermediate_file);
      fwrite(bytes , sizeof(bytes) , 1 , fptr);
      fclose(intermediate_file);
  }
  fclose(fptr);

  SSL_free(connection);
  close(sckt_val);
  SSL_CTX_free(ssl_ctx);

} // main

/** Note: PDF file is downloaded if URL is like https://arxiv.org/ftp/arxiv/papers/2310/2310.06456.pdf
 and will not download if the URL is like https://browse.arxiv.org/pdf/2301.00275.pdf */