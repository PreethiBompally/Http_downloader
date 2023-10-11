#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <fcntl.h>

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t file_write_mutex = PTHREAD_MUTEX_INITIALIZER;

// resolve the IP address of the web server based on its hostname. executed first to obtain the IP address
char* get_request_ip(char* host_name, char* ip_adrs_output)
{
  int dns_result;
  struct addrinfo *dns_list;
  struct addrinfo *temp_itr;
  char ip_address_temp[NI_MAXHOST];
  dns_result = getaddrinfo(host_name, "80", NULL, &dns_list );
  if( dns_result != 0)
  {
    fprintf(stderr,"DNS failed %s", gai_strerror(dns_result));
  }
  for( temp_itr=dns_list ; temp_itr != NULL; temp_itr = temp_itr->ai_next)
  {
    int conv_flag = getnameinfo(temp_itr->ai_addr , temp_itr->ai_addrlen , ip_address_temp , NI_MAXHOST ,NULL , 0 , NI_NUMERICHOST );
    if( conv_flag )
    {
      fprintf(stderr, "error in getnameinfo() %s \n", gai_strerror(conv_flag));
    }
    if( temp_itr->ai_family == AF_INET )
    {
      strcpy( ip_adrs_output , ip_address_temp );
      break;
    }
  }
  return ip_adrs_output;
} // get_request_ip

// create a TCP socket and establish a connection to the web server
int open_tcp_socket(char* ip_adrs_output)
{
  int sckt_num;
  sckt_num = socket(AF_INET , SOCK_STREAM , 0);
  struct sockaddr_in destination_address;
  destination_address.sin_family = AF_INET;
  destination_address.sin_port = htons(443);
  destination_address.sin_addr.s_addr = inet_addr(ip_adrs_output);
  int connection = connect(sckt_num, (struct sockaddr *) &destination_address, sizeof(destination_address));
  if( connection == -1)
  {
    fprintf(stderr, "Connection failed %s \n", gai_strerror(connection));
  }
  return sckt_num;
} //open_tcp_socket

// initialize an SSL/TLS session and bind it to the established TCP socket
SSL* bind_skt_and_tls_ssn(char* host_name , int sckt_num , SSL_CTX* ssl_ctx)
{
  SSL *conn = SSL_new(ssl_ctx);
  SSL_set_tlsext_host_name(conn, host_name);
  SSL_set_fd(conn,sckt_num);
  int err = SSL_connect(conn);
  if (err != 1)
  {
    printf("error in ssl\n");
    abort(); // handle error
  }
  return conn;
} //bind_skt_and_tls_ssn

void write_files(char *filename , char* buffer , int part , int length)
{
  pthread_mutex_lock(&file_write_mutex);
  if( strstr(buffer , "HTTP/1.1 206 Partial Content") == NULL)
  {
    char file_no[20];
    sprintf(file_no , "%d_" , part);
    FILE *fptr = fopen(strcat(file_no ,filename ) , "ab" );
    fwrite(buffer ,  1, length , fptr);
    fclose(fptr);
  }
  pthread_mutex_unlock(&file_write_mutex);
}// write_files

struct Arguments_for_thread_function
{
    char* host_name ;
    char* ip_adrs_output ;
    char* output_file_name ;
    SSL_CTX* ssl_ctx ;
    int i ;
    char* intermediate_request;
    int last_part_length ;
    int file_length;
}; //Arguments_for_thread_function

void* creating_thread(void* arguments)
{
    struct Arguments_for_thread_function* args = (struct Arguments_for_thread_function*) arguments;
    char* host_name = args->host_name;
    char* ip_adrs_output = args->ip_adrs_output ;
    char* output_file_name = args->output_file_name ;
    int i  = args->i;
    char* intermediate_request = args->intermediate_request;
    int last_part_length = args->last_part_length;
    SSL_library_init ();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ssl_ctx = SSL_CTX_new (SSLv23_client_method());
    int resp = 0;
    int prev = 0;
    char recur_buffer[last_part_length*2];
    char perm_buffer[args->file_length];
    int sckt_num = open_tcp_socket(ip_adrs_output);
    SSL *conn = bind_skt_and_tls_ssn(host_name , sckt_num , ssl_ctx);
    if( resp = SSL_write(conn , intermediate_request , strlen(intermediate_request)) < 0){
      perror("ERROR writing to ssl socket");
    }
    int k = 0;
    while(1) {      
          explicit_bzero(recur_buffer, last_part_length);
          if ((resp = SSL_read(conn, recur_buffer, last_part_length*2)) < 0) {
            perror("ERROR reading from socket.");
            break;
          }
          if (!resp){
            break;
          }
          else{
            if( strstr(recur_buffer , "HTTP/1.1 206 Partial Content") == NULL){
                k += resp;
                write_files(output_file_name , recur_buffer , i , resp);
            }
            else
            {
              char* offset = strstr(recur_buffer , "/r/n/r/n");
              if( offset != NULL)
              {
                offset = offset+4;
                k += strlen(offset);
                write_files(output_file_name, recur_buffer + (resp-strlen(offset)), i, strlen(offset));
              }
            }
            if( k == last_part_length){
              SSL_free(conn);
              close(sckt_num);
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
  char* no_of_tcp_conn = NULL;
  char host_name[64];
  char ip_adrs_output[NI_MAXHOST];
  char path[1024];
  int sckt_num;
  char intermediate_request[2048];
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
      no_of_tcp_conn = *(argv+i+1);
    }
  }
  
  sscanf(link_address , "%*[^:]%*[:/]%[^/]%s", host_name, path);
  strcpy(ip_adrs_output , get_request_ip(host_name , ip_adrs_output));
  sckt_num = open_tcp_socket(ip_adrs_output);
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
  SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());
  SSL *conn = bind_skt_and_tls_ssn(host_name , sckt_num , ssl_ctx);
  
  sprintf(intermediate_request , "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: PostmanRuntime/7.29.2\r\n\r\n" , path , host_name);

  char* request = intermediate_request;
  int resp = 0;
  if( resp = SSL_write(conn , request , strlen(request)) < 0)
  {
    perror("ERROR writing to ssl socket");
  }

  while(1)
  {
    explicit_bzero(buffer, 4096);
    if ((resp = SSL_read(conn, buffer, 4095)) < 0) {
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
  int no_of_tcp_conn_int = atoi(no_of_tcp_conn);
  int part_length = content_length/(no_of_tcp_conn_int);
  int last_part_length = part_length+content_length-(no_of_tcp_conn_int)*part_length;
  unsigned char recur_buffer[last_part_length];
  pthread_t threads[no_of_tcp_conn_int];
  char* user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
  for(int i = 0 ; i < no_of_tcp_conn_int ; i++ )
  {
    if( i != no_of_tcp_conn_int-1)
    {
      sprintf(intermediate_request , "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%d-%d\r\nUser-Agent: %s\r\n\r\n" , path , host_name , i*part_length , (i+1)*part_length-1 ,user_agent) ;
    }
    else
    {
      sprintf(intermediate_request , "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%d-%d\r\nUser-Agent: %s\r\n\r\n" , path , host_name , i*part_length , i*part_length + last_part_length-1 ,user_agent) ;
    }
    struct Arguments_for_thread_function arguments;
    arguments.host_name = host_name;
    arguments.output_file_name = output_file_name;
    arguments.i = i;
    arguments.ip_adrs_output = ip_adrs_output;
    arguments.intermediate_request = intermediate_request;
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
      sprintf(file_no , "%d_" , i);
      FILE *intermediate_file = fopen(strcat(file_no ,output_file_name) , "rb" );
      fseek(intermediate_file , 0 , SEEK_END);
      int size = ftell(intermediate_file);
      rewind(intermediate_file);
      char bytes[size];
      fread(bytes , sizeof(bytes) , 1 , intermediate_file);
      fwrite(bytes , sizeof(bytes) , 1 , fptr);
      fclose(intermediate_file);
  }
  fclose(fptr);

  SSL_free(conn);
  close(sckt_num);
  SSL_CTX_free(ssl_ctx);

} // main