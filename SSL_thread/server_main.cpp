 // ssl测试代码，不包含进webserver项目中
 
//  #include<string.h>
//  #include<sys/socket.h>
//  #include<netinet/in.h>
//  #include<arpa/inet.h>
//  #include<iostream>
//  #include<stdio.h>
//  #include<unistd.h>
//  #include<fcntl.h>
//  #include<sys/stat.h>
//  #include<sys/types.h>
//  #include<sys/un.h>
//  #include<sys/mman.h>
//  #include<assert.h>
//  #include"SSL_test.hpp"


//  using namespace std;

// // SSL连接简单实例
//  int main_ssl(int argc, char* argv[])
//  {
//     //输入参数处理
//     string cacert="/usr/lib/ssl/fd.crt";
//     string key="/usr/lib/ssl/fd.key";
//     string passwd="7492698wzy";
//     char *ip=argv[1];
//     int port=atoi(argv[2]);
//     cout<<"set port"<<port<<endl;
//     cout<<"set ip"<<ip<<endl;

//     //socket编程
//     char ssl_model=atoi(argv[3]);
//     int listenfd=socket(PF_INET, SOCK_STREAM, 0); //socket()
//     assert(listenfd!=-1);
//     // CTX_init(cacert.c_str(), key.c_str(), passwd.c_str());
//     SSL_test::ssl_init_ctx(cacert.c_str(), key.c_str(), passwd.c_str());

//     struct sockaddr_in m_addr;
//     bzero(&m_addr, sizeof(m_addr));
//     m_addr.sin_family=AF_INET;
//     m_addr.sin_port=htons(port);
//     m_addr.sin_addr.s_addr=inet_addr(ip);
//     if (bind(listenfd, (struct sockaddr*)&m_addr, sizeof(m_addr))==-1) //bind()
//     {
//         cout<<"bind socket failed!"<<endl;
//         return -1;
//     }
//     if (listen(listenfd,10)==-1) //listen
//     {
//         cout<<"listen failed!"<<endl;
//         return -1;
//     }
//     while (1)
//     {
//         //接收
//         struct sockaddr_in conn_addr;
//         socklen_t conn_len=sizeof(conn_addr);
//         int clientfd=accept(listenfd, (struct sockaddr*)&conn_addr, &conn_len);

//         //SSL_accept需要在accept之后调用，在已经建立的套接字基础上进行ssl握手。
//         SSL_test *ssl_socket=new SSL_test();
//         ssl_socket->ssl_init_fd(clientfd);
//         assert(ssl_socket->test_ssl_new());
//         ssl_socket->ssl_accept_m();

//         //生成回复报文
//         string html_file="welcome.html";
//         int fd=open(html_file.c_str(), O_RDONLY);
//         struct stat file_stat;
//         stat(html_file.c_str(), &file_stat);
//         void *html_=mmap(nullptr, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

//         string buf_w = "HTTP/1.1 200 OK\r\n"
//                         "Content-Type: text/html; charset=UTF-8\r\n"
//                         "Connection: close\r\n"
//                         "Date: Fri, 23 Nov 2018 02:01:05 GMT\r\n"
//                         "Content-Length: " + to_string(file_stat.st_size) + "\r\n"
//                         "\r\n";
//         buf_w += (char *)html_;

//         //发送回复报文、关闭连接
//         ssl_socket->ssl_write_m(buf_w);
//         munmap(html_, file_stat.st_size);
//         ssl_socket->ssl_close_m();
//         // cout<<"send"<<send(clientfd, buf_w.c_str(), buf_w.size(),0)<<"bytes"<<endl; //不启用SSL连接
//         // sleep(2);
//         // close(clientfd);
//     }
//     return 0;
//  }