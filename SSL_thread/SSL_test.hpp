#ifndef SRC_SSLCONTEXT_HPP_
#define SRC_SSLCONTEXT_HPP_

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <string>
#include "assert.h"
 #include<string.h>
 #include<sys/socket.h>
 #include<netinet/in.h>
 #include<arpa/inet.h>
 #include<iostream>
 #include<stdio.h>
 #include<unistd.h>
 #include<fcntl.h>
 #include<sys/stat.h>
 #include<sys/types.h>
 #include<sys/un.h>
 #include<sys/mman.h>

enum E_SSL_CHANNEL_STATUS
{
    SSL_CHANNEL_NO_CONNECTION=0,
    SSL_CHANNEL_ESTABLISHED,
    SSL_CHANNEL_WANT_READ,
    SSL_CHANNEL_WANT_WRITE,
    SSL_CHANNEL_SHUTDOWN_WANT_READ,
    SSL_CHANNEL_SHUTDOWN_WANT_WRITE,
    SSL_CHANNEL_WANT_SHUTDOWN,
    SSL_WANT_SHUTDOWN_READY,
    SSL_CHANNEL_BAD
};

class SSL_test
{
private:
    static SSL_CTX *ctx;
    SSL *m_ssl=nullptr;
    E_SSL_CHANNEL_STATUS m_ssl_status;
    int sockfd;

public:
    SSL_test() {} 
    int ssl_init_fd(int cnnfd);                                                          // 构造函数：创建已有套接字对应的ssl
    static bool ssl_init_ctx(const char *cacert, const char *key, const char *passwd); // 初始化ssl ctx
    SSL* get_m_ssl() {return m_ssl; } //get函数
    void set_m_ssl(SSL* ssl_mm) {m_ssl=ssl_mm; } //set函数
    // bool test_ssl_new();
    int ssl_accept_m();           // ssl握手
    E_SSL_CHANNEL_STATUS get_status();//获取当前SSL连接状态
    void set_status(E_SSL_CHANNEL_STATUS s);//获取当前SSL连接状态
    int ssl_read_m(void* buf, int num); //ssl读取数据
    int ssl_write_m(void* buf, int nums); // ssl写入数据
    int ssl_close_m();            // ssl关闭连接
    int ssl_get_error_m(int ret); // ssl异常识别
     ~SSL_test();
};

#endif