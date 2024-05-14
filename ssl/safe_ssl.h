#ifndef SAFE_SSL_H
#define SAFE_SSL_H

#include<openssl/ssl.h>
#include<openssl/err.h>
#include"./log/log.h"


class safe_ssl
{
private:
    
public:
    safe_ssl();
    int ssl_init(); //初始化OPENSSL
    void ssl_ctx_create();//创建ctx对象，存储安全连接的各种环境与数据
    ~safe_ssl();
};

safe_ssl::safe_ssl(/* args */)
{
}

safe_ssl::~safe_ssl()
{
}

int safe_ssl::ssl_init()
{
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL)==0)
    {
        cout<<"OPENSSL_init_ssl() failed!"<<endl;
        return 0;
    }
    ERR_clear_error();//empties the current thread's error queue.
}

void safe_ssl::ssl_ctx_create()
{
    SSL_CTX_new(TLS_server_method());

}



#endif