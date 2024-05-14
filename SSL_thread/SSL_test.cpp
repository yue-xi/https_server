#include"SSL_test.hpp"
#include<iostream>

SSL_CTX *SSL_test::ctx = NULL;


int SSL_test::ssl_init_fd(int cnnfd) // 建立连接
{
    m_ssl = SSL_new(ctx);
    assert(m_ssl!=nullptr);
    SSL_set_accept_state(m_ssl); // set ssl to work in server mode.
    assert(SSL_set_fd(m_ssl, cnnfd)==1);    // 关联sockfd和ssl
    sockfd=cnnfd;
    return 1;
}

bool SSL_test::ssl_init_ctx(const char *cacert, const char *key, const char *passwd)
{
    SSLeay_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_method());
    assert(ctx != NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    SSL_CTX_load_verify_locations(ctx, cacert, NULL);                     // 加载CA的证书
    assert(SSL_CTX_use_certificate_chain_file(ctx, cacert) == 1);         // cacert="/usr/lib/ssl/fd.crt"是证书的存储位置
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *)passwd);          // passwd="7492698wzy"
    assert(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) == 1); // key="/usr/lib/ssl/fd.key"私钥的存储位置
    assert(SSL_CTX_check_private_key(ctx) == 1);
    // std::cout<<"ctx set sucess"<<std::endl;
    return true;
}

int SSL_test::ssl_accept_m()
{
    int ret = SSL_accept(m_ssl);
    // std::cout<<"test ssl accept: code"<<ret<<std::endl;
    if (ret <= 0)
    {
        int err = SSL_get_error(m_ssl,ret);
        switch (err)
        {
        // 需要等待下一次被触发
        case SSL_ERROR_WANT_READ:
            m_ssl_status=SSL_CHANNEL_WANT_READ;
            break;
        case SSL_ERROR_WANT_WRITE:
            m_ssl_status=SSL_CHANNEL_WANT_WRITE;
            break;
        default:
            m_ssl_status=SSL_CHANNEL_BAD;
            // std::cout<<"system error!"<<std::endl;
            ERR_print_errors_fp(stderr);
            return -1;
        }
        return 0;
    }
    else
    {
        m_ssl_status=SSL_CHANNEL_ESTABLISHED;
        // std::cout<<"oh god ssl handshake sucess"<<std::endl;
        return 1;
    }
}

E_SSL_CHANNEL_STATUS SSL_test::get_status()//获取当前SSL连接状态
{
    return m_ssl_status;
}

void SSL_test::set_status(E_SSL_CHANNEL_STATUS s)//获取当前SSL连接状态
{
    m_ssl_status=s;
    return;
}


int SSL_test::ssl_read_m(void *buf, int num)
{
    int ret=SSL_read(m_ssl, buf, num);
    // std::cout<<"read"<<ret<<" bytes"<<std::endl;
    return ret;
}

int SSL_test::ssl_write_m(void * buf, int nums)
{
    int ret = SSL_write(m_ssl, buf, nums);
    // std::cout << "send " << ret << " bytes" << std::endl;
    return ret;
}

// return 1: sucess; 0: need further read, -1: system error
int SSL_test::ssl_close_m()
{
    // 向对方发送shutdown信号，设置SSL_SENT_SHUTDOWN标志，将当前打开的会话视为关闭，放入缓存以待后续重用
    int st = SSL_shutdown(m_ssl);
    // return <0: it can occur if an action is needed to continue the operation for nonblocking BIOs
    if (st<0)
    {
        int err=SSL_get_error(m_ssl, st);
        switch (err)
        {
        // 需要等待下一次被触发
        case SSL_ERROR_WANT_READ:
            m_ssl_status=SSL_CHANNEL_SHUTDOWN_WANT_READ;
            return 0;
        case SSL_ERROR_WANT_WRITE:
            m_ssl_status=SSL_CHANNEL_SHUTDOWN_WANT_WRITE;
            return 0;
        case SSL_ERROR_SYSCALL:
            ERR_print_errors_fp(stderr);
            // std::cout<<"system error!"<<std::endl;
            return -1;
        default:
            m_ssl_status=SSL_CHANNEL_BAD;
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }
    else
    {
        m_ssl_status=SSL_CHANNEL_NO_CONNECTION;
        SSL_free(m_ssl);
        close(sockfd);
        // std::cout<<"SSL free, socket close"<<std::endl;
        if (st==0)
        {
            // std::cout<<"shutdown code: 0"<<std::endl;
        }
    }
    return 1;
}

int SSL_test::ssl_get_error_m(int ret)
{
    //当一切正常
    if (ret==0) return 0; 
    //当ssl操作存在异常
    int err = SSL_get_error(m_ssl, ret);
    return err;
}

SSL_test::~SSL_test()
{
}