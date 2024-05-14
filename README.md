## TinyWebServer项目笔记

[TOC]

### 内容一（核心）：http连接处理

#### 接收http报文：IO复用技术——epoll

**使用目的：**服务器通过**epoll**这种I/O复用技术（还有select和poll）来实现对监听socket（`listenfd`）和连接socket（客户请求）的同时监听。

##### IO的阻塞、同步/异步、复用：

**<u>*阻塞与非阻塞：*</u>**

- IO分为阻塞IO与非阻塞IO，阻塞IO的系统调用可能会因为无法立即完成而被系统挂起直到等待的事件发生，socket的send, accept, connect, recv函数都是可能被阻塞的。非阻塞IO的系统调用总是立即返回。
- 需要注意的是，**阻塞IO等待的是「内核数据准备好」和「数据从内核态拷贝到用户态」这两个过程**。非阻塞IO虽然会在内核数据准备好之后再进行IO操作，但是数据从内核态拷贝到用户态的过程也是需要等待的过程。

**<u>*IO复用：*</u>**

IO复用是指程序向内核注册一组事件，内核将就绪的事件通知给应用程序。实际上IO复用函数也是阻塞的，但由于其可以同时监听多个IO，因此可以提高系统效率。而阻塞IO通常只能阻塞在等待一个IO事件发生的位置。

非阻塞IO常常与IO复用配合使用，内核将就绪的事件通知给应用程序后，应用程序调用非阻塞IO对事件进行处理。从而提高程序的效率。

**<u>*同步与异步：*</u>**

同步IO与异步IO的区别主要体现在「数据从内核态拷贝到用户态」这个过程是否是需要等待的。

同步IO：上述阻塞IO、非阻塞IO、IO复用，均为同步IO模型，同步IO模型中，IO的读写操作都是在IO事件发生之后由应用程序完成的，内核向应用程序通知的是IO就绪事件。

异步IO：用户可以直接对IO进行读写操作，这些操作只负责告诉内核缓冲区的位置以及IO操作完成后向用户通知的方式，而内核向应用通知的是IO完成事件。



##### Linux提供的IO复用函数：





##### Epoll使用方法：

epoll的两种触发模式：

- LT水平触发模式

- - epoll_wait检测到文件描述符有事件发生，则将其通知给应用程序，应用程序可以不立即处理该事件。
  - 当下一次调用epoll_wait时，epoll_wait还会再次向应用程序报告此事件，直至被处理

- ET边缘触发模式

- - epoll_wait检测到文件描述符有事件发生，则将其通知给应用程序，应用程序必须立即处理该事件

  - 必须要一次性将数据读取完，使用非阻塞I/O，读取到出现eagain

  - 代码中ET模式的具体体现 001 ：在ET模式下，**一次性可能会到来多个连接或者多个数据包。**如果你不在一个循环中处理这些，你可能会丢失事件，因为EPOLL不会再次告知你这些事件直到新的活动发生。所以，你需要循环读取所有的数据，直到没有更多数据可以读取，或者循环接受所有的连接，直到没有更多的连接尝试。

    ```c++
    while (1)
    {
    	int connfd = accept(m_listenfd, (struct sockaddr *)&client_address, &client_addrlength);
    	if (connfd < 0)
    	{
    		LOG_ERROR("%s:errno is:%d", "accept error", errno);
    		break;
    	}
    	if (http_conn::m_user_count >= MAX_FD)
    	{
    		utils.show_error(connfd, "Internal server busy");
    		LOG_ERROR("%s", "Internal server busy");
    		break;
    	}
    	timer(connfd, client_address);
    }
    return false;
    ```
    
  - Question: LT模式下是否会出现读取一次不完整从而导致数据无法处理的问题？
  
    - 答（GPT）：在LT模式下，尽管每次触发时可以只读取一次数据，但这并不意味着一次读取就能获取到完整的信息。实际上，LT模式下仍然可能需要多次读取来获取完整的数据，特别是在处理大量数据或网络传输较慢的情况下。LT模式的优点是它简化了读取逻辑，因为你不需要在每次事件触发时一次性读取所有数据；如果数据没有被完全读取，epoll会再次通知你。
    - 确保数据完整性的关键不在于LT或ET模式，而在于你的数据读取逻辑。无论是哪种模式，都应该根据你的应用协议来决定如何处理数据。例如，对于HTTP报文，通常需要读取头部信息，确定内容长度，然后根据这个长度读取完整的请求或响应体。这一过程可能需要根据数据的到达分多次进行。
    - 因此，在HTTP报文的处理过程（parse_line()函数)中，专门设置了line_open状态来判断该请求是否已经完全读入，读入的数据一行中以\r或没有\r\n结尾时，认定为该行不完整，设定行的读取状态为line_open；

epoll定义的函数：

```
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
```

其中op可以是EPOLL_CTL_ADD、EPOLL_CTL_MOD和EPOLL_CTL_DELETE, event则指向 `epoll_event` 结构的指针，该结构指定了需要监视的事件类型（EPOLLIN、EPOLLOUT、EPOLLONESHOT等）和用户数据。对于 `EPOLL_CTL_DEL`，此参数可以设为 `NULL`。

epoll的EPOLLONESHOT事件：

![image-20240301200517282](C:\Users\25786\AppData\Roaming\Typora\typora-user-images\image-20240301200517282.png)

因此，项目中的modfd()函数就可以实现这一功能。要注意重新注册fd时需要用到的操作类型是EPOLL_MOD而不是EPOLL_ADD



**服务器两种高效的IO事件、信号事件、定时事件的处理模式：**

- Practor模式：异步网络模式，通常用异步IO模型实现，可以用同步IO模拟出Practor模式。
- Reactor模式：非阻塞同步网络模式，通常用同步IO模型实现
  - 基础模式，主线程只负责

注：从目前的结果来看，这两种模式的主要区别在于读写任务是由IO处理单元，也即主线程来完成还是逻辑单元也即，工作线程来完成。

有关多Reactor多进程的实现等更深入的理解可以看下面的知乎链接[带你彻底搞懂高性能网络模式Reactor 和 Proactor - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/372277468)

有关Reactor操作的代码如图所示：

```c++
//WebServer::dealwithRead(int sockd)
//reactor
    if (1 == m_actormodel)
    {
        if (timer)
        {
            adjust_timer(timer);
        }

        //若监测到读事件，将该事件放入请求队列
        m_pool->append(users + sockfd, 0);

        while (true)
        {
            //等待有线程读了这个数据（也即，主线程成功将数据IO给工作线程）
            if (1 == users[sockfd].improv)
            {
                if (1 == users[sockfd].timer_flag)
                {
                    deal_timer(timer, sockfd);
                    users[sockfd].timer_flag = 0;
                }
                users[sockfd].improv = 0;
                break;
            }
        }
    }
```





#### 处理http报文

http与TCP/IP的关系：http是一类应用层协议，而TCP/IP是网络层

状态：

HTTP_CODE

##### **http报文结构：**

1. ***头部字段：***请求行+请求头部（格式为“属性名:属性值”）

第一行：GET  http://www.baidu.com/index.html HTTP/1.0 (**请求行**，包括请求方式GET, 客户端url以及http版本号)

- 请求方式：常用有GET: 以只读的方式申请资源；POST：向服务器提交数据；PUT：上传数据；DELETE：删除数据；等，本项目只用到了前两个，否则认定为非法请求。
- URL：统一资源定位符（Uniform Resource Locator）”简称为URL。**URL是web页的地址**，在这里表明了要操作的资源。这种地址会在浏览器顶部附近的Location或者URL框内显示出来。在本项目中，如果判断url合法，那么可以在读取环节就加入后面服务器希望显示的网页的名称，如... /judge.html，
- http版本号：本项目只支持HTTP/1.1

第二行：Use-Agent:Wget/1.12(linux-gnu) （User-Agent: <product> / <product-version> <comment>）（属于请求头中的其中一行）用来让网络协议的对端来识别发起请求的用户代理软件的应用类型、操作系统、软件开发商以及版本号。

第三行：Host:www.baidu.com （属于请求头中的其中一行）表示目标主机名

2. ***空行：***

only回车符和换行符（<CR><LF>）cpp识别中将其识别为'\0'空字符

3. ***请求体：***

注：http报文每一行均以\r\n结尾，判断行是否完整可以通过搜索'\r'和'\n'，



##### 读入http报文：有限状态机

- 解析http请求行，获得请求方法、目标url及http版本号
- 解析http头部
- 判断http请求是否被完整读入



#### 响应http报文：线程池实现多线程并发

线程池：





使用目的：IO复用技术本身是阻塞的，因此仍然只能按顺序处理任务，所以需要引入线程池来实现并发，为每个就绪的文件描述符分配一个线程来处理。

##### 关键代码段上锁：

通过sem对象实现。

响应http报文格式：

HTTP响应报文的格式主要由三个部分组成：状态行、响应头部(header)、消息正文(body)。以下是其基本结构的简要描述：

1. **状态行**：它是HTTP响应报文的第一行，包含了协议版本、状态码和状态消息。
   - 协议版本，如HTTP/1.1。
   - 状态码，如200、404等，用于表示服务器处理请求的结果。
   - 状态消息，如OK、Not Found等，是状态码的文本描述。
2. **响应头部**：紧接状态行之后，包含了零个或多个头部字段，每个字段包含了对消息正文或请求本身的描述和元数据。头部字段是由名称和值组成的键值对，例如`Content-Type: text/html`。响应头部中常见的字段包括`Content-Type`（响应体的MIME类型）、`Content-Length`（响应体的长度）、`Set-Cookie`（设置Cookie）等。
3. **消息正文**：最后是消息正文部分，包含了服务器响应的实际数据。不是所有的响应都有消息正文，例如一些响应状态码为204 (No Content)或304 (Not Modified)的响应就没有正文。

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 138
Set-Cookie: UserID=JohnDoe; Max-Age=3600; Version=1

<html>
  <head>
    <title>An Example Page</title>
  </head>
  <body>
    Hello World, this is a very simple HTML document.
  </body>
</html>

```

注：服务器向EPOLL注册EPOLLOUT事件后epoll_wait就会接收到该事件，而在epollfd初始化时不需要注册EPOLLOUT



##### 非活动连接处理：

实现逻辑：

``socketpair(PF_UNIX, SOCK_STREAM, 0, m_pipedfd)``

- 创建一对套接字进行进程间通信，这里创建了UNIX Domain Socket
- ``m_pipedfd``是一个长度为2的``int``数组，信号处理函数向``m_pipedfd[1]``中写入信号类型，``epoll``监听``m_pipedfd[0]``并通知主线程读取数据，主线程从``m_pipedfd[0]``中读数据，根据读到的信号来处理。

``sigaction(int signum, const struct sigaction act, struct sigaction oldact)``

- 该系统调用用于改变一个进程接收到某一个信号（signum）后的反应。信号处理函数设置在act.sa_handler中，act的sa_flags信号控制处理方式。

- SA_RESTART: 如果在 某个函数如`read()` 调用时接收到信号，那么由于设置了 `SA_RESTART`，`read()` 调用将在信号处理函数返回后自动继续，而不是失败并返回错误

**未解决问题：**

1. 为什么sigaction之前需要调用sigfillset函数？
2. 为什么信号处理函数中，为了保证函数的可重入性，需要保留原来的errno，目前认为是因为没有设置``SA_RESTART``导致函数可能会被中断而报错，所以需要保留errno

本日工作：搞清楚非活动连接处理模式、git学习，将项目上传到github，更新简历





#### 遇到的问题与回答

Q1: 在服务器编程中，为什么只需要为服务器定义一个socket即可? GPT回答结果如下：

在服务器编程中，通常只需要定义一个监听socket来开始接受连接请求，这是由TCP协议的工作方式决定的。下面是这种设计选择的一些原因：

**端口监听：**每个TCP服务器都在其上监听一个特定的端口号。所有发往该端口号的连接请求都会由操作系统传递给相应的监听socket。服务器的监听socket不是用来发送和接收应用层数据的，而是作为新连接请求的接收点。一旦接受了一个连接请求，就会为该连接创建一个新的socket （对应的文件描述符可能是从小到大排列的，所以系统预设的http_con数组大小为MAX_FD, 最大文件描述符）

**分离连接和监听逻辑：**监听socket只负责接受新的连接。当一个新的客户端连接请求到达时，监听socket会与客户端完成三次握手过程，并且创建一个新的socket来处理与该客户端的通信。这个新创建的socket将具有相同的端口号，但是它会与一个唯一的客户端地址和端口号关联，这样服务器就可以通过这个新的socket与客户端进行数据交换。

**多路复用：**单个监听socket可以接受来自不同客户端的多个连接请求，操作系统会为每个成功的连接请求创建一个新的socket实例。这样，服务器就能够使用一个端口号来处理多个并发连接。

**简化设计：**如果服务器为每个潜在的客户端预先创建socket，不仅会消耗大量的系统资源，而且这些资源中的大多数会闲置，因为并不是每个socket都会有连接请求。监听socket的设计使得资源只在实际需要时才被分配，从而提高了效率。

**操作系统的支持：**现代操作系统提供了高效的机制来处理监听socket和连接socket，例如select/poll、epoll（在Linux上）和kqueue（在BSD系统上），这些机制使得单个进程或线程可以高效地管理多个连接。

Q2：什么是回调函数和超时时间



### 内容二：MYSQL数据库

提到的 `mysql_query()` 函数实际上是在C语言中使用MySQL的C API时用到的，而不是在C++中。在C++中，通常推荐使用MySQL Connector/C++库，它提供了一个面向对象的接口来操作MySQL数据库。不过，如果你想在C++中使用C风格的MySQL API，你可以直接使用 `mysql_query()` 函数，它属于MySQL C API的一部分。

`mysql_query()` 函数的基本用途和描述如下：

- **函数原型**：`int mysql_query(MYSQL *connection, const char *query)`
- **功能描述**：执行指定为null终止的字符串 `query` 的SQL查询。该查询的字符串不应包含分号(`;`)或者 `\g`。复合语句或者多个语句的执行需要使用另外的函数。`mysql_query()` 用于发送单个查询（可能是多行的或者包含多个语句的）到数据库服务器。
- **参数**：
  - `connection`：一个指向MYSQL结构的指针，该结构代表了与MySQL数据库的一个连接。
  - `query`：要执行的SQL查询字符串。
- **返回值**：如果成功，返回0；如果发生错误，返回非0值。

使用 `mysql_query()` 时，通常的步骤包括：
1. 使用 `mysql_init()` 初始化MYSQL对象。
2. 使用 `mysql_real_connect()` 建立与数据库的连接。
3. 使用 `mysql_query()` 执行SQL语句。
4. 对于SELECT查询，使用 `mysql_store_result()` 或 `mysql_use_result()` 获取结果集。
5. 使用结果集处理函数，如 `mysql_fetch_row()`，遍历查询结果。
6. 使用 `mysql_free_result()` 释放结果集。
7. 最终使用 `mysql_close()` 关闭与数据库的连接。

`mysql_query()` 函数和其他C API函数可以在C++代码中使用，但需要确保链接了MySQL客户端库，并且在包含MySQL头文件时使用 `extern "C"` 来避免C++的名称修饰（如果你的编译器在处理外部C库时需要这样做）。





### 内容三：OpenSSL实现加密通信

官方API文档：[/docs/man3.0/man3/SSL_CTX_new.html (openssl.org)](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_new.html)



初始化SSL：原文链接：https://blog.csdn.net/qq_42370809/article/details/126352996

1. 创建ctx变量：SSL_CTX 类型
2. 设置ssl模式（通过设置ctx变量）
3. 设置发布证书的机构的目录，和自己的证书与私钥

```c++
bool InitSSL(const char* cacert, const char* key, const char* passwd){
    // CA证书位置：
    // 初始化
    SSLeay_add_ssl_algorithms(); //不清楚干什么的
    OpenSSL_add_all_algorithms(); //被弃用了，应该不需要这么设置
    SSL_load_error_strings(); //被弃用了
    ERR_load_BIO_strings(); 

    // 我们使用SSL V3,V2
    assert((ctx = SSL_CTX_new(SSLv23_method())) != NULL);

    // 要求校验对方证书，这里建议使用SSL_VERIFY_FAIL_IF_NO_PEER_CERT，详见https://blog.csdn.net/u013919153/article/details/78616737
    //对于服务器端来说如果使用的是SSL_VERIFY_PEER且服务器端没有考虑对方没交证书的情况，会出现只能访问一次，第二次访问就失败的情况。
    //设置模式与验证回调函数（这里设置的是NULL默认值），SSL_VERIFY_FAIL_IF_NO_PEER_CERT：服务器模式: 如果客户端没有返回证书，TLS/SSL 握手将立即以“握手失败”警告终止。此标志必须与 SSL _ VERIFY _ PEER 一起使用。
    SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL); 

    // 加载CA的证书
    assert(SSL_CTX_load_verify_locations(ctx, cacert, NULL));
    // 加载自己的证书
    assert(SSL_CTX_use_certificate_chain_file(ctx, cacert) > 0);
    //assert(SSL_CTX_use_certificate_file(ctx, "cacert.pem", SSL_FILETYPE_PEM) > 0);
 // 加载自己的私钥 
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)passwd);
    assert(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) > 0);
 
    // 判定私钥是否正确  
    assert(SSL_CTX_check_private_key(ctx));


    return true;
}
```

#### socket通信基础：

地址结构体：struct sockaddr_in

```c++
struct sockaddr_in {

　　short int sin_family; /* 通信类型 */同样为AF_INET

　　unsigned short int sin_port; /* 端口号，一般用htons来获得 */

　　struct in_addr sin_addr; /* Internet 地址，如127.0.0.1 */
   struct in_addr {

　　unsigned long s_addr;

	};

　　unsigned char sin_zero[8]; /* 与sockaddr结构的长度相同*/

};
```

创建套接字、绑定地址、开始监听、接收数据、发送数据、关闭连接[C++ Socket编程（基础） - MaxLij - 博客园 (cnblogs.com)](https://www.cnblogs.com/MaxLij/p/14584187.html)

注：Linux下socket **INADDR_ANY**表示一个服务器上的所有网卡，多个本地ip都进行绑定端口号侦听。

```c++
//创建套接字
    int serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  	// AF_INET :   表示使用 IPv4 地址		可选参数
    // SOCK_STREAM 表示使用面向连接的数据传输方式，
    // IPPROTO_TCP 表示使用 TCP 协议

    //将套接字和IP、端口绑定
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));  //每个字节都用0填充，也可以使用bzero函数
    serv_addr.sin_family = AF_INET;  //使用IPv4地址
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    serv_addr.sin_port = htons(1234);  //端口
    bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    //进入监听状态，等待用户发起请求
    listen(serv_sock, 20);

    //接收客户端请求
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

    //向客户端发送数据
    char str[] = "Hello World!";
    write(clnt_sock, str, sizeof(str));
   
    //关闭套接字
    close(clnt_sock);
    close(serv_sock);

```

#### 利用ssl进行socket通信：

根据抓包结果，ssl通信具体数据包发送情况如下：

TCP三次握手--> 客户端主动发送TLS包 client hello --> 服务器端发送TLS包交换安全套件（伴随一个TCP包）-->客户端发送安全套件（伴随一个回复TCP包）-->服务器发送应用数据

1. 正常创建socket监听、接收数据
2. 有客户连接后，建立一个新的SSL对象
3. 将SSL对象与客户连接对应的socket绑定
4. 利用ssl_accept()函数进行SSL握手。
5. 利用SSL_write而不是write函数传输数据
6. 关闭连接时也采用SSL_shutdown和SSL_free。

```c++
int main(int argc, char* argv[]){
    //开始监听后：
    while(1){
        struct sockaddr_in addr;
        socklen_t addrlen = sizeof(addr);
        int new_con = accept(listenfd, (sockaddr *)&addr, &addrlen);
        if(new_con == -1){
            printf("accept error, errno = %d",errno);
            continue;
        } else {
            printf("accept %d success\n", new_con);
        }
//ssl
        SSL *ssl = SSL_new(ctx);
        if(ssl == NULL)
        {
            printf("ssl new wrong\n");
            return 0;
        }
        SSL_set_accept_state(ssl);
        //关联sockfd和ssl
        SSL_set_fd(ssl, new_con);
        
        int ret = SSL_accept(ssl);
        if(ret != 1){
            printf("%s\n", SSL_state_string_long(ssl));
            printf("ret = %d, ssl get error %d\n", ret, SSL_get_error(ssl, ret));
        }

//
        string html_file = "welcome.html";
        int fd = open(html_file.c_str(), O_RDONLY);
        struct stat file_stat;
        stat(html_file.c_str(), &file_stat);
        void *html_ = mmap(nullptr, file_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        string buf_w = "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html; charset=UTF-8\r\n"
                        "Connection: close\r\n"
                        "Date: Fri, 23 Nov 2018 02:01:05 GMT\r\n"
                        "Content-Length: " + to_string(file_stat.st_size) + "\r\n"
                        "\r\n";
        buf_w += (char *)html_;
        //把send换成SSL_write
        //printf("send %d bytes\n", send(new_con, (void*)buf_w.c_str(), buf_w.size(), 0));
        printf("send %d bytes\n", SSL_write(ssl, (void*)buf_w.c_str(), buf_w.size()));
        munmap(html_, file_stat.st_size);
        
        //关闭
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_con);
    }
    
    SSL_CTX_free(ctx);
    return 0;
}
```

测试：

设置ip: 127.0.0.1, 端口号9006

SSL_free报错：确认为SSL_shutdown的问题，SSL_shutdown不能成功是由于write时调用了return SSL_write

SSL_write的问题：

- 客户端需要使用https请求而不是http请求，否则会报错。该点需要在后续代码中强化
- 设置ssk_set_verify选项为SSL_VERIFY_PEER或SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT时，系统连接失败

第二次连接浏览器显示连接被重置：可能是https写成了http导致的连接错误。



#### 非阻塞IO中实现SSL安全连接

- SSL_accept搭配EPOLL使用：
  - 原因：由于此时底层IO为非阻塞的，那么不等SSL握手完成SSL_accept就会直接返回握手失败信息
  - 解决方案一：[epoll + 非阻塞IO + openssl_epoll openssl-CSDN博客](https://blog.csdn.net/DefiniteGoal/article/details/123543656) 在程序中设置大循环等待ssl握手完成。（好像有点拉）
  - 解决方法二：[非阻塞/异步(epoll) openssl_ssl tcp可以用非阻塞-CSDN博客](https://blog.csdn.net/zhangzq86/article/details/50779606) 根据error值判断是否是非阻塞导致的握手失败，然后重新读取
  - 解决方案三：可能根本不是个问题，因为我们使用的epoll可以保证非阻塞IO正常运作，试一下吧应该没问题。
- 最终解决方案：参考解决方案二的思想，
- ssl读取、写入数据
  - 首先，socket编程用的是recv函数不是read函数，openssl库没有这样的函数，直接将recv换成了ssl_read
  - 其次，在EPOLL已经提示有数据可读的情况下是否会出现SSL_ERROR_WANT_READ这类问题，GPT的回答是会的，即使确定了 `EPOLLIN` 事件发生，`SSL_read` 仍可能只读取部分数据并返回，这是因为几个原因：
    1. **非阻塞模式**：即使 `epoll` 报告说 socket 可读（`EPOLLIN`），在非阻塞模式下，可读不保证你可以一次性读取所有数据。数据可能是分片到达的，或者当前可读的数据只是部分数据。
    2. **SSL/TLS 记录边界**：`SSL_read` 会尊重 SSL/TLS 记录的边界。一个 SSL/TLS 记录可能包含了你想读的数据的一部分，因此你可能需要多次调用 `SSL_read` 来读取完整的应用数据。
    3. **内部 SSL 状态机**：SSL/TLS 协议涉及复杂的状态机，其中包括握手和其他协议相关的消息。因此，即使是在你准备读取应用数据时，`SSL_read` 也可能在内部处理协议数据。
    4. **缓冲区大小限制**：`SSL_read` 的行为受到提供的缓冲区大小的限制。如果缓冲区大小小于待读取的数据，则会读取缓冲区大小的数据量，并将剩余的数据留在 SSL 层或底层 socket 缓冲区中，待下次读取。
  - 最后，根据实际测试发现ssl_accept问题更大，write和read不太有问题。
- ssl连接释放
  - SSL_shutdown嘎嘎出问题，测了一下午，希望能解决返回0时重新读取的问题，但是太复杂，因为关闭的方式很多，很难去统一。
  - 先从最简单的问题开始：ssl_shutdown很容易出现不返回1返回0或-1的问题，=0的话是不需要使用SSL_get_error来判断有什么错误的，不然会被误导存在SYS_ERROR, 此时ERR_print_errors_fp是不会输出任何信息的
  - 经测试，即使返回0的SSL_SHUTDOWN也可以被正常free掉，所以干脆就不搞太复杂



### 内容四：编译与测试

##### 测试记录：

**<u>2024.03.29：</u>**ET+ET触发模式下无法建立安全连接

<img src="C:\Users\25786\AppData\Roaming\Typora\typora-user-images\image-20240416210906585.png" alt="image-20240416210906585" style="zoom:25%;" />

原因分析：

ET模式下读取数据完成判断条件有点问题，导致每次读完数据后都返回-1，然后系统识别为关闭连接。已修改

**<u>2024.04.08：</u>**当触发EPOLLRDHUP事件后，调用deal_timer函数执行shutdown与关闭连接操作，SSL_shutdown函数会返回<0且错误代码为SSL_ERROR_SYSCALL

原因分析：

1. 可能是对方没有正确发送ssl关闭通知而是直接关闭了底层BIO
2. 没找到EPOLLRDHUP

**<u>2024.04.09：</u>**jmeter单个连接失败，读取数据后关闭连接，随后定时器又进行了一次连接关闭，导致程序发生段错误。

原因分析：

1. process_read()后返回的状态码为NO_RESOURCE，表示申请的资源不存在，调试后发现压测工具申请了./root/GET文件，应该是压测工具的参数不对。
2. 测试了项目源码后发现没有段错误的问题，所以是新增的SSLshutdown功能的问题。

修改日志：

修改了压测工具PATH路径设置，在定时器回调函数中加入对SSL_socket状态的检查，如果确认为已经关闭的连接，则回调函数不做任何处理，直接返回。

<u>**2024.04.08：**</u>非法指令：核心已转储问题如何定位：

1. 设置系统开启核心已转储：``ulimit -c 409600`` 其中数字代表核心转储文件大小上限。=0则关闭了核心转储
2. 查看转储文件生成路径：``cat /proc/sys/kernel/core_pattern`` 
3. 设置转储文件生成在当前路径：``echo 'core' > /proc/sys/kernel/core_pattern`` 
4. 使用gdb调试工具结合core文件进行调试：``gdb server core`` 

**<u>2024.04.19：</u>**无法正确放弃http连接请求：

原因分析：之前的代码未处理ssl握手失败（SSL_accept()返回-1）的问题

修改日志：http_conn::init中增加了对ssl握手失败的处理，逻辑为ssl连接失败则删除对该socket的监听，不将其加入http连接用户中。修改了Reactor模型中timer函数对http_conn::init()失败的处理模式，返回失败时不创建对应timer定时器。





##### 抓包工具：

wireshark+tcpdump测试：

[tcpdump 和 wireshark 抓包比较_ifconfig命令统计出来的包和wireshark统计的包有什么区别-CSDN博客](https://blog.csdn.net/hunanchenxingyu/article/details/8780513)

tcpdump的详解：

[Linux系统 tcpdump 抓包命令使用教程 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/74812069)

本项目的虚拟机内使用的tcpdump命令：



##### 压力测试：

- **查看测试中内存占用情况：**htop工具，[Linux系统状态命令htop最详细解释说明(没有之一!)_htop红色绿色-CSDN博客](https://blog.csdn.net/qq_34672033/article/details/89735983)

- Webbech压测：
  - **安装webbench:** wget http://blog.s135.com/soft/linux/webbench/webbench-1.5.tar.gz  
    tar zxvf webbench-1.5.tar.gz  
    cd webbench-1.5  
    make && sudo make install
  - **webbench调试错误：**
    - 找不到rpc/types.h头文件：可能ubuntu中不存在该文件，修对应位置为sys/types.h，centOS系统同上
    - 找不到ctags命令：apt-get安装ctags, 提示选择两个版本中的其中一个，选了universal-ctags
    - make后仍然无法正常使用：sudo make install
    - 不支持https: ![image-20240417100115070](C:\Users\25786\AppData\Roaming\Typora\typora-user-images\image-20240417100115070.png)

- JMeter压测：
  - 工具箱为JAVA开发，需安装JDK，采用了手动安装orcle版本的安装包并配置环境，语言环境配置方式如下：[Ubuntu安装JDK](https://developer.aliyun.com/article/704959)
  - JMeter安装：官方网站[Apache JMeter - Download Apache JMeter](https://jmeter.apache.org/download_jmeter.cgi) 解压缩目录：/usr/local/jmeter/
  - 创建测试计划、在非gui下运行，（目前的jmeter安装方式每次开一个终端都需要重新souce /etc/profile，后面再改吧
  - 2024.04.19：线程数1000：成功
  - 2024.04.21：线程数10000：失败7.74%
  - http连接压测：线程数10000：失败0%

![image-20240419111715007](C:\Users\25786\AppData\Roaming\Typora\typora-user-images\image-20240419111715007.png)

![image-20240421170222853](C:\Users\25786\AppData\Roaming\Typora\typora-user-images\image-20240421170222853.png)

![image-20240421170340348](C:\Users\25786\AppData\Roaming\Typora\typora-user-images\image-20240421170340348.png)



### 代码基础语法分析

- assert()：根据GPT所述，代码中的`assert`是在调试期间用来捕捉程序错误的，实际部署时通常会去掉。

- 函数指针：（定义如下）这个函数指针的类型是指向一个函数的指针，该函数接收一个指向`client_data`结构的指针作为参数，并且没有返回值（即返回类型为`void`）。这通常用于**回调函数**的定义，允许将一个函数作为参数传递给另一个函数，通常用于在某个事件发生时被调用。

```c++
void (* cb_func)(client_data *);
```

- errno错误处理：

- stat(): 返回所访问文件的属性。

- mmap()：将文件映射到内存以提高文件的访问速度（**POSIX标准定义的Unix系统调用**）这提供了一种让文件内容直接出现在虚拟地址空间的方法，这样程序就可以像访问内存一样对文件进行操作，而不是用传统的读写文件的方式。

  ```c++
  void* mmap(void* start,size_t length,int prot,int flags,int fd,off_t offset);
  // 如果start=NULL，则系统会选择一个地址去创建映射,从文件fd偏移量为offset的位置开始映射，大小为length字节，
  ```

- iovec：**是 POSIX 标准定义的一个数据结构**，主要用于 `readv`（读取数据）和 `writev`（写入数据）这类散布/聚集输入输出（scatter/gather I/O）系统调用。散布/聚集I/O允许程序一次性从多个缓冲区读取数据到一个单独的系统调用中，或者一次性将数据从一个系统调用写入到多个缓冲区中。这减少了系统调用的次数，可以提高I/O操作的效率。

- va_list/va_start/vsnprintf/va_end(): va_list是一个用于**存储可变数量参数信息的类型**。它是处理可变参数的函数（如 `vsnprintf`）所必需的，因为它提供了一个指向当前参数的指针，这样就可以依次访问所有参数。

  ```c++
  #include <stdio.h>
  #include <stdarg.h>
  
  void format_string(char *buffer, size_t buffer_size, const char *format, ...) {
      //要定义一个可变参数函数，需要使用省略号 ...，并且至少有一个固定的参数在其前面，因为可变参数列表的开始位置是由最后一个固定参数决定的。处理这些可变参数时，通常会用到 stdarg.h 头文件中定义的一系列宏：
      va_list args;
      va_start(args, format);
      vsnprintf(buffer, buffer_size, format, args);
      va_end(args);
  }
  
  ```

  

- main(int argc, char *argv[])

遇到输入参数不确定的情况如何处理？

- 利用可变参数列表生成http响应报文：

```c++
函数：
bool add_response (const char *format, ...)//...表示一个可变参数列表，format则为可变参数列表之前的最后一个已知参数
{
	va_list arg_list;
	va_start(arg_list, format); //初始化arg_list，使其指向可变参数列表中的第一个参数（即format之后的那个参数）
	int len=vsnprintf(char *str, size_t size, const char *format, va_list arg_list);
    // str指向缓冲区
}

调用格式：
add_response("%s %d %s\r\n", "HTTP/1.1", status, title)
```



### 参考资料

《Linux高性能服务器编程》by 游双

Linux系统调用手册，打开方式：man xxx(具体调用名称)

