CXX ?= g++
# 默认编译器为g++
# 可通过make CXX=clang++来修改

DEBUG ?= 1
# DEBUG模式，=1为默认的调试模式，生成的可执行文件中会包含许多调试信息
# !=1则设置为-02,启用优化级别2,这是编译器提供的一种中等程度的优化，尝试各种优化技术改进程序性能。
# 可通过make DEBUG=0修改
ifeq ($(DEBUG), 1)
    CXXFLAGS += -g
else
    CXXFLAGS += -O2

endif

server: main.cpp  ./timer/lst_timer.cpp ./http/http_conn.cpp ./log/log.cpp ./CGImysql/sql_connection_pool.cpp  webserver.cpp config.cpp ./SSL_thread/SSL_test.cpp
	$(CXX) -o server  $^ $(CXXFLAGS) -lpthread -lmysqlclient -lssl -lcrypto

# -lssl: 链接libssl库，提供SSL/TLS协议的实现
# -lcrypto: 链接libcrypto库，提供了广泛的加密算法如RSA等，libssl依赖lcrypto

clean:
	rm  -r server
