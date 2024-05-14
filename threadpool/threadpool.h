#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <list>
#include <cstdio>
#include <exception>
#include <pthread.h>
#include "../lock/locker.h"
#include "../CGImysql/sql_connection_pool.h"
#include "../SSL_thread/SSL_test.hpp"

template <typename T>
class threadpool
{
public:
    /*thread_number是线程池中线程的数量，max_requests是请求队列中最多允许的、等待处理的请求的数量*/
    threadpool(int actor_model, connection_pool *connPool, int thread_number = 8, int max_request = 10000);
    ~threadpool();
    bool append(T *request, int state);
    bool append_p(T *request);

private:
    /*工作线程运行的函数，它不断从工作队列中取出任务并执行之*/
    static void *worker(void *arg);
    void run();

private:
    int m_thread_number;        //线程池中的线程数
    int m_max_requests;         //请求队列中允许的最大请求数
    pthread_t *m_threads;       //描述线程池的数组，其大小为m_thread_number
    std::list<T *> m_workqueue; //请求队列
    locker m_queuelocker;       //保护请求队列的互斥锁
    sem m_queuestat;            //是否有任务需要处理
    connection_pool *m_connPool;  //数据库
    int m_actor_model;          //模型切换
};
template <typename T>
threadpool<T>::threadpool( int actor_model, connection_pool *connPool, int thread_number, int max_requests) : m_actor_model(actor_model),m_thread_number(thread_number), m_max_requests(max_requests), m_threads(NULL),m_connPool(connPool)
{
    if (thread_number <= 0 || max_requests <= 0)
        throw std::exception();
    m_threads = new pthread_t[m_thread_number];
    if (!m_threads)
        throw std::exception();
    for (int i = 0; i < thread_number; ++i)
    {
        //worker, 线程的启动函数, this：传递给线程的参数
        if (pthread_create(m_threads + i, NULL, worker, this) != 0)
        {
            delete[] m_threads;
            throw std::exception();
        }
        //执行线程分离, 不清楚干嘛用的
        if (pthread_detach(m_threads[i]))
        {
            delete[] m_threads;
            throw std::exception();
        }
    }
}
template <typename T>
threadpool<T>::~threadpool()
{
    delete[] m_threads;
}
//reactor模式向请求队列插入任务
template <typename T>
bool threadpool<T>::append(T *request, int state)
{
    m_queuelocker.lock();
    if (m_workqueue.size() >= m_max_requests)
    {
        m_queuelocker.unlock();
        return false;
    }
    request->m_state = state;
    m_workqueue.push_back(request);
    m_queuelocker.unlock();
    m_queuestat.post();
    return true;
}
//practor模式向请求队列插入任务
template <typename T>
bool threadpool<T>::append_p(T *request)
{
    m_queuelocker.lock();
    if (m_workqueue.size() >= m_max_requests)
    {
        m_queuelocker.unlock();
        return false;
    }
    m_workqueue.push_back(request);
    m_queuelocker.unlock();
    m_queuestat.post();
    return true;
}

// worker函数的工作：
template <typename T>
void *threadpool<T>::worker(void *arg)
{
    threadpool *pool = (threadpool *)arg;
    pool->run();
    return pool;
}
template <typename T>
void threadpool<T>::run()
{
    while (true)
    {
        m_queuestat.wait();
        m_queuelocker.lock();
        if (m_workqueue.empty())
        {
            m_queuelocker.unlock();
            continue;
        }
        T *request = m_workqueue.front();
        m_workqueue.pop_front();
        m_queuelocker.unlock();
        if (!request)
            continue;
        if (1 == m_actor_model)
        {
            //如果是读事件
            if (0 == request->m_state)
            {
                //如果是ssl连接未完成触发的读事件
                if (request->get_connection_status()==SSL_CHANNEL_WANT_READ)
                {
                    request->improv = 1;
                    //std::cout<<"deal with the read event during the ssl handshake"<<std::endl;
                    request->m_ssl_handshake();
                }
                //如果是ssl关闭连接未完成触发的读事件
                else if (request->get_connection_status()==SSL_CHANNEL_SHUTDOWN_WANT_READ)
                {
                    request->improv = 1;
                    //std::cout<<"deal with the read event during the ssl shutdown"<<std::endl;
                    request->close_conn();
                }
                //正常读数据
                else if (request->read_once())
                {
                    request->improv = 1;
                    connectionRAII mysqlcon(&request->mysql, m_connPool);
                    request->process();
                }
                // 如果没有读到数据
                else
                {
                    request->improv = 1;
                    request->timer_flag = 1;
                }
            }
            //如果是写事件
            else
            {
                //如果是ssl连接未完成触发的写事件
                if (request->get_connection_status()==SSL_CHANNEL_WANT_WRITE)
                {
                    request->improv = 1;
                    //std::cout<<"deal with the write event during the ssl handshake"<<std::endl;
                    request->m_ssl_handshake();
                }
                //如果是ssl关闭连接未完成触发的写事件
                else if (request->get_connection_status()==SSL_CHANNEL_SHUTDOWN_WANT_WRITE)
                {
                    request->improv = 1;
                    //std::cout<<"deal with the read event during the ssl shutdown"<<std::endl;
                    request->close_conn();
                }
                else if (request->write())
                {
                    request->improv = 1;
                }
                else
                {
                    request->improv = 1;
                    request->timer_flag = 1;
                }
            }
        }
        else
        {
            connectionRAII mysqlcon(&request->mysql, m_connPool);
            request->process();
        }
    }
}
#endif
