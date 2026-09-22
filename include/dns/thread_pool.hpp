#pragma once

#include <condition_variable>
#include <cstddef>
#include <functional>
#include <mutex>
#include <queue>
#include <stop_token>
#include <thread>
#include <vector>

namespace dns
{

class ThreadPool
{
  public:
    explicit ThreadPool(std::size_t worker_count);

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    ThreadPool(ThreadPool&&) = delete;
    ThreadPool& operator=(ThreadPool&&) = delete;

    ~ThreadPool();

    void submit(std::function<void()> job);

  private:
    void worker_loop(std::stop_token stop_token);

    std::vector<std::jthread> workers_;
    std::queue<std::function<void()>> jobs_;

    std::mutex mutex_;
    std::condition_variable_any job_available_;

    bool accepting_jobs_{true};
};

} // namespace dns
