#include "dns/thread_pool.hpp"

#include <cstddef>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <stop_token>
#include <utility>

namespace dns
{
ThreadPool::ThreadPool(std::size_t worker_count)
{
    if (worker_count == 0)
    {
        throw std::invalid_argument("thread_pool must have at least one worker");
    }

    workers_.reserve(worker_count);

    for (std::size_t index{}; index < worker_count; index++)
    {
        workers_.emplace_back([this](const std::stop_token& stop_token)
                              { worker_loop(stop_token); });
    }
}

ThreadPool::~ThreadPool() // destructor
{
    {
        std::lock_guard<std::mutex> lock{mutex_};
        accepting_jobs_ = false;
    } // unlock of mutex happens here

    job_available_.notify_all();
}

void ThreadPool::submit(std::function<void()> job)
{
    if (!job)
    {
        throw std::invalid_argument{"cannot submit an empty job"};
    }

    { // lock queue
        std::lock_guard<std::mutex> lock{mutex_};

        if (!accepting_jobs_) // check if pool is still running
        {
            throw std::runtime_error{"thread pool not accepting errors"};
        }

        jobs_.push(std::move(job)); // push job onto queue
    } // unlock queue

    job_available_.notify_one(); // wake up worker thread
}

void ThreadPool::worker_loop(std::stop_token stop_token)
{
    // wait until there is a job
    // take one job from queue
    // unlock queue
    // run job
    // repeat
    while (!stop_token.stop_requested())
    {

        std::function<void()> job; // declare to run

        {
            std::unique_lock<std::mutex> lock{mutex_};
            // wait until there is a job
            job_available_.wait(lock, stop_token,
                                [this] { return !jobs_.empty() || !accepting_jobs_; });

            if (jobs_.empty())
            {
                return;
            }

            job = std::move(jobs_.front());
            jobs_.pop();
        }

        try // run the job
        {
            job();
        }
        catch (const std::exception& error)
        {
            std::cerr << "Thread Pool job failed: " << error.what() << "\n";
        }
        catch (...)
        {
            std::cerr << "ThreadPool job failed with unknown exception" << "\n";
        }
    }
}
} // namespace dns
