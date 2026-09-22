#include "dns/thread_pool.hpp"

#include <gtest/gtest.h>

#include <condition_variable>
#include <mutex>
#include <stdexcept>

namespace dns
{
namespace
{

TEST(ThreadPoolTest, ConstructorRejectsZeroWorkers)
{
    EXPECT_THROW(ThreadPool{0}, std::invalid_argument);
}

TEST(ThreadPoolTest, RunsSubmittedJob)
{
    ThreadPool pool{1};

    std::mutex mutex;
    std::condition_variable done;
    bool ran{false};

    pool.submit(
        [&]
        {
            {
                std::lock_guard<std::mutex> lock{mutex};
                ran = true;
            }

            done.notify_one();
        });

    std::unique_lock<std::mutex> lock{mutex};

    EXPECT_TRUE(done.wait_for(lock, std::chrono::seconds{1}, [&] { return ran; }));
}

TEST(ThreadPoolTest, RejectsEmptyJob)
{
    ThreadPool pool{1};

    std::function<void()> empty_job{};

    EXPECT_THROW(pool.submit(empty_job), std::invalid_argument);
}

} // namespace
} // namespace dns
