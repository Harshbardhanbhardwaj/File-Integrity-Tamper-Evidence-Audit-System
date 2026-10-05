// thread_pool.hpp - fixed-size worker pool (producer/consumer with condvars).
#pragma once
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <type_traits>
#include <vector>

namespace fia {

class ThreadPool {
public:
    explicit ThreadPool(unsigned n) {
        if (n == 0) n = 1;
        for (unsigned i = 0; i < n; ++i)
            workers_.emplace_back([this] { worker_loop(); });
    }
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;
    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stopping_ = true;
        }
        cv_work_.notify_all();
        for (auto& t : workers_) t.join();
    }

    template <class F>
    auto submit(F&& f) -> std::future<std::invoke_result_t<F>> {
        using R = std::invoke_result_t<F>;
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
        auto fut = task->get_future();
        {
            std::lock_guard<std::mutex> lk(mu_);
            queue_.push([task] { (*task)(); });
            ++outstanding_;
        }
        cv_work_.notify_one();
        return fut;
    }

    // Blocks until every submitted task has finished.
    void wait_idle() {
        std::unique_lock<std::mutex> lk(mu_);
        cv_idle_.wait(lk, [this] { return outstanding_ == 0; });
    }

    unsigned size() const { return static_cast<unsigned>(workers_.size()); }

private:
    void worker_loop() {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_work_.wait(lk, [this] { return stopping_ || !queue_.empty(); });
                if (queue_.empty()) return;          // stopping_ and drained
                job = std::move(queue_.front());
                queue_.pop();
            }
            job();
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (--outstanding_ == 0) cv_idle_.notify_all();
            }
        }
    }

    std::vector<std::thread>          workers_;
    std::queue<std::function<void()>> queue_;
    std::mutex                        mu_;
    std::condition_variable           cv_work_, cv_idle_;
    std::size_t                       outstanding_ = 0;
    bool                              stopping_ = false;
};

} // namespace fia
