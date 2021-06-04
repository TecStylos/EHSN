#pragma once

#include <thread>
#include <queue>
#include <vector>
#include <mutex>
#include <functional>
#include <condition_variable>
#include <atomic>

#include "Reference.h"

namespace EHSN {
	class ThreadPool
	{
		typedef std::function<void(void)> Job;
	public:
		ThreadPool() = delete;
		ThreadPool(uint32_t nThreads);
		~ThreadPool();
	public:
		void pushJob(Job job);
		void wait();
		uint32_t size() const;
		void clear();
	private:
		void threadFunc();
	private:
		std::mutex m_mtxWait;
		std::condition_variable m_condWait;
		std::mutex m_mtxJob;
		std::atomic_bool m_terminateThreads;
		std::condition_variable m_condJob;
		std::queue<Job> m_jobs;
		std::atomic_uint32_t m_runningJobs;
		std::vector<Ref<std::thread>> m_threads;
	};
}