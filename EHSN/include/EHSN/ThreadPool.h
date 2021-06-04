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
		/*
		* Constructor of ThreadPool.
		* 
		* @param nThreads Number of threads to be created.
		*/
		ThreadPool(uint32_t nThreads);
		/*
		* Destructor of ThreadPool.
		* 
		* Waits for all threads to finish their jobs.
		*/
		~ThreadPool();
	public:
		void pushJob(Job job);
		/*
		* Wait until the job queue is empty and all threads are idle.
		*/
		void wait();
		/*
		* Get number of threads in the pool.
		* 
		* @returns Number of threads in the pool.
		*/
		uint32_t size() const;
		/*
		* Clears the job queue.
		*/
		void clear();
	private:
		/*
		* Main function for the threads.
		*/
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