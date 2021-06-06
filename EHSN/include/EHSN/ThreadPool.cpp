#include "ThreadPool.h"

namespace EHSN {
	ThreadPool::ThreadPool(uint32_t nThreads)
		: m_threads(nThreads), m_terminateThreads(false), m_runningJobs(0), m_nJobsDone(0), m_nextJobNum(1)
	{
		for (auto& t : m_threads)
			t = std::make_shared<std::thread>(&ThreadPool::threadFunc, this);
	}

	ThreadPool::~ThreadPool()
	{
		m_terminateThreads = true;
		m_condJob.notify_all();

		for (auto& t : m_threads)
			t->join();
	}

	uint64_t ThreadPool::pushJob(Job job)
	{
		{
			std::unique_lock<std::mutex> lock(m_mtxJob);
			m_jobs.push(job);
		}
		m_condJob.notify_one();
		return m_nextJobNum++;
	}

	void ThreadPool::wait()
	{
		std::unique_lock<std::mutex> lock(m_mtxWait);
		m_condWait.wait(lock,
			[this]()
			{
				return m_jobs.empty() && (m_runningJobs == 0);
			}
		);
	}

	void ThreadPool::wait(uint64_t jobNum)
	{
		std::unique_lock<std::mutex> lock(m_mtxWait);
		m_condWait.wait(lock,
			[this, jobNum]()
			{
				return m_nJobsDone >= jobNum;
			}
		);
	}

	uint32_t ThreadPool::size() const
	{
		return (uint32_t)m_threads.size();
	}

	void ThreadPool::clear()
	{
		std::unique_lock<std::mutex> lock(m_mtxJob);
		while (!m_jobs.empty())
			m_jobs.pop();
	}

	void ThreadPool::threadFunc()
	{
		while (!m_terminateThreads)
		{
			Job job = nullptr;
			{
				std::unique_lock<std::mutex> lock(m_mtxJob);
				if (m_jobs.empty())
				{
					m_condJob.wait(lock,
						[this]()
						{
							return !m_jobs.empty() || m_terminateThreads;
						}
					);
				}

				if (!m_jobs.empty())
				{
					job = m_jobs.front();
					m_jobs.pop();
				}
			}

			if (job != nullptr)
			{
				++m_runningJobs;

				try
				{
					job();
				}
				catch (...)
				{
					;
				}

				--m_runningJobs;
				++m_nJobsDone;

				m_condWait.notify_one();
			}
		}
	}
}