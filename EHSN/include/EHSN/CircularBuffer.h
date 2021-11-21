#pragma once

#include <vector>
#include <mutex>

namespace EHSN {
	class CircularBuffer
	{
	public:
		CircularBuffer() = delete;
		CircularBuffer(uint64_t size);
		CircularBuffer(const CircularBuffer&) = default;
		CircularBuffer(CircularBuffer&& other);
	public:
		void read(void* pData, uint64_t size);
		void write(const void* pData, uint64_t size);
		uint64_t nReadable() const;
		uint64_t nWritable() const;
	private:
		void moveOffset(std::atomic<uint64_t>& toMove, uint64_t nAdd);
	private:
		std::mutex m_mtxRead;
		std::mutex m_mtxWrite;
		std::mutex m_mtxOffset;
		std::atomic<uint64_t> m_readOffset = 0;
		std::atomic<uint64_t> m_writeOffset = 0;
		std::vector<char> m_buffer;
		std::condition_variable m_condNotify;
	};
} // namespace EHSN