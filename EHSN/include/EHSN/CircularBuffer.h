#pragma once

#include <vector>
#include <mutex>

namespace EHSN {
	class CircularBuffer
	{
	public:
		CircularBuffer() = delete;
		CircularBuffer(size_t size);
		CircularBuffer(const CircularBuffer&) = default;
		CircularBuffer(CircularBuffer&& other);
	public:
		void read(void* pData, size_t size);
		void write(const void* pData, size_t size);
		size_t nReadable() const;
		size_t nWritable() const;
	public:
		void moveReadOffset(size_t nAdd);
		void moveWriteOffset(size_t nAdd);
	private:
		std::mutex m_mtxRead;
		std::mutex m_mtxWrite;
		std::mutex m_mtxOffset;
		std::atomic<size_t> m_readOffset = 0;
		std::atomic<size_t> m_writeOffset = 0;
		std::vector<char> m_buffer;
		std::condition_variable m_condNotify;
	};
} // namespace EHSN