#include "CircularBuffer.h"

namespace EHSN
{
	CircularBuffer::CircularBuffer(uint64_t size)
		: m_buffer(size)
	{}

	CircularBuffer::CircularBuffer(CircularBuffer&& other)
	{
		std::swap(m_readOffset, other.m_readOffset);
		std::swap(m_writeOffset, other.m_writeOffset);
		std::swap(m_buffer, other.m_buffer);
	}

	void CircularBuffer::read(void* pData, uint64_t size)
	{
		std::lock_guard<std::mutex> lock(m_mtxRead);
		{
			std::unique_lock<std::mutex> offLock(m_mtxOffset);
			m_condNotify.wait(offLock, [&]() { return nReadable() >= size; });

			uint64_t seqLength = m_buffer.size() - m_readOffset;
			if (seqLength < size)
			{
				memcpy(pData, m_buffer.data() + m_readOffset, seqLength);
				pData = (char*)pData + seqLength;
				moveOffset(m_readOffset, seqLength);
				seqLength = size - seqLength;
			}
			else
			{
				seqLength = size;
			}
			memcpy(pData, m_buffer.data() + m_readOffset, seqLength);
			moveOffset(m_readOffset, size);
		}

		m_condNotify.notify_all();
	}

	void CircularBuffer::write(const void* pData, uint64_t size)
	{
		std::lock_guard<std::mutex> lock(m_mtxWrite);
		{
			std::unique_lock<std::mutex> offLock(m_mtxOffset);
			m_condNotify.wait(offLock, [&]() { return nWritable() >= size; });

			uint64_t seqLength = m_buffer.size() - m_readOffset;
			if (seqLength < size)
			{
				memcpy(m_buffer.data() + m_readOffset, pData, seqLength);
				pData = (char*)pData + seqLength;
				moveOffset(m_readOffset, seqLength);
				seqLength = size - seqLength;
			}
			else
			{
				seqLength = size;
			}
			memcpy(m_buffer.data() + m_readOffset, pData, seqLength);
			moveOffset(m_readOffset, size);
		}

		m_condNotify.notify_all();
	}

	uint64_t CircularBuffer::nReadable() const
	{
		if (m_readOffset < m_writeOffset)
			return m_writeOffset - m_readOffset;
		return m_buffer.size() - (m_readOffset - m_writeOffset);
	}
	
	uint64_t CircularBuffer::nWritable() const
	{
		return m_buffer.size() - nReadable();
	}

	void CircularBuffer::moveOffset(std::atomic<uint64_t>& toMove, uint64_t nAdd)
	{
		toMove = (toMove + nAdd) % m_buffer.size();
	}
}