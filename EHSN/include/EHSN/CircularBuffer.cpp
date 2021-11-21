#include "CircularBuffer.h"

namespace EHSN
{
	CircularBuffer::CircularBuffer(size_t size)
		: m_buffer(size)
	{}

	CircularBuffer::CircularBuffer(CircularBuffer&& other)
	{
		m_readOffset = other.m_readOffset.load();
		m_writeOffset = other.m_writeOffset.load();
		m_buffer = other.m_buffer;
	}

	void CircularBuffer::read(void* pData, size_t size)
	{
		std::lock_guard<std::mutex> lock(m_mtxRead);
		{
			std::unique_lock<std::mutex> offLock(m_mtxOffset);
			m_condNotify.wait(offLock, [&]() { return nReadable() >= size; });

			size_t seqLength = m_buffer.size() - m_readOffset;
			if (seqLength < size)
			{
				memcpy(pData, m_buffer.data() + m_readOffset, seqLength);
				pData = (char*)pData + seqLength;
				moveReadOffset(seqLength);
				seqLength = size - seqLength;
			}
			else
			{
				seqLength = size;
			}
			memcpy(pData, m_buffer.data() + m_readOffset, seqLength);
			moveReadOffset(seqLength);
		}

		m_condNotify.notify_all();
	}

	void CircularBuffer::write(const void* pData, size_t size)
	{
		std::lock_guard<std::mutex> lock(m_mtxWrite);
		{
			std::unique_lock<std::mutex> offLock(m_mtxOffset);
			m_condNotify.wait(offLock, [&]() { return nWritable() >= size; });

			size_t seqLength = m_buffer.size() - m_writeOffset;
			if (seqLength < size)
			{
				memcpy(m_buffer.data() + m_writeOffset, pData, seqLength);
				pData = (char*)pData + seqLength;
				moveWriteOffset(seqLength);
				seqLength = size - seqLength;
			}
			else
			{
				seqLength = size;
			}
			memcpy(m_buffer.data() + m_writeOffset, pData, seqLength);
			moveWriteOffset(size);
		}

		m_condNotify.notify_all();
	}

	size_t CircularBuffer::nReadable() const
	{
		if (m_readOffset <= m_writeOffset)
			return m_writeOffset - m_readOffset;
		return m_buffer.size() - (m_readOffset - m_writeOffset);
	}
	
	size_t CircularBuffer::nWritable() const
	{
		return m_buffer.size() - nReadable();
	}

	void CircularBuffer::moveReadOffset(size_t nAdd)
	{
		m_readOffset = (m_readOffset + nAdd) % m_buffer.size();
	}

	void CircularBuffer::moveWriteOffset(size_t nAdd)
	{
		m_writeOffset = (m_writeOffset + nAdd) % m_buffer.size();
	}
}