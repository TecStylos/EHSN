#pragma once

#include <vector>

namespace EHSN {
	template<typename T>
	class CircularBuffer
	{
	public:
		CircularBuffer() = delete;
		CircularBuffer(uint64_t size)
			: m_buffer(size)
		{}
	public:
		void push(T& obj) { m_buffer[increaseOffset()] = obj; }
		T& get(uint64_t index) { return m_buffer[virtualToRealIndex(index)]; }
		const T& get(uint64_t index) const { return m_buffer[virtualToRealIndex(index)]; }
		T& operator[](uint64_t index) { return get(index); }
		const T& operator[](uint64_t index) const { return get(index); }
		uint64_t size() const { return m_buffer.size(); }
	private:
		uint64_t increaseOffset() { return ++offset % m_buffer.size(); }
		uint64_t virtualToRealIndex(uint64_t virtualIndex) const { return (offset + virtualIndex) % m_buffer.size(); }
	private:
		uint64_t offset;
		std::vector<T> m_buffer;
	};
} // namespace EHSN