#ifndef IOCONTEXT_H
#define IOCONTEXT_H

#include <asio.hpp>

#include "EHSN/Reference.h"

namespace net {

	using asio::ip::tcp;

	class IOContext {
	public:
		/*
		* Get the io_context
		*
		* @returns io_context
		*/
		static asio::io_context& get() { return s_singleton.m_ioContext; }
	private:
		IOContext() = default;
		~IOContext() = default;
		asio::io_context m_ioContext;
	private:
		static IOContext s_singleton;
	};

} // namespace net

#endif // IOCONTEXT_H