#pragma once

#include <asio.hpp>

#include "EHSN/Reference.h"

namespace EHSN {
	namespace net {

		using asio::ip::tcp;

		class IOContext
		{
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
} // namespace EHSN