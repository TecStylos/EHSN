#pragma once

#include <memory>

namespace EHSN {
	template <typename T>
	using Ref = std::shared_ptr<T>;
}