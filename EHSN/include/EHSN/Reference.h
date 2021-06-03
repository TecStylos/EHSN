#ifndef REFERENCE_H
#define REFERENCE_H

#include <memory>

namespace EHSN {
	template <typename T>
	using Ref = std::shared_ptr<T>;
}

#endif // REFERENCE_H