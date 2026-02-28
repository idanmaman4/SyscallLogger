#pragma once

namespace debugging_utils {


#ifndef _DEBUG
	static constexpr bool is_debug = false;
#else
	static constexpr bool is_debug = true;
#endif
}