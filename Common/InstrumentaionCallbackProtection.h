#pragma once
#include "structres.h"
#include "Windows.h"

class InstrumentaionCallbackProtection
{
public:
    InstrumentaionCallbackProtection() noexcept  {
		 _TEB64* teb = reinterpret_cast<_TEB64*>(NtCurrentTeb());
        revert = teb->InstrumentationCallbackDisabled != true;
        teb->InstrumentationCallbackDisabled = true;

	}
    ~InstrumentaionCallbackProtection() noexcept {
        if (revert) {
          _TEB64* teb = reinterpret_cast<_TEB64*>(NtCurrentTeb());
          teb->InstrumentationCallbackDisabled = false;
        }
    }
    InstrumentaionCallbackProtection(InstrumentaionCallbackProtection&& other) = delete;
    InstrumentaionCallbackProtection& operator=(InstrumentaionCallbackProtection&& other) = delete;
    InstrumentaionCallbackProtection(const InstrumentaionCallbackProtection&)            = delete;
    InstrumentaionCallbackProtection& operator=(const InstrumentaionCallbackProtection&) = delete;

private: 
    bool revert = false;
};
