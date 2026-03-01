#pragma once
#include <windows.h>
#include <cstdint>
#include <iterator>
#include <string>

struct StackFrame
{
    uintptr_t rip             = 0;
    uintptr_t rsp             = 0;
    uintptr_t module_base     = 0;
    uintptr_t function_offset = 0;
    wchar_t     module_name[32];
    wchar_t    function_name[32];

    [[nodiscard]] bool valid() const noexcept
    {
        return rip != 0 && rip != static_cast<uintptr_t>(-1);
    }
};

// Implemented in StackUnwindIterator.cpp
void             resolve_symbols(StackFrame& f) noexcept;
[[nodiscard]] bool unwind_step(StackFrame& f)   noexcept;

class StackUnwindIterator
{
public:
    using iterator_category = std::input_iterator_tag;
    using value_type        = StackFrame;
    using difference_type   = std::ptrdiff_t;
    using pointer           = const StackFrame*;
    using reference         = const StackFrame&;

    StackUnwindIterator() noexcept = default;

    explicit StackUnwindIterator(uintptr_t rip, uintptr_t rsp) noexcept
        : done_(rip == 0 || rip == static_cast<uintptr_t>(-1))
    {
        frame_.rip = rip;
        frame_.rsp = rsp;
        if (!done_)
            resolve_symbols(frame_);
    }

    [[nodiscard]] reference operator*()  const noexcept { return frame_;  }
    [[nodiscard]] pointer   operator->() const noexcept { return &frame_; }

    StackUnwindIterator& operator++() noexcept
    {
        if (!done_)
            done_ = !unwind_step(frame_);
        return *this;
    }

    StackUnwindIterator operator++(int) noexcept
    {
        auto tmp = *this;
        ++(*this);
        return tmp;
    }

   
    [[nodiscard]] bool operator==(const StackUnwindIterator& rhs) const noexcept
    {
        if (done_ != rhs.done_) return false;
        if (done_)              return true;  
        return frame_.rip == rhs.frame_.rip &&
               frame_.rsp == rhs.frame_.rsp;
    }

private:
    StackFrame frame_{};
    bool       done_ = true;
};

struct StackUnwindRange
{
    uintptr_t start_rip;
    uintptr_t start_rsp;

    [[nodiscard]] StackUnwindIterator begin() const noexcept
    {
        return StackUnwindIterator{ start_rip, start_rsp };
    }

    [[nodiscard]] static StackUnwindIterator end() noexcept
    {
        return StackUnwindIterator{};
    }
};

static_assert(std::input_iterator<StackUnwindIterator>);