#include "StackUnwindIterator.hpp"
#include "Module.hpp"
#include "ModuleIterator.hpp"
#include "structres.h"
#include "debug_utils.hpp"

static bool do_unwind(uintptr_t module_start,
                      uintptr_t module_end,
                      RUNTIME_FUNCTION* rf,
                      uintptr_t&        rsp,
                      uintptr_t&        rip) noexcept
{
    if (!rf)
        return false;

    __try {
        if((module_start + rf->UnwindData) >= module_end) return false;
        const auto* ui = reinterpret_cast<const UnwindInfo*>(module_start + rf->UnwindData);
        for (;;) {
            UINT i = 0;
            while (i < ui->code_cnt) {
                const UnwindCode* uc = &ui->codes[i];
                switch (static_cast<UwOp>(uc->op)) {

                    case UwOp::PushNonvol:
                        rsp += 8;
                        i   += 1;
                        break;

                    case UwOp::AllocSmall:
                        rsp += static_cast<uintptr_t>(uc->op_info) * 8 + 8;
                        i   += 1;
                        break;

                    case UwOp::AllocLarge:
                        if (uc->op_info == 0) {
                            rsp += static_cast<uintptr_t>(
                                reinterpret_cast<const USHORT*>(&ui->codes[i + 1])[0]) * 8;
                            i += 2;
                        } else {
                            rsp += *reinterpret_cast<const ULONG*>(&ui->codes[i + 1]);
                            i   += 3;
                        }
                        break;

                    case UwOp::PushMachframe:
                        rsp += uc->op_info ? k_machframe_err : k_machframe;
                        i   += 1;
                        break;

                    case UwOp::SetFpReg:
                        i += 1;
                        break;

                    case UwOp::SaveNonvol:
                    case UwOp::SaveXmm128:
                        i += 2;
                        break;

                    case UwOp::SaveNonvolFar:
                    case UwOp::SaveXmm128Far:
                        i += 3;
                        break;

                    default:
                        i += 1;
                        break;
                }
            }

            if (!(ui->flags & k_chain_flag))
                break;

            const UINT  aligned = (ui->code_cnt + 1) & ~1u;
            const auto* chain   = reinterpret_cast<const RUNTIME_FUNCTION*>(&ui->codes[aligned]);
            ui = reinterpret_cast<const UnwindInfo*>(module_start + chain->UnwindData);
        }

        rip  = *reinterpret_cast<const uintptr_t*>(rsp);
        rsp += 8;

        return rip != 0 && rip != static_cast<uintptr_t>(-1);
    }
    __except(EXCEPTION_EXECUTE_HANDLER){
        return false;
    }
}


void resolve_symbols(StackFrame& f) noexcept
{
    std::optional<Module> mod = Module::createModule(f.rip);

    if (!mod.has_value()) {
        f.module_base     = 0;
        f.function_offset = 0;
        return;
    }

    f.module_base     = mod.value().m_start;

    RUNTIME_FUNCTION * rf = mod.value().lookup_rf(f.rip);
    if (rf) {
        f.function_offset = rf->BeginAddress;
    }

    if (debugging_utils::is_debug) {
        if (f.function_offset) {
            auto narrow = mod.value().find_export(f.module_base + f.function_offset).value_or("?");
            f.function_name = std::wstring(narrow.begin(), narrow.end());
        }
        auto* us = mod.value().module_name();
        if (us && us->Buffer && us->Length > 0)
            f.module_name = std::wstring(us->Buffer, us->Length / sizeof(WCHAR));
    }
 }


bool unwind_step(StackFrame& f) noexcept
{
    try {
        std::optional<Module> mod = Module::createModule(f.rip);

        if (mod.has_value()) {
            RUNTIME_FUNCTION* rf = mod.value().lookup_rf(f.rip);

            if (rf) {
                uintptr_t new_rsp = f.rsp;
                uintptr_t new_rip = 0;

                if (!do_unwind(mod.value().m_start, mod.value().end(), rf, new_rsp, new_rip))
                    return false;

                f     = StackFrame{};
                f.rip = new_rip;
                f.rsp = new_rsp;
                resolve_symbols(f);
                return f.valid();
            }
        }

        uintptr_t new_rip = *reinterpret_cast<const uintptr_t*>(f.rsp);
        uintptr_t new_rsp = f.rsp + 8;

        f     = StackFrame{};
        f.rip = new_rip;
        f.rsp = new_rsp;
        resolve_symbols(f);
        return f.valid();
    }
    catch (...) {
        return false;
    }
}