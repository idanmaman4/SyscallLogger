include ksamd64.inc

extern InstrumentationCallback:proc

EXTERNDEF __imp_RtlCaptureContext:QWORD

.code

InstrumentationCallbackThunk proc
				mov     gs:[2e0h], rsp            ; Win10 TEB InstrumentationCallbackPreviousSp
				mov     gs:[2d8h], r10            ; Win10 TEB InstrumentationCallbackPreviousPc
				mov     r10, rcx                 
				sub     rsp, 4d0h                 
				and     rsp, -10h                
				mov     rcx, rsp
				call    __imp_RtlCaptureContext  
				sub     rsp, 20h                  
				call    InstrumentationCallback
				int     3
InstrumentationCallbackThunk endp

end 