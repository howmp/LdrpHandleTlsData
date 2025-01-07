const std = @import("std");
const windows = std.os.windows;
const win32 = @import("struct.zig");
pub extern "kernel32" fn GetModuleHandleA(
    lpModuleName: ?windows.LPCSTR,
) callconv(windows.WINAPI) ?windows.PVOID;

pub fn main() u8 {
    trymain() catch |err| {
        return @truncate(@intFromError(err));
    };
    return 0;
}
fn trymain() !void {
    // LdrpHandleTlsData
    const writer = std.io.getStdOut().writer();
    const ntdll = GetModuleHandleA("ntdll.dll") orelse return error.DllNotFound;
    std.log.info("ntdll: {x}\n", .{@intFromPtr(ntdll)});
    const dos: *win32.IMAGE_DOS_HEADER = @ptrCast(@alignCast(ntdll));
    const nt: *win32.IMAGE_NT_HEADERS = @ptrFromInt(@intFromPtr(ntdll) + @as(usize, @as(u32, @bitCast(dos.e_lfanew))));
    const memory = @as([*c]u8, @ptrCast(ntdll))[nt.OptionalHeader.BaseOfCode..nt.OptionalHeader.SizeOfImage];
    // 先找到LdrpHandleTlsData字符串
    const strpos = std.mem.indexOfPosLinear(u8, memory, 0, "LdrpHandleTlsData") orelse return error.StrNotFound;
    const strptr = @intFromPtr(memory.ptr) + strpos;
    std.log.info("strptr: {x}\n", .{strptr});

    if (@sizeOf(usize) == 4) {
        // 32位定位流程
        const strRefPos = std.mem.indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&strptr)) orelse return error.ExceptFnNotFound;
        // 字符串被引用于异常处理函数中，定位其引用的指令
        // .text:7DEF201C                         loc_7DEF201C:                           ; DATA XREF: .text:stru_7DE9C120↑o
        // .text:7DEF201C                         ;   __except filter // owned by 7DEE2F75
        // .text:7DEF201C 8B 45 EC                mov     eax, [ebp+ms_exc.exc_ptr]
        // .text:7DEF201F 8B 08                   mov     ecx, [eax]
        // .text:7DEF2021 8B 09                   mov     ecx, [ecx]
        // .text:7DEF2023 89 4D BC                mov     [ebp+var_44], ecx
        // .text:7DEF2026 68 58 48 E9 7D          push    offset aLdrphandletlsd ; "LdrpHandleTlsData" <-------------
        // .text:7DEF202B 50                      push    eax
        // .text:7DEF202C E8 89 F8 01 00          call    _LdrpGenericExceptionFilter@8 ; LdrpGenericExceptionFilter(x,x)
        // .text:7DEF2031 C3                      retn

        // 在定位ms_exc.exc_ptr的偏移量0xEC,以及下一条mov指令0x8B
        const exceptfnkey = [2]u8{ 0xEC, 0x8B };
        const instPos = std.mem.lastIndexOfLinear(u8, memory[0..strRefPos], &exceptfnkey) orelse return error.ExceptFnNotFound;

        const exceptfnptr = @intFromPtr(memory.ptr) + instPos - 2;
        std.log.info("exceptfnptr: {x}\n", .{exceptfnptr});

        // 异常处理函数被引用在_EH4_SCOPETABLE结构的FilterFunc中
        // struct _EH4_SCOPETABLE {
        //         DWORD GSCookieOffset;
        //         DWORD GSCookieXOROffset;
        //         DWORD EHCookieOffset;
        //         DWORD EHCookieXOROffset;
        //         _EH4_SCOPETABLE_RECORD ScopeRecord[1];
        // };

        // struct _EH4_SCOPETABLE_RECORD {
        //         DWORD EnclosingLevel;
        //         long (*FilterFunc)();
        //             union {
        //             void (*HandlerAddress)();
        //             void (*FinallyFunc)();
        //     };
        // };
        // .text:7DE9C120 FE FF FF FF 00 00 00 00 88 FF FF FF 00 00 00 00 stru_7DE9C120   _EH4_SCOPETABLE <0FFFFFFFEh, 0, 0FFFFFF88h, 0, <0FFFFFFFEh, \
        // .text:7DE9C120 FE FF FF FF                                                                             ; DATA XREF: LdrpHandleTlsData(x)+2↓o
        // .text:7DE9C120 1C 20 EF 7D 32 20 EF 7D                                                          offset loc_7DEF201C, offset loc_7DEF2032>>
        const eh4key = struct {
            ehcookieOffset: u32 align(4),
            enclosingLevel: u32 align(4),
            filterFunc: usize align(4),
        }{
            .ehcookieOffset = 0,
            .enclosingLevel = 0xFFFFFFFE,
            .filterFunc = exceptfnptr,
        };

        var eh4pos = std.mem.indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&eh4key)) orelse return error.EH4NotFound;
        eh4pos -= 12;
        const eh4ptr = @intFromPtr(memory.ptr) + eh4pos;
        std.log.info("eh4ptr: {x}\n", .{eh4ptr});

        // EH4_SCOPETABLE结构被引用于LdrpHandleTlsData
        // .text:7DEAFFDE                         _LdrpHandleTlsData@4 proc near
        // .text:7DEAFFDE                         ; __unwind { // __SEH_prolog4
        // .text:7DEAFFDE 6A 58                                   push    58h
        // .text:7DEAFFE0 68 20 C1 E9 7D                          push    offset stru_7DE9C120 <-----------

        var fnpos = std.mem.indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&eh4ptr)) orelse return error.FnNotFound;
        fnpos -= 3;

        const LdrpHandleTlsData = @intFromPtr(memory.ptr) + fnpos;
        try std.fmt.formatInt(LdrpHandleTlsData, 16, .lower, .{}, writer);
    } else {
        // 64位定位流程
        // .text:0000000180166680                         LdrpHandleTlsData$filt$0:               ; DATA XREF: .rdata:00000001801A1CA8↓o
        // .text:0000000180166680                                                                 ; .pdata:00000001801E2DBC↓o
        // .text:0000000180166680                         ;   __except filter // owned by 18000B787
        // .text:0000000180166680 40 55                                   push    rbp
        // .text:0000000180166682 48 83 EC 30                             sub     rsp, 30h
        // .text:0000000180166686 48 8B EA                                mov     rbp, rdx
        // .text:0000000180166689 48 8D 15 C8 3A 03 00                    lea     rdx, aLdrphandletlsd ; "LdrpHandleTlsData"
        // .text:0000000180166690 E8 43 5F FF FF                          call    LdrpGenericExceptionFilter
        // .text:0000000180166695 90                                      nop
        // .text:0000000180166696 48 83 C4 30                             add     rsp, 30h
        // .text:000000018016669A 5D                                      pop     rbp
        // .text:000000018016669B C3                                      retn

        // 先找到LdrpHandleTlsData的引用
        const exceptfnkey1 = "\x48\x8D\x15";
        var pos: usize = 0;
        var value: i32 = undefined;
        while (true) {
            pos = std.mem.indexOfPosLinear(u8, memory, pos, exceptfnkey1) orelse return error.ExceptFnNotFound;
            value = @truncate(@as(isize, @bitCast(strptr -% (@intFromPtr(memory.ptr) + pos + 7))));
            if (@as(*align(1) i32, @alignCast(@ptrCast(&memory[pos + 3]))).* == value) {
                std.log.info("strRefaddr: {x}\n", .{@intFromPtr(memory.ptr) + pos});
                break;
            }
            pos += 7;
        }
        // 再定位push rbp
        const exceptfnkey2 = "\x40\x55";
        pos = std.mem.lastIndexOfLinear(u8, memory[0..pos], exceptfnkey2) orelse return error.ExceptFnNotFound;
        const exceptfnRVA: u32 = @truncate(@intFromPtr(memory.ptr) + pos - nt.OptionalHeader.ImageBase);
        std.log.info("exceptfnRVA: {x}\n", .{exceptfnRVA});

        // 定位UNWIND_INFO_HDR
        // .rdata:00000001801A1C84 19 2D 0B 00             stru_1801A1C84  UNWIND_INFO_HDR <1, 3, 2Dh, 0Bh, 0, 0>
        // .rdata:00000001801A1C84                                                                 ; DATA XREF: .pdata:00000001801D3930↓o
        // .rdata:00000001801A1C88 1B 64                                   UNWIND_CODE <1Bh, 4, 6> ; UWOP_SAVE_NONVOL
        // .rdata:00000001801A1C8A 28 00                                   dw 28h
        // .rdata:00000001801A1C8C 1B 34                                   UNWIND_CODE <1Bh, 4, 3> ; UWOP_SAVE_NONVOL
        // .rdata:00000001801A1C8E 27 00                                   dw 27h
        // .rdata:00000001801A1C90 1B 01                                   UNWIND_CODE <1Bh, 1, 0> ; UWOP_ALLOC_LARGE
        // .rdata:00000001801A1C92 20 00                                   dw 20h
        // .rdata:00000001801A1C94 14 F0                                   UNWIND_CODE <14h, 0, 15> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C96 12 E0                                   UNWIND_CODE <12h, 0, 14> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C98 10 D0                                   UNWIND_CODE <10h, 0, 13> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C9A 0E C0                                   UNWIND_CODE <0Eh, 0, 12> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C9C 0C 70                                   UNWIND_CODE <0Ch, 0, 7> ; UWOP_PUSH_NONVOL
        // .rdata:00000001801A1C9E 00 00                                   align 4
        // .rdata:00000001801A1CA0 B4 F2 15 00                             dd rva __GSHandlerCheck_SEH
        // .rdata:00000001801A1CA4 01 00 00 00                             dd 1
        // .rdata:00000001801A1CA8 87 B7 00 00 A9 B7 00 00                 C_SCOPE_TABLE <rva loc_18000B787, rva loc_18000B7A9, \
        // .rdata:00000001801A1CA8 80 66 16 00 A9 B7 00 00                                rva LdrpHandleTlsData$filt$0, rva loc_18000B7A9>

        // 先定位C_SCOPE_TABLE
        var cScopeTablePtr: usize = undefined;
        pos = 0;
        while (true) {
            // 这里可能有多处引用exceptfnVA，要确认是C_SCOPE_TABLE结构
            pos = std.mem.indexOfPosLinear(u8, memory, pos, std.mem.asBytes(&exceptfnRVA)) orelse return error.CScopeTableNotFound;
            if (@as(*u32, @alignCast(@ptrCast(&memory[pos - 12]))).* == 1) {
                // -12的位置是C_SCOPE_TABLE结构的个数，目前观测到是1
                cScopeTablePtr = @intFromPtr(memory.ptr) + pos - 8;
                break;
            }
            pos += 4;
        }
        std.log.info("cScopeTable: {x}\n", .{cScopeTablePtr});

        // 再定位UNWIND_INFO_HDR
        // -16是假设至少有一个或两个UNWIND_INFO
        var maybeUnwindHdrPtr: [*c]u32 = @ptrFromInt(cScopeTablePtr - 16);
        var wantCount: u8 = 2;
        const lastUnwindInfoPtr: *u16 = @ptrFromInt(cScopeTablePtr - 10);
        if (lastUnwindInfoPtr.* == 0) {
            // UNWIND_INFO有对齐填充
            wantCount = 1;
        }

        while (true) {
            const hdr: win32.UNWIND_INFO_HDR = @bitCast(maybeUnwindHdrPtr.*);
            if (hdr.Version == 1 and hdr.CntUnwindCodes == wantCount) {
                break;
            }
            maybeUnwindHdrPtr -= 1;
            wantCount += 2;
        }
        const hdrRVA: u32 = @truncate(@intFromPtr(maybeUnwindHdrPtr) - nt.OptionalHeader.ImageBase);
        std.log.info("unwindHdrRVA: {x}\n", .{hdrRVA});
        // 通过UNWIND_INFO_HDR找到RUNTIME_FUNCTION
        // .pdata:00000001801D3930 70 B5 00 00 B5 BB 00 00                 RUNTIME_FUNCTION <rva LdrpHandleTlsData, rva algn_18000BBB5, \
        // .pdata:00000001801D3930 84 1C 1A 00                                               rva stru_1801A1C84>

        pos = std.mem.indexOfPosLinear(u8, memory, 0, std.mem.asBytes(&hdrRVA)) orelse return error.RuntimeFunctionNotFound;
        const LdrpHandleTlsDataRVA = @as(*u32, @alignCast(@ptrCast(&memory[pos - 8]))).*;
        const LdrpHandleTlsData = LdrpHandleTlsDataRVA + nt.OptionalHeader.ImageBase;
        try std.fmt.formatInt(LdrpHandleTlsData, 16, .lower, .{}, writer);
    }
}
