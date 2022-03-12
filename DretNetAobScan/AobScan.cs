using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DretNetAobScan {
    public class AobScan : Helper {
        public AobScan(int id, byte[] pattern, byte[] buffer) {
            __process_id = id;
            __pattern = pattern;
            __buffer = buffer;
        }

        public void ReadMemory() {
            for (long i = 0x0; i < 0xFFFFFFFF;) {
                MEMORY_BASIC_INFORMATION mem_info = new MEMORY_BASIC_INFORMATION();
                if (VirtualQueryEx(GetProcess().Handle, new IntPtr(i), out mem_info, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) == 0) break;
                if ((mem_info.State & (uint)MEM_COMMIT) != 0 && (mem_info.Protect & (uint)PAGE_GUARD) != PAGE_GUARD) {
                    byte[] __read_buffer = new byte[mem_info.RegionSize];
                    uint __buffer_value = 0;
                    if (ReadProcessMemory(GetProcess().Handle, new IntPtr(mem_info.BaseAddress), __read_buffer, (uint)__read_buffer.Length, out __buffer_value) && __buffer_value > 0) {
                        int offset = __pattern_scan(__read_buffer, __pattern);
                        if (offset != -1) __addresses.Add(new IntPtr(mem_info.BaseAddress + offset));
                    }
                }
                i = mem_info.BaseAddress + mem_info.RegionSize;
            }
        }

        public void WriteMemory() {
            for (int i = 0; i < __addresses.Count(); i++) {
                uint __buffer_value = 0;
                WriteProcessMemory(GetProcess().Handle, __addresses[i], __buffer, (uint)__buffer.Length, __buffer_value);
            }
        }
    }
}
