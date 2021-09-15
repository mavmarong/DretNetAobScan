using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DretNetAobScan
{
    public class AobScan
    {
        #region Pinvokes
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, [Out] byte[] Buffer, UInt32 NumberOfBytesToRead, IntPtr NumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(Int32 processAccess, bool bInheritHandle, int processId);
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, IntPtr NumberOfBytesWritten);
        #endregion
        #region Variables
        int __process_id;
        byte[] __pattern;
        byte[] __buffer;

        public List<IntPtr> __addresses = new List<IntPtr>();
        private List<long> offsets = new List<long>();
        #endregion

        public AobScan(int id, byte[] pattern, byte[] buffer) {
            this.__process_id = id;
            this.__pattern = pattern;
            this.__buffer = buffer;
        }

        public Process process() {
            return Process.GetProcessById(__process_id);
        }

        public void ReadMemory() {
            byte[] __read_buffer = new byte[8192];

            for (long address = 0; address < 0x7FFFFF; address += 8192) {
                uint __buffer_value = (uint)__read_buffer.Length;
                NtReadVirtualMemory(process().Handle, new IntPtr(address), __read_buffer, __buffer_value, IntPtr.Zero);
                __pattern_scan(__read_buffer, __pattern);
                if (offsets.Count() > 0) {
                    for (int j = 0; j < offsets.Count(); j++) {
                        __addresses.Add(new IntPtr(address + offsets[j]));
                    }
                    offsets.Clear();
                }
                Thread.Sleep(1);
            }
        }

        public void WriteMemory() {
            for (int i = 0; i < __addresses.Count(); i++) {
                uint __buffer_value = (uint)__buffer.Length;
                NtWriteVirtualMemory(process().Handle, __addresses[i], __buffer, __buffer_value, IntPtr.Zero);
                Thread.Sleep(1);
            }
        }

        private void __pattern_scan(byte[] buffer, byte[] pattern) {
            long i = 0; long j = 0; long l = 0;
            while (i != buffer.Length) {
                if (buffer[i] == pattern[0]) {
                    j = i; l = 0;
                    while (buffer[j] == pattern[l]) {
                        j++; l++;
                        if (l == pattern.Length) offsets.Add(i);
                    }
                }
                i++;
                Thread.Sleep(1);
            }
        }

    }
}
