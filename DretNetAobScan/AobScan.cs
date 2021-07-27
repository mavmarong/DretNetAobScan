using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
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
        string __process_name;
        byte[] __pattern;
        byte[] __buffer;

        public List<IntPtr> __addresses = new List<IntPtr>();
        #endregion

        public AobScan(string pName, byte[] pattern, byte[] buffer) {
            this.__process_name = pName;
            this.__pattern = pattern;
            this.__buffer = buffer;
        }

        public Process process() {
            return Process.GetProcessesByName(__process_name).FirstOrDefault();
        }

        public void __read_memory() {
            byte[] __read_buffer = new byte[8192];

            for (long i = 0; i < 0x7FFFFF; i += 8192) {

                uint __null_value = 0;

                NtReadVirtualMemory(process().Handle, new IntPtr(i), __read_buffer, __null_value, IntPtr.Zero);

                int offset = __pattern_scan(__read_buffer, __pattern);

                if (offset != 1) {

                    __addresses.Add(new IntPtr(i + offset));

                }
            }
        }

        public void __write_memory() {
            for (int i = 0; i < __addresses.Count(); i++) {
                uint __null_value = 0;

                NtWriteVirtualMemory(process().Handle, __addresses[i], __buffer, __null_value, IntPtr.Zero);
            }
        }

        private int __pattern_scan(byte[] buffer, byte[] pattern) {

            for (int i = 0; i < buffer.Length; i++) {

                for (int j = 0; pattern[j] == buffer[i]; j++) {

                    for (int k = 1; pattern[j + k] == buffer[i + k]; k++) {

                        int x = j + k;
                        int y = i + k;

                        while (true) {

                            if (pattern[x] == pattern[y]) {

                                x++; y++;

                                if (x == pattern.Length || y == buffer.Length) {

                                    return i;

                                }

                            } else {

                                break;

                            }

                        }

                    }

                }

            }
            return -1;
        }

    }
}
