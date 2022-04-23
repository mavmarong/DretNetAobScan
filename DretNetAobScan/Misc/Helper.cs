using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DretNetAobScan {
    public class Helper {
        #region Pinvokes
        [DllImport( "kernel32.dll" )]
        public static extern bool ReadProcessMemory( IntPtr hProcess , IntPtr lpBaseAddress , byte[ ] buffer , uint size , out uint lpNumberOfBytesRead );

        [DllImport( "kernel32.dll" )]
        public static extern bool WriteProcessMemory( IntPtr hProcess , IntPtr lpBaseAddress , byte[ ] buffer , uint size , uint lpNumberOfBytesWritten );
        [DllImport( "kernel32.dll" , SetLastError = true )]
        public static extern int VirtualQueryEx( IntPtr hProcess , IntPtr lpAddress , out MEMORY_BASIC_INFORMATION lpBuffer , uint dwLength );
        #endregion

        #region Variables
        public int _process_id;

        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_GUARD = 0x00000100;

        public List<IntPtr> _addresses = new List<IntPtr>();
        #endregion

        public struct MEMORY_BASIC_INFORMATION {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }

        public static int _pattern_scan( byte[ ] buffer , byte[ ] pattern ) {
            for ( int i = 0 ; i != buffer.Length ; i++ ) {
                if ( buffer[ i ] == pattern[ 0 ] ) {
                    for ( int l = 0, j = i ; j < buffer.Length ; l++, j++ ) {
                        if ( buffer[ j ] != pattern[ l ] ) break;
                        if ( l == pattern.Length - 1 ) return i;
                    }
                }
            }
            return -1;
        }

        public static byte[ ] _string_to_aob( string AOB ) {
            string[ ] _string_aob = AOB.Split( ' ' );
            byte[ ] _byte_aob = new byte[ _string_aob.Length ];
            for ( int i = 0 ; i < _byte_aob.Length ; i++ ) {
                if ( _string_aob.Contains( "?" ) ) _byte_aob[ i ] = 0x0;
                else _byte_aob[ i ] = Convert.ToByte( _string_aob[ i ] , 16 );
            }
            return _byte_aob;
        }

        public Process GetProcess( ) => Process.GetProcessById( _process_id );
        public static int GetProcessID( string ProcessName ) => Process.GetProcessesByName( ProcessName ).FirstOrDefault( ).Id;
        public List<IntPtr> GetAddresses( ) => _addresses;
    }
}
