using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DretNetAobScan {
    public class Helper {
        #region Pinvokes
        [DllImport( "kernel32.dll" )]
        public static extern bool ReadProcessMemory( IntPtr hProcess , IntPtr lpBaseAddress , [Out] byte[ ] buffer , uint size , out uint lpNumberOfBytesRead );
        [DllImport( "kernel32.dll" )]
        public static extern bool WriteProcessMemory( IntPtr hProcess , IntPtr lpBaseAddress , byte[ ] buffer , uint size , uint lpNumberOfBytesWritten );
        [DllImport( "kernel32.dll" , SetLastError = true )]
        public static extern int VirtualQueryEx( IntPtr hProcess , IntPtr lpAddress , out MEMORY_BASIC_INFORMATION lpBuffer , uint dwLength );
        [DllImport( "kernel32.dll" , SetLastError = true )]
        public static extern IntPtr OpenProcess( uint processAccess , bool bInheritHandle , uint processId );
        #endregion

        #region Variables
        public int _process_id;

        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_GUARD = 0x00000100;

        public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

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
            for ( int i = 0 ; i != buffer.Length ; ++i ) {
                if ( buffer[ i ] == pattern[ 0 ] ) {
                    for ( int l = 0, j = i ; j < buffer.Length ; ++l, ++j ) {
                        if ( buffer[ j ] != pattern[ l ] ) break;
                        if ( l == pattern.Length - 1 ) return i;
                    }
                }
            }
            return -1;
        }

        public static byte[ ] GetBytes( object type ) {
            switch ( type.GetType( ).ToString( ) ) {
                case "System.String":
                    return Encoding.UTF8.GetBytes( type.ToString( ) );
                case "System.Double":
                    return BitConverter.GetBytes( Convert.ToDouble( type ) );
                case "System.Int32":
                    return BitConverter.GetBytes( Convert.ToInt32( type ) );
                case "System.Single":
                    return BitConverter.GetBytes( Convert.ToSingle( type ) );
                case "System.Int64":
                    return BitConverter.GetBytes( Convert.ToInt64( type ) );
            }
            return ( byte[ ] ) type; // it will give error if the type is not byte[].
        }
        public IntPtr GetProcessHandle( ) => OpenProcess( PROCESS_ALL_ACCESS , false , ( uint ) _process_id );
        public static int GetProcessID( string ProcessName ) => Process.GetProcessesByName( ProcessName ).FirstOrDefault( ).Id;
        public List<IntPtr> GetAddresses( ) => _addresses;
    }
}
