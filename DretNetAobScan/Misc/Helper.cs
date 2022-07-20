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
        public int m_ProcessID;

        public byte[] m_Results;

        public const int MEM_COMMIT = 0x00001000;
        public const int PAGE_GUARD = 0x00000100;

        public const uint PROCESS_ALL_ACCESS = 0x001F0FFF;

        public List<IntPtr> m_Addresses = new List<IntPtr>();
        #endregion

        #region Structs
        public struct MEMORY_BASIC_INFORMATION {
            public int BaseAddress;
            public int AllocationBase;
            public int AllocationProtect;
            public int RegionSize;
            public int State;
            public int Protect;
            public int lType;
        }
        #endregion

        #region Public Functions
        public static int m_CalcOffset( byte[ ] m_Buffer , byte[ ] m_Pattern ) {
            for ( int i = 0 ; i != m_Buffer.Length ; ++i ) 
                for ( int j = 0, k = i ; m_Buffer[ k ] == m_Pattern[ j ] && k < m_Buffer.Length ; ++j, ++k ) 
                    if ( j == m_Pattern.Length - 1 ) return i;
            return -1;
        }
        
        public static int m_CalcOffsetSendResult( byte[ ] m_Buffer , byte[ ] m_Pattern , long m_ResultsSize ,  out byte[ ] m_Results ) {
            m_Results = new byte[ m_ResultsSize ];
            for ( int i = 0, j = 0 ; i != m_Buffer.Length && j != 30 ; ++i ) {
                for ( int k = 0, l = 0, n = i ; j < m_Buffer.Length && k < m_ResultsSize; ++k, ++n ) {
                    if ( l < m_Pattern.Length ) 
                        if ( m_Buffer[ j ] != m_Pattern[ l ] ) break;
                    j = m_Buffer[ n ] == 0x00 ? ++j : 0;
                    m_Results[ k ] = m_Buffer[ n ];
                    l = l >= m_Pattern.Length ? ++l : l;
                }
                for ( int k = 0, l = i ; m_Buffer[ l ] == m_Pattern[ k ] && k < m_Buffer.Length ; ++k, ++l ) 
                    if ( k == m_Pattern.Length - 1 ) return i;
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
        public IntPtr m_GetProcessHandle( ) => OpenProcess( PROCESS_ALL_ACCESS , false , ( uint ) m_ProcessID );
        public static int GetProcessID( string ProcessName ) => Process.GetProcessesByName( ProcessName ).FirstOrDefault( ).Id;
        public List<IntPtr> GetAddresses( ) => m_Addresses;
        #endregion
    }
}
