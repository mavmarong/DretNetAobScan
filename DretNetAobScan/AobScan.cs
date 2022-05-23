using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DretNetAobScan {
    public class AobScan : Helper {
        public AobScan( int pid ) {
            m_ProcessID = pid;
        }

        public byte[ ] SendResults( object Pattern , long ResultsSize = 0xF0 ,  long StartAddress = 0x0 , long EndAddress = 0xFFFFFFFF ) { //TODO: Fix the offset calculation.
            byte[ ] m_Pattern = GetBytes( Pattern );
            for ( long i = StartAddress ; i < EndAddress ; ) {
                MEMORY_BASIC_INFORMATION m_MemInfo = new MEMORY_BASIC_INFORMATION();
                if ( VirtualQueryEx( m_GetProcessHandle( ) , new IntPtr( i ) , out m_MemInfo , ( uint ) Marshal.SizeOf( typeof( MEMORY_BASIC_INFORMATION ) ) ) == 0 ) break;
                if ( ( m_MemInfo.State & ( uint ) MEM_COMMIT ) != 0 && ( m_MemInfo.Protect & ( uint ) PAGE_GUARD ) != PAGE_GUARD ) {
                    byte[ ] m_ReadBuffer = new byte[ m_MemInfo.RegionSize ];
                    uint m_BufferValue = 0;
                    if ( ReadProcessMemory( m_GetProcessHandle( ) , new IntPtr( m_MemInfo.BaseAddress ) , m_ReadBuffer , ( uint ) m_ReadBuffer.Length , out m_BufferValue ) ) {
                        int m_Offset = m_CalcOffsetSendResult( m_ReadBuffer , m_Pattern , ResultsSize , out m_Results );
                        if ( m_Offset != -1 ) return m_Results;
                    }
                }
                i = m_MemInfo.BaseAddress + m_MemInfo.RegionSize;
            }
            return m_Results = GetBytes( "No results found." );
        }

        public void ReadMemory( object Pattern , long StartAddress = 0x0 , long EndAddress = 0xFFFFFFFF ) {
            byte[ ] m_Pattern = GetBytes( Pattern );
            for ( long i = StartAddress ; i < EndAddress ; ) {
                MEMORY_BASIC_INFORMATION m_MemInfo = new MEMORY_BASIC_INFORMATION();
                if ( VirtualQueryEx( m_GetProcessHandle( ) , new IntPtr( i ) , out m_MemInfo , ( uint ) Marshal.SizeOf( typeof( MEMORY_BASIC_INFORMATION ) ) ) == 0 ) break;
                if ( ( m_MemInfo.State & ( uint ) MEM_COMMIT ) != 0 && ( m_MemInfo.Protect & ( uint ) PAGE_GUARD ) != PAGE_GUARD ) {
                    byte[ ] m_ReadBuffer = new byte[ m_MemInfo.RegionSize ];
                    uint m_BufferValue = 0;
                    if ( ReadProcessMemory( m_GetProcessHandle( ) , new IntPtr( m_MemInfo.BaseAddress ) , m_ReadBuffer , ( uint ) m_ReadBuffer.Length , out m_BufferValue ) ) {
                        int m_Offset = m_CalcOffset( m_ReadBuffer , m_Pattern );
                        if ( m_Offset != -1 ) m_Addresses.Add( new IntPtr( m_MemInfo.BaseAddress + m_Offset ) );
                    }
                }
                i = m_MemInfo.BaseAddress + m_MemInfo.RegionSize;
            }
        }

        public void WriteMemory( object Buffer , uint BufferLength = 0 ) {
            byte[ ] m_Buffer = GetBytes( Buffer );
            for ( int i = 0 ; i < m_Addresses.Count( ) ; ++i ) {
                uint m_BufferValue = 0;
                WriteProcessMemory( m_GetProcessHandle( ) , m_Addresses[ i ] , m_Buffer , BufferLength == 0 ? ( uint ) m_Buffer.Length : BufferLength , m_BufferValue );
            }
        }
    }
}
