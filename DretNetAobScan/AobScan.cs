using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace DretNetAobScan {
    public class AobScan : Helper {
        public AobScan( int pid ) {
            _process_id = pid;
        }

        public byte[ ] SendResults( object pattern , long results_size = 0xF0 ,  long start_address = 0x0 , long end_address = 0xFFFFFFFF ) { //TODO: Fix the offset calculation.
            byte[ ] _pattern = GetBytes( pattern );
            for ( long i = start_address ; i < end_address ; ) {
                MEMORY_BASIC_INFORMATION mem_info = new MEMORY_BASIC_INFORMATION();
                if ( VirtualQueryEx( GetProcessHandle( ) , new IntPtr( i ) , out mem_info , ( uint ) Marshal.SizeOf( typeof( MEMORY_BASIC_INFORMATION ) ) ) == 0 ) break;
                if ( ( mem_info.State & ( uint ) MEM_COMMIT ) != 0 && ( mem_info.Protect & ( uint ) PAGE_GUARD ) != PAGE_GUARD ) {
                    byte[ ] _read_buffer = new byte[ mem_info.RegionSize ];
                    uint _buffer_value = 0;
                    if ( ReadProcessMemory( GetProcessHandle( ) , new IntPtr( mem_info.BaseAddress ) , _read_buffer , ( uint ) _read_buffer.Length , out _buffer_value ) ) {
                        int offset = _calc_offset_send_result( _read_buffer , _pattern , results_size , out results );
                        if ( offset != -1 ) return results;
                    }
                }
                i = mem_info.BaseAddress + mem_info.RegionSize;
            }
            return results = GetBytes( "No results found." );
        }

        public void ReadMemory( object pattern , long start_address = 0x0 , long end_address = 0xFFFFFFFF ) {
            byte[ ] _pattern = GetBytes( pattern );
            for ( long i = start_address ; i < end_address ; ) {
                MEMORY_BASIC_INFORMATION mem_info = new MEMORY_BASIC_INFORMATION();
                if ( VirtualQueryEx( GetProcessHandle( ) , new IntPtr( i ) , out mem_info , ( uint ) Marshal.SizeOf( typeof( MEMORY_BASIC_INFORMATION ) ) ) == 0 ) break;
                if ( ( mem_info.State & ( uint ) MEM_COMMIT ) != 0 && ( mem_info.Protect & ( uint ) PAGE_GUARD ) != PAGE_GUARD ) {
                    byte[ ] _read_buffer = new byte[ mem_info.RegionSize ];
                    uint _buffer_value = 0;
                    if ( ReadProcessMemory( GetProcessHandle( ) , new IntPtr( mem_info.BaseAddress ) , _read_buffer , ( uint ) _read_buffer.Length , out _buffer_value ) ) {
                        int offset = _calc_offset( _read_buffer , _pattern );
                        if ( offset != -1 ) _addresses.Add( new IntPtr( mem_info.BaseAddress + offset ) );
                    }
                }
                i = mem_info.BaseAddress + mem_info.RegionSize;
            }
        }

        public void WriteMemory( object buffer , uint buffer_length = 0 ) {
            byte[ ] _buffer = GetBytes( buffer );
            for ( int i = 0 ; i < _addresses.Count( ) ; ++i ) {
                uint _buffer_value = 0;
                WriteProcessMemory( GetProcessHandle( ) , _addresses[ i ] , _buffer , buffer_length == 0 ? ( uint ) _buffer.Length : buffer_length , _buffer_value );
            }
        }
    }
}
