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
        public AobScan( int pid ) {
            _process_id = pid;
        }

        public void ReadMemory( string pattern ) {
            byte[ ] _pattern = _string_to_aob( pattern );
            MEMORY_BASIC_INFORMATION mem_info = new MEMORY_BASIC_INFORMATION();
            for ( long i = 0x0 ; i < 0xFFFFFFFF ; ) {
                if ( VirtualQueryEx( GetProcess( ).Handle , new IntPtr( i ) , out mem_info , ( uint ) Marshal.SizeOf( typeof( MEMORY_BASIC_INFORMATION ) ) ) == 0 ) break;
                if ( ( mem_info.State & ( uint ) MEM_COMMIT ) != 0 && ( mem_info.Protect & ( uint ) PAGE_GUARD ) != PAGE_GUARD ) {
                    byte[ ] _read_buffer = new byte[ mem_info.RegionSize ];
                    uint _buffer_value = 0;
                    if ( ReadProcessMemory( GetProcess( ).Handle , new IntPtr( mem_info.BaseAddress ) , _read_buffer , ( uint ) _read_buffer.Length , out _buffer_value ) ) {
                        int offset = _pattern_scan( _read_buffer , _pattern );
                        if ( offset != -1 ) _addresses.Add( new IntPtr( mem_info.BaseAddress + offset ) );
                    }
                }
                i = mem_info.BaseAddress + mem_info.RegionSize;
            }
        }

        public void WriteMemory( string buffer, uint buffer_length ) {
            byte[ ] _buffer = _string_to_aob( buffer );
            for ( int i = 0 ; i < _addresses.Count( ) ; i++ ) {
                uint _buffer_value = 0;
                WriteProcessMemory( GetProcess( ).Handle , _addresses[ i ] , _buffer , buffer_length , _buffer_value );
            }
        }
    }
}
