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
        public AobScan( int id , byte[ ] pattern , byte[ ] buffer ) {
            _process_id = id;
            _pattern = pattern;
            _buffer = buffer;
        }

        public void ReadMemory( ) {
            MEMORY_BASIC_INFORMATION mem_info;
            for ( long i = 0x0 ; i < 0xFFFFFFFF ; ) {
                mem_info = new MEMORY_BASIC_INFORMATION();
                if ( VirtualQueryEx( GetProcess( ).Handle , new IntPtr( i ) , out mem_info , ( uint ) Marshal.SizeOf( typeof( MEMORY_BASIC_INFORMATION ) ) ) == 0 ) break;
                if ( ( mem_info.State & ( uint ) MEM_COMMIT ) != 0 && ( mem_info.Protect & ( uint ) PAGE_GUARD ) != PAGE_GUARD ) {
                    byte[ ] _read_buffer = new byte[ mem_info.RegionSize ];
                    uint _buffer_value = 0;
                    if ( ReadProcessMemory( GetProcess( ).Handle , new IntPtr( mem_info.BaseAddress ) , _read_buffer , ( uint ) _read_buffer.Length , out _buffer_value ) && _buffer_value > 0 ) {
                        int offset = _pattern_scan( _read_buffer , _pattern );
                        if ( offset != -1 ) _addresses.Add( new IntPtr( mem_info.BaseAddress + offset ) );
                    }
                }
                i = mem_info.BaseAddress + mem_info.RegionSize;
                Thread.Sleep( 1 );
            }
            GC.Collect( );
        }

        public void WriteMemory( ) {
            for ( int i = 0 ; i < _addresses.Count( ) ; i++ ) {
                uint _buffer_value = 0;
                WriteProcessMemory( GetProcess( ).Handle , _addresses[ i ] , _buffer , ( uint ) _pattern.Length , _buffer_value );
                Thread.Sleep( 1 );
            }
            GC.Collect( );
        }
    }
}
