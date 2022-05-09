using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DretNetAobScan.Test {
    [TestClass]
    public class Program {
        [TestMethod]
        public static void Main( ) {
            Console.WriteLine( "Insert the process name: " );
            string process = Console.ReadLine();
            Console.WriteLine( "Insert the string you wanna search: " );
            string strings = Console.ReadLine();
            
            AobScan ascan = new AobScan( AobScan.GetProcessID( process ) );

            ascan.ReadMemory( strings );
            
            // I recommend you to put the pattern length if you want to replace the whole string.
            ascan.WriteMemory( "Hello!" , ( uint ) AobScan.GetBytes(strings).Length );

            for ( int i = 0 ; i < ascan.GetAddresses( ).Count ; i++ )
                Console.WriteLine( $"0x{ascan.GetAddresses( )[ i ].ToString( "X" )}" );

            Console.ReadLine( );
        }
    }
}
