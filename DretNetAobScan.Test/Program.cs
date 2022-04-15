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

            AobScan ascan = new AobScan( AobScan.GetProcessID( process ) , Encoding.ASCII.GetBytes( strings ) , Encoding.ASCII.GetBytes( "Hello!" ) );

            ascan.ReadMemory( );
            ascan.WriteMemory( );

            for ( int i = 0 ; i < ascan.GetAddresses( ).Count ; i++ )
                Console.WriteLine( ascan.GetAddresses( )[ i ] );

            Console.ReadLine( );
        }
    }
}
