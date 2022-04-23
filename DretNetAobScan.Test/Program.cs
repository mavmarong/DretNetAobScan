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
            
            byte[ ] pattern = Encoding.ASCII.GetBytes( strings );
            byte[ ] buffer = Encoding.ASCII.GetBytes( "Hello!" );

            ascan.ReadMemory( BitConverter.ToString( pattern ).Replace( '-' , ' ' ) );
            
            // I recommend you to put the pattern length if you want to replace the whole string.
            ascan.WriteMemory( BitConverter.ToString( buffer ).Replace( '-' , ' ' ) , (uint) pattern.Length );

            for ( int i = 0 ; i < ascan.GetAddresses( ).Count ; i++ )
                Console.WriteLine( ascan.GetAddresses( )[ i ] );

            Console.ReadLine( );
        }
    }
}
