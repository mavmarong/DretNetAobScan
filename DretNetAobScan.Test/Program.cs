using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DretNetAobScan.Test {
    [TestClass]
    public class Program {
        [TestMethod]
        public void Main() {
            Console.WriteLine("Insert the process name: ");
            string process = Console.ReadLine();
            Console.WriteLine("Insert the string you wanna search");
            string strings = Console.ReadLine();

            AobScan ascan = new AobScan(process, Encoding.ASCII.GetBytes(strings), null); // You can also use other Encoding methods.

            // Read memory process
            ascan.__read_memory();

            // Here it prints every addresses that the program took from the string
            for (int i = 0; i < ascan.__addresses.Count; i++) {
                Console.WriteLine(ascan.__addresses[i]);
            }
            Console.ReadLine();
        }
    }
}
