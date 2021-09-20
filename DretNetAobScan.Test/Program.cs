using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DretNetAobScan.Test {
    [TestClass]
    public class Program {
        [TestMethod]
        public void Main() {
            Console.WriteLine("Insert the process id: ");
            int process = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("Insert the string you wanna search: ");
            string strings = Console.ReadLine();

            AobScan ascan = new AobScan(process, Encoding.ASCII.GetBytes(strings), Encoding.ASCII.GetBytes("Hello!"));

            ascan.ReadMemory();

            ascan.WriteMemory();

            for (int i = 0; i < ascan.GetAddresses().Count; i++) {
                Console.WriteLine(ascan.GetAddresses()[i]);
            }
            Console.ReadLine();
        }
    }
}
