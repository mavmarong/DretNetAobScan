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

            ascan.__read_memory();

            ascan.__write_memory();

            for (int i = 0; i < ascan.__addresses.Count; i++) {
                Console.WriteLine(ascan.__addresses[i]);
            }
            Console.ReadLine();
        }
    }
}
