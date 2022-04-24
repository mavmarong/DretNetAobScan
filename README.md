# DretNetAobScan
[![forthebadge](https://forthebadge.com/images/badges/made-with-c-sharp.svg)](https://forthebadge.com)


## What is this project?
This is a simple and clean Array Of Bytes Memory Scan helpful to make Memory hack programs.
## Examples:
```csharp
// Initialize the library
AobScan ascan = new AobScan(AobScan.GetProcessID("explorer"));

byte[] pattern = Encoding.ASCII.GetBytes("C:\Users\mavmarong");
byte[] buffer = Encoding.ASCII.GetBytes("Hello!");

// With this you can easly find the addresses of the string "C:\Users\mavmarong" in the memory of the indicated process id.
ascan.ReadMemory(BitConverter.ToString(pattern).Replace('-' , ' '));

// Automatically replace all the string containing "C:\Users\mavmarong" with "Hello!"
ascan.WriteMemory(BitConverter.ToString(buffer).Replace('-' , ' '), (uint) buffer.Length);
//^^ if you want to replace the whole string "C:\Users\mavmarong" put the pattern length in the second parameter of the WriteMemory function

// You can see all the addresses that got found after the process got readed
for (int i = 0; i < ascan.GetAddresses().Count; i++) {
    Console.WriteLine(ascan.GetAddresses()[i]);
}
```
## Recommendations:
I recommend you to start the ReadMemory function in a thread to make it faster and with more performances.
