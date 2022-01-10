# DretNetAobScan
[![forthebadge](https://forthebadge.com/images/badges/made-with-c-sharp.svg)](https://forthebadge.com)


## What is this project?
This is a simple and clean Array Of Bytes Memory Scan helpful to make Memory hack programs.
## Examples:
```csharp
// Initialize the library
AobScan ascan = new AobScan(5204, Encoding.ASCII.GetBytes("C:\Users\mavmarong"), Encoding.ASCII.GetBytes("Hello!"), 8192, 0x7FFFFF);

// With this you can easly find the addresses of the string "C:\Users\mavmarong" in the memory of the indicated process id.
ascan.ReadMemory();

// Automatically replace all the string containing "C:\Users\mavmarong" with "Hello!"
ascan.WriteMemory();

// You can see all the addresses that got found after the process got readed
for (int i = 0; i < ascan.GetAddresses().Count; i++) {
    Console.WriteLine(ascan.GetAddresses()[i]);
}
```
