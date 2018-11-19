# iOS-App-Security-Class
Simple class to check if iOS app has been cracked, being debugged or enriched with custom dylib and as well detect jailbroken environment<br>

# Usage
Just drag [SecurityClass.m](https://github.com/karek314/iOS-App-Security-Class/tree/master/iOS-App-Security) and [SecurityClass.h](https://github.com/karek314/iOS-App-Security-Class/tree/master/iOS-App-Security) to your project, then add
```objc
#import "SecurityClass.h"
```
If you want to just test and see how it works, clone repository, open in Xcode and compile.


<b>SecurityClass.m</b> allows you easily check if your iOS App:<br>
1. Has been cracked with tool like Clutch or manually<br>
2. Is being debugged with 2 different ways to check<br>
3. Has been treated with any custom library, for example Cycript or tweaks to crack InApp Purchases<br>
4. Is running on jailbroken device

Repository contains example app, feel free to test. If you want to import it in your project just copy <b>SecurityClass.m</b> & <b>SecurityClass.h</b>

This class shouldn't be used unobfuscated, and possibly should be splitted to inline code in desired function related to app security also strings used should be at least encrypted with AES. But for most attackers it will be hard at this point to crack it, even without obfuscation.

### Apple FairPlay Crack Detection
Check if currently running binary is encrypted (Signed by developer and Apple)
Simply check if app has been treated with tool like Clutch or manually dumped from memory
```objc
NSDictionary *resp = [SecurityClass getCurrentBinaryInfo];
NSLog(@"Binary Info:%@",resp); // <- Gives all necessary informations
```
"Encryption not found" or "cracked" - will appear if app has not been signed by you and/or Apple


### Custom dylib injected to memory
Check if any library has been injected into app process(can be easily done on jailbroken device)
```objc
bool IfAppContainsDylib = [SecurityClass isDylibInjectedToProcessWithName:@"dylib_name"];
if (IfAppContainsDylib) {
    NSLog(@"dylib_name has been injected to app");
} else {
    NSLog(@"Not found dylib_name in app");
}
```
Example - Checking if our app has been attacked with Cycript which uses <b>libcycript.dylib</b>
```objc
bool IfAppContainsCycript = [SecurityClass isDylibInjectedToProcessWithName:@"libcycript"];
if (IfAppContainsCycript) {
    NSLog(@"libcycript has been injected to app");
} else {
    NSLog(@"Not found libcycript in app");
}
```

### Debugger detection
Traditional way for checking if debugger is connected
```objc
bool isDebuggerConnected = [SecurityClass isDebuggerConnected];
if (isDebuggerConnected) {
    NSLog(@"App is being debugged");
} else {
    NSLog(@"Not found debugger");
}
```
/dev/tty way
```objc
bool isDebuggerConnected_tty = [SecurityClass ttyWayIsDebuggerConnected];
if (isDebuggerConnected_tty) {
    NSLog(@"App is being debugged /dev/tty");
} else {
    NSLog(@"Not found debugger /dev/tty");
}
```

### Proxied Connections
Check if connections between app and server side are being proxied by tools like [Charles Proxy](https://www.charlesproxy.com)<br>
For example charles default listening port is 8888 but if necessary all connections can be dropped when proxy is detected.<br>
```objc
bool isConnectionProxied = [SecurityClass isConnectionProxied];
if (isConnectionProxied) {
    NSLog(@"Connection is being proxied to %@:%@",[SecurityClass proxy_host],[SecurityClass proxy_port]);
} else {
    NSLog(@"Connection is not being proxied with http proxy");
}
```

### Jailbroken devices detection
Detect if device is jailbroken, sometimes may detect devices which were jailbroken but no longer are.<br>
Can be relatively easily hacked with tools on Cydia which sometimes work sometimes not work to give false result.<br>
I suggest using this method along with checking for processes and libraries injected specific for jailbroken device to get more reliable result.<br>
Unfortunately from iOS 9 it's not longer possible to get current list of running apps, sysctl now returns 0 for sandboxed environment and other tricks are also blocked by apple due "privacy concerns".

```objc
bool isDeviceJailbroken = [SecurityClass isDeviceJailbroken];
if (isDeviceJailbroken) {
    NSLog(@"Device is jailbroken");
} else {
    NSLog(@"Device is NOT jailbroken");
}
```
