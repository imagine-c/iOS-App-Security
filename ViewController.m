//
//  ViewController.m
//  iOS-App-Security
//
//  Created by karek314 on 13/10/16.
//  Copyright © 2016 karek314. All rights reserved.
//

#import "ViewController.h"
#import "SecurityClass.h"
#include "asl.h"
#import <objc/message.h>

#define NSLog(args...) CustomNSLog(__FILE__,__LINE__,__PRETTY_FUNCTION__,args);

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(newLog:) name:@"newLog" object:nil];
    [self.textField setText:@""];
    [self SecurityCheck];
    [self.textField setText:[NSString stringWithFormat:@"%@\n",self.textField.text]];
}

-(void)SecurityCheck{
    //////////////////////////////////
    ///////////BINARY INFO////////////
    //////////////////////////////////
    //Check if currently running binary is encrypted (Signed by developer and Apple - Apple FairPlay)
    //Simply check if app has been treated with tool like Clutch or manually dumped from memory
    
    NSDictionary *resp = [SecurityClass getCurrentBinaryInfo];
    NSLog(@"Binary Info:%@",resp); // <- Gives all necessary informations
    //Encryption not found or cracked will appear if app has not been signed by you and/or Apple
    
    
    
    
    //////////////////////////////////
    //////////INJECTED LIBS///////////
    //////////////////////////////////
    //Check if any library has been injected into app process, can be easily done on Jailbroken device
    
    bool IfAppContainsDylib = [SecurityClass isDylibInjectedToProcessWithName:@"dylib_name"];
    if (IfAppContainsDylib) {
        NSLog(@"dylib_name has been injected to app");
    } else {
        NSLog(@"Not found dylib_name in app");
    }
    //Example - Checking if our app has been attacked with Cycript
    bool IfAppContainsCycript = [SecurityClass isDylibInjectedToProcessWithName:@"libcycript"];
    if (IfAppContainsCycript) {
        NSLog(@"libcycript has been injected to app");
    } else {
        NSLog(@"Not found libcycript in app");
    }
    
    
    
    //////////////////////////////////
    //CHECK IF APP IS BEING DEBUGGED//
    //////////////////////////////////
    //Traditional way for checking if debugger is connected
    
    bool isDebuggerConnected = [SecurityClass isDebuggerConnected];
    if (isDebuggerConnected) {
        NSLog(@"App is being debugged");
    } else {
        NSLog(@"Not found debugger");
    }
    // /dev/tty way
    bool isDebuggerConnected_tty = [SecurityClass ttyWayIsDebuggerConnected];
    if (isDebuggerConnected_tty) {
        NSLog(@"App is being debugged /dev/tty");
    } else {
        NSLog(@"Not found debugger /dev/tty");
    }
    
    
    
    //////////////////////////////////
    /////////PROXY CONNECTION/////////
    //////////////////////////////////
    //Check if connections between app and server side are being proxied by tools like Charles - https://www.charlesproxy.com
    
    bool isConnectionProxied = [SecurityClass isConnectionProxied];
    if (isConnectionProxied) {
        NSLog(@"Connection is being proxied to %@:%@",[SecurityClass proxy_host],[SecurityClass proxy_port]);
        //For example charles default listening port is 8888 but if necessary all connections can be dropped when proxy is detected.
    } else {
        NSLog(@"Connection is not being proxied with http proxy");
    }
    
    
    
    //////////////////////////////////
    ////////JAILBROKEN DEVICES////////
    //////////////////////////////////
    //Detect if device is jailbroken, sometimes may detect devices which were jailbroken but no longer are
    //Can be relatively easily hacked with tools on Cydia which sometimes work sometimes not work to give false result
    //I suggest using this method along with checking for processes and libraries injected specific for jailbroken device to get more reliable result
    //Unfortunately from iOS 9 it's not longer possible to get current list of running apps, sysctl now returns 0 for sandboxed environment
    
    bool isDeviceJailbroken = [SecurityClass isDeviceJailbroken];
    if (isDeviceJailbroken) {
        NSLog(@"Device is jailbroken");
    } else {
        NSLog(@"Device is NOT jailbroken");
    }
}


void CustomNSLog(const char *file, int line, const char *name, NSString *format, ...){
    NSDateFormatter *formatter;
    NSString *dateString;
    formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"dd-MM-yyyy HH:mm"];
    dateString = [formatter stringFromDate:[NSDate date]];
    va_list ap;
    va_start (ap, format);
    if (![format hasSuffix: @"\n"])
    {
        format = [format stringByAppendingString: @"\n"];
    }
    NSString *body = [[NSString alloc] initWithFormat:format arguments:ap];
    va_end (ap);
    NSString *fileName = [[NSString stringWithUTF8String:file] lastPathComponent];
    fprintf(stderr, "%s %s %s:%d -> %s", [dateString UTF8String], name, [fileName UTF8String],line, [body UTF8String]);
    [[NSUserDefaults standardUserDefaults]setObject:body forKey:@"current_log"];
    objc_msgSend(objc_getClass("ViewController"), sel_registerName("updateTextFieldClass"), nil);
}

+(void)updateTextFieldClass{
    [[NSNotificationCenter defaultCenter] postNotificationName:@"newLog" object:self];
}

- (void)newLog:(NSNotification *)notification {
    [self.textField setText:[NSString stringWithFormat:@"%@%@",self.textField.text,[[NSUserDefaults standardUserDefaults]stringForKey:@"current_log"]]];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)check:(id)sender {
    [self SecurityCheck];
    [self.textField setText:[NSString stringWithFormat:@"%@\n",self.textField.text]];
    NSRange range = NSMakeRange(self.textField.text.length, 0);
    [self.textField scrollRangeToVisible:range];
}
@end
