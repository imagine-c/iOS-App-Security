//
//  SecurityClass.h
//  iOS-App-Security
//
//  Created by karek314 on 13/10/16.
//  Copyright © 2016 karek314. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SecurityClass : NSObject

+(NSMutableDictionary*)getCurrentBinaryInfo;
+(NSString*)binaryInfoForx64;
+(NSString*)binaryInfoForx32;
+(BOOL)isDylibInjectedToProcessWithName:(NSString*)dylib_name;
+(BOOL)isConnectionProxied;
+(NSString *)proxy_host;
+(NSString*)proxy_port;
+(BOOL)ttyWayIsDebuggerConnected;
+(BOOL)isDebuggerConnected;
+(BOOL)isDeviceJailbroken;

@end
