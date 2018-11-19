//
//  binaryInfo.m
//  binary_info
//
//  Created by karek314 on 13/10/16.
//  Copyright © 2016 karek314. All rights reserved.
//

#import "SecurityClass.h"
#import "UIKit/UIKit.h"
#include <sys/utsname.h>
#include <pwd.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#import <sys/ioctl.h>
#import <sys/param.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <TargetConditionals.h>
#if TARGET_IPHONE_SIMULATOR
#import <sys/conf.h>
#else
#if ! defined(D_DISK)
#define D_DISK  2
#endif
#endif

#if TARGET_IPHONE_SIMULATOR && !defined(LC_ENCRYPTION_INFO)
#define LC_ENCRYPTION_INFO 0x21
struct encryption_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
};
#endif

#if TARGET_IPHONE_SIMULATOR && !defined(LC_ENCRYPTION_INFO_64)
#define LC_ENCRYPTION_INFO_64 0x2C
struct encryption_info_command {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
};
#endif

@implementation SecurityClass

+(NSMutableDictionary*)getCurrentBinaryInfo{
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    #if TARGET_IPHONE_SIMULATOR
        [dictionary setObject:@"Simulator" forKey:@"unit_type"];
    #else
        [dictionary setObject:@"Device" forKey:@"unit_type"];
    #endif
    if (HardwareIs64BitArch()) {
        [dictionary setObject:@"x64" forKey:@"device_arch"];
        [dictionary setObject:[NSString stringWithFormat:@"%x",LC_ENCRYPTION_INFO_64] forKey:@"lc_info"];
        [dictionary setObject:[self binaryInfoForx64] forKey:@"binary_info"];
    } else {
        [dictionary setObject:@"x32" forKey:@"device_arch"];
        [dictionary setObject:[NSString stringWithFormat:@"%x",LC_ENCRYPTION_INFO] forKey:@"lc_info"];
        [dictionary setObject:[self binaryInfoForx32] forKey:@"binary_info"];
    }
    return dictionary;
}

+(NSString*)binaryInfoForx64{
    const struct mach_header_64 *header;
    Dl_info dlinfo;
    if (dladdr(main, &dlinfo) == 0 || dlinfo.dli_fbase == NULL) {
        return @"Error:can't get main";
    }
    header = dlinfo.dli_fbase;
    struct load_command *cmd = (struct load_command *) (header+1);
    for (uint32_t i = 0; cmd != NULL && i < header->ncmds; i++) {
        if (cmd->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command *crypt_cmd = (struct encryption_info_command *) cmd;
            if (crypt_cmd->cryptid < 1) {
                return @"cracked";
            } else {
                return @"encrypted";
            }
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }
    return @"notfound";
}

+(NSString*)binaryInfoForx32{
    const struct mach_header *header;
    Dl_info dlinfo;
    if (dladdr(main, &dlinfo) == 0 || dlinfo.dli_fbase == NULL) {
        return @"Error:can't get main";
    }
    header = dlinfo.dli_fbase;
    struct load_command *cmd = (struct load_command *) (header+1);
    for (uint32_t i = 0; cmd != NULL && i < header->ncmds; i++) {
        if (cmd->cmd == LC_ENCRYPTION_INFO) {
            struct encryption_info_command *crypt_cmd = (struct encryption_info_command *) cmd;
            if (crypt_cmd->cryptid < 1) {
                return @"cracked";
            } else {
                return @"encrypted";
            }
        }
        cmd = (struct load_command *) ((uint8_t *) cmd + cmd->cmdsize);
    }
    return @"notfound";
}

+(BOOL)isDylibInjectedToProcessWithName:(NSString*)dylib_name{
    int max = _dyld_image_count();
    for (int i = 0; i < max; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name != NULL) {
            NSString *namens = [NSString stringWithUTF8String:name];
            NSString *compare = [NSString stringWithString:dylib_name];
            if ([namens containsString:compare]) {
                return YES;
            }
        }
    }
    return NO;
}

+(BOOL)isConnectionProxied{
    if (![[self proxy_host] isEqualToString:@""] && ![[self proxy_port] isEqualToString:@""]){
        return YES;
    } else {
        return NO;
    }
}

+(NSString *)proxy_host {
    CFDictionaryRef dicRef = CFNetworkCopySystemProxySettings();
    const CFStringRef proxyCFstr = (const CFStringRef)CFDictionaryGetValue(dicRef,(const void*)kCFNetworkProxiesHTTPProxy);
    NSString *tmp = (__bridge NSString *)proxyCFstr;
    if ([tmp isEqualToString:@""] || [tmp isEqualToString:@"(null)"] || [tmp length] < 1) {
        const CFStringRef socksproxyCFstr = (const CFStringRef)CFDictionaryGetValue(dicRef,(const void*)kCFNetworkProxiesSOCKSProxy);
        tmp = (__bridge NSString *)socksproxyCFstr;
    }
    return  tmp;
    
}

+(NSString*)proxy_port {
    CFDictionaryRef dicRef = CFNetworkCopySystemProxySettings();
    const CFNumberRef portCFnum = (const CFNumberRef)CFDictionaryGetValue(dicRef, (const void*)kCFNetworkProxiesHTTPPort);
    SInt32 port;
    NSString *tmp = @"";
    if (portCFnum) {
        if (CFNumberGetValue(portCFnum, kCFNumberSInt32Type, &port)){
            tmp = [NSString stringWithFormat:@"%i",(int)port];
        }
    } else {
        const CFNumberRef portCFnumSocks = (const CFNumberRef)CFDictionaryGetValue(dicRef, (const void*)kCFNetworkProxiesSOCKSPort);
        if (portCFnumSocks) {
            if (CFNumberGetValue(portCFnumSocks, kCFNumberSInt32Type, &port)){
                tmp = [NSString stringWithFormat:@"%i",(int)port];
            }
        }
    }
    return tmp;
}

static int process_list(struct kinfo_proc **procList, size_t *procCount){
    int err;
    struct kinfo_proc * result;
    bool  done;
    static const int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t length;
    *procCount = 0;
    result = NULL;
    done = false;
    do {
        assert(result == NULL);
        length = 0;
        err = sysctl( (int *) name, (sizeof(name) / sizeof(*name)) - 1, NULL, &length, NULL, 0);
        if (err == -1) {
            err = errno;
        }
        if (err == 0) {
            result = malloc(length);
            if (result == NULL) {
                err = ENOMEM;
            }
        }
        if (err == 0) {
            err = sysctl( (int *) name, (sizeof(name) / sizeof(*name)) - 1, result, &length, NULL, 0);
            if (err == -1) {
                err = errno;
            }
            if (err == 0) {
                done = true;
            } else if (err == ENOMEM) {
                assert(result != NULL);
                free(result);
                result = NULL;
                err = 0;
            }
        }
    } while (err == 0 && ! done);
    if (err != 0 && result != NULL) {
        free(result);
        result = NULL;
    }
    *procList = result;
    if (err == 0) {
        *procCount = length / sizeof(result);
    }
    assert( (err == 0) == (*procList != NULL) );
    return err;
}

+(BOOL)isDeviceJailbroken{
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"]){
        return YES;
    } else if([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"]){
        return YES;
    } else if([[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"]){
        return YES;
    } else if([[NSFileManager defaultManager] fileExistsAtPath:@"/usr/sbin/sshd"]){
        return YES;
    } else if([[NSFileManager defaultManager] fileExistsAtPath:@"/etc/apt"]){
        return YES;
    } else if([[NSFileManager defaultManager] fileExistsAtPath:@"/private/var/lib/apt/"]){
        return YES;
    }else if (![[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/AppStore.app"]){
        //if PSProtector activated -- Tested on iOS 11.0.1
        return YES;
    }else if (![[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/MobileSafari.app"]){
        //if PSProtector activated -- Tested on iOS 11.0.1
        return YES;
    }
    if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]]){
        return YES;
    }
    FILE *f = fopen("/bin/bash", "r");
    if (f != NULL) {
        fclose(f);
        return YES;
    }
    fclose(f);
    f = fopen("/Applications/Cydia.app", "r");
    if (f != NULL) {
        fclose(f);
        return YES;
    }
    fclose(f);
    f = fopen("/Library/MobileSubstrate/MobileSubstrate.dylib", "r");
    if (f != NULL) {
        fclose(f);
        return YES;
    }
    fclose(f);
    f = fopen("/usr/sbin/sshd", "r");
    if (f != NULL) {
        fclose(f);
        return YES;
    }
    fclose(f);
    f = fopen("/etc/apt", "r");
    if (f != NULL) {
        fclose(f);
        return YES;
    }
    fclose(f);
    NSError *error;
    NSString *stringToBeWritten = @"if this string is saved, then device is jailbroken";
    [stringToBeWritten writeToFile:@"/private/test" atomically:YES encoding:NSUTF8StringEncoding error:&error];
    [[NSFileManager defaultManager] removeItemAtPath:@"/private/test" error:nil];
    if(error==nil){
        return YES;
    }
    return NO;
}

+(BOOL)ttyWayIsDebuggerConnected{
    int fd = STDERR_FILENO;
    if (fcntl(fd, F_GETFD, 0) < 0) {
        return NO;
    }
    char buf[MAXPATHLEN + 1];
    if (fcntl(fd, F_GETPATH, buf ) >= 0) {
        if (strcmp(buf, "/dev/null") == 0)
            return NO;
        if (strncmp(buf, "/dev/tty", 8) == 0)
            return YES;
    }
    int type;
    if (ioctl(fd, FIODTYPE, &type) < 0) {
        return NO;
    }
    return type != D_DISK;
}

+(BOOL)isDebuggerConnected{
    int                 junk;
    int                 mib[4];
    struct kinfo_proc   info;
    size_t              size;
    info.kp_proc.p_flag = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    size = sizeof(info);
    junk = sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &size, NULL, 0);
    assert(junk == 0);
    return ( (info.kp_proc.p_flag & P_TRACED) != 0 );
}

int main (int argc, char *argv[]);

static BOOL HardwareIs64BitArch(){
    #if __LP64__
        return YES;
    #endif
    static BOOL sHardwareChecked = NO;
    static BOOL sIs64bitHardware = NO;
    if(!sHardwareChecked) {
        sHardwareChecked = YES;
        #if TARGET_IPHONE_SIMULATOR
            sIs64bitHardware = DeviceIs64BitSimulator();
        #else
            struct host_basic_info host_basic_info;
            unsigned int count;
            kern_return_t returnValue = host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t)(&host_basic_info), &count);
            if(returnValue != KERN_SUCCESS){
                sIs64bitHardware = NO;
            }
            sIs64bitHardware = (host_basic_info.cpu_type == CPU_TYPE_ARM64);
        #endif
    }
    return sIs64bitHardware;
}

bool DeviceIs64BitSimulator(){
    bool is64bitSimulator = false;
    int mib[6] = {0,0,0,0,0,0};
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_ALL;
    long numberOfRunningProcesses = 0;
    struct kinfo_proc* BSDProcessInformationStructure = NULL;
    size_t sizeOfBufferRequired = 0;
    BOOL successfullyGotProcessInformation = NO;
    int error = 0;
    while (successfullyGotProcessInformation == NO) {
        error = sysctl(mib, 3, NULL, &sizeOfBufferRequired, NULL, 0);
        if (error){
            return NULL;
        }
        BSDProcessInformationStructure = (struct kinfo_proc*) malloc(sizeOfBufferRequired);
        if (BSDProcessInformationStructure == NULL) {
            return NULL;
        }
        error = sysctl(mib, 3, BSDProcessInformationStructure, &sizeOfBufferRequired, NULL, 0);
        if (error == 0) {
            successfullyGotProcessInformation = YES;
        } else {
            free(BSDProcessInformationStructure);
        }
    }
    numberOfRunningProcesses = sizeOfBufferRequired / sizeof(struct kinfo_proc);
    for (int i = 0; i < numberOfRunningProcesses; i++) {
        const char *name = BSDProcessInformationStructure[i].kp_proc.p_comm;
        if(strcmp(name, "SimulatorBridge") == 0) {
            int p_flag = BSDProcessInformationStructure[i].kp_proc.p_flag;
            is64bitSimulator = (p_flag & P_LP64) == P_LP64;
            break;
        }
    }
    free(BSDProcessInformationStructure);
    return is64bitSimulator;
}


@end
