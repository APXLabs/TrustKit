/*
 
 TrustKit.m
 TrustKit
 
 Copyright 2015 The TrustKit Project Authors
 Licensed under the MIT license, see associated LICENSE file for terms.
 See AUTHORS file for the list of project authors.
 
 */

#import "TrustKit.h"
#import "Reporting/TSKBackgroundReporter.h"
#import "Pinning/TSKSPKIHashCache.h"
#import "Swizzling/TSKNSURLConnectionDelegateProxy.h"
#import "Swizzling/TSKNSURLSessionDelegateProxy.h"
#import "Pinning/TSKSPKIHashCache.h"
#import "parse_configuration.h"
#import "TSKPinningValidatorResult.h"
#import "TSKLog.h"
#import "TSKPinningValidator_Private.h"


// Info.plist key we read the public key hashes from
static NSString * const kTSKConfiguration = @"TSKConfiguration";

// Default report URI - can be disabled with TSKDisableDefaultReportUri
// Email info@datatheorem.com if you need a free dashboard to see your App's reports
static NSString * const kTSKDefaultReportUri = @"https://overmind.datatheorem.com/trustkit/report";

static NSString * const kTSKDefaultIdentifier = @"TSKIdentifier";

static const char kTSKPinFailureReporterQueueLabel[] = "com.datatheorem.trustkit.reporterqueue";


#pragma mark TrustKit Global State


// Shared TrustKit singleton instance
static TrustKit *sharedTrustKit;

// A shared hash cache for use by all TrustKit instances
static TSKSPKIHashCache *sharedHashCache;

// Default logger block: only log in debug builds and add TrustKit at the beginning of the line
#if DEBUG
void (^_loggerBlock)(NSString *) = ^void(NSString *message) { NSLog(@"=== TrustKit: %@", message); };
#else
void (^_loggerBlock)(NSString *) = NULL;
#endif

// The logging function we use within TrustKit
void TSKLog(NSString *format, ...)
{
    if (_loggerBlock) {
        va_list args;
        va_start(args, format);
        NSString *message = [[NSString alloc] initWithFormat:format arguments:args];
        va_end(args);
        _loggerBlock(message);
    }
}


#pragma mark TrustKit Private API


@interface TrustKit ()
@property (nonatomic) TSKBackgroundReporter *pinFailureReporter;
@property (nonatomic) dispatch_queue_t pinFailureReporterQueue;
@property (nonatomic, readonly, nullable) NSDictionary *configuration;
@end


@implementation TrustKit


#pragma mark Singleton Initialization


+ (instancetype)sharedInstance
{
    if (!sharedTrustKit) {
        // TrustKit should only be initialized once so we don't double swizzle or get into anything unexpected
        [NSException raise:@"TrustKit was not initialized"
                    format:@"TrustKit must be initialized using +initSharedInstanceWithConfiguration: prior to accessing sharedInstance"];
    }
    return sharedTrustKit;
}

+ (void)initSharedInstanceWithConfiguration:(NSDictionary<TSKGlobalConfigurationKey, id> *)trustKitConfig
{
    TSKLog(@"Configuration passed via explicit call to initSharedInstanceWithConfiguration:");
    
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedTrustKit = [[TrustKit alloc] init];
        sharedHashCache = [[TSKSPKIHashCache alloc] initWithIdentifier:kTSKDefaultIdentifier];
        // NSURLConnection
        [TSKNSURLConnectionDelegateProxy swizzleNSURLConnectionConstructors:sharedTrustKit];
        // NSURLSession
        [TSKNSURLSessionDelegateProxy swizzleNSURLSessionConstructors:sharedTrustKit];
    });
    
    [sharedTrustKit setConfiguration:trustKitConfig];
}


#pragma mark Instance Initialization

-(instancetype)init {
    if ( self = [super init] ) {
        _pinningValidatorCallbackQueue = dispatch_get_main_queue();
        // Create a dispatch queue for activating the reporter
        // We use a serial queue targetting the global default queue in order to ensure reports are sent one by one
        // even when a lot of pin failures are occuring, instead of spamming the global queue with events to process
        _pinFailureReporterQueue = dispatch_queue_create(kTSKPinFailureReporterQueueLabel, DISPATCH_QUEUE_SERIAL);
        
        // Create our reporter for sending pin validation failures; do this before hooking NSURLSession so we don't hook ourselves
        _pinFailureReporter = [[TSKBackgroundReporter alloc] initAndRateLimitReports:YES
                                                           sharedContainerIdentifier:kTSKDefaultIdentifier];
        
    }
    return self;
}

- (void)setConfiguration:(NSDictionary<TSKGlobalConfigurationKey, id> *)trustKitConfig
{
    NSParameterAssert(trustKitConfig);
    if (!trustKitConfig) {
        return;
    }
    
    if (self && [trustKitConfig count] > 0) {
        // Convert and store the SSL pins in our global variable
        _configuration = parseTrustKitConfiguration(trustKitConfig);
        
        // Handle global configuration flags here
        // TSKIgnorePinningForUserDefinedTrustAnchors
#if TARGET_OS_IPHONE
        BOOL userTrustAnchorBypass = NO;
#else
        BOOL userTrustAnchorBypass = [_configuration[kTSKIgnorePinningForUserDefinedTrustAnchors] boolValue];
#endif
        
        __weak typeof(self) weakSelf = self;
        _pinningValidator = [[TSKPinningValidator alloc] initWithDomainPinningPolicies:_configuration[kTSKPinnedDomains]
                                                                             hashCache:sharedHashCache
                                                         ignorePinsForUserTrustAnchors:userTrustAnchorBypass
                                                               validationCallbackQueue:_pinFailureReporterQueue
                                                                    validationCallback:^(TSKPinningValidatorResult * _Nonnull result, NSString * _Nonnull notedHostname, TKSDomainPinningPolicy *_Nonnull notedHostnamePinningPolicy) {
                                                                        typeof(self) strongSelf = weakSelf;
                                                                        if (!strongSelf) {
                                                                            return;
                                                                        }
                                                                        
                                                                        // Invoke client handler if set
                                                                        TSKPinningValidatorCallback userDefinedCallback = strongSelf.pinningValidatorCallback;
                                                                        if (userDefinedCallback) {
                                                                            dispatch_async(strongSelf.pinningValidatorCallbackQueue, ^{
                                                                                userDefinedCallback(result, notedHostname, notedHostnamePinningPolicy);
                                                                            });
                                                                        }
                                                                        
                                                                        // Send analytics report
                                                                        [strongSelf sendValidationReport:result
                                                                                           notedHostname:notedHostname
                                                                                           pinningPolicy:notedHostnamePinningPolicy];
                                                                    }];
        
        TSKLog(@"Successfully initialized with configuration %@", _configuration);
    }
}


#pragma mark Validation Callback


// The block which receives pin validation results and turns them into pin validation reports
- (void)sendValidationReport:(TSKPinningValidatorResult *)result notedHostname:(NSString *)notedHostname pinningPolicy:(NSDictionary<TSKDomainConfigurationKey, id> *)notedHostnamePinningPolicy
{
    TSKTrustEvaluationResult validationResult = result.evaluationResult;
    
    // Send a report only if the there was a pinning failure
    if (validationResult != TSKTrustEvaluationSuccess)
    {
#if !TARGET_OS_IPHONE
        if (validationResult != TSKTrustEvaluationFailedUserDefinedTrustAnchor)
#endif
        {
            // Pin validation failed: retrieve the list of configured report URLs
            NSMutableArray *reportUris = [NSMutableArray arrayWithArray:notedHostnamePinningPolicy[kTSKReportUris]];
            // Do not report to default
            // Also enable the default reporting URL
//            if ([notedHostnamePinningPolicy[kTSKDisableDefaultReportUri] boolValue] == NO)
//            {
//                [reportUris addObject:[NSURL URLWithString:kTSKDefaultReportUri]];
//            }
            
            // If some report URLs have been defined, send the pin failure report
            if (reportUris.count > 0)
            {
                [self.pinFailureReporter pinValidationFailedForHostname:result.serverHostname
                                                                   port:nil
                                                       certificateChain:result.certificateChain
                                                          notedHostname:notedHostname
                                                             reportURIs:reportUris
                                                      includeSubdomains:[notedHostnamePinningPolicy[kTSKIncludeSubdomains] boolValue]
                                                         enforcePinning:[notedHostnamePinningPolicy[kTSKEnforcePinning] boolValue]
                                                              knownPins:notedHostnamePinningPolicy[kTSKPublicKeyHashes]
                                                       validationResult:validationResult
                                                         expirationDate:notedHostnamePinningPolicy[kTSKExpirationDate]];
            }
        }
    }
}

- (void)setPinningValidatorCallbackQueue:(dispatch_queue_t)pinningValidatorCallbackQueue
{
    _pinningValidatorCallbackQueue = pinningValidatorCallbackQueue ?: dispatch_get_main_queue();
}


#pragma mark Configuring Logging


+ (void)setLoggerBlock:(void (^)(NSString *))block
{
    _loggerBlock = block;
}

@end
