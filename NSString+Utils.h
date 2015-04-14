//
//  NSString+Utils.h
//  KXShow
//
//  Created by guo xiaojie on 11-5-5.
//  Copyright 2011年 kuxing.com. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (Utils)
- (NSString *)md5Sum;
+ (NSString *)encodeBase64:(NSString*)input;
+ (NSString *)encodeBase64WithData:(NSData *)input;
+ (NSString *)hmac_sha1:(NSString *)key text:(NSString *)text;
- (NSString *)urlEncode;
- (NSString *)urlDecode;
+ (NSString *)generateTimestamp;
+ (NSString *)generateNonce;
- (NSString *)gtm_stringByUnescapingFromHTML;
+ (NSDictionary *)params:(NSString *)str;
- (NSString *)stringByTrimmingLeadingCharactersInSet:(NSCharacterSet *)characterSet;
- (NSString *)stringByTrimmingLeadingWhitespaceAndNewlineCharacters;
- (NSString *)stringByTrimmingTrailingCharactersInSet:(NSCharacterSet *)characterSet;
- (NSString *)stringByTrimmingTrailingWhitespaceAndNewlineCharacters;
- (NSString *)trim;
- (NSString *)encodeUnicode;
- (NSString *)decodeUnicode;
- (NSString *)hexRepresentationWithSpaces_AS:(BOOL)spaces;
@end
