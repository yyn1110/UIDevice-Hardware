//
//  NSString+Utils.m
//  KXShow
//
//  Created by guo xiaojie on 11-5-5.
//  Copyright 2011年 kuxing.com. All rights reserved.
//

#import "NSString+Utils.h"
#include <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import "GTMBase64.h"

typedef struct {
	NSString *escapeSequence;
	unichar uchar;
} HTMLEscapeMap;

// Taken from http://www.w3.org/TR/xhtml1/dtds.html#a_dtd_Special_characters
// Ordered by uchar lowest to highest for bsearching
static HTMLEscapeMap gAsciiHTMLEscapeMap[] = {
	// A.2.2. Special characters
	{ @"&quot;", 34 },
	{ @"&amp;", 38 },
	{ @"&apos;", 39 },
	{ @"&lt;", 60 },
	{ @"&gt;", 62 },
	
    // A.2.1. Latin-1 characters
	{ @"&nbsp;", 160 }, 
	{ @"&iexcl;", 161 }, 
	{ @"&cent;", 162 }, 
	{ @"&pound;", 163 }, 
	{ @"&curren;", 164 }, 
	{ @"&yen;", 165 }, 
	{ @"&brvbar;", 166 }, 
	{ @"&sect;", 167 }, 
	{ @"&uml;", 168 }, 
	{ @"&copy;", 169 }, 
	{ @"&ordf;", 170 }, 
	{ @"&laquo;", 171 }, 
	{ @"&not;", 172 }, 
	{ @"&shy;", 173 }, 
	{ @"&reg;", 174 }, 
	{ @"&macr;", 175 }, 
	{ @"&deg;", 176 }, 
	{ @"&plusmn;", 177 }, 
	{ @"&sup2;", 178 }, 
	{ @"&sup3;", 179 }, 
	{ @"&acute;", 180 }, 
	{ @"&micro;", 181 }, 
	{ @"&para;", 182 }, 
	{ @"&middot;", 183 }, 
	{ @"&cedil;", 184 }, 
	{ @"&sup1;", 185 }, 
	{ @"&ordm;", 186 }, 
	{ @"&raquo;", 187 }, 
	{ @"&frac14;", 188 }, 
	{ @"&frac12;", 189 }, 
	{ @"&frac34;", 190 }, 
	{ @"&iquest;", 191 }, 
	{ @"&Agrave;", 192 }, 
	{ @"&Aacute;", 193 }, 
	{ @"&Acirc;", 194 }, 
	{ @"&Atilde;", 195 }, 
	{ @"&Auml;", 196 }, 
	{ @"&Aring;", 197 }, 
	{ @"&AElig;", 198 }, 
	{ @"&Ccedil;", 199 }, 
	{ @"&Egrave;", 200 }, 
	{ @"&Eacute;", 201 }, 
	{ @"&Ecirc;", 202 }, 
	{ @"&Euml;", 203 }, 
	{ @"&Igrave;", 204 }, 
	{ @"&Iacute;", 205 }, 
	{ @"&Icirc;", 206 }, 
	{ @"&Iuml;", 207 }, 
	{ @"&ETH;", 208 }, 
	{ @"&Ntilde;", 209 }, 
	{ @"&Ograve;", 210 }, 
	{ @"&Oacute;", 211 }, 
	{ @"&Ocirc;", 212 }, 
	{ @"&Otilde;", 213 }, 
	{ @"&Ouml;", 214 }, 
	{ @"&times;", 215 }, 
	{ @"&Oslash;", 216 }, 
	{ @"&Ugrave;", 217 }, 
	{ @"&Uacute;", 218 }, 
	{ @"&Ucirc;", 219 }, 
	{ @"&Uuml;", 220 }, 
	{ @"&Yacute;", 221 }, 
	{ @"&THORN;", 222 }, 
	{ @"&szlig;", 223 }, 
	{ @"&agrave;", 224 }, 
	{ @"&aacute;", 225 }, 
	{ @"&acirc;", 226 }, 
	{ @"&atilde;", 227 }, 
	{ @"&auml;", 228 }, 
	{ @"&aring;", 229 }, 
	{ @"&aelig;", 230 }, 
	{ @"&ccedil;", 231 }, 
	{ @"&egrave;", 232 }, 
	{ @"&eacute;", 233 }, 
	{ @"&ecirc;", 234 }, 
	{ @"&euml;", 235 }, 
	{ @"&igrave;", 236 }, 
	{ @"&iacute;", 237 }, 
	{ @"&icirc;", 238 }, 
	{ @"&iuml;", 239 }, 
	{ @"&eth;", 240 }, 
	{ @"&ntilde;", 241 }, 
	{ @"&ograve;", 242 }, 
	{ @"&oacute;", 243 }, 
	{ @"&ocirc;", 244 }, 
	{ @"&otilde;", 245 }, 
	{ @"&ouml;", 246 }, 
	{ @"&divide;", 247 }, 
	{ @"&oslash;", 248 }, 
	{ @"&ugrave;", 249 }, 
	{ @"&uacute;", 250 }, 
	{ @"&ucirc;", 251 }, 
	{ @"&uuml;", 252 }, 
	{ @"&yacute;", 253 }, 
	{ @"&thorn;", 254 }, 
	{ @"&yuml;", 255 },
	
	// A.2.2. Special characters cont'd
	{ @"&OElig;", 338 },
	{ @"&oelig;", 339 },
	{ @"&Scaron;", 352 },
	{ @"&scaron;", 353 },
	{ @"&Yuml;", 376 },
	
	// A.2.3. Symbols
	{ @"&fnof;", 402 }, 
	
	// A.2.2. Special characters cont'd
	{ @"&circ;", 710 },
	{ @"&tilde;", 732 },
	
	// A.2.3. Symbols cont'd
	{ @"&Alpha;", 913 }, 
	{ @"&Beta;", 914 }, 
	{ @"&Gamma;", 915 }, 
	{ @"&Delta;", 916 }, 
	{ @"&Epsilon;", 917 }, 
	{ @"&Zeta;", 918 }, 
	{ @"&Eta;", 919 }, 
	{ @"&Theta;", 920 }, 
	{ @"&Iota;", 921 }, 
	{ @"&Kappa;", 922 }, 
	{ @"&Lambda;", 923 }, 
	{ @"&Mu;", 924 }, 
	{ @"&Nu;", 925 }, 
	{ @"&Xi;", 926 }, 
	{ @"&Omicron;", 927 }, 
	{ @"&Pi;", 928 }, 
	{ @"&Rho;", 929 }, 
	{ @"&Sigma;", 931 }, 
	{ @"&Tau;", 932 }, 
	{ @"&Upsilon;", 933 }, 
	{ @"&Phi;", 934 }, 
	{ @"&Chi;", 935 }, 
	{ @"&Psi;", 936 }, 
	{ @"&Omega;", 937 }, 
	{ @"&alpha;", 945 }, 
	{ @"&beta;", 946 }, 
	{ @"&gamma;", 947 }, 
	{ @"&delta;", 948 }, 
	{ @"&epsilon;", 949 }, 
	{ @"&zeta;", 950 }, 
	{ @"&eta;", 951 }, 
	{ @"&theta;", 952 }, 
	{ @"&iota;", 953 }, 
	{ @"&kappa;", 954 }, 
	{ @"&lambda;", 955 }, 
	{ @"&mu;", 956 }, 
	{ @"&nu;", 957 }, 
	{ @"&xi;", 958 }, 
	{ @"&omicron;", 959 }, 
	{ @"&pi;", 960 }, 
	{ @"&rho;", 961 }, 
	{ @"&sigmaf;", 962 }, 
	{ @"&sigma;", 963 }, 
	{ @"&tau;", 964 }, 
	{ @"&upsilon;", 965 }, 
	{ @"&phi;", 966 }, 
	{ @"&chi;", 967 }, 
	{ @"&psi;", 968 }, 
	{ @"&omega;", 969 }, 
	{ @"&thetasym;", 977 }, 
	{ @"&upsih;", 978 }, 
	{ @"&piv;", 982 }, 
	
	// A.2.2. Special characters cont'd
	{ @"&ensp;", 8194 },
	{ @"&emsp;", 8195 },
	{ @"&thinsp;", 8201 },
	{ @"&zwnj;", 8204 },
	{ @"&zwj;", 8205 },
	{ @"&lrm;", 8206 },
	{ @"&rlm;", 8207 },
	{ @"&ndash;", 8211 },
	{ @"&mdash;", 8212 },
	{ @"&lsquo;", 8216 },
	{ @"&rsquo;", 8217 },
	{ @"&sbquo;", 8218 },
	{ @"&ldquo;", 8220 },
	{ @"&rdquo;", 8221 },
	{ @"&bdquo;", 8222 },
	{ @"&dagger;", 8224 },
	{ @"&Dagger;", 8225 },
    // A.2.3. Symbols cont'd  
	{ @"&bull;", 8226 }, 
	{ @"&hellip;", 8230 }, 
	
	// A.2.2. Special characters cont'd
	{ @"&permil;", 8240 },
	
	// A.2.3. Symbols cont'd  
	{ @"&prime;", 8242 }, 
	{ @"&Prime;", 8243 }, 
	
	// A.2.2. Special characters cont'd
	{ @"&lsaquo;", 8249 },
	{ @"&rsaquo;", 8250 },
	
	// A.2.3. Symbols cont'd  
	{ @"&oline;", 8254 }, 
	{ @"&frasl;", 8260 }, 
	
	// A.2.2. Special characters cont'd
	{ @"&euro;", 8364 },
	
	// A.2.3. Symbols cont'd  
	{ @"&image;", 8465 },
	{ @"&weierp;", 8472 }, 
	{ @"&real;", 8476 }, 
	{ @"&trade;", 8482 }, 
	{ @"&alefsym;", 8501 }, 
	{ @"&larr;", 8592 }, 
	{ @"&uarr;", 8593 }, 
	{ @"&rarr;", 8594 }, 
	{ @"&darr;", 8595 }, 
	{ @"&harr;", 8596 }, 
	{ @"&crarr;", 8629 }, 
	{ @"&lArr;", 8656 }, 
	{ @"&uArr;", 8657 }, 
	{ @"&rArr;", 8658 }, 
	{ @"&dArr;", 8659 }, 
	{ @"&hArr;", 8660 }, 
	{ @"&forall;", 8704 }, 
	{ @"&part;", 8706 }, 
	{ @"&exist;", 8707 }, 
	{ @"&empty;", 8709 }, 
	{ @"&nabla;", 8711 }, 
	{ @"&isin;", 8712 }, 
	{ @"&notin;", 8713 }, 
	{ @"&ni;", 8715 }, 
	{ @"&prod;", 8719 }, 
	{ @"&sum;", 8721 }, 
	{ @"&minus;", 8722 }, 
	{ @"&lowast;", 8727 }, 
	{ @"&radic;", 8730 }, 
	{ @"&prop;", 8733 }, 
	{ @"&infin;", 8734 }, 
	{ @"&ang;", 8736 }, 
	{ @"&and;", 8743 }, 
	{ @"&or;", 8744 }, 
	{ @"&cap;", 8745 }, 
	{ @"&cup;", 8746 }, 
	{ @"&int;", 8747 }, 
	{ @"&there4;", 8756 }, 
	{ @"&sim;", 8764 }, 
	{ @"&cong;", 8773 }, 
	{ @"&asymp;", 8776 }, 
	{ @"&ne;", 8800 }, 
	{ @"&equiv;", 8801 }, 
	{ @"&le;", 8804 }, 
	{ @"&ge;", 8805 }, 
	{ @"&sub;", 8834 }, 
	{ @"&sup;", 8835 }, 
	{ @"&nsub;", 8836 }, 
	{ @"&sube;", 8838 }, 
	{ @"&supe;", 8839 }, 
	{ @"&oplus;", 8853 }, 
	{ @"&otimes;", 8855 }, 
	{ @"&perp;", 8869 }, 
	{ @"&sdot;", 8901 }, 
	{ @"&lceil;", 8968 }, 
	{ @"&rceil;", 8969 }, 
	{ @"&lfloor;", 8970 }, 
	{ @"&rfloor;", 8971 }, 
	{ @"&lang;", 9001 }, 
	{ @"&rang;", 9002 }, 
	{ @"&loz;", 9674 }, 
	{ @"&spades;", 9824 }, 
	{ @"&clubs;", 9827 }, 
	{ @"&hearts;", 9829 }, 
	{ @"&diams;", 9830 }
};

@implementation NSString (Utils)

- (NSString *)md5Sum {
	unsigned char digest[CC_MD5_DIGEST_LENGTH], i;
	CC_MD5([self UTF8String], (uint32_t)[self lengthOfBytesUsingEncoding:NSUTF8StringEncoding], digest);
	NSMutableString *ms = [NSMutableString string];
	for (i=0;i<CC_MD5_DIGEST_LENGTH;i++) {
		[ms appendFormat: @"%02x", (int)(digest[i])];
	}
	return [[ms copy] autorelease];
}

+ (NSString *)encodeBase64:(NSString*)input 
{ 
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES]; 
    data = [GTMBase64 encodeData:data]; 
    NSString * base64String = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease]; 
    return base64String; 
}
+ (NSString *)encodeBase64WithData:(NSData *)input
{
    NSData *data = [GTMBase64 encodeData:input];
    NSString * base64String = [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] autorelease];
    return base64String;
}
+ (NSString *)hmac_sha1:(NSString *)key text:(NSString *)text
{
    const char *cKey  = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [text cStringUsingEncoding:NSUTF8StringEncoding];
    
    char cHMAC[CC_SHA1_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA1, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:CC_SHA1_DIGEST_LENGTH];
    NSData *hash = [GTMBase64 encodeData:HMAC];
    [HMAC release];
    return [[[NSString alloc] initWithData:hash encoding:NSUTF8StringEncoding] autorelease];
}
-(NSString *) urlEncode
{
    NSString *encodedString = (NSString *)CFURLCreateStringByAddingPercentEscapes( NULL, (CFStringRef)self, NULL, (CFStringRef)@"!*'();:@&=+$,/?%#[]", kCFStringEncodingUTF8 );
    return [encodedString autorelease];
}
- (NSString *)urlDecode
{
	NSString *result = (NSString *)CFURLCreateStringByReplacingPercentEscapesUsingEncoding(kCFAllocatorDefault,(CFStringRef)self,CFSTR(""),kCFStringEncodingUTF8);
    [result autorelease];
	return result;
}
+ (NSString *)generateTimestamp
{
    return [NSString stringWithFormat:@"%ld", time(NULL)];
}
+ (NSString *)generateNonce
{
	 return [[NSString stringWithFormat:@"%ld%ld", time(NULL), random()] md5Sum];
}

- (NSString *)gtm_stringByUnescapingFromHTML 
{
	NSRange range = NSMakeRange(0, [self length]);
	NSRange subrange = [self rangeOfString:@"&" options:NSBackwardsSearch range:range];
	
	// if no ampersands, we've got a quick way out
	if (subrange.length == 0) return self;
	NSMutableString *finalString = [NSMutableString stringWithString:self];
	do {
		NSRange semiColonRange = NSMakeRange(subrange.location, NSMaxRange(range) - subrange.location);
		semiColonRange = [self rangeOfString:@";" options:0 range:semiColonRange];
		range = NSMakeRange(0, subrange.location);
		// if we don't find a semicolon in the range, we don't have a sequence
		if (semiColonRange.location == NSNotFound) {
			continue;
		}
		NSRange escapeRange = NSMakeRange(subrange.location, semiColonRange.location - subrange.location + 1);
		NSString *escapeString = [self substringWithRange:escapeRange];
		NSUInteger length = [escapeString length];
		// a squence must be longer than 3 (&lt;) and less than 11 (&thetasym;)
		if (length > 3 && length < 11) {
			if ([escapeString characterAtIndex:1] == '#') {
				unichar char2 = [escapeString characterAtIndex:2];
				if (char2 == 'x' || char2 == 'X') {
					// Hex escape squences &#xa3;
					NSString *hexSequence = [escapeString substringWithRange:NSMakeRange(3, length - 4)];
					NSScanner *scanner = [NSScanner scannerWithString:hexSequence];
					unsigned value;
					if ([scanner scanHexInt:&value] && 
						value < USHRT_MAX &&
						value > 0 
						&& [scanner scanLocation] == length - 4) {
						unichar uchar = value;
						NSString *charString = [NSString stringWithCharacters:&uchar length:1];
						[finalString replaceCharactersInRange:escapeRange withString:charString];
					}
					
				} else {
					// Decimal Sequences &#123;
					NSString *numberSequence = [escapeString substringWithRange:NSMakeRange(2, length - 3)];
					NSScanner *scanner = [NSScanner scannerWithString:numberSequence];
					int value;
					if ([scanner scanInt:&value] && 
						value < USHRT_MAX &&
						value > 0 
						&& [scanner scanLocation] == length - 3) {
						unichar uchar = value;
						NSString *charString = [NSString stringWithCharacters:&uchar length:1];
						[finalString replaceCharactersInRange:escapeRange withString:charString];
					}
				}
			} else {
				// "standard" sequences
				for (unsigned i = 0; i < sizeof(gAsciiHTMLEscapeMap) / sizeof(HTMLEscapeMap); ++i) {
					if ([escapeString isEqualToString:gAsciiHTMLEscapeMap[i].escapeSequence]) {
						[finalString replaceCharactersInRange:escapeRange withString:[NSString stringWithCharacters:&gAsciiHTMLEscapeMap[i].uchar length:1]];
						break;
					}
				}
			}
		}
	} while ((subrange = [self rangeOfString:@"&" options:NSBackwardsSearch range:range]).length != 0);
	return finalString;
} // gtm_stringByUnescapingHTML

+ (NSDictionary *)params:(NSString *)str
{
	//解析string "type=comment&id=130019817"到dict
		
	NSMutableDictionary *dic = [[[NSMutableDictionary alloc]initWithCapacity:3]autorelease];
	
	if([str length])
	{		
		NSArray *pairs = [str componentsSeparatedByString:@"&"];
		
		if(pairs && [pairs count])
		{
			int count = (int)[pairs count];
			for (int i=0 ; i<count ; i++)
			{
				NSString *pair = [pairs objectAtIndex:i];
				NSArray *keyValue = [ pair componentsSeparatedByString:@"="];
				//[dic setObject:[keyValue objectAtIndex:1] forKey:[keyValue objectAtIndex:0]];				
				[dic setObject:[pair substringFromIndex:[[keyValue objectAtIndex:0] length] + 1] forKey:[keyValue objectAtIndex:0]];
			}
		}
	}
	
	return dic;
}
- (NSString *)stringByTrimmingLeadingCharactersInSet:(NSCharacterSet *)characterSet {
    NSRange rangeOfFirstWantedCharacter = [self rangeOfCharacterFromSet:[characterSet invertedSet]];
    if (rangeOfFirstWantedCharacter.location == NSNotFound) {
        return @"";
    }
    return [self substringFromIndex:rangeOfFirstWantedCharacter.location];
}

- (NSString *)stringByTrimmingLeadingWhitespaceAndNewlineCharacters {
    return [self stringByTrimmingLeadingCharactersInSet:
            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

- (NSString *)stringByTrimmingTrailingCharactersInSet:(NSCharacterSet *)characterSet {
    NSRange rangeOfLastWantedCharacter = [self rangeOfCharacterFromSet:[characterSet invertedSet]
                                                               options:NSBackwardsSearch];
    if (rangeOfLastWantedCharacter.location == NSNotFound) {
        return @"";
    }
    return [self substringToIndex:rangeOfLastWantedCharacter.location+1]; // non-inclusive
}

- (NSString *)stringByTrimmingTrailingWhitespaceAndNewlineCharacters {
    return [self stringByTrimmingTrailingCharactersInSet:
            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

- (NSString *)trim {
	return [self stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

- (BOOL)isNullOrEmpty
{
	if (self == nil || self == (NSString *)[NSNull null] || !self.length || [self isEqualToString:@""]) {
		return YES;
	}
	
	return NO;
}

- (NSString *)encodeUnicode {  
    CFStringRef nonAlphaNumValidChars = CFSTR("![        DISCUZ_CODE_1        ]’()*+,-./:;=?@_~&");          
    NSString *preprocessedString = (NSString *)CFURLCreateStringByReplacingPercentEscapesUsingEncoding(kCFAllocatorDefault, (CFStringRef)self, CFSTR(""), kCFStringEncodingUTF8);          
    NSString *newStr = [(NSString *)CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault,(CFStringRef)preprocessedString,NULL,nonAlphaNumValidChars,kCFStringEncodingUTF8) autorelease];  
    [preprocessedString release];  
    return newStr;          
}

- (NSString *)decodeUnicode {  
    NSString *tempStr2 = [[self stringByReplacingOccurrencesOfString:@"\\u" withString:@"\\U"] stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];  
    NSString *tempStr3 = [[@"\"" stringByAppendingString:tempStr2] stringByAppendingString:@"\""];  
    NSData   *tempData = [tempStr3 dataUsingEncoding:NSUTF8StringEncoding];  
    NSString* returnStr = [NSPropertyListSerialization propertyListFromData:tempData  
                                                           mutabilityOption:NSPropertyListImmutable  
                                                                     format:NULL  
                                                           errorDescription:NULL];
    return [returnStr stringByReplacingOccurrencesOfString:@"\\r\\n" withString:@"\n"];  
}
- (NSString*)hexRepresentationWithSpaces_AS:(BOOL)spaces
{
    const unsigned char* bytes = (const unsigned char*)[self UTF8String];
    NSUInteger nbBytes = [self length];
    //If spaces is true, insert a space every this many input bytes (twice this many output characters).
    static const NSUInteger spaceEveryThisManyBytes = 4UL;
    //If spaces is true, insert a line-break instead of a space every this many spaces.
    static const NSUInteger lineBreakEveryThisManySpaces = 4UL;
    const NSUInteger lineBreakEveryThisManyBytes = spaceEveryThisManyBytes * lineBreakEveryThisManySpaces;
    NSUInteger strLen = 2*nbBytes + (spaces ? nbBytes/spaceEveryThisManyBytes : 0);
    
    NSMutableString* hex = [[NSMutableString alloc] initWithCapacity:strLen];
    for(NSUInteger i=0; i<nbBytes; ) {
        [hex appendFormat:@"%02X", bytes[i]];
        //We need to increment here so that the every-n-bytes computations are right.
        ++i;
        
        if (spaces) {
            if (i % lineBreakEveryThisManyBytes == 0) [hex appendString:@"\n"];
            else if (i % spaceEveryThisManyBytes == 0) [hex appendString:@" "];
        }
    }
    return [hex autorelease];
}
@end
