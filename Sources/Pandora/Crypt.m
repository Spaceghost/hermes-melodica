#import "Crypt.h"
#include "melodica/blowfish.c"
#include "melodica/wire.c"

static int hexDigit(unichar ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

NSData *PandoraDecryptString(NSString *string, NSString *key) {
  if (string.length % 16) return nil;
  NSMutableData *data = [NSMutableData dataWithLength:string.length / 2];
  uint8_t *bytes = data.mutableBytes;
  for (NSUInteger i = 0; i < data.length; i++) {
    int hi = hexDigit([string characterAtIndex:i*2]);
    int lo = hexDigit([string characterAtIndex:i*2+1]);
    if (hi < 0 || lo < 0) return nil;
    bytes[i] = (hi << 4) | lo;
  }
  NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
  return melodica_wire_blocks(bytes, data.length, keyData.bytes, keyData.length, 1) ? data : nil;
}

NSData *PandoraEncryptData(NSData *input, NSString *key) {
  static const char hex[] = "0123456789abcdef";
  NSMutableData *padded = [input mutableCopy];
  [padded setLength:((input.length + 7) / 8) * 8];
  NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
  if (!melodica_wire_blocks(padded.mutableBytes, padded.length, keyData.bytes, keyData.length, 0)) return nil;
  NSMutableData *result = [NSMutableData dataWithLength:padded.length * 2];
  const uint8_t *from = padded.bytes;
  char *to = result.mutableBytes;
  for (NSUInteger i = 0; i < padded.length; i++) {
    to[2*i] = hex[from[i] >> 4];
    to[2*i+1] = hex[from[i] & 15];
  }
  return result;
}
