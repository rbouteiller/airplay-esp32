/*
 * This file is part of Shairport Sync.
 * Copyright (c) Mike Brady 2019
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string.h>

// these are headers for the ALAC decoder, utilities and endian utilities
#include "ALACBitUtilities.h"
#include "ALACDecoder.h"
#include "EndianPortable.h"

#include "apple_alac.h"
typedef struct magicCookie {
  ALACSpecificConfig config;
  ALACAudioChannelLayout channelLayoutInfo; // seems to be unused
} magicCookie;

static magicCookie cookie;
static ALACDecoder *theDecoder = nullptr;

extern "C" int apple_alac_init(int32_t fmtp[12]) {
  if (!fmtp) {
    return -1;
  }

  memset(&cookie, 0, sizeof(magicCookie));

  // create a magic cookie for the decoder from the fmtp information. It seems to be in the same
  // format as a simple magic cookie

  uint32_t frame_length = fmtp[1] > 0 ? (uint32_t)fmtp[1] : 352;
  cookie.config.frameLength = Swap32NtoB(frame_length);
  cookie.config.compatibleVersion = fmtp[2];         // should be zero, uint8_t
  cookie.config.bitDepth = fmtp[3];                  // uint8_t expected to be 16
  cookie.config.pb = fmtp[4];                        // uint8_t should be 40;
  cookie.config.mb = fmtp[5];                        // uint8_t should be 10;
  cookie.config.kb = fmtp[6];                        // uint8_t should be 14;
  cookie.config.numChannels = fmtp[7];               // uint8_t expected to be 2
  cookie.config.maxRun = Swap16NtoB(fmtp[8]);        // uint16_t expected to be 255
  cookie.config.maxFrameBytes = Swap32NtoB(fmtp[9]); // uint32_t should be 0;
  cookie.config.avgBitRate = Swap32NtoB(fmtp[10]);   // uint32_t should be 0;;
  cookie.config.sampleRate = Swap32NtoB(fmtp[11]);   // uint32_t expected to be 44100;

  if (theDecoder) {
    delete theDecoder;
    theDecoder = nullptr;
  }

  theDecoder = new ALACDecoder;
  if (!theDecoder) {
    return -1;
  }
  int32_t ret = theDecoder->Init(&cookie, sizeof(magicCookie));
  if (ret != 0) {
    delete theDecoder;
    theDecoder = nullptr;
    return (int)ret;
  }

  return 0;
}

extern "C" int apple_alac_decode_frame(unsigned char *sampleBuffer, uint32_t bufferLength,
                                       unsigned char *dest, int *outsize) {
  if (!theDecoder || !sampleBuffer || !dest || !outsize) {
    return -1;
  }
  uint32_t numFrames = 0;
  BitBuffer theInputBuffer;
  BitBufferInit(&theInputBuffer, sampleBuffer, bufferLength);
  int32_t ret = theDecoder->Decode(&theInputBuffer, dest, Swap32BtoN(cookie.config.frameLength),
                                  cookie.config.numChannels, &numFrames);
  if (ret != 0) {
    *outsize = 0;
    return (int)ret;
  }
  *outsize = numFrames;
  return 0;
}

extern "C" int apple_alac_terminate() {
  if (theDecoder) {
    delete theDecoder;
    theDecoder = nullptr;
  }
  return 0;
}
