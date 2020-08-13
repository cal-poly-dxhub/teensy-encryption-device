#ifndef _RSTED_H_
#define _RSTED_H_

/* RS-TED
 * Copyright 2020 Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdint.h>

#define KEYLENGTH 256
// For AES256, this should be a 32 byte (256 bit) key
// This will eventually be changeable, hardcoding encryption keys is bad
const unsigned char key[32] = { 0x09, 0xa9, 0x4f, 0xa2, 0x5c, 0x83, 0x5c, 0x7b,
                                0x9b, 0x49, 0xab, 0x5e, 0x96, 0x58, 0xad, 0x78,
                                0x49, 0xdc, 0xaf, 0x2a, 0x6d, 0x8a, 0x89, 0xcf,
                                0xae, 0x88, 0xde, 0x72, 0xdd, 0x76, 0xdf, 0x8e};

// nonce is a 16 byte (128 bit) nonce
// this needs to be known by the decryptor
// This should be set before the device is deployed, and will eventaully be
// changeable on the fly.
unsigned char nonce[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

unsigned char byte_buf[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

unsigned char plaintext[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// nc_off is used by mbedtls for AES CTR encryption to keep track of the current offset
// in the stream block, which is used for resuming
size_t nc_off = 0;

// the stream block is used internally by mbedtls as a sort of cache
unsigned char stream_block[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* structure for the section of the packet which is encrypted when encryption 
 * is turned on.  This is sent in plaintext when encryption is disabled.
 */ 
typedef struct __attribute__((__packed__)) {
    /* one bit for whether the next packet is encrypted. 0 or 1. */
    uint8_t encryption;
    /* hash for the plaintext. */
    uint16_t plaintext_hash;
    /* Two bits for the mode of the current command.  Valid values are:
     *      Normal: 0 (binary: 00)
     *      Set Key (128): 1 (binary: 01)
     *      Set Key (256): 2 (binary: 10)
     *      Set IV: 3 (binary: 11)
     * These are defined just below this struct as macros.
     */
    uint8_t mode;
    /* size of the remaining plaintext (size of the message we're sending) */ 
    uint8_t size;
    /* ptr to the actual message being sent.  This is a "variable" length 
     * 0~256 bits, depending on the mode (it will only be greater than
     * 128 bits when sending a new key, and when we're in AES-256 mode).
     * Uses a fixed size array because we know the maximum size it'll be, 
     * so this avoids a malloc call.*/
    uint8_t message[16];
} Payload;

#define PAYLOAD_MODE_NORMAL 0
#define PAYLAOD_MODE_KEY_128 1
#define PAYLOAD_MODE_KEY_256 2
#define PAYLOAD_MODE_IV 3

/* overall structure for the packets being sent. */
typedef struct {
    uint8_t payload_hash;
    /* since we're sending the whole payload, don't need a size.  Can timeout
     * if we don't receive the whole thing, and attempt to decrypt without
     * checking the counter against the hash (TODO) */
    Payload payload;
} Packet;


/* these are the available modes for the payload */


#endif
