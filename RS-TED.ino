#include <FastCRC_cpu.h>
#include <FastCRC.h>
#include <FastCRC_tables.h>

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
#include "src/mbedtls/aes.h"
#include "RS-TED.h"
#define HWSERIAL Serial3
#define USBSerial Serial
#define baud_rate 57600

/* wait time could be a function of baud rate and remaining bits, so we know
 * if we've missed a bit (or byte) immediatly.  Bits/bytes won't be late, 
 * but they will most likely get lost (satellite radio communication isn't
 * 100% reliable, sources tell us its ~70% for some cubesats, so some data
 * (~30%) will most likely be lost).
 */
#define wait_time 512

int byte_num = 0;
mbedtls_aes_context ctx;
FastCRC16 CRC16;

// used as a wrapper for sending encrypted data, so we can include a hash
// of the encrypted data to ensure data integrity.
Packet packet;
// serves as the input for encrypt
Payload payload;
// serves as the output for decrypt
Payload plaintext_payload;
// serves as the output for encrypt
Payload encrypted_payload;

// This code reads in data from an emulated serial port
// (Serial), encrypts it, and writes it out through a hardware
// serial port (HWSERIAL), inside of a packet which will eventually
// contain a hash of the data for error checking.  Currently, the hash
// is present, but checking is not enabled.

void setup() {
  USBSerial.begin(baud_rate);
  HWSERIAL.begin(baud_rate);
  // do nothing until the Serial initializes
  while (!HWSERIAL && !Serial);
  // wait one second after the Serial initialization
  delay(1000);
  // enable flow control - this may be helpful if you're loosing data.
  //  HWSERIAL.attachRts(18);
  //  HWSERIAL.attachCts(19);
  // init the context...
  mbedtls_aes_init( &ctx );
  // Set the key and the cipher mode (AES). 
  // Since ctr is symmetrical, can use enc for encryption and decryption.
  mbedtls_aes_setkey_enc( &ctx, key, KEYLENGTH);

  // Setup some defaults in the packet struct and payload struct.
  packet.payload.encryption = 1;
  packet.payload.mode = PAYLOAD_MODE_NORMAL;
  packet.payload_hash = 0;
}


void passthrough(){
  if (HWSERIAL.available() > 0){
    USBSerial.write(HWSERIAL.read());
  }
}

void encrypt(){
  if (USBSerial.available() > 0) {
    // elapsedMillis are automatically incremented and tracked
    // by the teensy's RTC, so no need to increment these manually
    elapsedMillis timeout;
    while (timeout < wait_time && byte_num < 16){
      /* ready to receive data and ready to send it, read it in from the buffer */
      if(USBSerial.available() > 0 && (HWSERIAL.availableForWrite() - byte_num) > 0){
        packet.payload.message[byte_num] = USBSerial.read();
        byte_num++;
        timeout = 0;
      } else if (USBSerial.available() > 0){
        /* data to be received, but cannot send it yet, so reset our timeout */
        timeout = 0;
      }
    }
  }

  if (byte_num > 0) {
    packet.payload.size = byte_num;
    /* note - this seems to be little endian (reversed)
     * for some strange reason - only this piece. Everything else appears as 
     * big (network) endian. This is only relevant for cross-platform usage.
     */
    packet.payload.plaintext_hash = CRC16.x25((uint8_t*)&packet.payload.message, byte_num);
    /* make sure we've enabled encryption and have the correct payload mode.
     * This is necesary since it is clobered by the encryption, as it outputs
     * back into this struct's same memory location.
     */
    packet.payload.encryption = 1;
    packet.payload.mode = PAYLOAD_MODE_NORMAL;
    /* encrypt the whole payload, since we don't know what endian type we're on.
     * This is alright without padding, since on the other end, we have the size
     * of the ciphertext that we care about inside the payload, so we can extract 
     * what we want. In reality, we will send a small amount of extra data when 
     * we're not 16 byte aligned.
     * 
     *  From the documentation:
     *   You can handle everything as a single message processed over
     *   successive calls to this function. In that case, you want to
     *   set \p nonce_counter and \p nc_off to 0 for the first call, and
     *   then preserve the values of \p nonce_counter, \p nc_off and \p
     *   stream_block across calls to this function as they will be
     *   updated by this function.
     *   With this strategy, you must not encrypt more than 2**128
     *   blocks of data with the same key.
     *   
     *  So doing things this way is fine, as long as we send less than 
     *  2^128 bytes of data (at minimum, each packet could have 16 bytes),
     *  and even if we send that much data, we can rotate keys (or nonces) 
     *  every 2^128 packets.  2^128 is really, really big though so even
     *  without key/nonce rotation we're (very) safe, especially at 57600baud,
     *  since it will take us (approximately) 10^25 centuries to send 
     *  2^128 bytes at 57600 baud.
     */
    mbedtls_aes_crypt_ctr(&ctx, sizeof(Payload), &nc_off, nonce, stream_block, 
                          (unsigned char *)&packet.payload, 
                          (unsigned char *)&packet.payload);
    /* calculate the checksum for the encrypted payload - can be used to detect transmission problems */
    packet.payload_hash == CRC16.x25((uint8_t*) &packet.payload, sizeof(packet.payload));
    /* send the whole packet struct, which contains the payload encrypted above. */
    HWSERIAL.write((char*)&packet, sizeof(Packet));
    byte_num = 0;
    /* we have to reset the message value, since we might not use it all next loop,
     * and it should be all zero in that case.
     */
    memset(&packet.payload.message, 0, 16);
  }
}

void decrypt(){
  if (HWSERIAL.available() > 0) {
    // elapsedMillis are automatically incremented and tracked
    // by the teensy's RTC, so no need to increment these manually
    elapsedMillis timeout;
    while (timeout < wait_time && byte_num < sizeof(Packet)){
      if(HWSERIAL.available() > 0){
        /* write the data byte by byte into the memory for the packet
         *  struct.  Need to cast to char* so that we can access by byte
         *  instead of by Packet.
         */
        ((char *)&packet)[byte_num] = HWSERIAL.read();
        byte_num++;
        timeout = 0;
      }
    }
  }
  if (byte_num > 0) {
// the transmission error code is commented out since there were problems with it - needs to be debugged!
//    if(packet.payload_hash == CRC8.smbus((uint8_t*) &packet.payload, sizeof(packet.payload))){
      mbedtls_aes_crypt_ctr(&ctx, sizeof(Payload), &nc_off, nonce, stream_block, 
                            (unsigned char *)&packet.payload, 
                            (unsigned char *)&plaintext_payload);
      /* We want to make sure that if a packet is lost, we don't lose track of our
       *  counter.  We can do this by bruteforcing our own counter, starting at the
       *  current value (this is a separate checksum from the sent packet's hash - this
       *  checksum makes sure we're decrypting data correctly, the packet's makes sure
       *  we received data correctly). 
       */
      
      /* Ideally, error messages / successes shouldn't end up in the data stream,
       * as they should either silently fail and retry, or go and tell someone
       * who can do something about it (the sender) after a number of retries.  
       * This should probably happen with some sort of message to the flight 
       * compute  r, or the groundstation controller, but for our purposes, this 
       * allows us to see when things work or don't. These prints should be 
       * commented out for sending binary data, as they'll pollute the datastream.
       * For a text stream, it is much easier differentiate valid data and print
       * statements.
       */
      while(plaintext_payload.plaintext_hash != CRC16.x25((uint8_t*)&plaintext_payload.message, plaintext_payload.size)){
        USBSerial.println("Message (plaintext) hash check failed.  We've probably missed a packet, and our count is off!");
        /* rerun our decryption - counter is already increased by one. */
        mbedtls_aes_crypt_ctr(&ctx, sizeof(Payload), &nc_off, nonce, stream_block, 
                      (unsigned char *)&packet.payload, 
                      (unsigned char *)&plaintext_payload);
      }
      USBSerial.println("Message (plaintext) hash check succeeded...");
      USBSerial.write(plaintext_payload.message, plaintext_payload.size);
//    } else{
//      /* there was a transmission error - this needs to be signalled to the ground / FC in some way. */
//      USBSerial.println("Message (plaintext) hash check failed.  We've probably missed a packet, and our count is off!");
//    }
    
    byte_num = 0;
    /* we have to reset the packet value, since we might not use it all next loop,
     * and it should be all zero in that case
     */
    memset(&packet, 0, sizeof(Packet));
  }
}

void loop() {
//  encrypt();
  passthrough();
  // right now its not a two way communication channel - swap to calling 'decrypt()' for the decryption teensy 
}
