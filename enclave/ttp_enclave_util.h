#ifndef TTP_ENCLAVE_UTIL_H
#define TTP_ENCLAVE_UTIL_H

#include <api_crypto_types.h>
#include <stdbool.h>
#include <msgq.h>
#include <cryptography.h>

#define F_KEY_AGREEMENT  0x0
#define F_ADD_1          0x1
#define F_MNIST          0x2
#define F_EXIT           0x20

typedef struct msg_t {
  int f;
  uintptr_t args[5];
  int ret;
  bool done;
} msg_t;

typedef struct key_entry_t {
  public_key_t public_key;
  symmetric_key_t shared_key;
  stream_key_t stream_key;
  stream_nonce_t nonce;
} key_entry_t;

#define SHARED_MEM_REG (0x8a000000)
#define SHARED_REQU_QUEUE ((queue_t *) SHARED_MEM_REG)
#define SHARED_RESP_QUEUE ((queue_t *) (SHARED_MEM_REG + sizeof(queue_t)))

#endif // TTP_ENCLAVE_UTIL_H
