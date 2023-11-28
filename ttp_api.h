#ifndef TTP_API_H
#define TTP_API_H

#include <msgq.h>
#include <untrusted_util.h>
#include <local_cryptography.h>

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

void request_key_agreement(const public_key_t * public_key);
void request_add_1(const void * encrypted_msg, const size_t msg_len);
void request_mnist(const void * encrypted_msg, const size_t msg_len, const void * encrypted_results);
void request_exit(void);

void init_enclave_queues();

#endif // TTP_API_H
