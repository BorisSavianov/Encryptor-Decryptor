#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SALT_SIZE crypto_pwhash_SALTBYTES
#define KEY_SIZE crypto_aead_xchacha20poly1305_ietf_KEYBYTES
#define NONCE_SIZE crypto_aead_xchacha20poly1305_ietf_NPUBBYTES

void die(const char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(1);
}

void derive_key(const char *password, unsigned char *salt, unsigned char *key) {
  if (crypto_pwhash(key, KEY_SIZE, password, strlen(password), salt,
                    3,          // Opslimit (good baseline)
                    1ULL << 26, // Memlimit: 64 MB
                    crypto_pwhash_ALG_ARGON2ID13) != 0) {
    die("Key derivation failed");
  }
}

void encrypt_file(const char *in, const char *out, const char *password) {
  FILE *fi = fopen(in, "rb");
  if (!fi)
    die("Cannot open input file");

  FILE *fo = fopen(out, "wb");
  if (!fo)
    die("Cannot open output file");

  // Generate salt and nonce
  unsigned char salt[SALT_SIZE];
  unsigned char nonce[NONCE_SIZE];
  unsigned char key[KEY_SIZE];

  randombytes_buf(salt, sizeof salt);
  randombytes_buf(nonce, sizeof nonce);

  // Derive key from password
  derive_key(password, salt, key);

  // Write salt + nonce to output file
  fwrite(salt, 1, SALT_SIZE, fo);
  fwrite(nonce, 1, NONCE_SIZE, fo);

  // Read whole file into memory
  fseek(fi, 0, SEEK_END);
  long size = ftell(fi);
  fseek(fi, 0, SEEK_SET);

  unsigned char *plaintext = malloc(size);
  unsigned char *ciphertext =
      malloc(size + crypto_aead_xchacha20poly1305_ietf_ABYTES);

  fread(plaintext, 1, size, fi);

  unsigned long long ciph_len = 0;

  crypto_aead_xchacha20poly1305_ietf_encrypt(
      ciphertext, &ciph_len, plaintext, size, NULL, 0, // no additional data
      NULL, nonce, key);

  fwrite(ciphertext, 1, ciph_len, fo);

  fclose(fi);
  fclose(fo);
  free(plaintext);
  free(ciphertext);

  printf("File encrypted successfully.\n");
}

void decrypt_file(const char *in, const char *out, const char *password) {
  FILE *fi = fopen(in, "rb");
  if (!fi)
    die("Cannot open input file");

  FILE *fo = fopen(out, "wb");
  if (!fo)
    die("Cannot open output file");

  unsigned char salt[SALT_SIZE];
  unsigned char nonce[NONCE_SIZE];
  unsigned char key[KEY_SIZE];

  // Read salt and nonce
  fread(salt, 1, SALT_SIZE, fi);
  fread(nonce, 1, NONCE_SIZE, fi);

  derive_key(password, salt, key);

  // Read rest of file (ciphertext)
  fseek(fi, 0, SEEK_END);
  long size = ftell(fi) - SALT_SIZE - NONCE_SIZE;
  fseek(fi, SALT_SIZE + NONCE_SIZE, SEEK_SET);

  unsigned char *ciphertext = malloc(size);
  unsigned char *plaintext = malloc(size);

  fread(ciphertext, 1, size, fi);

  unsigned long long plain_len = 0;

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(plaintext, &plain_len, NULL,
                                                 ciphertext, size, NULL, 0,
                                                 nonce, key) != 0) {
    die("Wrong password or corrupted file");
  }

  fwrite(plaintext, 1, plain_len, fo);

  fclose(fi);
  fclose(fo);
  free(ciphertext);
  free(plaintext);

  printf("File decrypted successfully.\n");
}

int main(int argc, char **argv) {
  if (sodium_init() < 0)
    die("sodium_init failed");

  if (argc != 4) {
    printf("Usage: %s enc|dec <input> <output>\n", argv[0]);
    return 1;
  }

  char password[256];
  printf("Enter password: ");
  fgets(password, sizeof(password), stdin);
  password[strcspn(password, "\n")] = 0;

  if (strcmp(argv[1], "enc") == 0) {
    encrypt_file(argv[2], argv[3], password);
  } else if (strcmp(argv[1], "dec") == 0) {
    decrypt_file(argv[2], argv[3], password);
  } else {
    die("Invalid mode (use enc or dec)");
  }

  return 0;
}