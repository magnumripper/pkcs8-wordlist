
// INFO
// Name  : Dictionary attacks on pkcs8 encrypted private keys.
// Author: David Klein, ***

// COMMENTS
// yum install openssl-devel glib-devel
// compiling on centos slightly annoying, not sure why, the below worked:
// gcc -lcrypto -I/usr/include/glib-2.0/ -I/usr/lib64/glib-2.0/include/ -lz /lib64/libglib-2.0.so.0 test.c

// example key gen with openssl genrsa | openssl pkcs8 -topk8 -inform PEM -outform DER | base64
// but it can come from anywhere (a common one is JAVA|.NET Bouncy Crypto)

#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>

#include <glib.h> // b64, couldn't tolerate openssl's

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <err.h>


void CHECKNULL(void *ptr, char *func) {
  if (NULL == ptr) {
    fprintf(stderr, "null ptr from %s\n",func);
    exit(EXIT_FAILURE);
  }
}

void strip(char *s) {
    char *p2 = s;
    while (*s != '\0') {
      if  (*s != '\n') *p2++ = *s++;
      else ++s;
    }
    *p2 = '\0';
}

// could keep callback return as int, but struct might be more descriptive.
int wordListDecrypt(const char * fileName, X509_SIG *key, PKCS8_PRIV_KEY_INFO *(*call_back)(X509_SIG *,const char*,int))
{
    FILE* file = fopen(fileName, "r"); 
    CHECKNULL(file,"fopen");

    // max for openssl pkcs8 anyway afaik
    char line[50];

    while (fgets(line, sizeof(line), file)) {

      strip(line);
      // strip is inplace, so line=stripped line after call.
      if (call_back(key, line, strlen(line))) {
        printf("password=%s\n",line);
        return 1;
      }
    }
    return 0;
}

// this only gets called once.
X509_SIG *initialise_ssl_load_enc_privkey(void) {
  X509_SIG            *p8    = NULL;
  BIO                 *mem   = NULL;
  gsize base64_outlen        = NULL;

  // later we might want to loop through multiple pkeys.
  // test pkey, password is Welcome1
  static const char *base64_input[] = { "MIIBgTAbBgkqhkiG9w0BBQMwDgQI3QtkDViPQlMCAggABIIBYH3/7ieseGgtn7YhD7PXMJFWwxm42vaMzL/XJ+2ZLgM6oyYWGhmfrPs0etpzTfbU4XthHCelVp57yhyU+czTVIRoBkfH8aHOkScxRLe7LPi1vSwySSiY7tnfmr3b+KxLFzK47lfJD9lc0xY58QMdtXK3fzaq/LyF5to83XaZNDooTFPcfNfR5SS4uuL09kWrTZxE7BEMYIAMc4qQYlx2eBzN0U6ElyQEBbrJWkhiHknDKhwfNBWEElRyQ4/gKfnU4XjeFwjOnQdFWF9mCuJfi3JKG2srTLgco3hq6PzmNq9tOfMU2GNu/PxHi5i05Be/scznor9ywvoR3Slbz1tGMHIYM9aickqAMncPMvepm/TSIT+fqFOYmRZcObfSLKUUiqfIW6gSWMPrJvpg5n/q3DDjntR6BsokFKRMaewMNtMkKM6lWdXFbcTSqO5LCJVDLPRdsTiWefDU+Rryw/tnEj0=" };    
  unsigned char *in = (unsigned char*)g_base64_decode(base64_input[0],&base64_outlen);

  // redundant because glib base64_decode throws assert on == NULL.
  // but keep just incase.
  CHECKNULL(in, "g_base64_decode");

  OpenSSL_add_all_algorithms();

  mem = BIO_new_mem_buf(in, base64_outlen);
  CHECKNULL(mem,"BIO_new_mem_buf");


  // hardcoded fro DER\ASN1 format.
  p8 = d2i_PKCS8_bio(mem,NULL);
  CHECKNULL(p8, "d2i_PKCS8_bio");
  return p8;
}


int main (void) {

  X509_SIG *p8 = initialise_ssl_load_enc_privkey();
  wordListDecrypt("wordlist.txt",p8,PKCS8_decrypt);

}
