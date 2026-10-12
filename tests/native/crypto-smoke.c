#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>
int main(void) {
 const unsigned char expected[16]={0xa4,0x48,0x01,0x7a,0xaf,0x21,0xd8,0x52,0x5f,0xc1,0x0a,0xe8,0x7a,0xa6,0x72,0x9d};
 OSSL_PROVIDER *legacy=OSSL_PROVIDER_load(NULL,"legacy");
 OSSL_PROVIDER *def=OSSL_PROVIDER_load(NULL,"default");
 EVP_MD *md=EVP_MD_fetch(NULL,"MD4",NULL);EVP_CIPHER *des=EVP_CIPHER_fetch(NULL,"DES-ECB",NULL);
 unsigned char out[64];unsigned int size=0;EVP_MD_CTX *ctx=EVP_MD_CTX_new();
 int ok=legacy && def && md && des && ctx && EVP_DigestInit_ex(ctx,md,NULL)==1 && EVP_DigestUpdate(ctx,"abc",3)==1 && EVP_DigestFinal_ex(ctx,out,&size)==1 && size==16 && memcmp(out,expected,16)==0;
 printf("Android native EAP primitives (MD4 known vector, DES, legacy provider): %s\n",ok?"PASS":"FAIL");
 EVP_MD_CTX_free(ctx);EVP_MD_free(md);EVP_CIPHER_free(des);OSSL_PROVIDER_unload(legacy);OSSL_PROVIDER_unload(def);return ok?0:1;
}
