
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(const char *msg, BIGNUM *bn) {
    char *bn_str = BN_bn2hex(bn);
    printf("%s %s\n", msg, bn_str);
    OPENSSL_free(bn_str);
}

void calculate_private_key(BIGNUM *p, BIGNUM *q, BIGNUM *e, BIGNUM *n, BIGNUM *d) {
    BN_CTX *ctx = BN_CTX_new();
    
    BIGNUM *phi_n = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();

    // Step 2: Calculate n = p * q
    BN_mul(n, p, q, ctx);
    printBN("n =", n);

    // Step 3: Calculate Φ(n) = (p-1) * (q-1)
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi_n, p_minus_1, q_minus_1, ctx);
    printBN("Φ(n) =", phi_n);

    // Step 5: Calculate d as the modular inverse of e mod Φ(n)
    if (BN_mod_inverse(d, e, phi_n, ctx) == NULL) {
        printf("Error: Unable to calculate d as modular inverse\n");
    }
    printBN("Private key (d) =", d);

    BN_free(phi_n);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_CTX_free(ctx);
}

void encrypt_message(BIGNUM *P, BIGNUM *e, BIGNUM *n, BIGNUM *C) {
    BN_CTX *ctx = BN_CTX_new();
    
    // printf("Values used for message encryption are\n");
    // printBN("P(hex value of plain text) ", P);
    // printBN("e = ", e);
    // printBN("n =", n);

    
    // Step 7: Calculate C = P^e mod n
    BN_mod_exp(C, P, e, n, ctx);
    printBN("Ciphertext (C) =", C);

    BN_CTX_free(ctx);
}

void decrypt_message(BIGNUM *C, BIGNUM *d, BIGNUM *n, BIGNUM *P) {
    BN_CTX *ctx = BN_CTX_new();

    // printf("Values used for message decryption are\n");
 
    // printBN ("C = ", C);
    // printBN("d = ", d);
    // printBN("n =", n);

    // Step 8: Calculate P = C^d mod n
    BN_mod_exp(P, C, d, n, ctx);


    printBN("Decrypted message (P) =", P);

    char *hex_str = BN_bn2hex(P);

    //Convert hex string to plain text
    printf("Decrypted message (plain text) = ");

    size_t len = strlen(hex_str);

    // Each two hex digits represent one ASCII character
    for (size_t i = 0; i < len; i += 2) {
        char byte[3] = {hex_str[i], hex_str[i + 1], '\0'};
        printf("%c", (char) strtol(byte, NULL, 16));
    }
    printf("\n");


    BN_CTX_free(ctx);
}

void Convert_to_hex(const char* message, BIGNUM* m)
{
   char hex_str[256] = {0};
   for (size_t i = 0; i < strlen(message); i++) {
        sprintf(hex_str + i * 2, "%02X", (unsigned char)message[i]);
   }

    BN_hex2bn(&m, hex_str);

}

void Sign_Message(BIGNUM* S, const char* message, BIGNUM* d, BIGNUM* n, BN_CTX* ctx)
{ 
   // S = m ^d mod n

   BIGNUM* m = BN_new();
   Convert_to_hex(message,m);

   BN_mod_exp(S, m, d, n, ctx);

}

 int verify_signature(const char *original_message, BIGNUM *S, BIGNUM *e, BIGNUM *n) {
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *decrypted_message_bn = BN_new();

    // Step 1: Calculate M = S^e mod n
    BN_mod_exp(decrypted_message_bn, S, e, n, ctx);
    printBN("Decrypted message (hex) =", decrypted_message_bn);

   
    char *hex_str2 = BN_bn2hex(decrypted_message_bn);

    //Convert hex string to plain text
    // printf("Decrypted message (plain text) = ");

    // size_t len = strlen(hex_str2);

    // // Each two hex digits represent one ASCII character
    // for (size_t i = 0; i < len; i += 2) {
    //     char byte[3] = {hex_str2[i], hex_str2[i + 1], '\0'};
    //     printf("%c", (char) strtol(byte, NULL, 16));
    // }
    // printf("\n");

    // Step 2: Convert the original message to hex and then to BIGNUM
    char hex_str[256] = {0};
    for (size_t i = 0; i < strlen(original_message); i++) {
        sprintf(hex_str + i * 2, "%02X", (unsigned char)original_message[i]);
    }
    BIGNUM *original_message_bn = BN_new();
    BN_hex2bn(&original_message_bn, hex_str);
    printBN("Original message (hex) =", original_message_bn);

    // Step 3: Compare decrypted message with the original message
    int is_valid = BN_cmp(decrypted_message_bn, original_message_bn) == 0;

    // Print verification result
    if (is_valid) {
        printf("Signature is valid.\n");
    } else {
        printf("Signature is invalid.\n");
    }

    // Free resources
    BN_free(decrypted_message_bn);
    BN_free(original_message_bn);
    BN_CTX_free(ctx);

    return is_valid;
}


void Task6()
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(); 
    BIGNUM *e = BN_new(); 
    BIGNUM *s = BN_new();
    BIGNUM *message = BN_new();
   
    BN_hex2bn(&n, "CF710624FA6BB636FED905256C56D277B7A12568AF1F4F9D6E7E18FBD95ABF260411570DB1200FA270AB557385B7DB2519371950E6A41945B351BFA7BFABBC5BE2430FE56EFC4F37D97E314F5144DCBA710F216EAAB22F031221161699026BA78D9971FE37D66AB75449573C8ACFFEF5D0A8A5943E1ACB23A0FF348FCD76B37C163DCDE46D6DB45FE7D23FD90E851071E51A35FED4946547F2C88C5F4139C97153C03E8A139DC690C32C1AF16574C9447427CA2C89C7DE6D44D54AF4299A8C104C2779CD648E4CE11E02A8099F04370CF3F766BD14C49AB245EC20D82FD46A8AB6C93CC6252427592F89AFA5E5EB2B061E51F1FB97F0998E83DFA837F4769A1");
    BN_hex2bn(&e, "10001");
    BN_hex2bn(&s, "04e16e023e0de32346f4e3963505933522020b845de27386d4744ffc1b27af3ecaadc3ce46d6fa0fe271f90d1a9a13b7d50848bd5058b35e20638629ca3ecccc7826e1598f5dca8bbc49316f61bd42ff6162e1223524269b57ebe5000dff40336c46c233770898b27af643f96d48dfbffefa281e7b8acf2d61ff6c8798a42c629abb108cff34487066b76d72c369f9394b683956bda1b36df477f3465b5c19ac4fb3746b8cc5f189cc93fe0c016f8817dc427160e3ed7330429ca92f3ba2788ec");
    BN_mod_exp(message, s,e,n,ctx);
    printBN("message = ", message);

}



int main() {
    BN_CTX *ctx = BN_CTX_new();

    // Step 1: Initialize p, q, e, n, and d
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();

    // Set values for p, q, and e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    printf("******** Task 1 ********* \n");

    // Step 6: Calculate public and private keys
    calculate_private_key(p, q, e, n, d);

    // Encrypt a message
    const char *message = "A top secret!";
    //char hex_str[256] = {0};
    printf("Message = ");

    int i = 0;

    while (message[i] != '\0') {
    printf("%c", message[i]);
    i++;
   }

    printf("\n");
    BIGNUM *P = BN_new();
    Convert_to_hex(message,P);
  

    // Convert hex string to BIGNUM P
    
    BIGNUM *C = BN_new();
    //BN_hex2bn(&P, hex_str);


    printf("******** Task 2 ********* \n");
    
    // Step 7: Encrypt the message
    encrypt_message(P, e, n, C);

    // Step 8: Decrypt the ciphertext

    printf("******** Task 3 ********* \n");

    BIGNUM *decrypted_P = BN_new();
    decrypt_message(C, d, n, decrypted_P);

    printf("******** Task 4 ********* \n");

    char message2[256] = "I owe you $2000";
    BIGNUM* S = BN_new();
    Sign_Message(S,message2,d,n,ctx);   
    printBN("Digital signature =",S); 
    
    strncpy(&message2[10], "$3000", 5);
  
    Sign_Message(S,message2,d,n,ctx);   
    printBN("Digital signature =",S); 

    
    printf("******** Task 5 ********* \n");
    // Set values for Task 5
    BIGNUM *M = BN_new();
    strcpy(message2, "Launch a missile");
    Sign_Message(S,message2,d,n,ctx);  
    Convert_to_hex(message2,M);

   // Set signature S, public exponent e, and modulus n
    BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
    BN_hex2bn(&e, "010001");  // Hex for decimal 65537
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
 

 //  Verify original signature
    printf("Verifying original signature:\n");
    verify_signature(message2, S, e, n);

    // Modify the last byte of S to simulate corruption
    BIGNUM *corrupted_S = BN_dup(S);
    BN_sub_word(corrupted_S, 0x10);  // Changes the last byte from 2F to 3F

    // Verify corrupted signature
    printf("\nVerifying corrupted signature:\n");
    verify_signature(message2, corrupted_S, e, n);


    Task6();


    // Cleanup
    BN_free(p);
    BN_free(q);
    BN_free(e);
    BN_free(n);
    BN_free(d);
    BN_free(P);
    BN_free(C);
    BN_free(decrypted_P);
    BN_free(S);
    BN_CTX_free(ctx);

    return 0;
}
