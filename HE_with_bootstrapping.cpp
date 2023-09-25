#include <iostream>
#include "seal/seal.h"
#include <chrono>
#include <thread>

using namespace std;
using namespace seal;

void bfv_scheme_with_seal()
{
    // Create a SEAL context
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(8192);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(8192));
    parms.set_plain_modulus(PlainModulus::Batching(4096, 20));
    SEALContext context(parms);

    // Generate the public and secret keys
    KeyGenerator keygen(context);
    PublicKey pk;
    keygen.create_public_key(pk);
    SecretKey secret_key = keygen.secret_key();

    // Create an encryptor and decryptor
    Encryptor encryptor(context, pk);
    Decryptor decryptor(context, secret_key);

    // Create an evaluator for homomorphic operations
    Evaluator evaluator(context);

    // Generate plaintexts for addition and multiplication
    Plaintext plaintext1("23");
    Plaintext plaintext2("30");

    // Encrypt the plaintexts
    Ciphertext ciphertext1;
    Ciphertext ciphertext2;
    encryptor.encrypt(plaintext1, ciphertext1);
    encryptor.encrypt(plaintext2, ciphertext2);


    // Perform homomorphic addition
    Ciphertext ciphertext_sum;
    evaluator.add(ciphertext1, ciphertext2, ciphertext_sum);

    // Perform homomorphic multiplication
    Ciphertext ciphertext_product;
    evaluator.multiply(ciphertext1, ciphertext2, ciphertext_product);

    // Print the results before bootstrapping
    Plaintext plaintext_sum_before;
    Plaintext plaintext_product_before;
    decryptor.decrypt(ciphertext_sum, plaintext_sum_before);
    decryptor.decrypt(ciphertext_product, plaintext_product_before);

    cout << "1st Integer: " << plaintext1.to_string() << endl;
    cout << "2nd Integer: " << plaintext2.to_string() << endl;

    cout << "Homomorphic Addition Result (Before Bootstrapping): " << plaintext_sum_before.to_string() << endl;
    cout << "Homomorphic Multiplication Result (Before Bootstrapping): " << plaintext_product_before.to_string() << endl;

    cout << "Noise in Addition Result Ciphetext (Before Bootstrapping): " << decryptor.invariant_noise_budget(ciphertext_sum) << endl;
    cout << "Noise in Multiplication Result Ciphetext (Before Bootstrapping): " << decryptor.invariant_noise_budget(ciphertext_product) << endl;

    // Perform bootstrapping   
    evaluator.mod_switch_to_next_inplace(ciphertext_sum);
    evaluator.mod_switch_to_next_inplace(ciphertext_product);

    // Decrypt the results after bootstrapping
    Plaintext plaintext_sum_after;
    Plaintext plaintext_product_after;
    decryptor.decrypt(ciphertext_sum, plaintext_sum_after);
    decryptor.decrypt(ciphertext_product, plaintext_product_after);

    // Print the results after bootstrapping
    cout << "Homomorphic Addition Result (After Bootstrapping): " << plaintext_sum_after.to_string() << endl;
    cout << "Homomorphic Multiplication Result (After Bootstrapping): " << plaintext_product_after.to_string() << endl;

    cout << "Noise in Addition Result Ciphetext (After Bootstrapping): " << decryptor.invariant_noise_budget(ciphertext_sum) << endl;
    cout << "Noise in Multiplication Result Ciphetext (After Bootstrapping): " << decryptor.invariant_noise_budget(ciphertext_product) << endl;

}

int main()
{
    using std::chrono::high_resolution_clock;
    using std::chrono::duration_cast;
    using std::chrono::duration;
    using std::chrono::milliseconds;

    auto t1 = high_resolution_clock::now();
    bfv_scheme_with_seal();
    auto t2 = high_resolution_clock::now();

    /* Getting number of milliseconds as a double. */
    duration<double, std::milli> ms_double = t2 - t1;

    std::cout << "Execution time: " << ms_double.count() << "ms\n";

    return 0;
}

