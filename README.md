# **sca-bearssl-protected-rsa**

This project implements countermeasures against **Side-Channel Attacks (SCA)** and **Fault Injection Attacks** in the RSA implementation of **BearSSL**.

---

### **1. Message and Exponent Blinding**

To protect against first-order SCA attacks, message and exponent blinding have been implemented. These countermeasures randomize the message and exponent values during RSA operations, effectively mitigating power analysis attacks.

- **Source Code:** [message_and_exp_blind.c](src/rsa/message_and_exp_blind.c)

---

### **2. Modulus Randomization**

The exponentiation algorithm ([i31_modpow2.c](src/int/i31_modpow2.c)) has been modified to incorporate modulus randomization during each iteration. This adds an additional layer of unpredictability, further protecting against side-channel leakage.

- **Source Code:** [mod_rand_pow.c](src/int/mod_rand_pow.c)

This modified algorithm is integrated into the RSA decryption process:

- **Source Code:** [modulus_randomization.c](src/rsa/modulus_randomization.c)

---

### **3. Key Randomization**

The secret key structure ([bearssl_rsa.h](inc/bearssl_rsa.h)) has been extended to include a pre-randomized key. The updated structure contains:

- The public modulus *n*,
- The public exponent *e*,
- Two random masks (*r₁* and *r₂*),
- Blinded Euler’s totient functions of the prime factors.

This pre-randomization ensures that secret key components are masked before use, protecting against both SCA and fault attacks.

- **Source Code:** [pre_randomization.c](src/rsa/pre_randomization.c)

---

### **4. Fault Injection Protection**

Fault injection countermeasures have been integrated into the SCA-protected RSA decryption algorithm to enhance robustness against hardware fault attacks.

First FI coutermeasure is inspired with this [paper](https://www.matthieurivain.com/files/ct-rsa14a.pdf)

- **Source Code:** [rsa_secured.c](src/rsa/rsa_secured.c)

Second FI coutermeasure is inpired with this [paper](https://marcjoye.github.io/papers/CJ05fdtc.pdf)

- **Source Code:** [FI-countermeasure.c](src/rsa/FI-countermeasure.c)

---

## **Current Status**

- **Message and exponent blinding:** Successfully implemented and tested.
- **Modulus randomization:** Successfully implemented and tested.
- **Key pre-randomization:** Successfully tested and integrated into the decryption flow.
- **Fault injection protection:** Initial protections added; further improvements planned.

---

## **Future Work**

- Enhance fault injection countermeasures for even stronger hardware-level protection.
- Test the implementation against a broader range of side-channel and fault injection attack scenarios.
- Optimize performance while maintaining strong security guarantees.

## **How to Contribute**
Contributions and suggestions are welcome! Please feel free to submit issues or pull requests.
