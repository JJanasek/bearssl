# **sca-bearssl-protected-rsa**

This project aims to implement countermeasures against **Side-Channel Attacks (SCA)** and **Fault Injection Attacks** in the RSA implementation of BearSSL.

---

## **Implemented Countermeasures**

### **1. Fault Injection Countermeasure**
I have implemented a fault injection countermeasure inspired by **Algorithm 4** from [this paper](https://eprint.iacr.org/2014/559.pdf). However, the current implementation still has some unresolved issues.

- **Source Code**: [FI-countermeasure.c](src/rsa/FI-countermeasure.c)

---

### **2. Message and Exponent Blinding**
To protect against first-order SCA attacks, I have implemented message and exponent blinding. This countermeasure is working as expected.

- **Source Code**: [message_and_exp_blind.c](src/rsa/message_and_exp_blind.c)

---

### **3. Modulus Randomization**
I have modified the exponentiation algorithm ([i31_modpow2.c](src/int/i31_modpow2.c)) to incorporate modulus randomization in each iteration. This modified algorithm is used in the [RSA decryption algorithm](src/rsa/modulus_randomization.c).

---

## **Current Status**
- Some countermeasures (e.g., fault injection) require further refinement.
- Message and exponent blinding have shown effective results.
- Modulus randomization has been successfully tested using my test vectors.
---

## **Future Work**
- Improve fault injection countermeasures for more robust protection.
- Test the implementation under various attack scenarios.

---

## **How to Contribute**
Contributions and suggestions are welcome! Please feel free to submit issues or pull requests.
