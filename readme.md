* references
  * https://stackoverflow.com/questions/43114733/java-complains-on-loading-pkcs-dll-from-softhsm
  * https://clydedcruz.medium.com/a-dive-into-softhsm-e4be3e70c7bc
  * https://www.ibm.com/docs/en/linux-on-systems?topic=introduction-what-is-pkcs-11
  * https://www.securew2.com/blog/what-is-pkcs11
  * https://blog.devgenius.io/what-is-hardware-security-module-a-brief-explanation-6ac448f2cfa9
  * https://clydedcruz.medium.com/a-dive-into-softhsm-e4be3e70c7bc
  * https://medium.com/@gerritjvv/java-cryptography-api-and-keystorage-88bd350ec1b7
  * https://medium.com/@mevan.karu/standard-api-for-connecting-hsms-with-client-applications-6296eb187d89
  * http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
  * https://docs.oracle.com/en/java/javase/12/security/pkcs11-reference-guide1.html#GUID-6DA72F34-6C6A-4F7D-ADBA-5811576A9331
  * https://thalesdocs.com/gphsm/ptk/5.9/docs/Content/PTK-C_Program/intro_PKCS11.htm
  * https://medium.com/@mevan.karu/want-to-know-how-to-talk-to-a-hsm-at-code-level-69cb9ba7b392
  * https://medium.com/@mevan.karu/secure-cryptographic-operations-with-hardware-security-modules-d54734834d7e

## pkcs11
* PKCS = The Public-Key Cryptography Standards
  * specified by OASIS Open which is a global nonprofit organization
    * works on the development, convergence, and adoption of open standards for security, IoT, energy, 
    content technologies, emergency management, and other areas
* specifies an API, called Cryptographic APIs (Cryptoki)
  * defines the most commonly used cryptographic object types
    * example: RSA keys, X.509 Certificates, DES/Triple DES keys, etc.
    * and all the functions needed to use
      * example: create/generate, modify, and delete those objects
* PKCS #11 is not an implementation of a API, it is a specification for the implementation of the API
  * OASIS Open provides only a set of ANSI C header files defining the interface exposed to client application
  * HSM vendor is responsible for providing concrete implementation of the functionalities specified in PKCS #11
* applications can address cryptographic devices (tokens)
  * example: smart cards, USB keys, and Hardware Security Modules (HSMs)
  * and can perform cryptographic functions as implemented by these tokens
    * example: create or delete cryptographic data like public-private key pairs
* comes with a series of C header files 
  * (pkcs11.h, pkcs11f.h and pkcs11t.h)
  * which different hardware providers provide implementations for
  * Java has to provide a JCA wrapper for it via JNI (sun.security.pkcs11.SunPKCS11)
* sun.security.pkcs11.SunPKCS11
  * just a huge wrapper class that via JNI calls into the native module (.so, .dll) that implements 
  the PKCS11 C header files
* glossary
  * token
    * logical view of the underlying cryptographic device
    * possesses a list of cryptographic functionalities supported by the device
  * slot
    * logical access point to the cryptographic device
      * physical device interface
      * example: smart card reader would represent a slot and the smart card would represent the token
    * objects that resides within a given slot is not visible to other slots
    * multiple slots may share the same token
      * what application sees is there’s a token inside each slot
        * example: if there is only one HSM then the token is same for all the slots
          * application gets the view of multiple independent tokens so HSM can be used by other 
          applications from different slots concurrently.
  * session
    * logical connection between an application and a token
    * two types
      * Read/Write
      * Read-Only
  * user
    * is a person or an application who has access to the cryptographic device through a slot
    * two users
      * SO(Security Officer)
        * has the authority to create a USER
      * USER for each slot
        * is responsible for using device for cryptographic operations
      * There can be only one SO and USER for a given slot.
  * objects
    * four classes
      * data objects - defined by an application
      * certificate objects - digital certificates such as X.509
      * key objects - public, private or secret cryptographic keys
      * vendor-defined objects
    * further defined as either
      * token object
        * visible by any application which has sufficient access permission and is connected to that token
        * important attribute: object remains on the token until a specific action is performed to remove it
      * session object
          * temporary and only remain in existence while the session is open
          * only visible to the application that created them
* debugging
  * adding showInfo=true in the SunPKCS11 provider configuration file
    * show debug info about Library, Slots, Token, and Mechanism
  * restart the Java processes with one of the following options
    * -Djava.security.debug=sunpkcs11
      * general SunPKCS11 provider debugging info
    * -Djava.security.debug=pkcs11keystore
      * For PKCS#11 keystore specific debugging info
* 
* Certain PKCS#11 operations, such as accessing private keys, require a login using a Personal Identification Number, or PIN, before the operations can proceed
* When accessing the PKCS#11 token as a keystore via the java.security.KeyStore class, you can supply the PIN in the password input parameter to the load method
  * char[] pin = ...;
    KeyStore ks = KeyStore.getInstance("PKCS11");
    ks.load(null, pin);
* An unextractable key on a secure token (such as a smartcard) is represented by a Java Key object that does not contain the actual key material. The Key object only contains a reference to the actual key.
  Software Key objects (or any Key object that has access to the actual key material) should implement the interfaces in the java.security.interfaces and javax.crypto.interfaces packages (such as DSAPrivateKey).









* pkcs#11 configuration file
  * example
    ```
    name = SoftHSM
    library = C:/SoftHSM2/lib/softhsm2-x64.dll
    slot = 875625480
    attributes(generate, *, *) = {
    CKA_TOKEN = true
    }
    attributes(generate, CKO_CERTIFICATE, *) = {
    CKA_PRIVATE = false
    }
    attributes(generate, CKO_PUBLIC_KEY, *) = {
    CKA_PRIVATE = false
    }
    ```
  * library = pathname of PKCS#11 implementation
  * name = name suffix of this provider instance
  * description = description of this provider instance
  * slot = slot id
    * id of the slot that this provider instance is to be associated with
  * slotListIndex = slot index
    * slot index that this provider instance is to be associated with
    * example: 0 indicates the first slot in the list
    * at most one of slot or slotListIndex may be specified
  * enabledMechanisms
    * example
      ```
      enabledMechanisms = {
          CKM_RSA_PKCS
          CKM_RSA_PKCS_KEY_PAIR_GEN
      }
      ```
    * not specified => mechanisms enabled are those that are supported
      by both the SunPKCS11 provider and the PKCS#11 token
  * attributes
    * example
      ```
      attributes(operation, keytype, keyalgorithm) = {
        name1 = value1
        [...]
      }
      ```
    * used to specify additional PKCS#11 that should be set when creating PKCS#11 key objects
    * by default, the SunPKCS11 provider only specifies mandatory PKCS#11 attributes when creating objects
      * example
        * RSA public keys
          * key type and algorithm (CKA_CLASS and CKA_KEY_TYPE)
          * key values for RSA public keys (CKA_MODULUS and CKA_PUBLIC_EXPONENT)
    * operation
      * generate - for keys generated via a KeyPairGenerator or KeyGenerator
      * import - for keys created via a KeyFactory or SecretKeyFactory
      * * - for keys created using either a generate or a create operation
    * keytype
      * CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, and CKO_SECRET_KEY and * to match any type of key
    * keyalgorithm
      * one of the CKK_xxx constants from the PKCS#11 specification
        * CKK_RSA, CKK_DSA, CKK_DH, CKK_AES, CKK_DES, CKK_DES3, CKK_RC4, CKK_BLOWFISH, CKK_GENERIC_SECRET, and CKK_EC
      * or * to match keys of any algorithm
      * attribute names and values
        * name must be a CKA_xxx constant from the PKCS#11 specification
          * example: CKA_SENSITIVE
        * value can be one of the following:
          * boolean value
          * integer
          * null = indicating that this attribute should not be specified when creating objects


## hsm
* example
  * application is using PKCS #11 supported HSM
    * needs to generate an AES key using HSM and encrypt a sample of data using the generated key
    * application authenticates itself as user ‘USER’ to the HSM and creates a secure communication passage (session between token and application)
    * application asks HSM to generate an AES key
    * HSM returns the created AES key
    * application sends set of data needs to be encrypted with the encryption key
    * HSM sends back the ciphered data
    * application closes the communication passage
* a physical device that protect and manage digital keys and provides crypto-processing function
  * example: generating the key, store the key, using the key for decrypt/encrypt operation, and discarding the key
* attaches directly to a server and is used to securely manage and perform operations on cryptographic keys
* secret key will never leave HSM in unencrypted format
* many different forms
    * PCIe, where the HSM came in PCIe form to be embedded in server
      * Example: Thales Luna PCIe HSM
    * standalone appliance, where the HSM came in the form of standalone appliance
      * Example: Utimaco Cryptoserver CP5
    * USB, where the HSM came in the form of USB stick
      * Example: YubiHSM 2
* use cases
  * generation, storage and operation of private key of Certificate Authority (CA)
  * generation, storage and operation of private key for https operation of an web server
  * digitally sign a PDF file
* to interact with the HSM, we need some kind of protocol
    * common protocol: PKCS#1
    * HSM Vendors will expose its function through this Cryptoki
    * usually, HSM Vendors also have their own proprietary protocol and SDK for developer to use
* The purpose of these devices is, among others, to generate cryptographic keys and sign information without revealing private-key material to the outside world
* HSMs are commonly used in Public Key Cryptography (PKI) deployments to secure Certificate Authority keys
* layers involved in interacting with an HSM
  ![alt text](img/hsm_layers.png)
  * Java Cryptography Architecture (JCA) and Java Cryptography Extension (JCE)
    * Java defines a set of programming interfaces for performing cryptographic operations
    * These interfaces are provider-based
      * This means that when performing a cryptographic operation in our application, the application talks to the interface, but the actual operation is performed in the configured provider which implements that interface
    * The Java Cryptography Api or JCA is a plugable architecture which tries to abstract the actual crypto implementation from the algorithm requested.
    * This allows our code to use Cipher.getInstance(“AES”), and not have to hard code the actual implementation, better or different implementations can be swapped out depending on deployment requirements.
    * At the heart of the JCA architecture is the Provider abstract class, a specific provider will register different algorithm implementations where each implementation implements a specific *SPI (service provider interface) abstract class depending on which algorithm it’s implementing.
  * Sun PKCS#11 provider does not implement cryptographic algorithms by itself, but acts as a bridge between the JCA, JCE APIs and the native PKCS#11 module
    * native module must be in the form of a shared-object library (.so file on Solaris and Linux) or dynamic-link library (.dll on Windows) and is provided by the vendor of the HSM device
      * Instead, it acts as a bridge between the Java JCA and JCE APIs and the native PKCS#11 cryptographic API, translating the calls and conventions between the two.
      * cryptographic devices such as Smartcards and hardware accelerators often come with software that includes a PKCS#11 implementation, which you need to install and configure according to manufacturer's instructions
    * The SunPKCS11 provider, in contrast to most other providers, does not implement cryptographic algorithms itself
    * for example
      * sun.security.pkcs12.PKCS12KeyStore extends java.security.KeyStoreSPI which is the JCA abstraction for a KeyStore
* As you can see for any application to use the HSM it should first initiate a session with a token.
  * All cryptographic operations provided in the HSM are used via an initiated session.
* Application doesn’t have to bear the burden of handling multiple HSMs because it is handled by the PKCS #11 API. PKCS #11 API is designed integrating load balancing techniques so that cryptographic operations are fairly distributed over set of HSMs connected to the application.
  ![alt text](img/hsm_multiple_slots.png)
* Multiple applications using multiple HSMs through PKCS #11 API
* HSM vendors provide the PKCS #11 implementation in C language. Hope you already know it, then here is an obvious question…
* How to develop a Java application using C module?
  * So we need a wrapper to map C data structures to Java data structures and vice versa.
  * Some of famous wrappers are SunPKCS11, IBM PKCS11 and IAIK PKCS11 wrapper
    * SunPKCS11 doesn’t provide an object oriented mapping of data structures and IBM wrapper isn’t an open source project
    * http://javadoc.iaik.tugraz.at/pkcs11_wrapper/current/index.html

* A HSM is a trusted, hardened, tamper resistant, dedicated crypto processor designed to perform strengthened cryptographic operations such as encrypting, decrypting, digital signing, digital sign verifying, hashing etc.
* HSM has a specially designed, well-tested hardware to perform cryptographic operations faster than a normal computer and security-focused OS to secure sensitive data from intruders
* Normally these modules can be attached to a computer or a network sever externally via a USB port
* HSM plays a major role in the aspect of system’s security and it can become a single point of failure to the system
  * Because of that most of the HSM vendors provide capability of using HSM clusters for high availability and load balancing.
* There are several benefits of using HSMs over software cryptographic providers
  * Secured key management process
    * HSMs are good at providing both logical and physical protection.
    * HSMs keep sensitive materials such as private keys, symmetric keys within the HSM throughout their life cycle without exposing them to outside
    * Since all key operations are taking place inside the HSM so that only authorized users can use the keys
    * Also HSMs provide additional security by being tamper resistant which means device become inoperable in case of a tampering
    * A HSM maintains a log containing all information on operations carried out using keys which makes it easier to determine if any intrusions or misuse of keys have been taken place.
  * Increase the throughput of the system
    * Software cryptographic providers utilize server resources for cryptographic operations causing performance degradation in the server
    * As I mentioned earlier HSMs are designed and optimized to carry out cryptographic operations more efficiently and securely
    * Integrating a HSM to a system causes increase in the overall performance of the system since, server resources can be utilized for business logic processing and also HSMs are much faster at crypto processing than a normal CPU.
  * Strong key generation
    *  computer is a finite state machine, since it is not capable of generating truly random values
    * But when it comes to HSMs, it uses a special physical processes to generate truly random keys which makes generated keys strong
    * So keys generated using software are inherently weaker than those generated using HSMs.
  * Can meet current standards and regulations on cyber security
    * FIPS 140-2 is an internationally recognized standard for hardware cryptographic devices which defines the level of security provided by them
    * There are four security levels defined in FIPS 140–2 and almost every HSM in the market is standardized under those levels
    * So integrating HSMs to a system makes it easier to get compliance with current security regulations.

## softhsm
* SoftHSM isn’t exactly an HSM per se, but a software implementation of a generic PKCS#11 device
* cmds
  *  softhsm2-util --show-slots

## attacks
* [Explaining HSMs | Part 3 - Common Attacks](https://www.youtube.com/watch?v=aRjuUPYE-tk)
* [Explaining HSMs | Part 4 - HSM Fuzzing](https://www.youtube.com/watch?v=bw0V7dl_zdA)