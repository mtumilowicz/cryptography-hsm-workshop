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
    * http://javadoc.iaik.tugraz.at/pkcs11_wrapper/current/index.html

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
        * which you need to install and configure according to manufacturer's instructions
* applications can address cryptographic devices (tokens)
    * example: smart cards, USB keys, and Hardware Security Modules (HSMs)
    * and can perform cryptographic functions as implemented by these tokens
        * example: create or delete cryptographic data like public-private key pairs
* comes with a series of C header files 
    * (pkcs11.h, pkcs11f.h and pkcs11t.h)
    * which different hardware providers provide implementations for
    * Java has to provide a JCA wrapper for it via JNI (sun.security.pkcs11.SunPKCS11)
        * some of famous wrappers:
            * SunPKCS11
                * doesn’t provide an object oriented mapping of data structures
                * in contrast to most other providers, does not implement cryptographic algorithms itself
            * IBM PKCS11
                * isn’t an open source project
            * IAIK PKCS11
                * open sourced
          * SunPKCS11 doesn’t provide an object oriented mapping of data structures and IBM wrapper isn’t an open source project
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
        * all cryptographic operations provided in the HSM are used via an initiated session
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
            * there can be only one SO and USER for a given slot
       * certain PKCS#11 operations, such as accessing private keys, require a login using PIN
    * objects
        * four classes
            * data objects - defined by an application
            * certificate objects - digital certificates such as X.509
            * key objects - public, private or secret cryptographic keys
                * digression
                    * unextractable key on a secure token is represented by a Java Key object that does not
                    contain the actual key material
                        * Key object only contains a reference to the actual key
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
* a physical device that protect and manage digital keys and provides crypto-processing function
    * example: generating the key, store the key, using the key for decrypt/encrypt operation, and discarding the key
* trusted, hardened, tamper resistant, dedicated crypto processor designed to perform strengthened cryptographic
has a specially designed, well-tested hardware to perform cryptographic operations faster than a normal computer
and security-focused OS to secure sensitive data from intruders
* attaches directly to a server and is used to securely manage and perform operations on cryptographic keys
    * plays a major role in the aspect of system’s security and it can become a single point of failure to the system
        * most of the HSM vendors provide capability of using HSM clusters for high availability and load balancing
* secret key will never leave HSM in unencrypted format
    * main purpose: generate cryptographic keys and sign information without revealing private-key material
    to the outside world
* many different forms
    * PCIe, where the HSM came in PCIe form to be embedded in server
      * Example: Thales Luna PCIe HSM
    * standalone appliance, where the HSM came in the form of standalone appliance
      * Example: Utimaco Cryptoserver CP5
    * USB, where the HSM came in the form of USB stick
      * Example: YubiHSM 2
* HSMs vs software cryptographic providers
    * secured key management process
        * HSMs are good at providing both logical and physical protection.
        * HSMs keep sensitive materials such as private keys, symmetric keys within the HSM throughout their life cycle
        without exposing them to outside
        * all key operations are taking place inside the HSM => only authorized users can use the keys
        * HSMs provide additional security by being tamper resistant
            * device become inoperable in case of a tampering
        * HSMs maintain a log containing all information on operations carried out using keys
            * makes it easier to determine if any intrusions or misuse of keys have been taken place
    * increase the throughput of the system
        * software cryptographic providers utilize server resources
            * causes performance degradation in the server
        * HSMs are designed and optimized to carry out cryptographic operations
            * increase in the overall performance of the system since
                * server resources can be utilized for business logic processing
                * HSMs are much faster at crypto processing than a normal CPU.
    * strong key generation
        * keys generated using software are inherently weaker than those generated using HSMs
            * computer is a finite state machine => is not capable of generating truly random values
            * HSMs are using a special physical processes to generate truly random keys
    * meet current standards and regulations on cyber security
        * FIPS 140-2
            * an internationally recognized standard for hardware cryptographic devices
            * four security levels
                * almost every HSM in the market is standardized under those levels
        * integrating HSMs to a system makes it easier to get compliance with current security regulations
* use cases
    * generation, storage and operation of private key of Certificate Authority (CA)
    * generation, storage and operation of private key for https operation of an web server
    * digitally sign a PDF file
* to interact with the HSM, we need some kind of protocol
    * common protocol: PKCS#1
    * HSM Vendors will expose its function through this Cryptoki
    * usually, HSM Vendors also have their own proprietary protocol and SDK for developer to use
    * example
        * application is using PKCS #11 supported HSM
            * needs to generate an AES key using HSM and encrypt a sample of data using the generated key
            * application authenticates itself as user ‘USER’ to the HSM and creates a secure communication passage
            (session between token and application)
            * application asks HSM to generate an AES key
            * HSM returns the created AES key
            * application sends set of data needs to be encrypted with the encryption key
            * HSM sends back the ciphered data
            * application closes the communication passage
* layers involved in interacting with an HSM
    ![alt text](img/hsm_layers.png)
    ![alt text](img/pkcs11_communication.png)
    * Java Cryptography Architecture (JCA) and Java Cryptography Extension (JCE)
        * set of programming interfaces for performing cryptographic operations
        * provider-based
            * actual operation is performed in the configured provider which implements that interface
        * tries to abstract the actual crypto implementation from the algorithm requested
            * example
                * using Cipher.getInstance(“AES”), and not have to hard code the actual implementation
                    * different implementations can be swapped out depending on deployment requirements.
        * heart of the JCA architecture: Provider abstract class
            * specific provider will register different algorithm implementations where each implementation
            implements a specific *SPI (service provider interface) abstract class depending on which
            algorithm it’s implementing
                * example:
    * Sun PKCS#11: bridge between the JCA, JCE APIs and the native PKCS#11 module
        * native module: a shared-object library provided by the vendor of the HSM device
            * .so file on Solaris and Linux
            * or dynamic-link library (.dll on Windows)
* multiple HSMs are handled by the PKCS #11 API
    ![alt text](img/hsm_multiple_slots.png)
    * PKCS #11 API is designed integrating load balancing techniques so that cryptographic operations are fairly
    distributed over set of HSMs connected to the application.

## softhsm
* SoftHSM isn’t exactly an HSM per se, but a software implementation of a generic PKCS#11 device
* cmds
  *  softhsm2-util --show-slots

## attacks
* [Explaining HSMs | Part 3 - Common Attacks](https://www.youtube.com/watch?v=aRjuUPYE-tk)
* [Explaining HSMs | Part 4 - HSM Fuzzing](https://www.youtube.com/watch?v=bw0V7dl_zdA)