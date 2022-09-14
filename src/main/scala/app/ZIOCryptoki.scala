package app

import iaik.pkcs.pkcs11.objects.{Key, KeyPair, RSAPrivateKey, RSAPublicKey}
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, MechanismInfo, Module, Session, Token}
import zio.{RIO, Scope, Task, ZIO}


object ZIOCryptoki {

  def generateRSAKeyPair(privateKeyAlias: String, publicKeyAlias: String): RIO[Session, KeyPair] = for {
    session <- ZIO.service[Session]
    keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN)
    token = session.getToken
    mechanismInfo <- ZIO.attemptBlocking(token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)))
    publicKey = publicKeyTemplate("RSAPublicKey", mechanismInfo)
    privateKey = privateKeyTemplate("RSAPrivateKey", mechanismInfo)
    keyPair <- ZIO.attemptBlocking(session.generateKeyPair(keyPairGenerationMechanism, publicKey, privateKey))
  } yield keyPair

  def retrieveKey(keyTemplate: Key): RIO[Session with UserStateContext.LoggedIn, Key] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attemptBlocking(session.findObjectsInit(keyTemplate))
    secretKeys <- ZIO.attemptBlocking(session.findObjects(1))
    _ <- ZIO.attemptBlocking(session.findObjectsFinal())
    result <- secretKeys.headOption match {
      case Some(value) => ZIO.attemptBlocking(value.asInstanceOf[Key])
      case None => ZIO.fail(new RuntimeException("Key retrieval error"))
    }
  } yield result

  def encrypt(keyAlias: String, dataToEncrypt: String):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(prepareKey(keyAlias))
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      bytes = dataToEncrypt.getBytes("utf-8")
      encryption <- encrypt(bytes, secretKey, mechanism)
    } yield encryption
  }

  def decrypt(keyAlias: String, dataToDecrypt: Array[Byte]):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(prepareKey(keyAlias))
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      decryption <- decrypt(dataToDecrypt, secretKey, mechanism, padding(dataToDecrypt.length).length)
    } yield decryption
  }

  private def sign(data: Array[Byte],
           privateKey: Key,
           signMechanism: Mechanism): RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(signMechanism.isSingleOperationSignVerifyMechanism || signMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attemptBlocking(session.signInit(signMechanism, privateKey))
    signature <- ZIO.attemptBlocking(session.sign(data))
  } yield signature

  def sign(data: String,
           keyAlias: String,
           signMechanism: Mechanism): RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    privateKey <- retrieveKey(prepareKey(keyAlias))
    signature <- sign(data.getBytes("utf-8"), privateKey, signMechanism)
  } yield signature

  def verify(data: Array[Byte],
             signature: Array[Byte],
             publicKeyAlias: String,
             verifyMechanism: Mechanism):
  RIO[Session with UserStateContext.LoggedIn, Boolean] = for {
    session <- ZIO.service[Session]
    publicKey <- retrieveKey(prepareKey(publicKeyAlias))
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(verifyMechanism.isSingleOperationSignVerifyMechanism || verifyMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attemptBlocking(session.verifyInit(verifyMechanism, publicKey))
    result <- ZIO.attemptBlocking(session.verify(data, signature)).fold(_ => false, _ => true)
  } yield result

  def initiateSession(slotListNo: Int, behavior: SessionMode): RIO[Module with Scope, Session] = for {
    pkcs11Module <- ZIO.service[Module]
    slotList <- ZIO.attemptBlocking(pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT))
    _ <- ZIO.fail(new RuntimeException("Session initiation error")).unless(slotList.length > slotListNo)
    slot = slotList(slotListNo)
    token <- ZIO.attemptBlocking(slot.getToken)
    session <- ZIO.acquireRelease(openSession(token, behavior))(session => ZIO.attemptBlocking(session.closeSession()).orDie)
  } yield session

  def loadModule(): RIO[AppConfig, Module] = for {
    config <- ZIO.service[AppConfig]
    module <- ZIO.attemptBlocking(Module.getInstance(config.pkcs11LibPath))
    _ <- ZIO.attemptBlocking(module.initialize(null))
  } yield module

  val login: RIO[Session with Scope with AppConfig, UserStateContext.LoggedIn] = for {
    session <- ZIO.service[Session]
    config <- ZIO.service[AppConfig]
    _ <- ZIO.attemptBlocking(session.login(Session.UserType.USER, config.userPin.toCharArray)).withFinalizer(_ => logout().orDie)
  } yield new UserStateContext.LoggedIn

  private def logout(): RIO[Session, UserStateContext.LoggedOut] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attemptBlocking(session.logout())
  } yield new UserStateContext.LoggedOut

  private def openSession(token: Token, behavior: SessionMode): Task[Session] = {
    ZIO.attemptBlocking(token.openSession(Token.SessionType.SERIAL_SESSION,
      behavior.toPkcs11, null, null))
  }

  private def encrypt(data: Array[Byte],
                      encryptionKey: Key,
                      encryptionMechanism: Mechanism):
  RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(encryptionMechanism.isSingleOperationEncryptDecryptMechanism || encryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.encryptInit(encryptionMechanism, encryptionKey))
    iv = padding(data.length)
    toEncrypt = iv ++ data
    chunkSize = 16 + (toEncrypt.length / 16) * 16
    outBuffer = Array.ofDim[Byte](toEncrypt.length)
    _ <- ZIO.attemptBlocking(session.encrypt(toEncrypt, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer

  private def decrypt(data: Array[Byte],
                      decryptionKey: Key,
                      decryptionMechanism: Mechanism,
                      paddingFirstBytes: Int):
  RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(decryptionMechanism.isSingleOperationEncryptDecryptMechanism || decryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.decryptInit(decryptionMechanism, decryptionKey))
    chunkSize = 16 + (data.length / 16) * 16
    outBuffer = Array.ofDim[Byte](chunkSize)
    _ <- ZIO.attemptBlocking(session.decrypt(data, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer.slice(paddingFirstBytes, Integer.parseInt(outBuffer.take(paddingFirstBytes).mkString, 2) + paddingFirstBytes)

  private def padding(i: Int): Array[Byte] = {
    Integer.toBinaryString((1 << 5) | i).map(_ - '0').map(_.toByte).drop(1).toArray
  }

  def prepareKey(keyAlias: String): Key = {
    val key = new Key()
    key.getLabel.setCharArrayValue(keyAlias.toCharArray)
    key
  }

  private def privateKeyTemplate(alias: String, mechanismInfo: MechanismInfo): RSAPrivateKey = {
    val privateKeyTemplate = new RSAPrivateKey()
    privateKeyTemplate.getSensitive.setBooleanValue(true)
    privateKeyTemplate.getToken.setBooleanValue(true)
    privateKeyTemplate.getPrivate.setBooleanValue(true)
    privateKeyTemplate.getLabel.setCharArrayValue(alias.toCharArray)
    privateKeyTemplate.getSign.setBooleanValue(mechanismInfo.isSign)
    privateKeyTemplate.getSignRecover.setBooleanValue(mechanismInfo.isSignRecover)
    privateKeyTemplate.getDecrypt.setBooleanValue(mechanismInfo.isDecrypt)
    privateKeyTemplate.getDerive.setBooleanValue(mechanismInfo.isDerive)
    privateKeyTemplate.getUnwrap.setBooleanValue(mechanismInfo.isUnwrap)
    privateKeyTemplate
  }

  private def publicKeyTemplate(alias: String, mechanismInfo: MechanismInfo): RSAPublicKey = {
    val publicKeyTemplate = new RSAPublicKey()
    publicKeyTemplate.getLabel.setCharArrayValue(alias.toCharArray)
    publicKeyTemplate.getPublicExponent.setByteArrayValue(BigInt(5).toByteArray)
    publicKeyTemplate.getToken.setBooleanValue(true)
    publicKeyTemplate.getModulusBits.setLongValue(1024)
    publicKeyTemplate.getVerify.setBooleanValue(mechanismInfo.isVerify)
    publicKeyTemplate.getVerifyRecover.setBooleanValue(mechanismInfo.isVerifyRecover)
    publicKeyTemplate.getEncrypt.setBooleanValue(mechanismInfo.isEncrypt)
    publicKeyTemplate.getDerive.setBooleanValue(mechanismInfo.isDerive)
    publicKeyTemplate.getWrap.setBooleanValue(mechanismInfo.isWrap)
    publicKeyTemplate
  }

}
