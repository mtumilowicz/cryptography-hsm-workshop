package app

import iaik.pkcs.pkcs11.objects.Key
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Module, Session, Token}
import zio.{RIO, Scope, Task, ZIO}

object ZIOCryptoki {

  def retrieveKey(keyTemplate: Key): RIO[Session, Key] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attemptBlocking(session.findObjectsInit(keyTemplate))
    secretKeys <- ZIO.attemptBlocking(session.findObjects(1))
    _ <- ZIO.attemptBlocking(session.findObjectsFinal())
    result <- secretKeys.headOption match {
      case Some(value) => ZIO.attemptBlocking(value.asInstanceOf[Key])
      case None => ZIO.fail(new RuntimeException("Key retrieval error"))
    }
  } yield result

  def encrypt(keyAlias: String, dataToEncrypt: String, userPin: String):
  ZIO[Session, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      _ <- login(userPin)
      key = prepareKey(keyAlias)
      secretKey <- retrieveKey(key)
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      bytes = dataToEncrypt.getBytes("utf-8")
      encryption <- encrypt(bytes, secretKey, mechanism)
    } yield encryption
  }

  private def encrypt(data: Array[Byte],
              encryptionKey: Key,
              encryptionMechanism: Mechanism): RIO[Session, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(encryptionMechanism.isSingleOperationEncryptDecryptMechanism || encryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.encryptInit(encryptionMechanism, encryptionKey))
    iv = padding(data.length)
    toEncrypt = iv ++ data
    chunkSize = 16 + (toEncrypt.length / 16) * 16
    outBuffer = Array.ofDim[Byte](toEncrypt.length)
    _ <- ZIO.attemptBlocking(session.encrypt(toEncrypt, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer

  def decrypt(keyAlias: String, dataToDecrypt: Array[Byte], userPin: String):
  ZIO[Session, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      _ <- login(userPin)
      key = prepareKey(keyAlias)
      secretKey <- retrieveKey(key)
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      decryption <- decrypt(dataToDecrypt, secretKey, mechanism, padding(dataToDecrypt.length).length)
    } yield decryption
  }

  def decrypt(data: Array[Byte],
              decryptionKey: Key,
              decryptionMechanism: Mechanism,
              paddingFirstBytes: Int): RIO[Session, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(decryptionMechanism.isSingleOperationEncryptDecryptMechanism || decryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.decryptInit(decryptionMechanism, decryptionKey))
    chunkSize = 16 + (data.length / 16) * 16
    outBuffer = Array.ofDim[Byte](chunkSize)
    _ <- ZIO.attemptBlocking(session.decrypt(data, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer.slice(paddingFirstBytes, Integer.parseInt(outBuffer.take(paddingFirstBytes).mkString, 2) + paddingFirstBytes)

  def sign(data: Array[Byte],
           signKey: Key,
           signMechanism: Mechanism): RIO[Session, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(signMechanism.isSingleOperationSignVerifyMechanism || signMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attemptBlocking(session.signInit(signMechanism, signKey))
    signature <- ZIO.attemptBlocking(session.sign(data))
  } yield signature

  def verify(data: Array[Byte],
             signature: Array[Byte],
             verifyKey: Key,
             verifyMechanism: Mechanism): RIO[Session, Boolean] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(verifyMechanism.isSingleOperationSignVerifyMechanism || verifyMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attemptBlocking(session.verifyInit(verifyMechanism, verifyKey))
    _ <- ZIO.attemptBlocking(session.verify(data, signature))
  } yield true


  def initiateSession(slotListNo: Int): RIO[Module with Scope, Session] = for {
    pkcs11Module <- ZIO.service[Module]
    slotList <- ZIO.attemptBlocking(pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT))
    _ <- ZIO.fail(new RuntimeException("Session initiation error")).unless(slotList.length > slotListNo)
    slot = slotList(slotListNo)
    token <- ZIO.attemptBlocking(slot.getToken)
    session <- ZIO.acquireRelease(readOnlySession(token))(session => ZIO.attemptBlocking(session.closeSession()).orDie)
  } yield session

  def readOnlySession(token: Token): Task[Session] = {
    ZIO.attemptBlocking(token.openSession(Token.SessionType.SERIAL_SESSION,
      Token.SessionReadWriteBehavior.RW_SESSION, null, null))
  }

  def loadModule(): Task[Module] = for {
    module <- ZIO.attemptBlocking(Module.getInstance("C:/SoftHSM2/lib/softhsm2-x64.dll"))
    _ <- ZIO.attemptBlocking(module.initialize(null))
  } yield module

  def login(userPin: String): RIO[Session with Scope, Unit] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attemptBlocking(session.login(Session.UserType.USER, userPin.toCharArray)).withFinalizer(_ => logout().orDie)
  } yield ()

  def logout(): RIO[Session, Unit] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attemptBlocking(session.logout())
  } yield ()

  def padding(i: Int): Array[Byte] = {
    Integer.toBinaryString((1 << 5) | i).map(_ - '0').map(_.toByte).drop(1).toArray
  }

  def prepareKey(keyAlias: String): Key = {
    val key = new Key()
    key.getLabel.setCharArrayValue(keyAlias.toCharArray)
    key
  }

}
