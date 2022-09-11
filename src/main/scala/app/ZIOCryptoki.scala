package app

import iaik.pkcs.pkcs11.objects.Key
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Module, Session, Token}
import zio.{RIO, Scope, Task, ZIO, ZIOAppDefault, ZLayer}

import java.nio.ByteBuffer

object ZIOCryptoki {

  def retrieveKey(keyTemplate: Key): RIO[Session, Key] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attempt(session.findObjectsInit(keyTemplate))
    secretKeys <- ZIO.attempt(session.findObjects(1))
    _ <- ZIO.attempt(session.findObjectsFinal())
    result <- secretKeys.headOption match {
      case Some(value) => ZIO.attempt(value.asInstanceOf[Key])
      case None => ZIO.fail(new RuntimeException("Key retrieval error"))
    }
  } yield result

  def encrypt(data: Array[Byte],
              encryptionKey: Key,
              encryptionMechanism: Mechanism): RIO[Session, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(encryptionMechanism.isSingleOperationEncryptDecryptMechanism || encryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attempt(session.encryptInit(encryptionMechanism, encryptionKey))
    iv = padding(data.length)
    toEncrypt = iv ++ data
    chunkSize = 16 + (toEncrypt.length / 16) * 16
    outBuffer = Array.ofDim[Byte](toEncrypt.length)
    _ <- ZIO.attempt(session.encrypt(toEncrypt, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer

  def decrypt(data: Array[Byte],
              decryptionKey: Key,
              decryptionMechanism: Mechanism,
              paddingFirstBytes: Int): RIO[Session, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(decryptionMechanism.isSingleOperationEncryptDecryptMechanism || decryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attempt(session.decryptInit(decryptionMechanism, decryptionKey))
    chunkSize = 16 + (data.length / 16) * 16
    outBuffer = Array.ofDim[Byte](chunkSize)
    _ <- ZIO.attempt(session.decrypt(data, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer.slice(paddingFirstBytes, Integer.parseInt(outBuffer.take(paddingFirstBytes).mkString, 2) + paddingFirstBytes)

  def sign(data: Array[Byte],
           signKey: Key,
           signMechanism: Mechanism): RIO[Session, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(signMechanism.isSingleOperationSignVerifyMechanism || signMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attempt(session.signInit(signMechanism, signKey))
    signature <- ZIO.attempt(session.sign(data))
  } yield signature

  def verify(data: Array[Byte],
             signature: Array[Byte],
             verifyKey: Key,
             verifyMechanism: Mechanism): RIO[Session, Boolean] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(verifyMechanism.isSingleOperationSignVerifyMechanism || verifyMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attempt(session.verifyInit(verifyMechanism, verifyKey))
    _ <- ZIO.attempt(session.verify(data, signature))
  } yield true


  def initiateSession(userPin: Array[Char], slotNo: Int): RIO[Module, Session] = for {
    pkcs11Module <- ZIO.service[Module]
    slotsWithTokens <- ZIO.attempt(pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT))
    _ <- ZIO.fail(new RuntimeException("Session initiation error")).unless(slotsWithTokens.length > slotNo)
    slot = slotsWithTokens(slotNo)
    token <- ZIO.attempt(slot.getToken)
    session <- ZIO.attempt(token.openSession(Token.SessionType.SERIAL_SESSION,
      Token.SessionReadWriteBehavior.RW_SESSION, null, null))
  } yield session

  def initiateSession2(userPin: Array[Char], slotNo: Int): RIO[Module with Scope, Session] =
    ZIO.acquireRelease(initiateSession(userPin, slotNo))(session => ZIO.attempt(session.closeSession()).orDie)


  def loadModule(): Task[Module] = for {
    module <- ZIO.attempt(Module.getInstance("C:/SoftHSM2/lib/softhsm2-x64.dll"))
    _ <- ZIO.attempt(module.initialize(null))
  } yield module

  def login(): RIO[Session with Scope, Unit] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attempt(session.login(Session.UserType.USER, "1989".toCharArray)).withFinalizer(_ => logout().orDie)
  } yield ()

  def logout(): RIO[Session, Unit] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attempt(session.logout())
  } yield ()

  def padding(i: Int): Array[Byte] = {
    Integer.toBinaryString((1 << 5) | i).map(_ - '0').map(_.toByte).drop(1).toArray
  }

}
