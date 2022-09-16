package app

import app.ZKey.retrieveKey
import iaik.pkcs.pkcs11.objects.Key
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Session}
import zio.{RIO, ZIO}

object ZCipher {

  def encrypt(keyAlias: String, dataToEncrypt: String):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(keyAlias)
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      bytes = dataToEncrypt.getBytes("utf-8")
      encryption <- encrypt(bytes, secretKey, mechanism)
    } yield encryption
  }

  def decrypt(keyAlias: String, dataToDecrypt: Array[Byte]):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(keyAlias)
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      decryption <- decrypt(dataToDecrypt, secretKey, mechanism, padding(dataToDecrypt.length).length)
    } yield decryption
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

}
