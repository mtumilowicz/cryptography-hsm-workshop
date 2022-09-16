package app

import app.ZKey.retrieveKey
import iaik.pkcs.pkcs11.objects.Key
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Session}
import zio.{RIO, ZIO}

object ZCipher {

  def encrypt(keyAlias: String, data: String):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(keyAlias)
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      dataToEncrypt = data.length.toString + "||" + data
      bytes = dataToEncrypt.getBytes("utf-8")
      encryption <- encrypt(bytes, secretKey, mechanism)
    } yield encryption
  }

  def decrypt(keyAlias: String, dataToDecrypt: Array[Byte]):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, Array[Byte]] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(keyAlias)
      mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
      bytes <- decrypt(dataToDecrypt, secretKey, mechanism)
      asString = new String(bytes)
      length = asString.takeWhile(_ != '|').toInt
      data = asString.dropWhile(_ != '|').slice(2, length + 2)
    } yield data.getBytes("utf-8")
  }

  private def encrypt(data: Array[Byte],
                      encryptionKey: Key,
                      encryptionMechanism: Mechanism):
  RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(encryptionMechanism.isSingleOperationEncryptDecryptMechanism || encryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.encryptInit(encryptionMechanism, encryptionKey))
    chunkSize = 1024
    outBuffer = Array.ofDim[Byte](chunkSize)
    _ <- ZIO.attemptBlocking(session.encrypt(data, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer

  private def decrypt(data: Array[Byte],
                      decryptionKey: Key,
                      decryptionMechanism: Mechanism):
  RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(decryptionMechanism.isSingleOperationEncryptDecryptMechanism || decryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.decryptInit(decryptionMechanism, decryptionKey))
    chunkSize = 1024
    outBuffer = Array.ofDim[Byte](chunkSize)
    _ <- ZIO.attemptBlocking(session.decrypt(data, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer

}
