package app

import app.ZKey.retrieveKey
import iaik.pkcs.pkcs11.objects.Key
import iaik.pkcs.pkcs11.{Mechanism, Session}
import org.bouncycastle.util.encoders.Base64
import zio.{RIO, ZIO}

import java.nio.charset.StandardCharsets

object ZCipher {

  def encrypt(keyAlias: String,
              data: String,
              mechanism: Mechanism,
              chunkSize: Int):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, String] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(keyAlias)
      dataToEncrypt = data.length.toString + "||" + data
      bytes = dataToEncrypt.getBytes(StandardCharsets.UTF_8)
      encryption <- encrypt(bytes, secretKey, mechanism, chunkSize)
    } yield Base64.toBase64String(encryption)
  }

  def decrypt(keyAlias: String,
              data: String,
              mechanism: Mechanism,
              chunkSize: Int):
  ZIO[Session with UserStateContext.LoggedIn, Throwable, String] = ZIO.scoped {
    for {
      secretKey <- retrieveKey(keyAlias)
      bytes <- decrypt(Base64.decode(data), secretKey, mechanism, chunkSize)
      asString = new String(bytes)
      length = asString.takeWhile(_ != '|').toInt
      data = asString.dropWhile(_ != '|').slice(2, length + 2)
    } yield data
  }

  private def encrypt(data: Array[Byte],
                      encryptionKey: Key,
                      encryptionMechanism: Mechanism,
                      chunkSize: Int):
  RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(encryptionMechanism.isSingleOperationEncryptDecryptMechanism || encryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.encryptInit(encryptionMechanism, encryptionKey))
    outBuffer = Array.ofDim[Byte](chunkSize)
    _ <- ZIO.attemptBlocking(session.encrypt(data, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer

  private def decrypt(data: Array[Byte],
                      decryptionKey: Key,
                      decryptionMechanism: Mechanism,
                      chunkSize: Int):
  RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Key retrieval error")).unless(decryptionMechanism.isSingleOperationEncryptDecryptMechanism || decryptionMechanism.isFullEncryptDecryptMechanism)
    _ <- ZIO.attemptBlocking(session.decryptInit(decryptionMechanism, decryptionKey))
    outBuffer = Array.ofDim[Byte](chunkSize)
    _ <- ZIO.attemptBlocking(session.decrypt(data, 0, chunkSize, outBuffer, 0, chunkSize))
  } yield outBuffer

}
