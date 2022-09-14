package app

import app.ZIOCryptoki._
import iaik.pkcs.pkcs11.{Mechanism, Session}
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import zio.{Scope, ZIO, ZIOAppDefault, ZLayer}

object App extends ZIOAppDefault {
  override def run: ZIO[Any, Any, Any] = {
    val dataToEncrypt = "abcdefghi"
    program2(dataToEncrypt).provide(
      ZLayer.fromZIO(initiateSession(0, SessionMode.ReadOnly)),
      ZLayer.fromZIO(loadModule()),
      AppConfig.live,
      Scope.default
    )
  }

  def program(dataToEncrypt: String):
  ZIO[Session with AppConfig, Throwable, Array[Byte]] = for {
    config <- ZIO.service[AppConfig]
    keyAlias = config.keyAlias
    userPin = config.userPin
    encrypted <- encrypt(keyAlias, dataToEncrypt, userPin)
    decrypted <- decrypt(keyAlias, encrypted, userPin)
    _ <- zio.Console.printLine(new String(decrypted))
  } yield decrypted

  def program2(data: String):
  ZIO[Session with AppConfig, Throwable, Boolean] = ZIO.scoped {
    for {
      config <- ZIO.service[AppConfig]
      _ <- login(config.userPin)
//      session <- ZIO.service[Session]
//      _ <- ZIO.attemptBlocking(generateRSAKeyPair(session))
      privateKey <- retrieveKey(prepareKey("RSAPrivateKey"))
      publicKey <- retrieveKey(prepareKey("RSAPublicKey"))
      signed <- sign(data.getBytes("utf-8"), privateKey, Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))
      verified <- verify(data.getBytes("utf-8"), signed, publicKey, Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))
      _ <- zio.Console.printLine(verified)
    } yield verified
  }

}
