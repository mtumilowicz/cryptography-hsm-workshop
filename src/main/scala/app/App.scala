package app

import app.ZCipher._
import app.ZPkcs11._
import app.ZSession._
import app.ZSignature._
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Session}
import zio.{Scope, ZIO, ZIOAppDefault, ZLayer}

object App extends ZIOAppDefault {
  override def run: ZIO[Any, Any, Any] = {
    val dataToEncrypt = "abcdefghi"
    cipher(dataToEncrypt).provide(
      ZLayer.fromZIO(initiateSession(0, SessionMode.ReadWrite)),
      ZLayer.fromZIO(loadModule()),
      ZLayer.fromZIO(login),
      AppConfig.live,
      Scope.default
    )
  }

  def cipher(dataToEncrypt: String):
  ZIO[Session with AppConfig with UserStateContext.LoggedIn, Throwable, Array[Byte]] = for {
    config <- ZIO.service[AppConfig]
    keyAlias = config.keyAlias
    mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
    chunkSize = 1024 // AES - 16 byte block
    encrypted <- encrypt(keyAlias, dataToEncrypt, mechanism, chunkSize)
    decrypted <- decrypt(keyAlias, encrypted, mechanism, chunkSize)
    _ <- zio.Console.printLine(new String(decrypted))
  } yield decrypted

  def signature(data: String):
  ZIO[Session with AppConfig with UserStateContext.LoggedIn, Throwable, Boolean] = for {
    _ <- ZIO.service[Session]
    mechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)
    signed <- sign(data, "RSAPrivateKey", mechanism)
    verified <- verify(data.getBytes("utf-8"), signed, "RSAPublicKey", mechanism)
    _ <- zio.Console.printLine(verified)
  } yield verified

}
