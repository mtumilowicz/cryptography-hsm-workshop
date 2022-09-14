package app

import app.ZIOCryptoki._
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Session}
import zio.{Scope, ZIO, ZIOAppDefault, ZLayer}

object App extends ZIOAppDefault {
  override def run: ZIO[Any, Any, Any] = {
    val dataToEncrypt = "abcdefghi"
    program2(dataToEncrypt).provide(
      ZLayer.fromZIO(initiateSession(0, SessionMode.ReadOnly)),
      ZLayer.fromZIO(loadModule()),
      ZLayer.fromZIO(login),
      AppConfig.live,
      Scope.default
    )
  }

  def program(dataToEncrypt: String):
  ZIO[Session with AppConfig with UserStateContext.LoggedIn, Throwable, Array[Byte]] = for {
    config <- ZIO.service[AppConfig]
    keyAlias = config.keyAlias
    encrypted <- encrypt(keyAlias, dataToEncrypt)
    decrypted <- decrypt(keyAlias, encrypted)
    _ <- zio.Console.printLine(new String(decrypted))
  } yield decrypted

  def program2(data: String):
  ZIO[Session with AppConfig with UserStateContext.LoggedIn, Throwable, Boolean] = for {
    _ <- ZIO.service[Session]
    mechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)
    signed <- sign(data, "RSAPrivateKey", mechanism)
    verified <- verify(data.getBytes("utf-8"), signed, "RSAPublicKey", mechanism)
    _ <- zio.Console.printLine(verified)
  } yield verified

}
