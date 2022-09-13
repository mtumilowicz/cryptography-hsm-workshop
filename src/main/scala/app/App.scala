package app

import app.ZIOCryptoki._
import iaik.pkcs.pkcs11.Session
import zio.{Scope, ZIO, ZIOAppDefault, ZLayer}

object App extends ZIOAppDefault {
  override def run: ZIO[Any, Any, Any] = {
    val dataToEncrypt = "abcdefghi"
    program(dataToEncrypt).provide(
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

}
