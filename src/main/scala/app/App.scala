package app

import app.ZIOCryptoki._
import iaik.pkcs.pkcs11.Session
import pureconfig._
import pureconfig.generic.auto._
import zio.{Scope, ZIO, ZIOAppDefault, ZLayer}

object App extends ZIOAppDefault {

  case class AppConfig(keyAlias: String, userPin: String)

  override def run: ZIO[Any, Any, Any] = {
    val dataToEncrypt = "abcdefghi"
    program(dataToEncrypt).provide(
      ZLayer.fromZIO(initiateSession(0)),
      ZLayer.fromZIO(loadModule()),
      Scope.default
    )
  }

  def program(dataToEncrypt: String):
  ZIO[Session, Throwable, Array[Byte]] = for {
    config <- loadConfig
    keyAlias = config.keyAlias
    userPin = config.userPin
    encrypted <- encrypt2(keyAlias, dataToEncrypt, userPin)
    decrypted <- decrypt2(keyAlias, encrypted, userPin)
    _ <- zio.Console.printLine(new String(decrypted))
  } yield decrypted

  private val loadConfig = ZIO.fromEither(ConfigSource.default.load[AppConfig])
    .mapError(failures => new RuntimeException(failures.toList.mkString(", ")))


}
