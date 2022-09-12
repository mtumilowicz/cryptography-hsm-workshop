package app

import app.ZIOCryptoki._
import iaik.pkcs.pkcs11.Session
import zio.{Scope, ZIO, ZIOAppDefault, ZLayer}

object App extends ZIOAppDefault {

  override def run: ZIO[Any, Any, Any] = {
    val keyAlias = "AA"
    val userPin = "1989"
    val dataToEncrypt = "abcdefghi"
    program(keyAlias, dataToEncrypt, userPin).provide(
      ZLayer.fromZIO(initiateSession(0)),
      ZLayer.fromZIO(loadModule()),
      Scope.default
    )
  }

  def program(keyAlias: String, dataToEncrypt: String, userPin: String):
  ZIO[Session, Throwable, Array[Byte]] = for {
    encrypted <- encrypt2(keyAlias, dataToEncrypt, userPin)
    decrypted <- decrypt2(keyAlias, encrypted, userPin)
    _ <- zio.Console.printLine(new String(decrypted))
  } yield decrypted


}
