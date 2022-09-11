package app

import iaik.pkcs.pkcs11.objects.Key
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Module, Session, Token}
import zio.{RIO, Scope, Task, ZIO, ZIOAppDefault, ZLayer}
import ZIOCryptoki._

object ABC extends ZIOAppDefault {

  // initiateSession2("1989".toCharArray, 0)
  override def run: ZIO[Any, Any, Any] =
    program.provide(
      ZLayer.fromZIO(initiateSession2("1989".toCharArray, 0)),
      ZLayer.fromZIO(loadModule()),
      Scope.default
    )

  def prepareKey(): Key = {
    val key = new Key()
    key.getLabel.setCharArrayValue("AA".toCharArray)
    key
  }

  val program: ZIO[Session with Scope, Throwable, Any] = for {
    _ <- logout()
    _ <- login()
    secretKey <- retrieveKey(prepareKey())
    mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
    encryption <- encrypt("hehe".getBytes("utf-8"), secretKey, mechanism)
    decryption <- decrypt(encryption, secretKey, mechanism)
    _ <- zio.Console.printLine(new String(decryption))
  } yield ()




}
