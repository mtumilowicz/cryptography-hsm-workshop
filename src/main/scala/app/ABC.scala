package app

import iaik.pkcs.pkcs11.{Session, TokenException}
import iaik.pkcs.pkcs11.objects.Key
import zio.{RIO, Task, ZIO, ZIOAppDefault}

object ABC extends ZIOAppDefault {

  override def run: ZIO[Any, Any, Any] =
    zio.Console.printLine("hello world!")

  def retrieveKey(keyTemplate: Key): RIO[Session, Key] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attempt(session.findObjectsInit(keyTemplate))
    secretKeys = session.findObjects(1)
    result <- secretKeys.headOption match {
      case Some(value) => ZIO.attempt(value.asInstanceOf[Key])
      case None => ZIO.fail(new RuntimeException("Key retrieval error"))
    }
  } yield result

}
