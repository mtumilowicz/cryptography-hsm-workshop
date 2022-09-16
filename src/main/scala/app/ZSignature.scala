package app

import app.ZKey._
import iaik.pkcs.pkcs11.objects.Key
import iaik.pkcs.pkcs11.{Mechanism, Session}
import zio.{RIO, ZIO}

object ZSignature {

  def sign(data: String,
           keyAlias: String,
           signMechanism: Mechanism):
  RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    privateKey <- retrieveKey(keyAlias)
    signature <- sign(data.getBytes("utf-8"), privateKey, signMechanism)
  } yield signature

  def verify(data: Array[Byte],
             signature: Array[Byte],
             publicKeyAlias: String,
             verifyMechanism: Mechanism):
  RIO[Session with UserStateContext.LoggedIn, Boolean] = for {
    session <- ZIO.service[Session]
    publicKey <- retrieveKey(publicKeyAlias)
    _ <- ZIO.fail(new RuntimeException("Mechanism is not designed for signing")).unless(verifyMechanism.isSingleOperationSignVerifyMechanism || verifyMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attemptBlocking(session.verifyInit(verifyMechanism, publicKey))
    result <- ZIO.attemptBlocking(session.verify(data, signature)).fold(_ => false, _ => true)
  } yield result

  private def sign(data: Array[Byte],
                   privateKey: Key,
                   signMechanism: Mechanism): RIO[Session with UserStateContext.LoggedIn, Array[Byte]] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.fail(new RuntimeException("Mechanism is not design for verifying")).unless(signMechanism.isSingleOperationSignVerifyMechanism || signMechanism.isFullSignVerifyMechanism)
    _ <- ZIO.attemptBlocking(session.signInit(signMechanism, privateKey))
    signature <- ZIO.attemptBlocking(session.sign(data))
  } yield signature

}
