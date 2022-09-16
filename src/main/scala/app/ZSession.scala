package app

import iaik.pkcs.pkcs11.{Module, Session, Token}
import zio.{RIO, Scope, Task, ZIO}

object ZSession {

  def initiateSession(slotListNo: Int, behavior: SessionMode):
  RIO[Module with Scope, Session] = for {
    pkcs11Module <- ZIO.service[Module]
    slotList <- ZIO.attemptBlocking(pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT))
    _ <- ZIO.fail(new RuntimeException("Session initiation error")).unless(slotList.length > slotListNo)
    slot = slotList(slotListNo)
    token <- ZIO.attemptBlocking(slot.getToken)
    session <- ZIO.acquireRelease(openSession(token, behavior))(session => ZIO.attemptBlocking(session.closeSession()).orDie)
  } yield session

  val login: RIO[Session with Scope with AppConfig, UserStateContext.LoggedIn] = for {
    session <- ZIO.service[Session]
    config <- ZIO.service[AppConfig]
    _ <- ZIO.attemptBlocking(session.login(Session.UserType.USER, config.userPin.toCharArray))
      .withFinalizer(_ => logout().orDie)
  } yield new UserStateContext.LoggedIn

  private def logout(): RIO[Session, UserStateContext.LoggedOut] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attemptBlocking(session.logout())
  } yield new UserStateContext.LoggedOut

  private def openSession(token: Token, behavior: SessionMode): Task[Session] = {
    ZIO.attemptBlocking(token.openSession(Token.SessionType.SERIAL_SESSION,
      behavior.toPkcs11, null, null))
  }

}
