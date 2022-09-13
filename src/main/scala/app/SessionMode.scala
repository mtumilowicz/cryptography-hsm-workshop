package app

import iaik.pkcs.pkcs11.Token

sealed trait SessionMode {
  def toPkcs11: Boolean = {
    this match {
      case SessionMode.ReadOnly => Token.SessionReadWriteBehavior.RO_SESSION
      case SessionMode.ReadWrite => Token.SessionReadWriteBehavior.RW_SESSION
    }
  }
}

object SessionMode {
  case object ReadOnly extends SessionMode
  case object ReadWrite extends SessionMode
}