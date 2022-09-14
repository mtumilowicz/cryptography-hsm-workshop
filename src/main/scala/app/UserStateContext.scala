package app

trait UserStateContext

object UserStateContext {
  class LoggedIn extends UserStateContext

  class LoggedOut extends UserStateContext
}
