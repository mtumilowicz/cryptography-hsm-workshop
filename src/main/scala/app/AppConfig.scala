package app

import pureconfig.ConfigSource
import zio.{ZIO, ZLayer}
import pureconfig.generic.auto._

case class AppConfig(keyAlias: String,
                     userPin: String,
                     pkcs11LibPath: String)

object AppConfig {

  val live = ZLayer.fromZIO(load)

  private def load = ZIO.fromEither(ConfigSource.default.load[AppConfig])
    .mapError(failures => new RuntimeException(failures.toList.mkString(", ")))
}
