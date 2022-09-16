package app

import pureconfig.ConfigSource
import pureconfig.generic.auto._
import zio.{ZIO, ZLayer}

case class AppConfig(keyAlias: String,
                     userPin: String,
                     pkcs11LibPath: String)

object AppConfig {

  val live = ZLayer.fromZIO(load)

  private def load = ZIO.fromEither(ConfigSource.default.load[AppConfig])
    .mapError(failures => new RuntimeException(failures.toList.mkString(", ")))
}
