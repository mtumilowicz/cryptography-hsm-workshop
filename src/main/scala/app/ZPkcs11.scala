package app

import iaik.pkcs.pkcs11.Module
import zio.{RIO, ZIO}


object ZPkcs11 {

  def loadModule(): RIO[AppConfig, Module] = for {
    config <- ZIO.service[AppConfig]
    module <- ZIO.attemptBlocking(Module.getInstance(config.pkcs11LibPath))
    _ <- ZIO.attemptBlocking(module.initialize(null))
  } yield module

}
