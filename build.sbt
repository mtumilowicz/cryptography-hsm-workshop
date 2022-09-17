ThisBuild / version := "0.1.0-SNAPSHOT"

ThisBuild / scalaVersion := "2.13.8"

lazy val root = (project in file("."))
  .settings(
    name := "cryptography-hsm-workshop"
  )

libraryDependencies += "dev.zio" %% "zio" % "2.0.2"
libraryDependencies += "dev.zio" %% "zio-test" % "2.0.2"
libraryDependencies += "com.github.pureconfig" %% "pureconfig" % "0.17.1"
libraryDependencies += "org.xipki.iaik" % "sunpkcs11-wrapper" % "1.4.10"
libraryDependencies += "org.bouncycastle" % "bcprov-jdk18on" % "1.71.1"