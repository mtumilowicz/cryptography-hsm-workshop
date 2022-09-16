package app

import app.KeyTemplates._
import iaik.pkcs.pkcs11.objects.{Key, KeyPair}
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Session}
import zio.{RIO, ZIO}

object ZKey {

  def generateRSAKeyPair(privateKeyAlias: String, publicKeyAlias: String):
  RIO[Session with UserStateContext.LoggedIn, KeyPair] = for {
    session <- ZIO.service[Session]
    keyPairGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN)
    token = session.getToken
    mechanismInfo <- ZIO.attemptBlocking(token.getMechanismInfo(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)))
    publicKey = rsaPublicKeyTemplate("RSAPublicKey", mechanismInfo)
    privateKey = rsaPrivateKeyTemplate("RSAPrivateKey", mechanismInfo)
    keyPair <- ZIO.attemptBlocking(session.generateKeyPair(keyPairGenerationMechanism, publicKey, privateKey))
  } yield keyPair

  def generateAESKey(alias: String): RIO[Session with UserStateContext.LoggedIn, Key] = for {
    session <- ZIO.service[Session]
    keyMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN)
    pkcs11Object <- ZIO.attemptBlocking(session.generateKey(keyMechanism, aesSecretKeyTemplate(alias)))
    key <- ZIO.attemptBlocking(pkcs11Object.asInstanceOf[Key])
  } yield key

  def retrieveKey(keyAlias: String): RIO[Session with UserStateContext.LoggedIn, Key] = for {
    session <- ZIO.service[Session]
    _ <- ZIO.attemptBlocking(session.findObjectsInit(prepareKey(keyAlias)))
    secretKeys <- ZIO.attemptBlocking(session.findObjects(1))
    _ <- ZIO.attemptBlocking(session.findObjectsFinal())
    result <- secretKeys.headOption match {
      case Some(value) => ZIO.attemptBlocking(value.asInstanceOf[Key])
      case None => ZIO.fail(new RuntimeException("Key retrieval error"))
    }
  } yield result

  private def prepareKey(keyAlias: String): Key = {
    val key = new Key()
    key.getLabel.setCharArrayValue(keyAlias.toCharArray)
    key
  }
}
