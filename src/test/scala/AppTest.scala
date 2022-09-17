import app.ZCipher._
import app.ZPkcs11._
import app.ZSession._
import app.ZSignature._
import app.{AppConfig, SessionMode, UserStateContext}
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import iaik.pkcs.pkcs11.{Mechanism, Session}
import zio.test.Assertion._
import zio.test.TestAspect.sequential
import zio.test._
import zio.{ZIO, ZLayer}

object AppTest extends ZIOSpecDefault {

  val tests = suite("App test")(
    test("encrypt / decrypt")(
      check(Gen.stringBounded(1, 10)(Gen.alphaNumericChar)) { data =>
        for {
          decryption <- encryptDecrypt(data)
        } yield assert(data)(equalTo(new String(decryption)))
      }
    ),
    test("sign / verify")(
      check(Gen.stringBounded(1, 10)(Gen.alphaNumericChar)) { data =>
        for {
          verified <- signVerify(data)
        } yield assertTrue(verified)
      }
    ),
    test("verify wrong signature")(
      check(Gen.chunkOfN(10)(Gen.byte), Gen.chunkOfN(20)(Gen.byte)) { (data, signature) =>
        for {
          verified <- verify(data.toArray,
            signature.toArray,
            "RSAPublicKey",
            Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)
          )
        } yield assert(verified)(isFalse)
      }
    )
  ) @@ sequential

  def spec =
    tests
      .provideSomeShared(
        ZLayer.fromZIO(initiateSession(0, SessionMode.ReadOnly)),
        ZLayer.fromZIO(loadModule()),
        ZLayer.fromZIO(login),
        AppConfig.live)

  private def encryptDecrypt(dataToEncrypt: String):
  ZIO[Session with AppConfig with UserStateContext.LoggedIn, Throwable, String] = for {
    config <- ZIO.service[AppConfig]
    keyAlias = config.keyAlias
    mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
    chunkSize = 1024 // AES - 16 byte block
    encrypted <- encrypt(keyAlias, dataToEncrypt, mechanism, chunkSize)
    decrypted <- decrypt(keyAlias, encrypted, mechanism, chunkSize)
  } yield decrypted

  private def signVerify(dataToSign: String):
  ZIO[Session with AppConfig with UserStateContext.LoggedIn, Throwable, Boolean] = for {
    _ <- ZIO.service[Session]
    mechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)
    signed <- sign(dataToSign, "RSAPrivateKey", mechanism)
    verified <- verify(dataToSign.getBytes("utf-8"), signed, "RSAPublicKey", mechanism)
  } yield verified
}
