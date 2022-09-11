import app.ABC.prepareKey
import app.ZIOCryptoki._
import iaik.pkcs.pkcs11.Mechanism
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants
import zio.ZLayer
import zio.test.Assertion._
import zio.test._

object ABCTest extends ZIOSpecDefault {

  def spec = suite("Add Spec")(
    test("hehe2")(
      check(Gen.stringBounded(1, 10)(Gen.alphaNumericChar)) { data =>
        for {
          secretKey <- retrieveKey(prepareKey())
          mechanism = Mechanism.get(PKCS11Constants.CKM_AES_ECB)
          bytes = data.getBytes("utf-8")
          encryption <- encrypt(bytes, secretKey, mechanism)
          decryption <- decrypt(encryption, secretKey, mechanism, padding(data.length).length)
        } yield assert(bytes)(equalTo(decryption))
      }
    )
  ).provideSome(ZLayer.fromZIO(initiateSession2("1989".toCharArray, 0)),
    ZLayer.fromZIO(login()),
    ZLayer.fromZIO(loadModule()))
}
