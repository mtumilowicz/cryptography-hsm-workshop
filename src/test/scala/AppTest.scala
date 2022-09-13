import app.App
import app.ZIOCryptoki._
import zio.ZLayer
import zio.test.Assertion._
import zio.test._

object AppTest extends ZIOSpecDefault {
  def spec = suite("App test")(
    test("encrypt / decrypt")(
      check(Gen.stringBounded(1, 10)(Gen.alphaNumericChar)) { data =>
        for {
          decryption <- App.program(data)
        } yield assert(data)(equalTo(new String(decryption)))
      }
    )
  ).provideSome(ZLayer.fromZIO(initiateSession(0)),
    ZLayer.fromZIO(loadModule()))
}
