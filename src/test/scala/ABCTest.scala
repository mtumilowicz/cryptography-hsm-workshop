import zio.{Random, Scope}
import zio.test._
import zio.test.Assertion._

object ABCTest extends ZIOSpecDefault {

  val genTicker: Gen[Random with Sized, String] =
    Gen.asciiString

  override def spec: Spec[TestEnvironment with Scope, Any] = {
    suite("huhu")(
      test("hehe") {
        assert(5 + 5)(equalTo(10))
      },
      test("hehe2") {
        assert(5 + 5)(equalTo(10))
      }
    )
  }
}
