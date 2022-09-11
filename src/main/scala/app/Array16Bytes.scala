package app

case class Array16Bytes private(private val array: Array[Byte]) {
  val length = array.length

  val value = array.clone()
}

object Array16Bytes {
  def fromArray(array: Array[Byte]): Either[Throwable, Array16Bytes] = {
    if (array.length > 16) Left(new IllegalArgumentException("Array12Bytes - max length: 12"))
    else Right(Array16Bytes(array))
  }

  def fromString(string: String): Either[Throwable, Array16Bytes] =
    fromArray(string.getBytes("utf-8"))

}
