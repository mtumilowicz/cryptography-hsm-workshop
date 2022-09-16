package app

import iaik.pkcs.pkcs11.MechanismInfo
import iaik.pkcs.pkcs11.objects._
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants

object KeyTemplates {

   def rsaPrivateKeyTemplate(alias: String, mechanismInfo: MechanismInfo): RSAPrivateKey = {
    val privateKeyTemplate = new RSAPrivateKey()
    privateKeyTemplate.getSensitive.setBooleanValue(true)
    privateKeyTemplate.getToken.setBooleanValue(true)
    privateKeyTemplate.getPrivate.setBooleanValue(true)
    privateKeyTemplate.getLabel.setCharArrayValue(alias.toCharArray)
    privateKeyTemplate.getSign.setBooleanValue(mechanismInfo.isSign)
    privateKeyTemplate.getSignRecover.setBooleanValue(mechanismInfo.isSignRecover)
    privateKeyTemplate.getDecrypt.setBooleanValue(mechanismInfo.isDecrypt)
    privateKeyTemplate.getDerive.setBooleanValue(mechanismInfo.isDerive)
    privateKeyTemplate.getUnwrap.setBooleanValue(mechanismInfo.isUnwrap)
    privateKeyTemplate
  }

   def rsaPublicKeyTemplate(alias: String, mechanismInfo: MechanismInfo): RSAPublicKey = {
    val publicKeyTemplate = new RSAPublicKey()
    publicKeyTemplate.getLabel.setCharArrayValue(alias.toCharArray)
    publicKeyTemplate.getPublicExponent.setByteArrayValue(BigInt(5).toByteArray)
    publicKeyTemplate.getToken.setBooleanValue(true)
    publicKeyTemplate.getModulusBits.setLongValue(1024)
    publicKeyTemplate.getVerify.setBooleanValue(mechanismInfo.isVerify)
    publicKeyTemplate.getVerifyRecover.setBooleanValue(mechanismInfo.isVerifyRecover)
    publicKeyTemplate.getEncrypt.setBooleanValue(mechanismInfo.isEncrypt)
    publicKeyTemplate.getDerive.setBooleanValue(mechanismInfo.isDerive)
    publicKeyTemplate.getWrap.setBooleanValue(mechanismInfo.isWrap)
    publicKeyTemplate
  }

   def aesSecretKeyTemplate(alias: String): SecretKey = {
    val secretKeyTemplate = new ValuedSecretKey(PKCS11Constants.CKK_AES)
    secretKeyTemplate.getPrivate.setBooleanValue(true)
    secretKeyTemplate.getSensitive.setBooleanValue(true)
    secretKeyTemplate.getExtractable.setBooleanValue(false)
    secretKeyTemplate.getLabel.setCharArrayValue(alias.toCharArray)
    secretKeyTemplate.getEncrypt.setBooleanValue(true)
    secretKeyTemplate.getDecrypt.setBooleanValue(true)
    secretKeyTemplate.getWrap.setBooleanValue(true)
    secretKeyTemplate.getUnwrap.setBooleanValue(true)
    secretKeyTemplate.getToken.setBooleanValue(true)
    secretKeyTemplate.getValueLen.setLongValue(32)
    secretKeyTemplate
  }

}
