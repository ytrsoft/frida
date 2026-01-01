Java.perform(() => {
  const Coded = Java.use('com.immomo.momo.util.jni.Coded')
  Coded.aesEncode.implementation = function(data, dataLen, key, keyLen, output) {
    console.log('byte[] key = new byte[]{' + key.toString() + '};')
    return this.aesEncode(data, dataLen, key, keyLen, output)
  }
})
