const inet_pton = Module.findExportByName('libc.so', 'inet_pton')
console.log(inet_pton)
if (inet_pton != null) {
  Interceptor.attach(inet_pton, {
    onEnter: (args) => {
      console.log(args[1].readUtf8String())
    }
  })
}
