const attachLibc = (name, handle) => {
  const addr = Module.findExportByName('libc.so', name)
  Interceptor.attach(addr, {
    onEnter(args) {
      this.arg0 = args[0]
      this.arg1 = args[1]
      this.arg2 = args[2]
      this.arg4 = args[4]
    },
    onLeave() {
      const size = this.arg2.toInt32()
      if (size > 0) {
        handle && handle(this)
      }
    }
  })
}

attachLibc('sendto', (ctx) => {
  const size = ctx.arg2.toInt32()
  if (size > 0) {
    console.log(hexdump(ctx.arg1, { length: size }))
  }
})
