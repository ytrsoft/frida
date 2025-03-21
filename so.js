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

const charLine = (char) => {
  return Array(100).fill(char).join('')
}

const socket = (fd) => {
  const type = Socket.type(fd)
  if (type !== null) {
    const peer = Socket.peerAddress(fd)
    const local = Socket.localAddress(fd)
    if (peer.ip && peer.port && local.ip && local.port) {
      console.log(`${peer.ip}:${peer.port} => ${local.ip}:${local.port}`)
    }
  }
}

attachLibc('sendto', (ctx) => {
  const fd = ctx.arg0.toInt32()
  const size = ctx.arg2.toInt32()
  if (size > 0) {
    console.log(charLine('>'))
    socket(fd)
    console.log(hexdump(ctx.arg1, { length: size }))
    console.log(charLine('<'))
  }
})
