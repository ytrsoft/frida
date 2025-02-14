const groups = {}
const caches = []

const PKGS = {
  USER_SERVICE: 'com.immomo.momo.service.user.UserService',
  MSG_HELPER: 'com.immomo.momo.message.helper.p',
  MSG_SENDER: 'com.immomo.momo.mvp.message.task.c'
}



Java.perform(() => {
  // const { momoid, remoteId, content } = msg
  const msg = {
    momoid: '979025201',
    remoteId: '994491371',
    content: '===110==='
  }
  const MessageSender = Java.use(PKGS.MSG_SENDER)
  const MessageHelper = Java.use(PKGS.MSG_HELPER)
  const UserService = Java.use(PKGS.USER_SERVICE)
  const US = UserService.getInstance()
  const owner = US.get(msg.momoid)
  const remote = US.get(msg.remoteId)
  const helper = MessageHelper.a()
  const message = helper.a(msg.content, remote, null, 1)
  message.owner.value = owner
  const sender = MessageSender.$new()
  sender.b(message)
})

