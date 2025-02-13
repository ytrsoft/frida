const WRAPS = [
  'Byte', 'Short', 'Integer', 'Long', 'Float', 'Double', 'Character', 'Boolean', 'String'
]

const PKGS = {
  MODIFIER: 'java.lang.reflect.Modifier',
  MSG_HELPER: 'com.immomo.momo.message.helper.p',
  MSG_SENDER: 'com.immomo.momo.mvp.message.task.c',
  USER_SERVICE: 'com.immomo.momo.service.user.UserService',
  MSG_SERVICE: 'com.immomo.momo.messages.service.l',
}

const isWrapType = (instance) => {
  const name = getInstName(instance)
  return WRAPS.includes(name)
}

const isStatic = (field) => {
  const Modifier = Java.use(PKGS.MODIFIER)
  const modifiers = field.getModifiers()
  return Modifier.isStatic(modifiers)
}

const getInstName = (instance) => {
  const classes = instance.getClass()
  return classes.getSimpleName()
}

const getFields = (instance) => {
  const classes = instance.getClass()
  return classes.getDeclaredFields()
}

const getMethods = (instance) => {
  const classes = instance.getClass()
  return classes.getDeclaredMethods()
}

const getValue = (instance, field) => {
  const ref = {}
  try {
    field.setAccessible(true)
    ref.value = field.get(instance)
  } catch (e) {
    ref.value = undefined
  }
  return ref.value
}

const setValue = (instance, key, value) => {
  const classes = instance.getClass()
  const field = classes.getDeclaredField(key)
  field.setAccessible(true)
  field.set(instance, value)
}

const invoke = (instance, index, ...value) => {
  const classes = instance.getClass()
  const ms = classes.getDeclaredMethods()
  ms[index].setAccessible(true)
  ms[index].invoke(instance, value)
}

const getTime = (date) => {
  const regex = /^(\w+)\s(\w+)\s(\d{1,2})\s(\d{2}:\d{2}:\d{2})\sGMT([+\-]\d{2}):(\d{2})\s(\d{4})$/
  const months = {
    'Jan': 0, 'Feb': 1, 'Mar': 2, 'Apr': 3, 'May': 4, 'Jun': 5,
    'Jul': 6, 'Aug': 7, 'Sep': 8, 'Oct': 9, 'Nov': 10, 'Dec': 11
  }
  const match = date.toString().match(regex)
  if (!match) return undefined
  const month = months[match[2]]
  const day = parseInt(match[3], 10)
  const year = parseInt(match[7], 10)
  const [hours, minutes, seconds] = match[4].split(':').map(num => parseInt(num, 10))
  const offsetHour = parseInt(match[5], 10)
  const offsetMinute = parseInt(match[6], 10)
  const totalOffsetMinutes = offsetHour * 60 + offsetMinute
  const dateUTC = Date.UTC(year, month, day, hours, minutes, seconds)
  const timeStamp = dateUTC - totalOffsetMinutes * 60 * 1000
  return timeStamp
}

const dispatched = (value) => {
  if (value == null) {
    return undefined
  }
  if (isWrapType(value)) {
    return value.toString()
  } else {
    const name = getInstName(value)
    if (name === 'Date') {
      const st = value.toString()
      return getTime(st)
    } else if (name === 'User') {
      return serialize(value)
    } else {
      return undefined
    }
  }
}

const serialize = (instance) => {
  const result = {}
  const fields = getFields(instance)
  fields.forEach((field) => {
    if (!isStatic(field)) {
      const name = field.getName()
      const value = getValue(instance, field)
      if (value !== null) {
        result[name] = dispatched(value)
      }
    }
  })
  return result
}

const setup = (handle) => {
  let value
  Java.perform(() => {
    value = handle()
  })
  return value
}

const getUser = (id) => {
  const UserService = Java.use(PKGS.USER_SERVICE)
  return UserService.getInstance().get(id)
}

const post = (msg) => {
  return setup(() => {
    const { momoid, remoteId, content } = msg
    const MessageSender = Java.use(PKGS.MSG_SENDER)
    const MessageHelper = Java.use(PKGS.MSG_HELPER)
    const owner = getUser(momoid)
    const remote = getUser(remoteId)
    const helper = MessageHelper.a()
    const message = helper.a(content, remote, null, 1)
    setValue(message, 'owner', owner)
    const sender = MessageSender.$new()
    invoke(sender, 0, message)
    return serialize(message)
  })
}

const getUserProfile = (id) => {
  const user = {}
  const info = profileApi(id)
  const profile = info.profile
  user.momoid = profile.momoid
  user.age = profile.age
  user.sex = profile.sex
  user.constellation = profile.constellation
  user.name = profile.name
  user.photo = profile.photos[0]
  user.location = profile.show_location
  user.status = profile.online_status
  return user
}

const receive = () => {
  return setup(() => {
    const SingleMsgService = Java.use(PKGS.MSG_SERVICE)
    const overload = SingleMsgService.a.overloads[21]
    overload.implementation = function(...args) {
      const result = {}
      const message = serialize(args[0])
      const id = message.remoteId
      const profile = getUserProfile(id)
      result.remoteUser = profile
      result.msgId = message.msgId
      result.content = message.content
      result.momoid = message.myMomoId
      result.timestamp = message.timestamp
      if (result.content) {
        send(result)
      }
      return this.a.apply(this, args)
    }
  })
}

rpc.exports = {
  post,
  receive
}
