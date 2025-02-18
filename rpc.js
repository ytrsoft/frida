let LOGIN_USER = null
const USER_CACHE = {}

const API_BASE = 'https://api.immomo.com'
const USER_API = `${API_BASE}/v3/user/profile/info`

const TYPES = {
  INIT: 0,
  MESSAGE: 1
}

const PKGS = {
  IMJ: 'com.immomo.momo.im.e$1',
  IM_APP: 'com.immomo.momo.im.b',
  HASH_MAP: 'java.util.HashMap',
  ARRAY_LIST: 'java.util.ArrayList',
  HTTP_CLIENT: 'com.immomo.momo.protocol.http.a',
  MSG_SERVICE: 'com.immomo.momo.messages.service.l',
  USER_SERVICE: 'com.immomo.momo.service.user.UserService',
  MSG_HELPER: 'com.immomo.momo.message.helper.p',
  MSG_SENDER: 'com.immomo.momo.mvp.message.task.c'
}

const serialize = (instance) => {
  const json = {}
  const className = instance.getClass()
  const fields = className.getDeclaredFields()
  fields.forEach((field) => {
    field.setAccessible(true)
    const name = field.getName()
    const value = field.get(instance)
    json[name] = value && value.toString()
  })
  return json
}

const postRequest = (url, args) => {
  const HashMap = Java.use(PKGS.HASH_MAP)
  const map = HashMap.$new()
  Object.keys(args).forEach(key => map.put(key, args[key]))
  const httpClient = Java.use(PKGS.HTTP_CLIENT).$new()
  return httpClient.doPost(url, map)
}

const parsePopularity = (text) => {
  const match = text.match(/([\d\.]+)(万)?获赞\s·\s([\d\.]+)(万)?粉丝/)
  if (!match) return { likes: 0, followers: 0 }

  const likes = parseFloat(match[1]) * (match[2] ? 10000 : 1)
  const followers = parseFloat(match[3]) * (match[4] ? 10000 : 1)
  return { likes, followers }
}

const parseUserProfile = (profile) => {
  const { likes, followers } = parsePopularity(profile?.user_popular_text || '')
  return {
    id: profile?.momoid,
    name: profile?.name,
    height: profile?.height,
    age: profile?.age,
    sex: profile?.sex === 'F' ? 0 : 1,
    sexText: profile?.sex === 'F' ? '女' : '男',
    constellation: profile?.constellation,
    sign: profile?.sign,
    photos: profile?.photos,
    regTime: profile?.regtime,
    location: profile?.show_location,
    onlineStatus: profile?.online_status?.status,
    onlineType: profile?.profile_onlinetag?.type,
    level: profile?.growup?.level,
    vipLevel: profile?.vip?.active_level,
    svipLevel: profile?.svip?.active_level,
    authStatus: profile?.realAuth?.status,
    device: profile?.device_info?.device,
    living: profile?.sp_living?.name,
    company: profile?.sp_company?.name,
    workplace: profile?.sp_workplace?.name,
    hometown: profile?.sp_hometown?.name?.split(' ') || [],
    job: profile?.sp_industry?.name,
    school: profile?.sp_school?.map(s => s.name) || [],
    likes,
    followers,
    questionList: (profile?.question_list || []).map(q => ({
      question: q.question,
      answer: q.answer,
    }))
  }
}

const getUserProfile = (id) => {
  const body = postRequest(USER_API, { remoteid: id })
  const json = JSON.parse(body || '{}')
  return parseUserProfile(json.data.profile)
}

const post = (message) => {
  Java.perform(() => {
    const MessageSender = Java.use(PKGS.MSG_SENDER)
    const MessageHelper = Java.use(PKGS.MSG_HELPER)
    const UserService = Java.use(PKGS.USER_SERVICE)
    const US = UserService.getInstance()
    const owner = US.get(message.momoid)
    const remote = US.get(message.remoteId)
    const helper = MessageHelper.a()
    const msg = helper.a(message.content, remote, null, 1)
    msg.owner.value = owner
    const sender = MessageSender.$new()
    sender.b(msg)
  })
}

const handleMesage = (message, handle) => {
  const json = serialize(message)
  const id = json.remoteId
  const msg = {
    id: json.msgId,
    distance: json.distance,
    content: json.content,
    fromId: json.remoteId,
    toId: json.myMomoId,
    type: Number(json.contentType)
  }
  // 只有文本模式才回传
  if (msg.type === 0) {
    if (!USER_CACHE[id]) {
      USER_CACHE[id] = getUserProfile(id)
    }
    msg.remoteUser = USER_CACHE[id]
    handle && handle(msg)
  }
}

const onMessage = (handle) => {
  const Im = Java.use(PKGS.IMJ)
  const List = Java.use(PKGS.ARRAY_LIST)
  const classes = [
    'java.lang.String',
    'android.os.Bundle',
    'java.lang.Object'
  ]
  const overload = Im.a.overload(...classes)
  overload.implementation = function(...args) {
    const keys = args[1].keySet().toArray().toString()
    if (keys.includes('msgs')) {
      const msgs = args[1].get('msgs')
      const list = List.$new(msgs)
      for (let i = 0; i < list.size(); i++) {
        handleMesage(list.get(i), handle)
      }
    }
    return this.a(...args)
  }
}

const init = () => {
  Java.perform(() => {
    const IMApp = Java.use(PKGS.IM_APP)
    const id = IMApp.a().c().getId()
    if (!LOGIN_USER) {
      LOGIN_USER = getUserProfile(id)
      send({ type: TYPES.INIT, data: LOGIN_USER })
    }
  })
}

const receive = () => {
  Java.perform(() => {
    onMessage((message) => {
      send({ type: TYPES.MESSAGE, data: message })
    })
  })
}

rpc.exports = {
  receive,
  post,
  init
}
