const API_BASE = 'https://api.immomo.com'
const USER_API = `${API_BASE}/v3/user/profile/info`

const PKGS = {
  IM_APP: 'com.immomo.momo.im.b',
  HASH_MAP: 'java.util.HashMap',
  HTTP_CLIENT: 'com.immomo.momo.protocol.http.a',
  MSG_SERVICE: 'com.immomo.momo.messages.service.l',
  USER_SERVICE: 'com.immomo.momo.service.user.UserService',
  MSG_HELPER: 'com.immomo.momo.message.helper.p',
  MSG_SENDER: 'com.immomo.momo.mvp.message.task.c'
}

let currentUser = {}
const userCache = {}
const messageHistory = []

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
  if (!id) return {}
  const body = postRequest(USER_API, { remoteid: id })
  const json = JSON.parse(body || '{}')
  return parseUserProfile(json.data?.profile || {})
}

const cacheUserInfo = (msg) => {
  const { mode, fromId } = msg
  if (mode === 0) {
    msg.avatar = currentUser.photos[0]
    msg.name = currentUser.name
    msg.constellation = currentUser.constellation
  } else {
    if (!userCache[fromId]) {
      userCache[fromId] = getUserProfile(fromId)
    }
    const photos = userCache[fromId]?.photos
    msg.avatar = photos && photos[0]
    msg.name = userCache[fromId]?.name
    msg.sex = userCache[fromId]?.sex
    msg.device = userCache[fromId]?.device
    msg.constellation = userCache[fromId]?.constellation
  }
}

const getCurrentId = () => {
  const IMApp = Java.use(PKGS.IM_APP)
  return IMApp.a().c().getId()
}

const initUser = () => {
  const id = getCurrentId()
  currentUser = getUserProfile(id)
}

const receiveMessage = (callback) => {
  const MsgService = Java.use(PKGS.MSG_SERVICE)
  const overload = MsgService.a.overloads[21]

  overload.implementation = function(args) {
    const message = {
      msgId: args.msgId.value,
      msgType: args.contentType.value,
      distance: args.distance.value,
      content: args.content.value,
      toId: args.myMomoId.value,
      fromId: args?.owner?.value?.getId(),
      mode: (args?.owner?.value?.getId() === currentUser.id) ? 0 : 1
    }
    if (message.msgType == 0) {
      cacheUserInfo(message)
      messageHistory.push(message)
      callback(message)
    }
    return this.a(args)
  }
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

const getCurrentUser = () => {
  Java.perform(() => {
    let value
    Java.perform(() => {
      value = handle()
    })
    return value
  })
}

const receive = () => {
  Java.perform(() => {
    initUser()
    receiveMessage((msg) => {
      const message = {
        currentUser,
        currentMsg: msg,
        userGroup: userCache,
        messageHistory
      }
      send(message)
    })
  })
}

rpc.exports = {
  receive,
  post
}
