const MSG_TYPES = {
  INIT: 0,
  MESSAGE: 1,
  POST: 2,
}

const createWS = (handle) => {
  const socket = new WebSocket("ws://localhost:8080/ws")
  socket.onopen = () => {
    console.log("===开启IMJ===")
  }
  socket.onclose = () => {
    console.log("===关闭IMJ===")
  }
  socket.onerror = ({ message }) => {
    console.error("===IMJ错误===", message)
  }
  socket.onmessage = (event) => {
    const message = JSON.parse(event.data)
    handle && handle(message)
  }
  return socket
}

new Vue({
  el: '#app',
  delimiters: ['[[',']]'],
  data() {
    return {
      ws: null,
      selectId: null,
      user: null,
      ids: [],
      users: [],
      chats: [],
    }
  },
  mounted() {
    this.initWS()
  },
  methods: {
    km(meters) {
      const km = meters / 1000
      return km.toFixed(2) + 'km'
    },
    initWS() {
      this.ws = createWS(this.onMessage)
    },
    changeItem(id) {
    this.selectId = id
    },
    sendMsg() {
      const content = this.$refs.content.value
      const p = this;
      debugger
      if (content && this.ws && this.selectId && this.user) {
        const message = {
          content,
          momoid: this.user.id,
          remoteId: this.selectId
        }
        this.chats.push({
          showType: 1,
          content,
          remoteUser: this.user
        })
        const json = JSON.stringify({
          type: MSG_TYPES.POST,
          data: message
        })
        this.ws.send(json)
        this.$refs.content.value = ''
        this.scrollToBottom()
      }
    },
    onMessage(msgList) {
      msgList.forEach((msg) => {
        this.onMsgHandle(msg)
      })
    },
    onMsgHandle({ type, data }) {
      if (type === MSG_TYPES.INIT) {
        this.user = data
      } else {
        this.onMsgNextHandle(data)
      }
    },
    onMsgNextHandle(message) {
      message.showType = 0
      this.chats.push(message)
      const id = message.remoteUser.id
      this.selectId = id
      if (!this.ids.includes(id)) {
        this.ids.push(id)
        this.users.push(message.remoteUser)
      }
      this.scrollToBottom()
    },
    scrollToBottom() {
      const chatsContainer = this.$refs.chatsContainer
      this.$nextTick(() => {
        chatsContainer.scrollTop = chatsContainer.scrollHeight
      })
    }
  }
})
