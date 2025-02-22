const MSG_TYPES = {
  INIT: 0,
  MESSAGE: 1,
  POST: 2,
  REPLAY: 3,
  ENABLE: 4,
  DISABLE: 5
}

const UUID = () => {
  return 'xxxxxxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    var r = Math.random() * 16 | 0
    var v = (c === 'x' ? r : (r & 0x3 | 0x8))
    return v.toString(16)
  })
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
      input: '',
      gpt: true,
      selectId: null,
      user: {},
      ids: [],
      chats: [],
      users: []
    }
  },
  mounted() {
    this.initWS()
  },
  methods: {
    onSelected(id) {
      this.selectId = id
    },
    changeMode() {
      let type = MSG_TYPES.ENABLE
      this.gpt = !this.gpt
      if (!this.gpt) {
        type = MSG_TYPES.DISABLE
      }
      const json = JSON.stringify({
        type
      })
      this.ws.send(json)
    },
    initWS() {
      this.ws = createWS(this.onMessage)
    },
    onMessage(msgList) {
      msgList.forEach((msg) => {
        this.onMsgHandle(msg)
      })
    },
    onMsgHandle({ type, data }) {
      if (type === MSG_TYPES.INIT) {
        this.user = data
      } else if (type === MSG_TYPES.REPLAY) {
        this.onMessageReplay(data)
      } else {
        this.onMsgNextHandle(data)
      }
    },
    onMessageReplay(content) {
      message = {
        remoteUser: this.user,
        content: content
      }
      this.$nextTick(() => {
        this.chats.push(message)
        this.scrollToBottom()
      })
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
    onMessageReplay({ content, remoteId }) {
      const replayUser = this.users.find((u) => u.id === remoteId)
      message = {
        id: UUID(),
        showType: 1,
        replayUser,
        remoteUser: this.user,
        content: content
      }
      this.$nextTick(() => {
        this.chats.push(message)
        this.scrollToBottom()
      })
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
    sendMessage() {
      const content = this.input.trim()
      if (content && this.ws && this.selectId && this.user) {
        const replayUser = this.users.find((u) => u.id === this.selectId)
        const message = {
          content,
          momoid: this.user.id,
          remoteId: this.selectId
        }
        const p = {
          showType: 1,
          content,
          id: UUID(),
          replayUser,
          remoteUser: this.user
        }
        const json = JSON.stringify({
          type: MSG_TYPES.POST,
          data: message
        })
        this.ws.send(json)
        this.input = ''
        this.chats.push(p)
        this.scrollToBottom()
      }
    },
    scrollToBottom() {
      this.$nextTick(() => {
        const chatArea = this.$refs.chatArea
        chatArea.scrollTop = chatArea.scrollHeight
      })
    },
  },
  watch: {
    selectId(newId) {
      this.$nextTick(() => {
        const selectedElement = this.$refs[`user-${newId}`][0]
        if (selectedElement) {
          selectedElement.scrollIntoView({
            behavior: 'smooth',
            block: 'center'
          })
        }
      })
    }
  }
})
