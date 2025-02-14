const km = (value) => {
  const kilometers = value / 1000
  return parseFloat(kilometers.toFixed(1))
}

const setData = (payload) => {
  localStorage.setItem('PLALOAD', JSON.stringify(payload))
}

const getData = () => {
  const payload = localStorage.getItem('PLALOAD')
  if (payload) {
    return JSON.parse(payload)
  }
  return null
}

const handleSSEMessage = (event) => {
  let payload = JSON.parse(event.data).payload
  if (payload.length !== 0) {
    setData(payload)
    handlePayload(payload)
  } else {
    payload = getData()
    if (payload != null) {
      handlePayload(payload)
    }
  }
}

const handlePayload = (payload) => {
  payload.forEach((item) => {
    const unzip = item.replaceAll("'", '"')
    const { messageHistory, userGroup } = JSON.parse(unzip)
    renderMessageHistory(messageHistory)
    renderGroupMembers(userGroup)
  })
}

const renderMessageHistory = (messageHistory) => {
  const chat = document.querySelector('#chat')
  chat.innerHTML = messageHistory.map((message) => {
    return message.mode === 0 ? createRightMsg(message) : createLeftMsg(message)
  }).join('')
}

const renderGroupMembers = (userGroup) => {
  const users = document.querySelector('#users')
  const members = Object.values(userGroup || {})
  users.innerHTML = members.map((user, index) => {
    const border = user.sex === 'F' ? 'border-pink-500' : 'border-blue-500'
    return `
        <div class="group p-4 user-item hover:bg-gray-800 rounded-lg cursor-pointer flex items-center space-x-4 transition-all ease-in-out" data-index="${index}">
        <div class="relative">
          <div class="bg-green-500 text-white w-12 h-12 flex items-center justify-center rounded-full overflow-hidden shadow-md border-2 ${border}">
            <img class="w-full h-full object-cover rounded-full" src="/image/${user.photos[0]}" />
          </div>
        </div>
        <div class="flex flex-col ml-3 space-y-1">
          <div class="flex items-center space-x-2">
            <span class="text-white text-base font-semibold">${user.name}</span>
            <span class="bg-gray-600 text-gray-300 text-[10px] px-[4px] py-[2px]l rounded-[4px]">${user.age}岁</span>
          </div>
          <div class="text-gray-500 text-sm">${user.sign}</div>
        </div>
      </div>
    `
  }).join('')
}

const createLeftMsg = (message) => {
  const border = !message.sex ? 'border-pink-500' : 'border-blue-500'
  return `
    <div class="flex justify-start space-x-4">
      <div class="flex items-start space-x-4">
        <div class="${border} border mr-[15px] bg-[#1D4ED8] text-white w-[48px] h-[48px] flex items-center justify-center rounded-full text-xl">
          <img class="w-[48px] h-[48px] rounded-full" src="/image/${message.avatar}" />
        </div>
        <div class="flex flex-col">
          <div class="flex items-center space-x-2 text-xs text-[#A0A0A0]">
            <span class="font-semibold">${message.name}</span>
            <span>· ${km(message.distance)}km</span>
          </div>
          <div class="mt-4 bg-[#3B82F6] text-white p-4 rounded-lg shadow-md w-[280px]">
            ${message.content}
          </div>
        </div>
      </div>
    </div>
  `
}

const createRightMsg = (message) => {
  const border = !message.sex ? 'border-pink-500' : 'border-blue-500'
  return `
    <div class="flex justify-end space-x-4">
      <div class="flex items-start space-x-4">
        <div class="mr-[15px] flex flex-col items-end">
          <div class="flex items-center space-x-2 text-xs text-[#A0A0A0]">
            <span class="font-semibold">${message.name}</span>
            <span>· ${km(message.distance)}km</span>
          </div>
          <div class="mt-4 bg-[#4CAF50] text-white p-4 rounded-lg shadow-md w-[280px]">
            ${message.content}
          </div>
        </div>
        <div class="${border} shadow-md border-2 bg-[#1D4ED8] text-white w-[48px] h-[48px] flex items-center justify-center rounded-full text-xl">
          <img class="w-[48px] h-[48px] rounded-full" src="/image/${message.avatar}" />
        </div>
      </div>
    </div>
  `
}

const sendMessage = async () => {
  const message = document.querySelector('#message')
  const data = {
    momoid: '979025201',
    remoteId: '994491371',
    content: message.value,
  }
  await fetch('/post', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(data),
  })
  message.value = ''
}

const initSSEConnect = () => {
  const event = new EventSource('/sse')
  event.onmessage = handleSSEMessage
}

window.onload = initSSEConnect
