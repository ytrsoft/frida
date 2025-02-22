const getVar = (name) => {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(`--${name}`)
    .trim()
}

const fetchNearly = async (lng, lat) => {
  const res = await fetch(
    `/nearly/${lng}/${lat}`
  )
  const json = await res.json()
  return json.value
}

const fetchData = async (name) => {
  const res = await fetch(
    `https://geo.datav.aliyun.com/areas_v3/bound/${name}.json`
  )
  return await res.json()
}

const postMessage = async (message) => {
  const res = await fetch(
    `/post`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(message)
    }
  )
  return await res.json()
}

new Vue({
  el: '#app',
  delimiters: ['[[',']]'],
  data() {
    return {
      point: null,
      map: null,
      name: '100000_full',
      cache: [],
      history: [],
      nearlys: [],
      markPoint: [],
      locked: true
    }
  },
  beforeDestroy() {
    this.dispose()
    window.removeEventListener('resize', this.resizeChart)
  },
  mounted() {
    window.addEventListener('resize', this.resizeChart)
    this.$nextTick(() => {
      this.renderMap()
    })
  },
  methods: {
    onSelected(user, index) {
      if (!user.use) {
        const sender = {
          content: `小${user.sex !== 0 ? '哥哥' : '姐姐'}，你好🙂`,
          momoid: user.momoid,
          remoteId: user.id
        }
        postMessage(sender)
        user.use = true
        this.$set(this.nearlys, index, user)
      }
    },
    dispose() {
      if (this.map) {
        this.map.dispose()
        this.map = null
      }
    },
    changeMode() {
      this.locked = !this.locked
    },
    async itemClick(index) {
      if (index === -1) {
        this.name = '100000_full'
        this.history = []
      } else {
        const current = this.history[index]
        this.name = `${current.adcode}_full`
        this.history.splice(index + 1)
      }
      await this.renderMap()
    },
    async goBack() {
      const len = this.history.length
      if (len === 0) {
        this.itemClick(-1)
      } else {
        this.itemClick(len - 2)
      }
    },
    initChart() {
      this.dispose()
      const el = this.$refs.mapBox
      const instance = echarts.init(el)
      instance.on('click', this.onMapClick)
      this.map = instance
    },
    async renderMap() {
      this.initChart()

      const sg = getVar('bg-secondary')
      const bc = getVar('border-color')
      const tc = getVar('text-secondary')

      const data = await fetchData(this.name)
      echarts.registerMap(this.name, data)

      this.cache = data.features.map((feature) => feature.properties)

      const settings = this.isRoot ? {
        zoom: 1.5,
        center: [105, 34]
      } : { zoom: 1 }

      this.map.setOption({
        geo: [
          {
            map: this.name,
            ...settings,
            itemStyle: {
              color: sg,
              opacity: 1,
              borderWidth: 0.5,
              borderColor: bc
            },
            label: {
              show: true,
              distance: 5,
              formatter: (params) => params.name ? params.name : ' ',
              textStyle: {
                color: tc,
                fontSize: 8
              }
            },
            emphasis: {
              label: {
                show: true,
                textStyle: {
                  color: tc,
                  fontSize: 10
                }
              },
              itemStyle: {
                color: bc
              }
            }
          }
        ],
        series: [
          {
            type: 'effectScatter',
            coordinateSystem: 'geo',
            data: this.markPoint
          }
        ]
      })
    },
    async onMapClick({ name, event }) {
      if (this.locked) {
        const { offsetX, offsetY } = event
        const p = this.map.convertFromPixel('geo', [
          offsetX, offsetY
        ])
        this.point = { lng: parseInt(p[0]), lat: parseInt(p[1]) }
        this.markPoint = [
          {
            name: '标记点',
            value: [...p],
            itemStyle: {
              color: '#e6a23c'
            }
          }
        ]
        this.nearlys = await fetchNearly(...p)
        await this.renderMap()
      } else {
        const current = this.cache.find((c) => c.name === name)
        const { adcode, level } = current
        if (level === 'district') return
        this.name = `${adcode}_full`
        this.history.push(current)
        await this.renderMap()
      }
    },
    resizeChart() {
      if (this.map) {
        this.map.resize()
      }
    }
  },
  computed: {
    isRoot() {
      return this.name === '100000_full'
    }
  }
})
