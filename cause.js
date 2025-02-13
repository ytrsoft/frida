const WRAPS = [
  'Byte', 'Short', 'Integer', 'Long', 'Float', 'Double', 'Character', 'Boolean', 'String'
]

const isWrapType = (instance) => {
  const name = getInstName(instance)
  return WRAPS.includes(name)
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
    } else {
      return serialize(value)
    }
  }
}

const serialize = (instance) => {
  const result = {}
  const fields = getFields(instance)
  fields.forEach((field) => {
    const name = field.getName()
    const value = getValue(instance, field)
    if (value !== null) {
      result[name] = dispatched(value)
    }
  })
  return result
}

const equalLine = (s) => {
  return Array(s).fill('=').join('')
}

const bytes_text = (bytes) => {
  return JSON.stringify(bytes)
}

const mapJSON = (map) => {
  const JSONObject = Java.use('org.json.JSONObject')
  return JSONObject.$new(map)
}

const main = (handle) => {
  Java.perform(handle)
}

const forMethod = (options) => {
  const TargetClass = Java.use(options.pkg)
  const methods = TargetClass.class.getDeclaredMethods()
  methods.forEach((method) => {
    const methodName = method.getName()
    const methodOverloads = TargetClass[methodName].overloads
    methodOverloads.forEach((overload, overloadIndex) => {
      overload.implementation = function (...args) {
        const methodProps = {
          type: 2,
          name: methodName,
          overloadIndex,
          overload,
          args,
          self: this
        }
        if (options.before) {
          options.on(methodProps)
        }
        const result = this[methodName](...args)
        if (!options.before) {
          options.on(methodProps)
        }
        return result
      }
    })
  })
}

const forConstruct = (options) => {
  const TargetClass = Java.use(options.pkg)
  const constructOverloads = TargetClass.$init.overloads
  constructOverloads.forEach((overload, overloadIndex) => {
    overload.implementation = function(...args) {
      const methodProps = {
        type: 1,
        name: methodName,
        overloadIndex,
        overload,
        args,
        self: this
      }
      if (options.before) {
        options.on(methodProps)
      }
      const result = this[methodName](...args)
      if (!options.before) {
        options.on(methodProps)
      }
      return result
    }
  })
}
