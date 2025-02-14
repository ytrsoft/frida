const main = (callback) => {
  Java.perform(callback)
}

const hookMethod = (cls, name, overload, index, args, callback) => {
  const methodProps = {
    type: 'method',
    name,
    index,
    overload,
    args,
    self: this,
    result: null
  }

  if (callback.before) {
    callback.on(methodProps)
  }

  const result = this[name](...args)

  if (!callback.before) {
    methodProps.result = result
    callback.on(methodProps)
  }

  return result
}

const hookConstructor = (cls, overload, index, args, callback) => {
  const methodProps = {
    type: 'constructor',
    name: 'constructor',
    index,
    overload,
    args,
    self: this
  }

  if (callback.before) {
    callback.on(methodProps)
  }

  const result = this.$init(...args)

  if (!callback.before) {
    callback.on(methodProps)
  }

  return result
}

const interceptMethods = (options) => {
  const cls = Java.use(options.pkg)
  const methods = cls.class.getDeclaredMethods()

  methods.forEach((method) => {
    const name = method.getName()
    const overloads = cls[name].overloads

    overloads.forEach((overload, index) => {
      overload.implementation = function (...args) {
        hookMethod(cls, name, overload, index, args, options)
        return this[name](...args)
      }
    })
  })
}

const interceptConstructors = (options) => {
  const cls = Java.use(options.pkg)
  const overloads = cls.$init.overloads

  overloads.forEach((overload, index) => {
    overload.implementation = function (...args) {
      hookConstructor(cls, overload, index, args, options)
      return this.$init(...args)
    }
  })
}

const setup = (opts) => {
  const { init = false } = opts || {}
  main(() => {
    if (init) {
      interceptConstructors(opts)
    } else {
      interceptMethods(opts)
    }
  })
}
