const mapToObj = (javaMap) => {
  if (javaMap == null) return null
  var map = Java.cast(javaMap, Java.use('java.util.Map'))
  var keys = map.keySet().iterator()
  var obj = {}
  while (keys.hasNext()) {
    var key = keys.next()
    var value = map.get(key)
    obj[key] = value ? value.toString() : null
  }
  return JSON.stringify(obj)
}

const parseObject = function(input) {
  var res = input
  if (typeof input === 'string') {
    try {
      var parsed = JSON.parse(input)
      if (parsed !== null && typeof parsed === 'object') {
        res = parsed
      } else {
        return input
      }
    } catch (e) {
      return input
    }
  }
  if (res !== null && typeof res === 'object') {
    for (var key in res) {
      if (Object.prototype.hasOwnProperty.call(res, key)) {
        res[key] = parseObject(res[key])
      }
    }
  }
  return res
}

const setup = () => {
  Java.perform(() => {
    const request = {}
    const ApiSecurity = Java.use('com.immomo.momoenc.e');
    ApiSecurity.a.overload('java.util.Map', 'java.util.Map').implementation = function (map, map2) {
      request.body = mapToObj(map)
      request.header = mapToObj(map2)
      return this.a(map, map2)
    }
    ApiSecurity.a.overload('com.immomo.momoenc.g').implementation = function (gVar) {
      const result = this.a(gVar)
      send({
        url: this.m.value,
        header: parseObject(request.header),
        body: parseObject(request.body),
        response: parseObject(result)
      })
      return result
    }
  })
}

rpc.exports = {
  setup
}
