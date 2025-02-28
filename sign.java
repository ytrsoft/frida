/*生成apk签名*/
// .method public static O()Ljava/lang/String;
//     .registers 1

//     const-string v0, "apksign"

//     return-object v0
// .end method

// {
//   "username": "id",
//   "session": "?",
//   "resource": "android",
//   "cflag": "24b",
//   "uid": "?",
//   "version": 12715,
//   "extraData": {
//     "abtest": "?"
//   }
// }

//  adb logcat -s SHELL

// const-string v0, "SHELL"
// invoke-virtual {p1}, Lcom/immomo/im/X;->toString()Ljava/lang/String;
// move-result-object v1
// invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

public static String O() throws Exception {
  try {
      Signature S = S();
      if (S != null) {
          return com.immomo.mmutil.m.b(S.toCharsString());
      }
      return null;
  } catch (Exception unused) {
      return null;
  }
}


