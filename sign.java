/*生成apk签名*/
// .method public static O()Ljava/lang/String;
//     .registers 1

//     const-string v0, "apksign"

//     return-object v0
// .end method

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


