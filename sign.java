/*生成apk签名*/
// .method public static O()Ljava/lang/String;
//     .registers 1

//     const-string v0, "apksign"

//     return-object v0
// .end method

// {
//   "username": "momoid",
//   "session": "login session",
//   "resource": "android",
//   "cflag": "24b",
//   "uid": "ea783e5dfa32dd306b0861d2e6d7f4ef",
//   "version": 12715,
//   "extraData": {
//     "abtest": "nearbypeopleliveexp-kmjyjy_blank;aisayhi-bmhtje_blank;test-rsxyxo_blank;morenew-wkhqld_A;microcosm-jtgdzn_blank;active-wklfmo_blank;location-vwzlkp_A;nearbyfeedlive-mclxen_blank"
//   }
// }

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


