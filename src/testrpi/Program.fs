open System
open System.Security.Cryptography
open AronParker.Hkdf

/////////////////////////////////////////////////////////////////////
// 日次キーにある TEK から PRI を割り出すプログラム
// 
// 参照先
//  Exposure Notification Cryptography Specification 
//  https://blog.google/documents/69/Exposure_Notification_-_Cryptography_Specification_v1.2.1.pdf
// 
// NuGet 
//   Hkdf https://github.com/AronParker/Hkdf
/////////////////////////////////////////////////////////////////////

/// ASCII文字列をバイト配列に変換
let stobytes( s: string ) : byte[] =
    [| for ch in s -> byte(ch) |]
// 16進数文字列をバイト配列に変換
let hextobytes( s: string ) : byte[] =
    [|
        for i = 0 to s.Length/2-1 do
            let ch1 = s.[i*2]
            let ch2 = s.[i*2+1]
            byte("0123456789abcdef".IndexOf(ch1) * 16 + "0123456789abcdef".IndexOf(ch2))
    |]
// int型を4バイトの配列に変換
let itobytes( v: int ) : byte[] =
    [|
        byte(v &&& 0xFF)
        byte((v >>> 8) &&& 0xFF)
        byte((v >>> 16) &&& 0xFF)
        byte((v >>> 24) &&& 0xFF)
    |]
// バイト配列を16進数の文字列に変換
let bytestohex( ary: byte[] ) : string =
    let mutable s = ""
    for x in ary do
        s <- s + x.ToString("x02")
    s

printfn "test PRI"
#if false
(*
 *   [001]:[80585c0960d903338d22f3ee57250b00]
 *      [transmission_risk_level       ]:[0]
 *      [rolling_start_interval_number ]:[2665440]
 *      [rolling_period                ]:[144]
 *)
//////////////////////////////////////////////////////////////
// probeCOCOATek で取得できる TEK DAta
//////////////////////////////////////////////////////////////
let TEKi_S = "80585c0960d903338d22f3ee57250b00"
let TEKi : byte[] = hextobytes(TEKi_S)
let rolling_start_interval_number = 2665440
#else
//////////////////////////////////////////////////////////////
// Google のテストコードから
/// TestVectors.java にテストデータがある
//////////////////////////////////////////////////////////////
let TEMPORARY_TRACING_KEY : byte[] = [| 0x75uy; 0xc7uy; 0x34uy; 0xc6uy; 0xdduy; 0x1auy; 0x78uy; 0x2duy; 0xe7uy; 0xa9uy; 0x65uy; 0xdauy; 0x5euy; 0xb9uy; 0x31uy; 0x25uy |]
let RPIK : byte[] = [| 0x18uy; 0x5auy; 0xd9uy; 0x1duy; 0xb6uy; 0x9euy; 0xc7uy; 0xdduy; 0x04uy; 0x89uy; 0x60uy; 0xf1uy; 0xf3uy; 0xbauy; 0x61uy; 0x75uy |]
let TEKi = TEMPORARY_TRACING_KEY
let KEY_GENERATION_NSECONDS = 1585785600;
let CTINTERVAL_NUMBER_OF_GENERATED_KEY = 2642976 // KEY_GENERATION_NSECONDS/600  
let rolling_start_interval_number = CTINTERVAL_NUMBER_OF_GENERATED_KEY
#endif


//////////////////////////////////////////////////////////////
// UTC の tempstamp は全デバイス共通になる
//////////////////////////////////////////////////////////////
// 24時間固定
let rolling_period = 144
// そのまま
let ENINi = rolling_start_interval_number  

// HKDF クラス (System.Security.Cryptography) | Microsoft Docs 
// https://docs.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.hkdf?view=net-5.0&viewFallbackFrom=netframework-4.8
// PRIKi を生成する
// https://tools.ietf.org/html/rfc5869
// https://github.com/AronParker/Hkdf

let HKDF(ikm,salt,info,len) = 
    let hash = HashAlgorithmName.SHA256
    let hkdf = new Hkdf(hash)
    let actualPrk = hkdf.Extract(ikm, salt)
    let actualOkm = hkdf.Expand(actualPrk, len, info)
    actualOkm

let EN_PRIK : byte[] = stobytes("EN-RPIK")
let RPIKi = HKDF( TEKi, null, EN_PRIK ,16)  // solt は null 固定

printfn "TEKi  %s" (bytestohex(TEKi))
printfn "RPIKi %s" (bytestohex(RPIKi))

// https://docs.microsoft.com/ja-jp/dotnet/api/system.security.cryptography.aescryptoserviceprovider?view=net-5.0

let aes = new AesCryptoServiceProvider();
aes.BlockSize <- 128;
aes.KeySize <- 128;
aes.IV <- [| for i in 0..15 -> byte(0) |]    // IV は null 固定
aes.Key <- RPIKi
aes.Mode <- CipherMode.ECB;
aes.Padding <- PaddingMode.PKCS7;
printfn "key %s IV %s" (bytestohex( aes.Key )) (bytestohex( aes.IV ))

/// PaddedDatajを144個分まとめて暗号化する
/// その後で144分割して16バイトにする
/// 最後に16バイト余るが無視でよいらしい
// PaddedDataj[0..5] = "EN-PRI"
// PaddedDataj[6..11] = 0x0
// PaddedDataj[12..15] = ENINj
let PaddedDataj : byte[] = 
    Array.concat [
        for i in 0..143 do
            Array.concat [
                stobytes("EN-RPI") 
                [| for i=6 to 11 do byte(0) |]
                itobytes(ENINi + i )
            ]
    ]
let AES(data: byte[]) =
    let encrypt = aes.CreateEncryptor()
    let encrypted = encrypt.TransformFinalBlock( data, 0, data.Length )
    encrypted
let RPIij = AES(PaddedDataj)
printfn "PaddedDataj len: %d" PaddedDataj.Length
printfn "RPIij len: %d" RPIij.Length
// 144分割する
for i in 0..143 do 
    let RPIj = RPIij.AsSpan(0+16*i,16).ToArray()
    let ENINj = ENINi + i 
    printfn "%d RPI %s" ENINj  (bytestohex( RPIj ))



// 参照コード
// https://github.com/google/exposure-notifications-internals/blob/main/exposurenotification/src/main/cpp/matching_helper.cc#L68 
(*

bool MatchingHelper::GenerateIds(const uint8_t *diagnosis_key,
                                 uint32_t rolling_start_number, uint8_t *ids) {
  uint8_t rpi_key[kRpikLength];
  // RPIK <- HKDF(tek, NULL, UTF8("EN-PRIK"), 16).
  if (HKDF(rpi_key, kRpikLength, EVP_sha256(), diagnosis_key, kTekLength,
      /*salt=*/nullptr, /*salt_len=*/0,
           reinterpret_cast<const uint8_t *>(kHkdfInfo), kHkdfInfoLength) != 1) {
    return false;
  }

  if (EVP_EncryptInit_ex(&context, EVP_aes_128_ecb(), /*impl=*/nullptr, rpi_key,
      /*iv=*/nullptr) != 1) {
    return false;
  }

  uint32_t en_interval_number = rolling_start_number;
  for (int index = 0; index < kIdPerKey * kIdLength;
       index += kIdLength, en_interval_number++) {
    *((uint32_t * ) (&aesInputStorage[index + 12])) = en_interval_number;
  }

  int out_length;
  return EVP_EncryptUpdate(&context, ids, &out_length, aesInputStorage,
                           kIdPerKey * kIdLength) == 1;
}


    // From TestVectors.h.txt
    // ------------------------------------------------------------------------------
    public static final int KEY_GENERATION_NSECONDS = 1585785600;
    public static final int CTINTERVAL_NUMBER_OF_GENERATED_KEY = 2642976;
    public static final int ID_ROLLING_PERIOD_MINUTES = 10;
    public static final int KEY_ROLLING_PERIOD_MULTIPLE_OF_ID_PERIOD = 144;

    private static final byte[] TEMPORARY_TRACING_KEY =
            asBytes(
                    0x75, 0xc7, 0x34, 0xc6, 0xdd, 0x1a, 0x78, 0x2d, 0xe7, 0xa9, 0x65, 0xda, 0x5e, 0xb9, 0x31,
                    0x25);

    private static final byte[] RPIK =
            asBytes(
                    0x18, 0x5a, 0xd9, 0x1d, 0xb6, 0x9e, 0xc7, 0xdd, 0x04, 0x89, 0x60, 0xf1, 0xf3, 0xba, 0x61,
                    0x75);
    private static final byte[] AEMK =
            asBytes(
                    0xd5, 0x7c, 0x46, 0xaf, 0x7a, 0x1d, 0x83, 0x96, 0x5b, 0x9b, 0xed, 0x8b, 0xd1, 0x52, 0x93,
                    0x6a);
    private static final byte[] BLE_METADATA = asBytes(0x40, 0x08, 0x00, 0x00);
    private static final byte[] RPI0 =
            asBytes(
                    0x8b, 0xe6, 0xcd, 0x37, 0x1c, 0x5c, 0x89, 0x16, 0x04, 0xbf, 0xbe, 0x49, 0xdf, 0x84, 0x50,
                    0x96);
    private static final byte[] AEM0 = asBytes(0x72, 0x03, 0x38, 0x74);
    private static final byte[] RPI1 =
            asBytes(
                    0x3c, 0x9a, 0x1d, 0xe5, 0xdd, 0x6b, 0x02, 0xaf, 0xa7, 0xfd, 0xed, 0x7b, 0x57, 0x0b, 0x3e,
                    0x56);

*)
   
