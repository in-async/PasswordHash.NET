# PasswordHash.NET
`PasswordHash.NET` は .NET で簡易にパスワードハッシュ関数を使用する為のライブラリです。

## Features
### 対応しているパスワードハッシュ関数
- [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) (HMAC-SHA-1)
	- NIST 推奨の一つ。セキュリティ強度 128 bits。
	- よりセキュリティ強度の高い HMAC-SHA-256（セキュリティ強度 256 bits）以上を PRF に使用する場合は、ターゲットフレームワークを .NET Core 2.0+ / .NET Framework 4.7.2+ にしてビルド。

### [Modular Crypt Format](http://passlib.readthedocs.io/en/stable/modular_crypt_format.html) ハッシュ文字列を出力
- Salt やストレッチング回数込みの文字列を出力する為、ハッシュ管理が容易。
- [パスワードハッシュのアップグレード](https://www.owasp.org/index.php/Password_Storage_Cheat_Sheet#Upgrading_your_existing_password_hashing_solution)への備え。

### Salt / ストレッチング回数のデフォルト値
- `saltSize=16` (128 bits) は [NIST SP800-132](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf) の推奨最小値。
- `iterationCount=10000` は [NIST SP800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5) の推奨最小値。
	- 目標とするハッシュ計算時間により要調整。

### [passlib.hash.pbkdf2_{digest}](http://passlib.readthedocs.io/en/stable/lib/passlib.hash.pbkdf2_digest.html) との互換性
- dkLen（PBKDF2 で導出されるキー長） を hLen（内部 PRF の出力長） に揃えてる。  
PRF が HMAC-SHA-1 なら 160 bits。

## Target Frameworks
- .NET Standard 1.3+
- .NET Core 1.0+
- .NET Framework 4.6+

## Usage
### パスワードを PBKDF2 でハッシュ文字列化
主にサインアップ処理で使用。
```cs
var password = "password123";

var hasher = new PBKDF2();
var hash = hasher.Hash(password);
Console.WriteLine(hash.ToString());
// $pbkdf2$10000$oLs2Pk11k85ekfB97qr9Nw$QvsHZBmsOgjmd8/SZK5EUf/TQ.0
```

### 入力されたパスワードの検証
主にサインイン処理で使用。
```cs
var password = "password123";

var hashStr = "$pbkdf2$10000$oLs2Pk11k85ekfB97qr9Nw$QvsHZBmsOgjmd8/SZK5EUf/TQ.0";
var result = PasswordHash.Verify(password, hashStr);
Console.Write(result);
// True
```
or
```cs
var password = "password123";

PasswordHash.TryParse("$pbkdf2$10000$oLs2Pk11k85ekfB97qr9Nw$QvsHZBmsOgjmd8/SZK5EUf/TQ.0", out var hash);
var result = hash.Verify(password);
Console.Write(result);
// True
```

## Licence
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
