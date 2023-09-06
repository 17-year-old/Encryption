program Demo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  AnsiStrings,
  dpapi in '..\lib\dpapi.pas',
  libsodium in '..\lib\libsodium.pas';

procedure WinDpapi;
//使用Windows API加密,使用用户密码的摘要来加密和解密
//所以不用考虑密钥的问题，但是只能在本地使用（不同的电脑或用户加密结果不一样）
//可以用于本地配置文件等的加密
var
  Ciphertext: string;
  Res: string;
begin
  Writeln('------------dpapi------------');

  Ciphertext := DPEncryptString('123456中文测试');
  Writeln('加密：' + Ciphertext);
  Res := DpDecryptStringToString(Ciphertext);
  Writeln('解密：' + Res);
  Writeln('');
end;

procedure InitSodium;
begin
  Writeln('------------初始化Sodium库------------');

  if sodium_init < 0 then
  begin
    Writeln('加载sodium库失败');
  end
  else
  begin
    Writeln('加载sodium库成功');
  end;
  Writeln('');
end;

procedure BinAndHex;
//二进制、十六进制互相转换
var
  hex: array of Byte;
  bin: array of Byte;
  len: NativeUInt;
begin
  Writeln('------------BinAndHex------------');

  bin := [106, 107, 108, 109, 110, 115]; //jklmns
  SetLength(hex, Length(bin) * 2 + 1); //一个字节最多用两个16进制字符表示
  sodium_bin2hex(@hex[0], Length(hex), @bin[0], Length(bin));
  Writeln('原字符串:' + PAnsiChar(bin));
  Writeln('bin2hex:' + PAnsiChar(hex));

  bin := [0, 0, 0, 0, 0, 0, 0];
  sodium_hex2bin(@bin[0], Length(bin), @hex[0], Length(hex), nil, @len, nil);
  Writeln('hex2bin:' + PAnsiChar(bin));
  Writeln('');
end;

function Bin2HexString(bin: array of Byte): string;
//二进制转换为十六进制字符串
var
  hex: array of Ansichar;
begin
  SetLength(hex, Length(bin) * 2 + 1); //一个字节最多用两个16进制字符表示
  sodium_bin2hex(@hex[0], Length(hex), @bin[0], Length(bin));
  Result := string(AnSistring(PAnsiChar(hex)));
end;

procedure PasswordHash;
//密码加密存储
//密码通过网络传输应该使用HTTPS，不能通过HTTP传输
//可以使用非对称加密传输密码，这和HTTPS实现方式类似
//为了兼容性考虑(需要和其它代码共用时)，密码加密存储可以使用Scrypt算法
//crypto_pwhash_scryptsalsa208sha256_str
//crypto_pwhash_scryptsalsa208sha256_str_verify
var
  hashed_password: PAnsiChar;
  passwd: PAnsiChar;
  WrongPasswd: PAnsiChar;
begin
  Writeln('------------PasswordHash------------');

  hashed_password := AnsiStrings.AnsiStrAlloc(crypto_pwhash_strbytes);
  passwd := '123456';
  if crypto_pwhash_str(PByte(hashed_password), PByte(passwd), Length(passwd), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_memlimit_sensitive) = 0 then
  begin
    Writeln('加密：' + hashed_password);
    if crypto_pwhash_str_verify(PByte(hashed_password), PByte(passwd), Length(passwd)) = 0 then
    begin
      Writeln('验证密码123456，密码正确');
    end
    else
    begin
      Writeln('验证密码123456，密码错误');
    end;

    WrongPasswd := '234567';
    if crypto_pwhash_str_verify(PByte(hashed_password), PByte(WrongPasswd), Length(WrongPasswd)) = 0 then
    begin
      Writeln('验证密码234567，密码正确');
    end
    else
    begin
      Writeln('验证密码234567，密码错误');
    end;
  end;
  Writeln('');
end;

procedure Base64;
var
  bin: array of Byte;
  len: NativeUInt;
  b64: array of AnsiChar;
begin
  Writeln('------------Base64------------');

  bin := [48, 49, 50, 51, 52, 53, 54]; //0123456
  len := sodium_base64_encoded_len(Length(bin), sodium_base64_VARIANT_ORIGINAL);
  Writeln('Base64Length:' + len.ToString);
  sodium_bin2base64(@b64[0], len, @bin[0], length(bin), sodium_base64_VARIANT_ORIGINAL);

  bin := [0, 0, 0, 0, 0, 0, 0, 0];
  sodium_base642bin(@bin[0], length(bin), @b64[0], length(b64), nil, @len, nil, sodium_base64_VARIANT_ORIGINAL);
  Writeln('Decodelength:' + len.ToString);
  Writeln('Base64Decode:' + AnsiString(PAnsiChar(bin)));
  Writeln('');
end;

procedure DoHash;
//计算摘要
//推荐crypto_generichash，目前使用 BLAKE2b
//建议需要和其它库混用时才使用sha256

//多次传入数据后hash，比如数据量太大一次传入不合适的情况或者需要一边接收数据一边计算摘要
//crypto_generichash_init
//crypto_generichash_update
//crypto_generichash_final

//crypto_shorthash
//crypto_hash_sha256_init
//crypto_hash_sha256_update
//crypto_hash_sha256_final

//crypto_hash_sha512
//crypto_hash_sha512_init
//crypto_hash_sha512_update
//crypto_hash_sha512_final
var
  msg: array of AnsiChar;
  hash: array of Byte;
begin
  Writeln('------------Hash------------');

  SetLength(hash, crypto_generichash_bytes_max);
  msg := ['0', '1', '2', '3', '4', '5', '6'];
  Writeln('MESSAGE:' + AnsiString(msg));
  //一次传入所有数据并hash
  crypto_generichash(@hash[0], Length(hash), @msg[0], Length(msg), nil, 0);
  Writeln('BLAKE2b HEX:' + Bin2HexString(hash));

  //sha256
  SetLength(hash, crypto_hash_sha256_BYTES);
  crypto_hash_sha256(@hash[0], @msg[0], Length(msg));
  Writeln('sha256 HEX:' + Bin2HexString(hash));

  Writeln('');
end;

procedure Secretkey_AuthenticatedEncryption;
//对称加密
//这些函数不仅有加密，同时还有MAC的功能
//如果没有MAC的话，任意数据可以用任意密钥进行解密，只是结果多半无意义
//判断不了原始消息是否被篡改
var
  msg: array of AnsiChar;
  key: array of Byte;
  nonce: array of Byte;
  cipher: array of Byte;
  decrypted: array of AnsiChar;
begin
  Writeln('------------Secretkey_AuthenticatedEncryption------------');

  SetLength(key, crypto_secretbox_KEYBYTES);
  crypto_secretbox_keygen(@key[0]);
  Writeln('key:' + Bin2HexString(key));

  SetLength(nonce, crypto_secretbox_NONCEBYTES);
  randombytes_buf(nonce, Length(nonce));
  Writeln('nonce:' + Bin2HexString(nonce));

  msg := ['1', '2', '3', '4', '5', '6'];
  SetLength(cipher, crypto_secretbox_MACBYTES + 6);
  crypto_secretbox_easy(@cipher[0], @msg[0], Length(msg), @nonce[0], @key[0]);
  Writeln('加密:' + Bin2HexString(cipher));

  SetLength(decrypted, Length(msg));
  crypto_secretbox_open_easy(@decrypted[0], @cipher[0], Length(cipher), @nonce[0], @key[0]);
  Writeln('解密:' + AnsiString(decrypted));

  //crypto_secretbox_detached
  //crypto_secretbox_open_detached

  Writeln('');
end;

procedure Secretkey_Authentication;
//消息验证码 MAC(Authentication)
//摘要（只有明文参与运算，没有密钥）只能验证数据的完整性，但是无法保证数据防篡改，无法避免中间人攻击
//因为中间人可以在替换原始消息的同时替换摘要，接收人无法判断
//MAC需要密码参与运算，没有密码的情况下无法篡改消息和MAC码
//消息验证不是为了加密，消息可以明文也可以是密文，消息验证只是为了保证数据未被篡改
//默认是HMAC-SHA-512-256(crypto_auth_hmacsha512256)算法，这个和HMAC-SHA-512(crypto_auth_hmacsha512)的区别是
//HMAC-SHA-512输出是512 bit, HMAC-SHA-512-256是只输出了前256 bit
var
  msg: array of AnsiChar;
  key: array of Byte;
  mac: array of Byte;
begin
  Writeln('------------Secretkey_Authentication------------');

  SetLength(key, crypto_auth_KEYBYTES);
  crypto_auth_keygen(@key[0]);
  Writeln('key:' + Bin2HexString(key));

  msg := ['1', '2', '3', '4', '5', '6'];
  SetLength(mac, crypto_auth_BYTES);
  crypto_auth(@mac[0], @msg[0], Length(msg), @key[0]);
  Writeln('MAC:' + Bin2HexString(mac));

  if crypto_auth_verify(@mac[0], @msg[0], Length(msg), @key[0]) = 0 then
  begin
    Writeln('MAC校验正确');
  end
  else
  begin
    Writeln('MAC校验错误');
  end;

  Writeln('');
end;

procedure Secretkey_AEAD;
//AEAD
//这个和对称加密（crypto_secretbox_easy）类似
//区别在于加密时所有数据都要加密
//AEAD不用对所有数据加密，可以附加明文，比如明文可能会包含数据长度，编码方式之类的数据，AEAD也会对明文计算摘要
//解密前先要验证明文和密文的完整性
//推荐使用 crypto_aead_xchacha20poly1305
//还包含了 crypto_aead_chacha20poly1305
//         crypto_aead_chacha20poly1305
//crypto_aead_aes256gcm建议只在必要的时候（需要和其它库共用的时候）使用
var
  msg: array of AnsiChar;
  key: array of Byte;
  additional: array of AnsiChar;
  nonce: array of Byte;
  cipher: array of Byte;
  len: UInt64;
  decrypted: array of Byte;
begin
  Writeln('------------Secretkey_AEAD------------');

  SetLength(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  crypto_aead_xchacha20poly1305_ietf_keygen(@key[0]);
  Writeln('key:' + Bin2HexString(key));

  SetLength(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  randombytes_buf(nonce, Length(nonce));
  Writeln('nonce:' + Bin2HexString(nonce));

  msg := ['1', '2', '3', '4', '5', '6'];
  additional := ['1', '2', '3', '4', '5', '6'];
  SetLength(cipher, crypto_aead_xchacha20poly1305_ietf_ABYTES + Length(msg));
  crypto_aead_xchacha20poly1305_ietf_encrypt(@cipher[0], @len, @msg[0], Length(msg), @additional[0], Length(additional), nil, @nonce[0], @key[0]);
  Writeln('加密:' + Bin2HexString(cipher));

  SetLength(decrypted, Length(msg));
  crypto_aead_xchacha20poly1305_ietf_decrypt(@decrypted[0], @len, nil, @cipher[0], Length(cipher), @additional[0], Length(additional), @nonce[0], @key[0]);
  Writeln('解密:' + AnsiString(decrypted));

  Writeln('');
end;

procedure Publickey_AuthenticatedEncryption;
//非对称加密
//通讯双方各自需要一对密钥，并使用同一个随机数
//通讯双方都需要直到对方的公钥，但不需要对方的私钥
//公钥需要提前发送给对方
//随机数应该每次重新生成，并且随同加密数据一起发送给对方，随机数不用保密
//使用X25519算法生成共享密钥
//使用XSalsa20加密数据
//使用Poly1305生成消息验证码
//调用这个方法，不仅可以加密消息，还会校验MAC

//需要加密数据和MAC分开存储时调用
//crypto_box_detached
//crypto_box_open_detached

//和同一方多次通讯时
//可以调用以下方法提前生成一次共享密钥
//后面通讯时直接使用共享密钥，而不是重新计算，可以提高速度
//crypto_box_beforenm
//crypto_box_easy_afternm
//crypto_box_open_easy_afternm
//crypto_box_detached_afternm
//crypto_box_open_detached_afternm
var
  msg: array of AnsiChar;
  alice_publickey: array of Byte;
  alice_secretkey: array of Byte;
  bob_publickey: array of Byte;
  bob_secretkey: array of Byte;
  nonce: array of Byte;
  cipher: array of Byte;
  decrypted: array of Byte;
begin
  Writeln('------------Publickey_AuthenticatedEncryption------------');

  SetLength(alice_publickey, crypto_box_PUBLICKEYBYTES);
  SetLength(alice_secretkey, crypto_box_SECRETKEYBYTES);
  crypto_box_keypair(@alice_publickey[0], @alice_secretkey[0]);

  SetLength(bob_publickey, crypto_box_PUBLICKEYBYTES);
  SetLength(bob_secretkey, crypto_box_SECRETKEYBYTES);
  crypto_box_keypair(@bob_publickey[0], @bob_secretkey[0]);

  SetLength(nonce, crypto_box_NONCEBYTES);
  randombytes_buf(nonce, Length(nonce));

  msg := ['1', '2', '3', '4', '5', '6'];
  SetLength(cipher, crypto_box_MACBYTES + Length(msg));

  //alice用自己的私钥、bob的公钥和随机数nonce加密数据
  crypto_box_easy(@cipher[0], @msg[0], Length(msg), @nonce[0], @bob_publickey[0], @alice_secretkey[0]);
  Writeln('加密:' + Bin2HexString(cipher));

  //bob用自己的私钥、alice的公钥和随机数解密数据
  SetLength(decrypted, Length(msg));
  crypto_box_open_easy(@decrypted[0], @cipher[0], Length(cipher), @nonce[0], @alice_publickey[0], @bob_secretkey[0]);
  Writeln('解密:' + AnsiString(decrypted));

  Writeln('');
end;

procedure Publickey_Signature;
//数字签名
//签名者使用私钥签名，并将数据、签名和公钥一起公开
//其他任何人都可以使用公钥来验证数据和签名
//验证成功可以证明签名是由对应的私钥生成的，且数据和签名时是一致的
//数字签名不是加密，不一定要对原数据进行加密

//其它模式的数字签名，用法请参考官方文档
//crypto_sign_detached
//crypto_sign_verify_detached

//crypto_sign_init
//crypto_sign_update
//crypto_sign_final_create
//crypto_sign_final_verify
var
  msg: array of AnsiChar;
  publickey: array of Byte;
  secretkey: array of Byte;
  signed_message: array of Byte;
  len1, len2: UInt64;
  decrypted: array of Byte;
begin
  Writeln('------------Publickey_Signature------------');

  SetLength(publickey, crypto_sign_PUBLICKEYBYTES);
  SetLength(secretkey, crypto_sign_SECRETKEYBYTES);
  crypto_sign_keypair(@publickey[0], @secretkey[0]);

  msg := ['1', '2', '3', '4', '5', '6'];
  SetLength(signed_message, crypto_sign_BYTES + Length(msg));

  //此方法会将签名和元数据拼接在一起
  crypto_sign(@signed_message[0], @len1, @msg[0], Length(msg), @secretkey[0]);
  Writeln('数字签名:' + Bin2HexString(signed_message));

  //验证数字签名
  SetLength(decrypted, Length(msg));
  if crypto_sign_open(@decrypted[0], @len2, @signed_message[0], len1, @publickey[0]) = 0 then
  begin
    Writeln('验签成功，原文:' + AnsiString(decrypted));
  end
  else
  begin
    Writeln('验签失败');
  end;

  Writeln('');
end;

procedure Publickey_SealedBoxes;
//数字信封
//匿名发送消息给接收方，发出消息后只有接收方能解开，发送方自己也解不开数字信封
//接收方不需要直到发送方的公钥*
//数字信封加密时先生成一对临时密钥，使用接收方的公钥加密临时密钥的公钥，
//然后使用临时密钥的私钥来加密消息，加密完成后临时密钥对销毁了
//解密时接收方先用私钥解密出临时密钥的公钥，再用临时密钥的公钥去解密消息
//临时密钥的私钥只在加密时短暂出现在加密方的内存中
//这种方式更安全
var
  msg: array of AnsiChar;
  publickey: array of Byte;
  secretkey: array of Byte;
  cipher: array of Byte;
  decrypted: array of Byte;
begin
  Writeln('------------Publickey_SealedBoxes------------');

  SetLength(publickey, crypto_box_PUBLICKEYBYTES);
  SetLength(secretkey, crypto_box_SECRETKEYBYTES);
  crypto_box_keypair(@publickey[0], @secretkey[0]);

  msg := ['1', '2', '3', '4', '5', '6'];
  SetLength(cipher, crypto_box_SEALBYTES + Length(msg));

  crypto_box_seal(@cipher[0], @msg[0], Length(msg), @publickey[0]);
  SetLength(decrypted, Length(msg));
  if crypto_box_seal_open(@decrypted[0], @cipher[0], Length(cipher), @publickey[0], @secretkey[0]) = 0 then
  begin
    Writeln('解密:' + AnsiString(decrypted));
  end;

  Writeln('');
end;

begin
  try
    //https://learn.microsoft.com/zh-cn/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
    WinDpapi;

    //libsodium
    //文档 https://doc.libsodium.org/
    //文件下载 https://download.libsodium.org/libsodium/releases/
    InitSodium;

    //辅助函数
    //sodium_mlock，sodium_munlock，sodium_memzero，sodium_malloc，sodium_allocarray，sodium_free
    //sodium_mprotect_noaccess，sodium_mprotect_readonly，sodium_mprotect_readwrite
    //sodium_increment，sodium_add，sodium_sub，sodium_compare，sodium_is_zero，sodium_stackzero
    //任何敏感数据都应该在使用结束后尽快调用sodium_memzero方法，从内存中清除

    BinAndHex;
    Base64;

    //随机函数
    //randombytes_random,randombytes_buf,randombytes_uniform

    DoHash;

    PasswordHash;

    Secretkey_AuthenticatedEncryption;

    //文件和流加密
    //crypto_secretstream_*

    Secretkey_Authentication;
    Secretkey_AEAD;

    Publickey_AuthenticatedEncryption;
    Publickey_Signature;
    Publickey_SealedBoxes;

    Writeln('--------------执行完成----------------');
    Readln;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

