program Demo;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  AnsiStrings,
  dpapi in '..\lib\dpapi.pas',
  libsodium in '..\lib\libsodium.pas';

var
  hashed_password: PAnsiChar;
  passwd: PAnsiChar;
  Ciphertext: string;
  temp: string;

begin
  try
    //使用Windows API加密,不考虑密钥的问题，但是好像只能在本地使用
    //可以用于配置文件等加密
    Ciphertext := DPEncryptString('中文来了123456考验来了');
    Writeln('加密结果：' + Ciphertext);
    temp := DpDecryptStringToString(Ciphertext);
    Writeln('解密结果：' + temp);

    if sodium_init < 0 then
    begin
      Writeln('加载库失败');
    end
    else
    begin
      Writeln('加载库完成');
    end;

    //
    //sodium_mlock，sodium_munlock，sodium_memzero，sodium_malloc，sodium_free等函数可以用来保护内存中的密码

    //二进制转十六进制
    //sodium_bin2hex

    //base64
    //sodium_bin2base64,sodium_base642bin

    //随机
    //randombytes_random,randombytes_buf

    //摘要算法 BLAKE2b
    //crypto_generichash

    //crypto_generichash_init
    //crypto_generichash_update
    //crypto_generichash_final

    //crypto_shorthash

    //摘要算法
    //crypto_hash_sha256
    //crypto_hash_sha512
    //好像没有 md5

    //密码加密存储
    //密码通过网络传输应该使用HTTPS，不能通过HTTP传输
    //可以使用非对称加密传输密码，这和HTTPS实现方式类似
    hashed_password := AnsiStrings.AnsiStrAlloc(crypto_pwhash_strbytes);
    passwd := '123456';
    if crypto_pwhash_str(PByte(hashed_password), PByte(passwd), Length(passwd), crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_memlimit_sensitive) = 0 then
    begin
      Writeln(hashed_password);
      if crypto_pwhash_str_verify(PByte(hashed_password), PByte(passwd), Length(passwd)) = 0 then
      begin
        Writeln('密码正确');
      end
      else
      begin
        Writeln('密码错误');
      end;
    end;
    //为了兼容性考虑，密码加密存储可以使用Scrypt算法
    //crypto_pwhash_scryptsalsa208sha256_str

    //对称加密(Authenticated encryption)
    //这个函数不仅有加密，同时还有MAC的功能
    //如果没有MAC的话，任意数据可以用任意密钥进行解密，只是结果多半无意义
    //但是判断不了原始消息是否被篡改
    //crypto_secretbox_easy
    //crypto_secretbox_open_easy
    //crypto_secretbox_detached
    //crypto_secretbox_open_detached

    //文件和流加密
    //crypto_secretstream_*

    //消息验证码 MAC(Authentication)
    //摘要（只有明文参与运算，没有密钥）只能验证数据的完整性，但是无法保证数据防篡改，无法避免中间人攻击
    //因为中间人可以在替换原始消息的同时替换摘要，接收人无法判断
    //MAC需要密码参与运算，没有密码的情况下无法篡改消息和MAC码
    //消息验证不是为了加密，消息可以明文也可以是密文，消息验证只是为了保证数据未被篡改
    //crypto_auth
    //crypto_auth_verify

    //AEAD
    //这个和前面的对称加密（crypto_secretbox_easy）类似
    //区别在于加密时所有数据都要加密
    //AEAD不用对所有数据加密，可以附加明文，比如明文可能会包含数据长度，编码方式之类的数据，AEAD也会对明文计算摘要
    //解密前先要验证明文和密文的完整性
    //chacha20poly1305
    //crypto_aead_chacha20poly1305*

    //AES
    //crypto_aead_aes256gcm_encrypt
    //crypto_aead_aes256gcm_decrypt
    //crypto_aead_aes256gcm_encrypt_detached
    //crypto_aead_aes256gcm_decrypt_detached

    //非对称加密(Authenticated encryption)
    //crypto_box_keypair
    //crypto_box_easy
    //crypto_box_open_easy
    //crypto_box_detached
    //crypto_box_open_detached

    //数字签名
    //crypto_sign_keypair
    //crypto_sign
    //crypto_sign_open
    //crypto_sign_detached
    //crypto_sign_verify_detached
    //crypto_sign_init
    //crypto_sign_update
    //crypto_sign_final_create
    //crypto_sign_final_verify

    //数字信封
    //匿名发送消息给接收方，发出消息后只有接收方能解开，发送方自己也解不开数字信封
    //接收方不需要直到发送方的公钥*
    //数字信封加密时先生成一对临时密钥，使用接收方的公钥加密临时密钥的公钥，
    //然后使用临时密钥的私钥来加密消息，加密完成后临时密钥对销毁了
    //解密时接收方先用私钥解密出临时密钥的公钥，再用临时密钥的公钥去解密消息
    //临时密钥的私钥只在加密时短暂出现在加密方的内存中
    //这种方式更安全
    //crypto_box_seal
    //crypto_box_seal_open
    Readln;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.

