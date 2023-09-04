unit dpapi;

interface

uses
  System.Types, System.SysUtils, Winapi.Windows, System.NetEncoding;

type
  DATA_BLOB = record
    cbData: DWORD;
    pbData: PByte;
  end;

  PDATA_BLOB = ^DATA_BLOB;

  _CRYPTPROTECT_PROMPTSTRUCT = record
    cbSize: DWORD;
    dwPromptFlags: DWORD;
    hwndApp: HWND;
    szPrompt: PWideChar;
  end;

  CRYPTPROTECT_PROMPTSTRUCT = _CRYPTPROTECT_PROMPTSTRUCT;

  PCRYPTPROTECT_PROMPTSTRUCT = ^CRYPTPROTECT_PROMPTSTRUCT;

const
  CRYPTPROTECT_UI_FORBIDDEN = $1;
  CRYPTPROTECT_LOCAL_MACHINE = $4;
  CRYPTPROTECT_CRED_SYNC = $8;
  CRYPTPROTECT_FIRST_RESERVED_FLAGVAL = $0FFFFFFF;
  CRYPTPROTECT_LAST_RESERVED_FLAGVAL = DWORD($FFFFFFFF);

function DPEncryptString(const Plaintext: string; const AdditionalEntropy: string = ''): string;

function DPEncryptStringToBytes(const Plaintext: string; const AdditionalEntropy: string = ''): TBytes;

function DpDecryptBytesToString(const Blob: TBytes; const AdditionalEntropy: string = ''): string;

function DpDecryptStringToString(const Ciphertext: string; const AdditionalEntropy: string = ''): string;

function CryptProtectData(pDataIn: PDATA_BLOB; //
  szDataDescr: PWideChar; //
  pOptionalEntropy: PDATA_BLOB; //
  pvReserved: PVOID; //
  pPromptStruct: PCRYPTPROTECT_PROMPTSTRUCT;  //
  dwFlags: DWORD; //
  pDataOut: PDATA_BLOB //
): BOOL; stdcall; external 'Crypt32.dll' name 'CryptProtectData';

function CryptUnprotectData(pDataIn: PDATA_BLOB; //
  ppszDataDescr: PPWideChar; //
  pOptionalEntropy: PDATA_BLOB; //
  pvReserved: PVOID; //
  pPromptStruct: PCRYPTPROTECT_PROMPTSTRUCT; //
  dwFlags: DWORD; //
  pDataOut: PDATA_BLOB//
): BOOL; stdcall; external 'Crypt32.dll' name 'CryptUnprotectData';

function CryptProtectMemory(pDataIn: PByte; //
  cbDataIn: DWORD; //
  dwFlags: DWORD //
): BOOL; stdcall; external 'Crypt32.dll' name 'CryptProtectMemory';

function CryptUnprotectMemory(pDataIn: PByte; //
  cbDataIn: DWORD; //
  dwFlags: DWORD //
): BOOL; stdcall; external 'Crypt32.dll' name 'CryptUnprotectMemory';

implementation

function DPEncryptStringToBytes(const Plaintext: string; const AdditionalEntropy: string): TBytes;
var
  blobIn: DATA_BLOB;
  blobOut: DATA_BLOB;
  entropyBlob: DATA_BLOB;
  pEntropy: Pointer;
  bRes: Boolean;
begin
  blobIn.pbData := Pointer(TEncoding.UTF8.GetBytes(Plaintext));
  blobIn.cbData := TEncoding.UTF8.GetByteCount(Plaintext);

  pEntropy := nil;
  if AdditionalEntropy <> '' then
  begin
    entropyBlob.pbData := Pointer(TEncoding.UTF8.GetBytes(AdditionalEntropy));
    entropyBlob.cbData := TEncoding.UTF8.GetByteCount(AdditionalEntropy);
    pEntropy := @entropyBlob;
  end;

  bRes := CryptProtectData(@blobIn, //
    nil, //data description (PWideChar)
    pEntropy, //optional entropy (PDATA_BLOB)
    nil, //reserved
    nil, //prompt struct
    CRYPTPROTECT_UI_FORBIDDEN, //flags
    @blobOut);

  if not bRes then
    RaiseLastOSError;

  //Move output blob into resulting TBytes
  SetLength(Result, blobOut.cbData);
  Move(blobOut.pbData^, Result[0], blobOut.cbData);

  // hen you have finished using the DATA_BLOB structure, free its pbData member by calling the LocalFree function
  LocalFree(HLOCAL(blobOut.pbData));
end;

function DPEncryptString(const Plaintext: string; const AdditionalEntropy: string): string;
var
  Temp: TBytes;
begin
  Temp := DPEncryptStringToBytes(Plaintext, AdditionalEntropy);
  Result := TNetEncoding.Base64String.EncodeBytesToString(Temp);
end;

function DpDecryptBytesToString(const blob: TBytes; const AdditionalEntropy: string): string;
var
  dataIn: DATA_BLOB;
  entropyBlob: DATA_BLOB;
  pentropy: PDATA_BLOB;
  dataOut: DATA_BLOB;
  bRes: BOOL;
begin
  dataIn.pbData := Pointer(blob);
  dataIn.cbData := Length(blob);

  pentropy := nil;
  if AdditionalEntropy <> '' then
  begin
    entropyBlob.pbData := Pointer(TEncoding.UTF8.GetBytes(AdditionalEntropy));
    entropyBlob.cbData := TEncoding.UTF8.GetByteCount(AdditionalEntropy);
    pentropy := @entropyBlob;
  end;

  bRes := CryptUnprotectData(@dataIn, //
    nil, //data description (PWideChar)
    pentropy, //optional entropy (PDATA_BLOB)
    nil, //reserved
    nil, //prompt struct
    CRYPTPROTECT_UI_FORBIDDEN, //
    @dataOut);
  if not bRes then
    RaiseLastOSError;

  Result := TEncoding.UTF8.GetString(TBytes(dataOut.pbData), 0, dataOut.cbData);
  LocalFree(HLOCAL(dataOut.pbData));
end;

function DpDecryptStringToString(const Ciphertext: string; const AdditionalEntropy: string = ''): string;
begin
  Result := DpDecryptBytesToString(TNetEncoding.Base64String.DecodeStringToBytes(Ciphertext), AdditionalEntropy);
end;

end.

