import os
import base64
import typing

from cryptography.fernet import Fernet
from cryptography import utils
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.backends.interfaces import Backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC


key  = input("Key Giriniz(tırnaksız) : ").encode()

print(key)

ferdi = Fernet(key)

def sifrele(veri):
    with open(veri,"rb") as oku:
         oku = oku.read()
        
         
    try:
         with open(veri,"wb") as yaz:
             passw = ferdi.decrypt(oku)
             yaz.write(passw)
    except:pass

         
for dosya_konum , gereksiz , dosya_liste in os.walk("/home/elifilhan/anaconda3/fidye"):
    if dosya_liste:
        for dosya in dosya_liste:
            veri = dosya_konum+"/"+dosya
            sifrele(veri=veri)
            

def decrypt(self, token: bytes, ttl: typing.Optional[int] = None) -> bytes:
        timestamp, data = Fernet._get_unverified_token_data(token)
        if ttl is None:
            time_info = None
        else:
            time_info = (ttl, int(time.time()))
        return self._decrypt_data(data, timestamp, time_info)
        
def decrypt_at_time(
        self, token: bytes, ttl: int, current_time: int
    ) -> bytes:
        if ttl is None:
            raise ValueError(
                "decrypt_at_time() can only be used with a non-None ttl"
            )
        timestamp, data = Fernet._get_unverified_token_data(token)
        return self._decrypt_data(data, timestamp, (ttl, current_time))

def extract_timestamp(self, token: bytes) -> int:
        timestamp, data = Fernet._get_unverified_token_data(token)
        # Verify the token was not tampered with.
        self._verify_signature(data)
        return timestamp

@staticmethod
def _get_unverified_token_data(token: bytes) -> typing.Tuple[int, bytes]:
        utils._check_bytes("token", token)
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or data[0] != 0x80:
            raise InvalidToken

        try:
            (timestamp,) = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp, data

def _verify_signature(self, data: bytes) -> None:
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

def _decrypt_data(
        self,
        data: bytes,
        timestamp: int,
        time_info: typing.Optional[typing.Tuple[int, int]],
    ) -> bytes:
        if time_info is not None:
            ttl, current_time = time_info
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        self._verify_signature(data)

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded
