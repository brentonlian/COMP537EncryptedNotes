import pickle
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag


class PrivNotes:
  MAX_NOTE_LEN = 2048;

  def __init__(self, password, data = None, checksum = None):
    """Constructor.
    
    Args:
      password (str) : password for accessing the notes
      data (str) [Optional] : a hex-encoded serialized representation to load
                              (defaults to None, which initializes an empty notes database)
      checksum (str) [Optional] : a hex-encoded checksum used to protect the data against
                                  possible rollback attacks (defaults to None, in which
                                  case, no rollback protection is guaranteed)

    Raises:
      ValueError : malformed serialized format
    """
    self.kvs = {}
    self.counter = 0

    #New database
    if data is None:
      self.salt = os.urandom(16)

    else:
      try:
        raw = bytes.fromhex(data)

        if checksum is not None:
          digest = hashes.Hash(hashes.SHA256())
          digest.update(raw)

        if digest.finalize().hex() != checksum:
          raise ValueError("Invalid checksum")

        saved = pickle.loads(raw)

        self.salt = saved["salt"]
        self.kvs = saved["kvs"]
        self.counter = saved["counter"]
        stored_password_check = saved["password_check"]

      except Exception:
        raise ValueError("Malformed serialized format")

     # PBKDF2 is called exactly once
    kdf = PBKDF2HMAC(
          algorithm=hashes.SHA256(),
          length=32,
          salt=self.salt,
          iterations=2000000
      )

    source_key = kdf.derive(bytes(password, "ascii"))

      # Derive several keys from the one PBKDF2 key
    self.title_key = self._hmac(source_key, b"title")
    self.enc_key = self._hmac(source_key, b"encryption")
    self.nonce_key = self._hmac(source_key, b"nonce")
    self.check_key = self._hmac(source_key, b"password")

    self.password_check = self._hmac(
          self.check_key,
          b"password-check"
    )

    # When loading, immediately verify the password
    if data is not None:
        if self.password_check != stored_password_check:
            raise ValueError("Incorrect password")

        #Make sure every encrypted note is valid
    try:
      for title_key in self.kvs:
        note_counter, ciphertext = self.kvs[title_key]
        self._decrypt(title_key, note_counter, ciphertext)
    except Exception:
      raise ValueError("Tampered data")
   

  def dump(self):
    """Computes a serialized representation of the notes database
       together with a checksum.
    
    Returns: 
      data (str) : a hex-encoded serialized representation of the contents of the notes
                   database (that can be passed to the constructor)
      checksum (str) : a hex-encoded checksum for the data used to protect
                       against rollback attacks (up to 32 characters in length)
    """
    saved = {
      "salt": self.salt,
      "kvs": self.kvs,
      "counter": self.counter,
      "password_check": self.password_check
    }

    raw = pickle.dumps(saved)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    checksum = digest.finalize().hex()

    return raw.hex(), checksum

    

  def get(self, title):
    """Fetches the note associated with a title.
    
    Args:
      title (str) : the title to fetch
    
    Returns: 
      note (str) : the note associated with the requested title if
                       it exists and otherwise None
    """
    title_token = self._title_token(title)

    if title_token in self.kvs:

        counter, ciphertext = self.kvs[title_token]

        return self._decrypt(
            title_token,
            counter,
            ciphertext
        )

    return None

  def set(self, title, note):
    """Associates a note with a title and adds it to the database
       (or updates the associated note if the title is already
       present in the database).
       
       Args:
         title (str) : the title to set
         note (str) : the note associated with the title

       Returns:
         None

       Raises:
         ValueError : if note length exceeds the maximum
    """
    if len(bytes(note, "ascii")) > self.MAX_NOTE_LEN:
      raise ValueError("Maximum note length exceeded")

    title_token = self._title_token(title)

    ciphertext = self._encrypt(
        title_token,
        note,
        self.counter
    )

    self.kvs[title_token] = (
        self.counter,
        ciphertext
    )

    self.counter += 1


  def remove(self, title):
    """Removes the note for the requested title from the database.
       
       Args:
         title (str) : the title to remove

       Returns:
         success (bool) : True if the title was removed and False if the title was
                          not found
    """
    title_token = self._title_token(title)

    if title_token in self.kvs:
        del self.kvs[title_token]
        return True

    return False

  #Add hmac class
  def _hmac(self, key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

  def _title_token(self, title):
    # Hide the real title using HMAC
    return self._hmac(
        self.title_key,
        bytes(title, "ascii")
    )


  def _nonce(self, counter):
      # Derive a 12-byte nonce from the counter
      # rather than using new external randomness
      counter_bytes = counter.to_bytes(8, "little")

      return self._hmac(
          self.nonce_key,
          counter_bytes
      )[:12]


  def _encrypt(self, title_token, note, counter):
      note_bytes = bytes(note, "ascii")

      # Store the real length in the first two bytes
      length = len(note_bytes).to_bytes(2, "little")

      # Pad every note to exactly MAX_NOTE_LEN bytes
      padding = b"\x00" * (self.MAX_NOTE_LEN - len(note_bytes))

      plaintext = length + note_bytes + padding

      # Bind the ciphertext to the title and counter.
      # This also helps prevent swap attacks.
      aad = title_token + counter.to_bytes(8, "little")

      return AESGCM(self.enc_key).encrypt(
          self._nonce(counter),
          plaintext,
          aad
      )


  def _decrypt(self, title_token, counter, ciphertext):

      aad = title_token + counter.to_bytes(8, "little")

      try:
          plaintext = AESGCM(self.enc_key).decrypt(
              self._nonce(counter),
              ciphertext,
              aad
          )

      except InvalidTag:
          raise ValueError("Invalid ciphertext")

      # First two bytes tell us the real note length
      note_length = int.from_bytes(
          plaintext[:2],
          "little"
      )

      if note_length > self.MAX_NOTE_LEN:
          raise ValueError("Invalid note")

      return plaintext[2:2 + note_length].decode("ascii")
