from private_notes import PrivNotes

import re

import pickle

def error(s):
  print('=== ERROR: %s' % s)

print('Initializing notes')
priv_notes = PrivNotes('123456')

print('Adding notes')
kvs = { 'Groceries': 'lettuce\nbread\nchocolate',
        'Idea': 'We will take a forklift to the moon!',
        'Secrets': 'The secret word is bananas.' }
for title in kvs:
  priv_notes.set(title, kvs[title])

print('Trying to fetch notes')
for title in kvs:
  note = priv_notes.get(title)
  if note != kvs[title]:
    error('get failed for title %s (expected %s, received %s)' % (title, kvs[title], note))
note = priv_notes.get('non-existent')
if note is not None:
  error('get failed for title non-existent (expected None, received %s)' % note)

print('Trying to remove notes')
if not priv_notes.remove('Groceries'):
  error('remove failed for title Groceries')
note = priv_notes.get('Groceries')
if note is not None:
  error('get failed for title Groceries (expected None, received %s)' % note)
if priv_notes.remove('non-existent'):
  error('remove failed for title non-existent')

print('Serializing notes')
data, checksum = priv_notes.dump()

print('Loading notes')
new_notes_instance = PrivNotes('123456', data, checksum)
for title in kvs:
  note1 = priv_notes.get(title)
  note2 = new_notes_instance.get(title)
  if note1 != note2:
    error('get mismatch for title %s (received values %s and %s)' % (title, note1, note2))

print('Testing complete')

print('Testing incorrect password')

try:
    bad_notes = PrivNotes('wrongpassword', data, checksum)
    error('incorrect password was accepted')
except ValueError:
    print('success!')


print('Testing incorrect checksum')

try:
    bad_notes = PrivNotes('123456', data, '00')
    error('incorrect checksum was accepted')
except ValueError:
    print('success!')


print('Testing maximum note length')

try:
    priv_notes.set('Too Long', 'a' * 2049)
    error('note longer than 2048 characters was accepted')
except ValueError:
    print('success!')

print('Testing ciphertext tampering')

tampered_saved = pickle.loads(bytes.fromhex(data))

first_title = next(iter(tampered_saved["kvs"]))

counter, ciphertext = tampered_saved["kvs"][first_title]

# Change one byte of ciphertext
tampered_ciphertext = bytearray(ciphertext)
tampered_ciphertext[0] ^= 1

tampered_saved["kvs"][first_title] = (
    counter,
    bytes(tampered_ciphertext)
)

tampered_data = pickle.dumps(tampered_saved).hex()

try:
    bad_notes = PrivNotes(
        '123456',
        tampered_data,
        None
    )

    error('accepted tampered ciphertext')

except ValueError:
    print('success!')

print('Testing swap attack')

swap_saved = pickle.loads(bytes.fromhex(data))

titles = list(swap_saved["kvs"].keys())

if len(titles) >= 2:

    first = titles[0]
    second = titles[1]

    swap_saved["kvs"][first], swap_saved["kvs"][second] = (
        swap_saved["kvs"][second],
        swap_saved["kvs"][first]
    )

    swap_data = pickle.dumps(swap_saved).hex()

    try:
        bad_notes = PrivNotes(
            '123456',
            swap_data,
            None
        )

        error('accepted swapped records')

    except ValueError:
        print('success!')

print('Testing plaintext hiding')

raw_data = bytes.fromhex(data)

if b'Secrets' in raw_data:
    error('plaintext title found in serialized data')

if b'The secret word is bananas.' in raw_data:
    error('plaintext note found in serialized data')

print('success!')

print('Testing counter tampering')

counter_saved = pickle.loads(bytes.fromhex(data))

counter_saved["counter"] = 0

counter_data = pickle.dumps(counter_saved).hex()

try:
    bad_notes = PrivNotes(
        '123456',
        counter_data,
        None
    )

    error('accepted modified counter')

except ValueError:
    print('success!')


print('Additional basic tests complete')
