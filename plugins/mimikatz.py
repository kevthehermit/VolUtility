# Volatility mimikatz plugin
#
# Based on the research made by Gentil_Kiwi for his mimikatz
# http://blog.gentilkiwi.com/mimikatz
# https://code.google.com/p/mimikatz/
#
# Author: Francesco Picasso <francesco.picasso@gmail.com>
#
# April 2017, modified to reflect the new Construct API
#
# This plugin is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This plugin is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this plugin.  If not, see <http://www.gnu.org/licenses/>.

"""
@author       : Francesco Picasso
@license      : GPL 2 or later
@contact      : francesco.picasso@gmail.com
@organization : www.realitynet.it
"""

import construct
import os
import re
import struct
import volatility.obj as obj
import volatility.debug as debug
import volatility.commands as commands
import volatility.constants as constants
import volatility.utils as utils
import volatility.win32.tasks as tasks

from Crypto.Cipher import AES
from Crypto.Cipher import DES3

#------------------------------------------------------------------------------

class Credential():
  """TODO: add description here."""

  def __init__(self, module='', username='', domain='', epwd='', pwd=''):
    self.module = module
    self.username = username
    self.domain = domain
    self.epwd = epwd
    self.pwd = pwd
    self.signature = module + username + domain + epwd.encode('hex')

  def decrypt_epwd(self, decryptor):
    if self.epwd and decryptor:
      self.pwd = decryptor.decrypt(self.epwd)
      try:
        self.pwd = self.pwd.decode('utf-16-le').rstrip('\0')
      except UnicodeDecodeError:
        debug.warning('[Credential:decrypt_epwd] unicode decode error')
        self.pwd = self.pwd.encode('hex')
    
  def dump(self):
    debug.notice('m<{}> u<{}> d<{}> ep<{}> p<{}>'.format(
        self.module, self.username, self.domain,
        self.epwd.encode('hex'), self.pwd))


class Credentials():
  """TODO: add description here."""

  def __init__(self):
    self.credentials = []
    
  def add_credential(self, credential):
    already_in = False
    for cred in self.credentials:
      if cred.signature == credential.signature:
        already_in = True
    if not already_in:
      self.credentials.append(credential)

#------------------------------------------------------------------------------

class MemoryScanner(object):
  """An address space scanner based on scudette's Yara Scanner"""

  def __init__(self, task):
    self.task = task

  def _find_first(self, address_space, offset, maxlen, signature):
    """Raw memory scanner with overlap."""
    # Allow some bytes for overlapping signatures
    overlap = 1024
    i = offset
    while i < offset + maxlen:
      to_read = min(
        constants.SCAN_BLOCKSIZE + overlap, offset + maxlen - i)
      block = address_space.zread(i, to_read)
      if block:
        match = block.find(signature)
        if match >= 0:
          return match
      i += constants.SCAN_BLOCKSIZE

  def find_first(self, offset, signature):
    """Find the first match using VADs. It retuns a VA."""
    task_as = self.task.get_process_address_space()
    task_vads = self.task.get_vads(skip_max_commit = True)
    for vad, __ in task_vads:
      if offset >= vad.Start and offset <= vad.Start + vad.Length:
        position = self._find_first(task_as, vad.Start, vad.Length, signature)
        if position:
          return position + vad.Start

#------------------------------------------------------------------------------

class MimikatzBase(object):
  """The mimikatz base class, used to defined common attributes/methods."""
  SIZEOF_LONG = 4
  SIZEOF_PTR = None
  UNPACK_PTR = None
  UNPACK_LONG = '<L'
  
  def __init__(self, task):
    self.task = task
    self.task_as = task.get_process_address_space()
    
  def get_ptr(self, pos):
    raw_data = self.task_as.zread(pos, self.SIZEOF_PTR)
    if raw_data:
      return struct.unpack(self.UNPACK_PTR, raw_data)[0]
      
  def get_data(self, pos, size):
    if pos and size:
      return self.task_as.zread(pos, size)
    return ''


class Mimikatz_x86(MimikatzBase):
  """The mimikatz x86 base class."""
  SIZEOF_PTR = 4
  UNPACK_PTR = '<L'
  
  def __init__(self, task):
    MimikatzBase.__init__(self, task)
    MimikatzBase.__init__(self, task)
    
  def get_ptr_with_offset(self, pos):
    return self.get_ptr(pos)


class Mimikatz_x64(MimikatzBase):
  """The mimikatz x64 base class."""
  SIZEOF_PTR = 8
  UNPACK_PTR = '<Q'
  
  def __init__(self, task):
    MimikatzBase.__init__(self, task)
    
  def get_ptr_with_offset(self, pos):
    raw_data = self.task_as.zread(pos, self.SIZEOF_LONG)
    if raw_data:
      ptr = struct.unpack(self.UNPACK_LONG, raw_data)[0]
      return pos + self.SIZEOF_LONG + ptr
    
#------------------------------------------------------------------------------    

class LsaDecryptor():
  """TODO: add description."""
  SIGNATURE = None
  IV_LENGTH = 16
  PTR_IV_OFFSET = None
  PTR_AES_KEY_OFFSET = None
  PTR_DES_KEY_OFFSET = None
  UUUR_TAG = 0x55555552
  MSSK_TAG = 0x4d53534b

  #HARD_KEY = construct.Struct('KIWI_HARD_KEY',
  #    construct.Int32ul('cbSecret'),
  #    construct.Field('data', lambda ctx: ctx.cbSecret))
  HARD_KEY = construct.Struct(
      'cbSecret'/construct.Int32ul,
      'data'/construct.Bytes(construct.this.cbSecret))

  # Modified to include HARD_KEY size.
  '''
  BCRYPT_KEY = construct.Struct('KIWI_BCRYPT_KEY',
      construct.Int32ul('size'),
      construct.Int32ul('tag'), # 'MSSK'.
      construct.Int32ul('type'),
      construct.Int32ul('unk0'),
      construct.Int32ul('unk1'),
      construct.Int32ul('unk2'),
      construct.Int32ul('cbSecret'))
'''
  BCRYPT_KEY = construct.Struct(
      'size'/construct.Int32ul,
      'tag'/construct.Int32ul, # 'MSSK'.
      'type'/construct.Int32ul,
      'unk0'/construct.Int32ul,
      'unk1'/construct.Int32ul,
      'unk2'/construct.Int32ul,
      'cbSecret'/construct.Int32ul)

  def __init__(self):
    self.iv = ''
    self.aes_key = ''
    self.des_key = ''
    
  def find_signature(self):
    for mod in self.task.get_load_modules():
      if str(mod.BaseDllName).lower() == 'lsasrv.dll':
        scanner = MemoryScanner(self.task)
        return scanner.find_first(mod.DllBase.v(), self.SIGNATURE)
    debug.warning('[LsaDecryptor:find_signature()] signature not found!')

  def get_IV(self, pos):
    ptr_iv = self.get_ptr_with_offset(pos + self.PTR_IV_OFFSET)
    if ptr_iv:
      return self.get_data(ptr_iv, self.IV_LENGTH)

  def get_key(self, pos, key_offset):
    ptr_key = self.get_ptr_with_offset(pos + key_offset)
    if ptr_key:
      ptr_key = self.get_ptr(ptr_key)
      if ptr_key:
        size = self.BCRYPT_HANDLE_KEY.sizeof()
        data = self.get_data(ptr_key, size)
        if data:
          kbhk = self.BCRYPT_HANDLE_KEY.parse(data)
          if kbhk.tag == self.UUUR_TAG:
            ptr_key = kbhk.ptr_kiwi_bcrypt_key
            size = self.BCRYPT_KEY.sizeof()
            data = self.get_data(ptr_key, size)
            if data:
              kbk = self.BCRYPT_KEY.parse(data)
              if kbk.tag == self.MSSK_TAG:
                #adjust = construct.Int32ul('').sizeof()
                adjust = 4
                size = kbk.cbSecret + adjust
                ptr_key = ptr_key + self.BCRYPT_KEY.sizeof() - adjust
                data = self.get_data(ptr_key, size)
                if data:
                  khk = self.HARD_KEY.parse(data)
                  return khk.data
                else:
                  debug.warning('get_key() unable to get HARD_KEY.')
              else:
                debug.warning('get_key() BCRYPT_KEY invalid tag')
            else:
              debug.warning('get_key() unable to read BCRYPT_KEY data.')
          else:
            debug.warning('get_key() BCRYPT_HANDLE_KEY invalid tag')
            debug.warning(kbhk)
        else:
          debug.warning('get_key() unable to read BCRYPT_HANDLE_KEY data.')
      else:
        debug.warning('get_key() unable to get BCRYPT_HANDLE_KEY pointer.')
    else:
      debug.warning('get_key()unable to get first pointer.')

  def get_des_key(self, pos):
    return self.get_key(pos, self.PTR_DES_KEY_OFFSET)
    
  def get_aes_key(self, pos):
    return self.get_key(pos, self.PTR_AES_KEY_OFFSET)

  def acquire_crypto_material(self):
    sigpos = self.find_signature()
    if not sigpos:
      debug.warning('[LsaDecryptor] unable to find signature!')
      return
    self.iv = self.get_IV(sigpos)
    self.des_key = self.get_des_key(sigpos)
    self.aes_key = self.get_aes_key(sigpos)

  def decrypt(self, encrypted):
    # TODO: NT version specific, move from here in subclasses.
    cleartext = ''
    size = len(encrypted)
    if size:
      if size % 8:
        if not self.aes_key or not self.iv:
          return cleartext
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.iv)
      else:
        if not self.des_key or not self.iv:
          return cleartext
        cipher = DES3.new(self.des_key, DES3.MODE_CBC, self.iv[:8])
      cleartext = cipher.decrypt(encrypted)
    return cleartext

  def dump(self):
    print 'Dumping LSA Decryptor'
    print '     IV ({}): {}'.format(len(self.iv), self.iv.encode('hex'))
    print 'DES_KEY ({}): {}'.format(
        len(self.des_key), self.des_key.encode('hex'))
    print 'AES_KEY ({}): {}'.format(
        len(self.aes_key), self.aes_key.encode('hex'))

    
class LsaDecryptor_x86(LsaDecryptor, Mimikatz_x86):
  """TODO: add description."""
  def __init__(self, lsass_task):
    Mimikatz_x86.__init__(self, lsass_task)
    LsaDecryptor.__init__(self)


class LsaDecryptor_x64(LsaDecryptor, Mimikatz_x64):
  """TODO: add description."""
  def __init__(self, lsass_task):
    Mimikatz_x64.__init__(self, lsass_task)
    LsaDecryptor.__init__(self)


class LsaDecryptor_Vista_x86(LsaDecryptor_x86):
  """Class for Windows Vista x86."""
  # MIMIKATZ x86: BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]
  SIGNATURE	= '\x8b\xf0\x3b\xf3\x7c\x2c\x6a\x02\x6a\x10\x68'
  PTR_IV_OFFSET = 11;
  PTR_AES_KEY_OFFSET = -15;
  PTR_DES_KEY_OFFSET = -70;

  '''
  BCRYPT_HANDLE_KEY = construct.Struct('KIWI_BCRYPT_HANDLE_KEY',
      construct.Int32ul('size'),
      construct.Int32ul('tag'), # Tag 'UUUR', 0x55555552.
      construct.Int32ul('ptr_void_algorithm'),
      construct.Int32ul('ptr_kiwi_bcrypt_key'),
      construct.Int32ul('ptr_unknown'))
  '''
  BCRYPT_HANDLE_KEY = construct.Struct(
      'size'/construct.Int32ul,
      'tag'/construct.Int32ul, # Tag 'UUUR', 0x55555552.
      'ptr_void_algorithm'/construct.Int32ul,
      'ptr_kiwi_bcrypt_key'/construct.Int32ul,
      'ptr_unknown'/construct.Int32ul)

  def __init__(self, lsass_task):
    LsaDecryptor_x86.__init__(self, lsass_task)


class LsaDecryptor_Win7_x86(LsaDecryptor_x86):
  """Class for Windows 7 x86."""
  # MIMIKATZ x86: BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]
  SIGNATURE	= '\x8b\xf0\x3b\xf3\x7c\x2c\x6a\x02\x6a\x10\x68'
  PTR_IV_OFFSET = 11;
  PTR_AES_KEY_OFFSET = -15;
  PTR_DES_KEY_OFFSET = -70;

  '''
  BCRYPT_HANDLE_KEY = construct.Struct('KIWI_BCRYPT_HANDLE_KEY',
      construct.Int32ul('size'),
      construct.Int32ul('tag'), # Tag 'UUUR', 0x55555552.
      construct.Int32ul('ptr_void_algorithm'),
      construct.Int32ul('ptr_kiwi_bcrypt_key'),
      construct.Int32ul('ptr_unknown'))
'''
  BCRYPT_HANDLE_KEY = construct.Struct(
      'size'/construct.Int32ul,
      'tag'/construct.Int32ul, # Tag 'UUUR', 0x55555552.
      'ptr_void_algorithm'/construct.Int32ul,
      'ptr_kiwi_bcrypt_key'/construct.Int32ul,
      'ptr_unknown'/construct.Int32ul)

  def __init__(self, lsass_task):
    LsaDecryptor_x86.__init__(self, lsass_task)


class LsaDecryptor_Vista_x64(LsaDecryptor_x64):
  """Class for Vista x64."""
  SIGNATURE	= '\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
  PTR_IV_OFFSET = 63;
  PTR_AES_KEY_OFFSET = 25;
  PTR_DES_KEY_OFFSET = -69;

  '''
  BCRYPT_HANDLE_KEY = construct.Struct('KIWI_BCRYPT_HANDLE_KEY',
      construct.Int32ul('size'),
      construct.Int32ul('tag'), # Tag 'UUUR', 0x55555552.
      construct.Int64ul('ptr_void_algorithm'),
      construct.Int64ul('ptr_kiwi_bcrypt_key'),
      construct.Int64ul('ptr_unknown'))
  '''
  BCRYPT_HANDLE_KEY = construct.Struct(
      'size'/construct.Int32ul,
      'tag'/construct.Int32ul, # Tag 'UUUR', 0x55555552.
      'ptr_void_algorithm'/construct.Int64ul,
      'ptr_kiwi_bcrypt_key'/construct.Int64ul,
      'ptr_unknown'/construct.Int64ul)


  def __init__(self, lsass_task):
    LsaDecryptor_x64.__init__(self, lsass_task)


class LsaDecryptor_Win7_x64(LsaDecryptor_x64):
  """Class for Windows 7 x64."""
  # MIMIKATZ x64: BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[]
  SIGNATURE	= '\x83\x64\x24\x30\x00\x44\x8b\x4c\x24\x48\x48\x8b\x0d'
  PTR_IV_OFFSET = 59;
  PTR_AES_KEY_OFFSET = 25;
  PTR_DES_KEY_OFFSET = -61;
  '''
  BCRYPT_HANDLE_KEY = construct.Struct('KIWI_BCRYPT_HANDLE_KEY',
      construct.Int32ul('size'),
      construct.Int32ul('tag'), # Tag 'UUUR', 0x55555552.
      construct.Int64ul('ptr_void_algorithm'),
      construct.Int64ul('ptr_kiwi_bcrypt_key'),
      construct.Int64ul('ptr_unknown'))
  '''
  BCRYPT_HANDLE_KEY = construct.Struct(
      'size'/construct.Int32ul,
      'tag'/construct.Int32ul, # Tag 'UUUR', 0x55555552.
      'ptr_void_algorithm'/construct.Int64ul,
      'ptr_kiwi_bcrypt_key'/construct.Int64ul,
      'ptr_unknown'/construct.Int64ul)

  def __init__(self, lsass_task):
    LsaDecryptor_x64.__init__(self, lsass_task)

#------------------------------------------------------------------------------    

class Wdigest():
  """TODO: add description."""
  SIGNATURE = None
  FIRST_ENTRY_OFFSET = 0
  WDIGEST_LIST_ENTRY = None
  MODULE_NAME = 'wdigest'
  MAX_WALK = 32

  def __init__(self, credentials_obj):
    self.entries = []
    self.entries_seen = {}
    self.credentials_obj = credentials_obj
    
  def find_signature(self):
    for mod in self.task.get_load_modules():
      if str(mod.BaseDllName).lower() == 'wdigest.dll':
        scanner = MemoryScanner(self.task)
        return scanner.find_first(mod.DllBase.v(), self.SIGNATURE)
    debug.warning('[Wdigest] no wdigest.dll found in lsass process!')

  def get_entry_at(self, ptr):
    if ptr:
      size = self.WDIGEST_LIST_ENTRY.sizeof()
      data = self.get_data(ptr, size)
      if data:
        entry = self.WDIGEST_LIST_ENTRY.parse(data)
        return entry
        
  def get_first_entry(self):
    position = self.find_signature()
    if position:
      ptr_entry = self.get_ptr_with_offset(position + self.FIRST_ENTRY_OFFSET)
      if ptr_entry:
        ptr_entry = self.get_ptr(ptr_entry)
        if ptr_entry:
          entry = self.get_entry_at(ptr_entry)
          if entry:
            return entry, ptr_entry
    else:
      debug.warning('[Wdigest] no wdigest package found.')
      return None, None

  def get_unicode_string_at(self, ptr, size):
    data = self.get_data(ptr, size)
    if data:
      data_str = ''
      try:
        data_str = data.decode('utf-16-le').rstrip('\0')
      except UnicodeDecodeError as ee:
        debug.error(
            '[Wdigest] get_unicode_string_at() unicode error {}'.format(
            ee))
        debug.warning('[Wdigest] src data is <{}>'.format(data_str))
      return data_str
    else:
      debug.error('[Wdigest] get_unicode_string_at() unable to get data')
      return ''
  
  def add_entry(self, entry, found_at):
    if entry.usage_count:
      if entry.this_entry == found_at:
        user = domain = epwd = ''
        if entry.user_string_ptr and entry.user_len:
          user = self.get_unicode_string_at(
              entry.user_string_ptr, entry.user_max_len)
        if entry.domain_string_ptr and entry.domain_len:
          domain = self.get_unicode_string_at(
              entry.domain_string_ptr, entry.domain_max_len)
        if entry.password_encrypted_ptr and entry.password_len:
          epwd = data = self.get_data(
              entry.password_encrypted_ptr, entry.password_max_len)
        if user:
          cred_entry = Credential(self.MODULE_NAME, user, domain, epwd)
          self.credentials_obj.add_credential(cred_entry)

  def walk_entries(self):
    entry, found_at = self.get_first_entry()
    if entry:
      walk_num = 1
      while walk_num < self.MAX_WALK:
        self.add_entry(entry, found_at)
        self.entries_seen[found_at] = 1
        found_at = entry.previous
        entry = self.get_entry_at(found_at)
        if not entry:
          debug.error('Next entry not found!')
          break
        if entry.this_entry in self.entries_seen:
          break
        walk_num += 1

    
class Wdigest_x86(Wdigest, Mimikatz_x86):
  """TODO: add description."""

  '''
  WDIGEST_LIST_ENTRY = construct.Struct('WdigestListEntry',
      construct.Int32ul('previous'),
      construct.Int32ul('next'),
      construct.Int32ul('usage_count'),
      construct.Int32ul('this_entry'),
      construct.Int64ul('luid'),
      construct.Int64ul('flag'),
      construct.Int16ul('user_len'),
      construct.Int16ul('user_max_len'),
      construct.Int32ul('user_string_ptr'),
      construct.Int16ul('domain_len'),
      construct.Int16ul('domain_max_len'),
      construct.Int32ul('domain_string_ptr'),
      construct.Int16ul('password_len'),
      construct.Int16ul('password_max_len'),
      construct.Int32ul('password_encrypted_ptr'))
  '''
  WDIGEST_LIST_ENTRY = construct.Struct(
      'previous'/construct.Int32ul,
      'next'/construct.Int32ul,
      'usage_count'/construct.Int32ul,
      'this_entry'/construct.Int32ul,
      'luid'/construct.Int64ul,
      'flag'/construct.Int64ul,
      'user_len'/construct.Int16ul,
      'user_max_len'/construct.Int16ul,
      'user_string_ptr'/construct.Int32ul,
      'domain_len'/construct.Int16ul,
      'domain_max_len'/construct.Int16ul,
      'domain_string_ptr'/construct.Int32ul,
      'password_len'/construct.Int16ul,
      'password_max_len'/construct.Int16ul,
      'password_encrypted_ptr'/construct.Int32ul)


  def __init__(self, lsass_task, credentials_obj):
    Mimikatz_x86.__init__(self, lsass_task)
    Wdigest.__init__(self, credentials_obj)


class Wdigest_x64(Wdigest, Mimikatz_x64):
  """TODO: add description."""
  '''
  WDIGEST_LIST_ENTRY = construct.Struct('WdigestListEntry',
      construct.Int64ul('previous'),
      construct.Int64ul('next'),
      construct.Int32ul('usage_count'),
      construct.Int32ul('align1'),
      construct.Int64ul('this_entry'),
      construct.Int64ul('luid'),
      construct.Int64ul('flag'),
      construct.Int16ul('user_len'),
      construct.Int16ul('user_max_len'),
      construct.Int32ul('align2'),
      construct.Int64ul('user_string_ptr'),
      construct.Int16ul('domain_len'),
      construct.Int16ul('domain_max_len'),
      construct.Int32ul('align3'),
      construct.Int64ul('domain_string_ptr'),
      construct.Int16ul('password_len'),
      construct.Int16ul('password_max_len'),
      construct.Int32ul('align4'),
      construct.Int64ul('password_encrypted_ptr'))
  '''
  WDIGEST_LIST_ENTRY = construct.Struct(
      'previous'/construct.Int64ul,
      'next'/construct.Int64ul,
      'usage_count'/construct.Int32ul,
      'align1'/construct.Int32ul,
      'this_entry'/construct.Int64ul,
      'luid'/construct.Int64ul,
      'flag'/construct.Int64ul,
      'user_len'/construct.Int16ul,
      'user_max_len'/construct.Int16ul,
      'align2'/construct.Int32ul,
      'user_string_ptr'/construct.Int64ul,
      'domain_len'/construct.Int16ul,
      'domain_max_len'/construct.Int16ul,
      'align3'/construct.Int32ul,
      'domain_string_ptr'/construct.Int64ul,
      'password_len'/construct.Int16ul,
      'password_max_len'/construct.Int16ul,
      'align4'/construct.Int32ul,
      'password_encrypted_ptr'/construct.Int64ul)

  def __init__(self, lsass_task, credentials_obj):
    Mimikatz_x64.__init__(self, lsass_task)
    Wdigest.__init__(self, credentials_obj)


class Wdigest_Vista_x86(Wdigest_x86):
  """Class for Windows Vista x86."""
  SIGNATURE	= '\x74\x11\x8b\x0b\x39\x4e\x10'
  FIRST_ENTRY_OFFSET = -6
  
  def __init__(self, lsass_task, credentials_obj):
    Wdigest_x86.__init__(self, lsass_task, credentials_obj)


class Wdigest_Win7_x86(Wdigest_x86):
  """Class for Windows 7 x86."""
  SIGNATURE	= '\x74\x11\x8b\x0b\x39\x4e\x10'
  FIRST_ENTRY_OFFSET = -6
  
  def __init__(self, lsass_task, credentials_obj):
    Wdigest_x86.__init__(self, lsass_task, credentials_obj)


class Wdigest_Win7_x64(Wdigest_x64):
  """Class for Windows 7 x64."""
  SIGNATURE	= '\x48\x3b\xd9\x74'
  FIRST_ENTRY_OFFSET = -4
  
  def __init__(self, lsass_task, credentials_obj):
    Wdigest_x64.__init__(self, lsass_task, credentials_obj)


class Wdigest_Vista_x64(Wdigest_x64):
  """Class for Windows Vista x64."""
  SIGNATURE	= '\x48\x3b\xd9\x74'
  FIRST_ENTRY_OFFSET = -4
  
  def __init__(self, lsass_task, credentials_obj):
    Wdigest_x64.__init__(self, lsass_task, credentials_obj)

#------------------------------------------------------------------------------
          
class mimikatz(commands.Command):
  """mimikatz offline"""
  def __init__(self, config, *args, **kwargs):
    commands.Command.__init__(self, config, *args, **kwargs)
    self.profile = config.get_value('profile')
    self.credentials_obj = Credentials()
    
  def find_lsass(self):
    addr_space = utils.load_as(self._config)
    for task in tasks.pslist(addr_space):
      if str(task.ImageFileName) == 'lsass.exe':
        return task

  def init_objects(self, lsass_task):
    lsa_decryptor = None
    wdigest = None
    if len(self.profile) >= 7:
      arch = self.profile[-3:]
      sp = self.profile[-6:-3]
      os = self.profile[:-6]
      if os == 'Vista':
        if arch == 'x86':
          lsa_decryptor = LsaDecryptor_Vista_x86(lsass_task)
          wdigest = Wdigest_Vista_x86(lsass_task, self.credentials_obj)
        elif arch == 'x64':
          lsa_decryptor = LsaDecryptor_Vista_x64(lsass_task)
          wdigest = Wdigest_Vista_x64(lsass_task, self.credentials_obj)
      elif os == 'Win7':
        if arch == 'x86':
          lsa_decryptor = LsaDecryptor_Win7_x86(lsass_task)
          wdigest = Wdigest_Win7_x86(lsass_task, self.credentials_obj)
        elif arch == 'x64':
          lsa_decryptor = LsaDecryptor_Win7_x64(lsass_task)
          wdigest = Wdigest_Win7_x64(lsass_task, self.credentials_obj)
      else:
        pass
    return lsa_decryptor, wdigest

  def calculate(self):
    lsass_task = self.find_lsass()
    if not lsass_task:
      debug.error('lsass_task process not found!!')
      return

    lsa_decryptor, wdigest = self.init_objects(lsass_task)
    if not lsa_decryptor or not wdigest:
      return

    lsa_decryptor.acquire_crypto_material()
    wdigest.walk_entries()
    
    for cred in self.credentials_obj.credentials:
      cred.decrypt_epwd(lsa_decryptor)

  def render_text(self, outfd, data):
    self.table_header(outfd, [("Module", "8"), 
                              ("User", "16"), 
                              ("Domain", "16"),
                              ("Password", "40")])
    for cred in self.credentials_obj.credentials:
      self.table_row(
          outfd, cred.module, cred.username, cred.domain, cred.pwd)
