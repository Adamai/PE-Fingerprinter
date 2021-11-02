#!/usr/bin/python
# -*- coding: utf-8 -*-


import pefile
import win32api
import win32con
import ctypes
from ctypes import windll
from ctypes import wintypes
import os
import re
import glob
import hashlib
import mimetypes
import vt
import requests

class Depn:
  def __init__(self, name, path, md5, sha256, unsurePathFlag, functions):
    self.name = name
    self.path = path
    self.md5 = md5
    self.sha256 = sha256
    self.unsurePathFlag = unsurePathFlag
    self.functions = functions
      

def getDLLPath(dllName, directory, is32bit, deepLocalSearch, prioritizeLocal):
  directory = directory.replace('\\', '/')
  windowsPath = os.environ['WINDIR']
  windowsPath = windowsPath.replace('\\', '/')
  sys32path = windowsPath+"/System32";
  syswow64path = windowsPath+"/SysWOW64";
  kernel32 = ctypes.WinDLL('Kernel32', use_last_error=True)
  DLLpath = ""
  uncertainFlag = False
  dllHandle = None
  print(dllName)
  
  h_module_base=None
  try:
    dllHandle = win32api.LoadLibraryEx(dllName, 0, win32con.LOAD_LIBRARY_AS_DATAFILE)
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleFileNameW.restype = wintypes.DWORD
    kernel32.GetModuleFileNameW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
    h_module_base = kernel32.GetModuleHandleW(dllName)
  except:
    h_module_base=None
  finally:
    if(h_module_base is None):
      #print("Module base is none!!!!!!!")
      #SYSTEM32 CHECKED FOR 64-bit binaries, SYSWOW64 CHECKED FOR 32-bit binaries
      filesFoundLocal = []
      filesFoundSystem = []
      #match deepLocalSearch, prioritizeLocal:
      #match is new to Python 3.10. Not using yet to avoid dependencies blowing up
        #case True, False:
      if((deepLocalSearch) and not(prioritizeLocal)):
          if(is32bit):
            filesFoundSystem = glob.glob(syswow64path + "/**/" + dllName, recursive = True)
          else:
            filesFoundSystem = glob.glob(sys32path + "/**/" + dllName, recursive = True)
          if(not filesFoundSystem):
            filesFoundLocal = glob.glob(directory + "/**/" + dllName, recursive = True)
        #case False, True:
      elif(not (deepLocalSearch) and (prioritizeLocal)):
          filesFoundLocal = glob.glob(directory + "/**/" + dllName, recursive = True)
          if(is32bit and not(filesFoundLocal)):
            filesFoundSystem = glob.glob(syswow64path + "/**/" + dllName, recursive = True)
          elif(not filesFoundLocal):
            filesFoundSystem = glob.glob(sys32path + "/**/" + dllName, recursive = True)
        #case False, False:
      else:
          if(is32bit):
            filesFoundSystem = glob.glob(syswow64path + "/**/" + dllName, recursive = True)
          else:
            filesFoundSystem = glob.glob(sys32path + "/**/" + dllName, recursive = True)

      if(filesFoundLocal):
        DLLpath = filesFoundLocal[0]
        if(len(filesFoundLocal) > 1):
          print("Dependency of same name found in more than one place in local subdirectory")
          print(filesFoundLocal)
          uncertainFlag=True
      elif(filesFoundSystem):
        DLLpath = filesFoundSystem[0]
        if(len(filesFoundSystem) > 1):
          print("Dependency of same name found in more than one place in Windows subdirectory")
          print(filesFoundSystem)
          uncertainFlag=True
      else:
        #File not found
        #print("File could not be found")
        DLLpath = "Not found"
        uncertainFlag=True

      #if(prioritizeLocal):
      #  filesFoundLocal = glob.glob(directory + "/**/*" + dllName, recursive = True)

      #if(is32bit and not(filesFoundLocal)):
      #  filesFoundSystem = glob.glob(syswow64path + "/**/*" + dllName, recursive = True)
      #elif(not(filesFoundLocal)):
      #  filesFoundSystem = glob.glob(sys32path + "/**/*" + dllName, recursive = True)
      
      #if((not ((directory == syswow64path) or (directory == sys32path))) and (deepLocalSearch)):
      #  filesFoundLocal = glob.glob(directory + "/**/*" + dllName, recursive = True)
      #elif(not (prioritizeLocal)):
      #  filesFoundLocal = filesFoundSystem

      #if((not filesFoundLocal) and (filesFoundSystem)):
      #  if(len(filesFoundSystem) > 1):
       #   print("More than one of the same dll found? Assuming the first")
       #   print(filesFoundSystem)
       #   uncertainFlag=True

       # DLLpath = filesFoundSystem[0]
      #elif(filesFoundLocal):
       # if(len(filesFoundLocal) > 1):
       #   print("File found in multiple directories inside base directory. Assuming first found")
       #   print(filesFoundLocal)
        #  uncertainFlag=True

      #  DLLpath = filesFoundLocal[0]

    #  if((not filesFoundSystem) and (not filesFoundLocal)):
        #File not found
    #    print("File could not be found")
    #    DLLpath = "Not found"
    #    uncertainFlag=True

    
    else:
      module_path = ctypes.create_unicode_buffer(255)
      kernel32.GetModuleFileNameW(h_module_base,module_path,255)
      #pe = pefile.PE(module_path.value)
      DLLpath = module_path.value
      if(not 'Windows' in DLLpath):
       if('Python' in DLLpath):
          if(is32bit):
            filesFoundSystem = glob.glob(syswow64path + "/**/" + dllName, recursive = True)
          else:
            filesFoundSystem = glob.glob(sys32path + "/**/" + dllName, recursive = True)
          if(filesFoundSystem):
            DLLpath = filesFoundSystem[0]
          else:
            uncertainFlag=True
            print(DLLpath)
      

    if dllHandle is not None:
      win32api.FreeLibrary(dllHandle)

    DLLpath = DLLpath.replace("/", "\\")
    return [DLLpath, uncertainFlag]

def getHashes(fileP):
  md5_hash = hashlib.md5()
  sha_hash = hashlib.sha256()
  a_file = open(fileP, "rb")
  content = a_file.read()
  md5_hash.update(content)
  sha_hash.update(content)
  digest_md5 = md5_hash.hexdigest()
  digest_sha = sha_hash.hexdigest()
  a_file.close()
  return [digest_md5, digest_sha]

def getDLLs(filePath, deepLocalSearch, prioritizeLocal):
  pe =  pefile.PE(filePath, fast_load=False)
  pe.parse_data_directories()
  fullDLLs = []
  is32bit = False
  if hex(pe.FILE_HEADER.Machine) == '0x14c':
    #"32-bit binary"
    is32bit  =True
  if(not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')):
    return [Depn('No dependencies', 'Not found', '', '', False, ['Empty'])]
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    #print(entry.dll)
    #peDLLs.append(entry.dll)
    DLLfunctions = []
    dllName = str(entry.dll)
    if("b'" in dllName):
      dllName = re.search("b'(.*)'", str(dllName)).group(1)
    for imp in entry.imports:
      #print('\t', hex(imp.address), imp.name)
      functionName= str(imp.name)
      if("b'" in functionName):
        functionName = re.search("b'(.*)'", str(functionName)).group(1)
      DLLfunctions.append(functionName)
    #print("---------")
    dllPathArray = getDLLPath(dllName, filePath.rpartition('/')[0], is32bit, deepLocalSearch, prioritizeLocal)
    if(dllPathArray[0] != '' and not('ot found' in dllPathArray[0])):
      hashes = getHashes(dllPathArray[0])
    else:
      hashes = ['','']
    dll = Depn(dllName, dllPathArray[0], hashes[0], hashes[1], dllPathArray[1], DLLfunctions)
    fullDLLs.append(dll)
  #print("END of Directory Entry Imports------------")
  return fullDLLs

#used to find subdependencies without searching for their own dependencies.
def getDLLsNoSearch(filePath):
  pe =  pefile.PE(filePath, fast_load=False)
  pe.parse_data_directories()
  fullDLLs = []
  if(not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT')):
    return [Depn('No dependencies', 'Not found', 'Empty', 'Empty', False, ['Empty'])]
  for entry in pe.DIRECTORY_ENTRY_IMPORT:
    DLLfunctions = []
    dllName = str(entry.dll)
    if("b'" in dllName):
      dllName = re.search("b'(.*)'", str(dllName)).group(1)
    for imp in entry.imports:
      functionName= str(imp.name)
      if("b'" in functionName):
        functionName = re.search("b'(.*)'", str(functionName)).group(1)
      DLLfunctions.append(functionName)
    
    #hashes = getHashes(filePath)
    dll = Depn(dllName, "", '', '', False, DLLfunctions)
    fullDLLs.append(dll)
  #print("END of Directory Entry Imports------------")
  return fullDLLs

def getFileInfo(filePath):
  pe =  pefile.PE(filePath, fast_load=False)
  pe.parse_data_directories()
  fileName = filePath.rpartition('/')[2]
  fileName = fileName.rpartition('\\')[2]

  string_version_info = {}
  string_version_info['CurrentFileName'] = fileName
  if hasattr(pe, 'FileInfo'):
    for fileinfo in pe.FileInfo[0]:
      if fileinfo.Key.decode() == 'StringFileInfo':
        for st in fileinfo.StringTable:
          for entry in st.entries.items():
            string_version_info[entry[0].decode()] = entry[1].decode()

  string_version_info['TimeDateStamp'] = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
  if hex(pe.FILE_HEADER.Machine) == '0x14c':
      string_version_info['BinaryType'] = "32-bit binary"
  else:
      string_version_info['BinaryType'] = "64-bit binary"
  
  preExtension, extension = os.path.splitext(filePath)
  string_version_info['File type (extension)'] = str(extension)
  guess = mimetypes.guess_type(filePath)
  string_version_info['File type guess(mimetype)'] = str(guess)

  hashes = getHashes(filePath)
  string_version_info['MD5'] = hashes[0]
  string_version_info['SHA256'] = hashes[1]
  return string_version_info

def getVTinfo(sha):
  #CHANGING TO USE AN EXTERNAL FILE LATER
  VTclient = vt.Client("INSERT KEY HERE")

  VTfileInfo = VTclient.get_object("/files/"+sha)

  VTclient.close()

  return VTfileInfo

def getCVEresults(string):
  #key:
  response = requests.get("https://services.nvd.nist.gov/rest/json/cves/1.0?keyword="+string)
  return response.json()