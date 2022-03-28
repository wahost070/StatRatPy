from contextlib import contextmanager
from distutils import extension
from urllib.parse import urlparse
import aiohttp
import asyncio
import hashlib
import json
import logging
import magic
import os
import pefile
from pprint import pprint as pp
import re
import requests
import shutil
import yara
import zipfile
import peutils
import time
import tempfile
from pathlib import PurePath
import errno
import platform
import subprocess
from dotenv import load_dotenv
from multiprocessing import Process, Queue
import uuid


"""
https://cuckoo.readthedocs.io/en/latest/usage/submit/
https://developers.virustotal.com/reference/file-behaviour-summary
"""
    
LOCAL = True
DEBUG = True
SCAN_STRINGS = False
local_hash_table = set()

class LoadMalware(object):
    
    def __init__(self, file_name):
        self.pe_file = None
        
        try:
            self.pe_file = pefile.PE(file_name, fast_load=False)
        except pefile.PEFormatError as e:
            logging.critical(f"Couldn't read PE magic bytes: {e}")
            self.pe_file = e
            
    def __enter__(self):
        return self.pe_file

    def __exit__(self, type, value, traceback):
        try:
            self.pe_file.close()
        except Exception as e:
            pass
        
        return True


class StatRat(object):

# ----------------------------- get absolute path ---------------------------- #
    def list_absolute_dir(self, dir):
        return [os.path.join(dir, file) for file in os.listdir(dir)]


# ----------------------------- get relative path ---------------------------- #
    def get_relative_path(self, path, withoutExtension=False):
        if withoutExtension is True:
            return PurePath(path.replace(PurePath(path).suffix, '')).name
        
        else:
            return PurePath(path).name
        
# ------------------------- create temp dir workspace ------------------------ #
# * https://rules.sonarsource.com/python/RSPEC-5445

    @contextmanager
    def make_temp_directory(self):
        t = tempfile.TemporaryDirectory(dir=f"{self.cwd}")
        temp_dir = t.name
        try:
            logging.info(f"Creating temp directory called {self.get_relative_path(temp_dir)}")
            yield temp_dir
        finally:
            logging.info(f"Deleting temp directory {self.get_relative_path(temp_dir)}")

            try:
                t.cleanup()
                #shutil.rmtree(temp_dir)
                logging.debug(f"Successfully deleted {self.get_relative_path(temp_dir)}")
                
            except OSError:
                # file has already been deleted
                logging.error(f"Error cleaning up {temp_dir}")
                

# -------------------------------- unzip file -------------------------------- #
    def unzip_file(self, temp_dir, zip):
        pword = "infected"
        try:

            if self.isWindows:
                logging.debug("Using 7zip for Windows")
                seven_zip = f"{self.cwd}/7zip/7za.exe"
                
            else:
                logging.debug("Using 7zip for Linux")
                seven_zip = f"{self.cwd}/7zip/7za"
                
            ret = subprocess.check_output([seven_zip, "x", f"{zip}", f"-o{temp_dir}", f"-p{pword}"])

            if b"Everything is Ok" not in ret:
                raise zipfile.BadZipFile
                
        except Exception as e:
            logging.error(f"Error unzipping: {e}")
            return None

        return f"{os.path.abspath(temp_dir)}"

# ------------------------------ get magic bytes ----------------------------- #
# * https://stackoverflow.com/questions/43580/how-to-find-the-mime-type-of-a-file-in-python
# * https://stackoverflow.com/questions/18374103/exception-valuefailed-to-find-libmagic-check-your-installation-in-windows-7
    """
    pip install python-magic==0.4.15
    pip install python-magic-bin==0.4.14
    pip install libmagic
    """
    
    def get_magic_bytes(self, malware_path):
        d = {"file_type": magic.from_file(malware_path)}
        return d

# ------------------------------- get file size ------------------------------ #
    def get_file_size(self, malware_path):
        d = {"file_size": os.path.getsize(malware_path)}
        return d
        
# ------------------------------- get hash of file ------------------------------- #
# * https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
# * https://brain-upd.com/programming/how-to-use-virustotal-api-with-python/

    def get_file_hash(self, malware_path):
        x = {}
        if LOCAL is True:
            BUF_SIZE = 65536

            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha1()

            with open(malware_path, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)

            x["md5"] = md5.hexdigest()
            x["sha1"] = sha1.hexdigest()
            x["sha256"] = sha256.hexdigest()
        else:
            api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            
            #TODO: hide this API key
            params = dict(apikey=os.getenv('VT_API_KEY'))
            with open(malware_path, "rb") as file:
                files = dict(file=(malware_path, file))
                response = requests.post(api_url, files=files, params=params)
            if response.status_code == 200:
                result = response.json()

            x["md5"] = result["md5"]
            x["sha1"] = result["sha1"]
            x["sha256"] = result["sha256"]

        d = {"hashes": x}
        return d
    
# ----------------------------- get imported symbols ---------------------------- #
    def get_imported_symbols(self, pe_file):
        
        # *https://malwology.com/2018/08/24/python-for-malware-analysis-getting-started/

        imports = {}

        try:
            for item in pe_file.DIRECTORY_ENTRY_IMPORT:
                for i in item.imports:
                    imports[item.dll.decode("utf-8")] = {"address": hex(i.address), "functions": [i.name.decode('utf-8') for i in item.imports]}
            
        except Exception as e:
            logging.warning(f"Couldn't get imports: {e}")
        
        d = {"imports": imports}
        return d

# --------------------------- get exported symbols --------------------------- #
    def get_exported_symbols(self, pe_file):
        exports = {}
        try:
            for exp in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                exports[exp.name.decode("utf-8")] = {"address": hex(pe_file.OPTIONAL_HEADER.ImageBase + exp.address), "ordinal": exp.ordinal}
        except AttributeError as e:
            # no EXPORTS attribute
            logging.warning(f"No export symbols detected or error: {e}")

        d = {"exports": exports}
        return d
# ---------------------- download yara rules --------------------- #
# TODO: IMPLEMENT YARA

# ----------------------------- packer detection ----------------------------- #
    def get_packer_detection(self, pe_file):
        d = {"packers": None}
        
        signatures = peutils.SignatureDatabase(f"{self.cwd}/userdb.txt")
        matches = signatures.match_all(pe_file, ep_only=True)
        t = set(matches[-1]) # the last match is most accurate as most bytes will have been matched

        d["packers"] = list(t)
        return d

# --------------------------- list section adresses -------------------------- #

    def get_section_addresses(self, pe_file):
        s = {}
        for section in pe_file.sections:
            name = section.Name.decode("utf-8").rstrip("\x00")
            s[name] = {"virtual_addr": hex(section.VirtualAddress), "virtual_size": hex(section.Misc_VirtualSize), "raw_data_size": section.SizeOfRawData}

        d = {"sections": s}
        return d
    
# ---------------------------- write to json file ---------------------------- #

    def write_to_json_file(self, d, **kwargs):
        if len(kwargs) == 2:
            
            mal = self.get_relative_path(kwargs['mal'], True)
            z = self.get_relative_path(kwargs['zippie'], True)
            
            try:
                os.makedirs(f"{self.cwd}/results/{z}")
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
            
            with open(f"{self.cwd}/results/{z}/{mal}_{d['hashes']['md5']}.json", 'w') as json_f:
                json.dump(d, json_f, sort_keys=True, indent=4, separators=(',', ': '))
                
            logging.info(f"Created log at {os.curdir}/results/{z}/{mal}_{d['hashes']['md5']}.json")
        else:
            # TODO: ERROR HANDLE OUTPUT

            try:
                os.makedirs(f"{self.cwd}/results")
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise
                
            with open(f"{self.cwd}/results/err.json", 'w+') as json_f:
                try:
                    j = json.load(json_f)
                    j.append(d)
                    json.dump(j, json_f, sort_keys=True, indent=4, separators=(',', ': '))
                except json.JSONDecodeError:
                    json.dump(d, json_f, sort_keys=True, indent=4, separators=(',', ': '))

# --------------------------- get import table hash -------------------------- #
# * https://malwology.com/2018/08/24/python-for-malware-analysis-getting-started/

    def get_import_table_hash(self, pe_file):
        x = {"import_table_hash_md5": pe_file.get_imphash()}
        return x
            
# --------------------------- get security warnings -------------------------- #
    def get_security_warnings(self, pe_file):
        x = {"pe_warnings": pe_file.get_warnings()}
        return x
            
# ------------------------------ get entry addr ------------------------------ #
    def get_entry_addr(self, pe_file):
        x = {"entry_address": hex(pe_file.OPTIONAL_HEADER.AddressOfEntryPoint)}
        return x

# ---------------------------- get image bass addr --------------------------- #
    def get_image_base_addr(self, pe_file):
        x = {"image_base_address": hex(pe_file.OPTIONAL_HEADER.ImageBase)}
        return x
    
# ---------------------------- get linker version ---------------------------- #
    def get_linker_version(self, pe_file):
        x = {
            "linker_version": {
                "major": pe_file.OPTIONAL_HEADER.MajorLinkerVersion,
                "minor": pe_file.OPTIONAL_HEADER.MinorLinkerVersion
            }
        }
        return x
    
# --------------------------- get os linker version -------------------------- #
    def get_os_version(self, pe_file):
        x = {
            "os_version": {
                "major": pe_file.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                "minor": pe_file.OPTIONAL_HEADER.MinorOperatingSystemVersion
            }
        }
        return x
    
# ----------------------------- get os linker architecture ----------------------------- #
    def get_os_architecture(self, pe_file):
        d = {}
        arch = pe_file.FILE_HEADER.Machine
        
        if arch == 0x14c:
            d["machine"] = "x86"
        elif arch == 0x14d:
            d["machine"] = "486"
        elif arch == 0x14e:
            d["machine"] = "Pentium"
        elif arch == 0x0200:
            d["machine"] = "AMD64"
        elif pe_file.OPTIONAL_HEADER.Magic == 0x20b:
            d["machine"] = "x64"
        else:
            d["machine"] = "Unknown"
        
        return d
    
# --------------------------- get file architecture -------------------------- #
    def get_file_architecture(self, pe_file):
        if pe_file.FILE_HEADER.Machine == 0x8664:
            d = {"file_arch": 64}
        else:
            d = {"file_arch": 32}
        return d
            
# ----------------------------- get compile time ----------------------------- #
    def get_compile_time(self, pe_file):
        d = {}
        try:
            d["compile_time"] = f"{time.asctime(time.gmtime(pe_file.FILE_HEADER.TimeDateStamp))} UTC"
        except Exception as e:
            d["compile_time"] = None
            
        return d

# -------------------------- find strings in binary -------------------------- #
    def get_strings(self, malware_path):
        x = []
        with open(malware_path, "rb") as f_binary:
            x = re.findall(b"([a-zA-Z]{4,})", f_binary.read())
            
        d = {"strings": [v.decode("utf-8") for v in x]}
        return d

    def pfriendly_analyse_malware(self, queue, zip, counter_zip, uuid_name):
        logging.debug(f"NEW THREAD: {uuid_name}")
        logging.info(f"Extracting {self.get_relative_path(zip)}")
        global local_hash_table
        
        # make temp directory
        with self.make_temp_directory() as temp_dir:
        #with tempfile.TemporaryDirectory(dir=f"{self.cwd}") as temp_dir:
            print(temp_dir)
            # get directory name of the extracted malware
            m = self.unzip_file(temp_dir, zip)
            # break if we couldnt unzip correctly
            if m is None:
                logging.error("WE COULDN'T UNZIP PROPERLY; SKIPPING")
                return
            else:
                malware_extracted_dir = m
            
            # iterate through all files in the extracted directory
            for counter_malware, malware_file_path in enumerate(self.list_absolute_dir(malware_extracted_dir)):
                with LoadMalware(malware_file_path) as pe_file:
                    if pe_file is type(Exception):
                        e = pe_file
                        failpoint = {"malware_name": self.get_relative_path(malware_file_path), "zip": zip, "error": f"{e}"}
                        self.write_to_json_file(failpoint)
                        continue
                    
                    d = {}
                    
                    logging.debug(f"Zip {counter_zip}, file {counter_malware}")
                    logging.info(f"Scanning {self.get_relative_path(malware_file_path)}")
                    
                    d.update(self.get_file_hash(malware_file_path))

                    if d["hashes"]["md5"] in local_hash_table:
                        logging.warning("Duplicate hash in table, skipping!")
                        continue
                        
                    local_hash_table.add(d["hashes"]["md5"])
                
                    d["found_in"] = self.get_relative_path(zip)
                    d["file_name"] = self.get_relative_path(malware_file_path)
                    
                    d.update(self.get_file_size(malware_file_path))
                    d.update(self.get_magic_bytes(malware_file_path))
                    d.update(self.get_import_table_hash(pe_file))
                    d.update(self.get_entry_addr(pe_file))
                    d.update(self.get_image_base_addr(pe_file))
                    d.update(self.get_exported_symbols(pe_file))
                    d.update(self.get_imported_symbols(pe_file))
                    d.update(self.get_section_addresses(pe_file))
                    d.update(self.get_os_version(pe_file))
                    d.update(self.get_linker_version(pe_file))
                    d.update(self.get_os_architecture(pe_file))
                    d.update(self.get_file_architecture(pe_file))
                    d.update(self.get_compile_time(pe_file))
                    d.update(self.get_security_warnings(pe_file))
                    d.update(self.get_packer_detection(pe_file))

                    if SCAN_STRINGS:
                        d.update(self.get_strings(malware_file_path))
                        
                    if not self.isWindows:
                        # download yara rules
                        pass
                    
                    # write outputs to a file
                self.write_to_json_file(d, mal=malware_file_path, zippie=zip)
        #uuid_namequeue.put("SUCCESS")
                    #pe_file.close()

    def main(self):
        zip_dir_path = f"{self.cwd}/malware/"

        queue = Queue()
        jobs = []
        # repeat for every zip in the directory
        for counter_zip, zip in enumerate(self.list_absolute_dir(zip_dir_path)):
            
            #self.pfriendly_analyse_malware(zip, counter_zip)
            
            uuid_name = uuid.uuid4().hex
            p = Process(target=self.pfriendly_analyse_malware, name=uuid_name, args=(queue, zip, counter_zip, uuid_name,))
            jobs.append(p)

        for p in jobs:
            logging.debug(f"Starting {len(jobs)} {'jobs' if len(jobs) > 1 else 'job'}")
            p.start()

        #print(queue.get())
        for p in jobs:
            p.join()
            
    
    def __init__(self, isWindows):
        self.isWindows = isWindows
        self.cwd = os.path.dirname(os.path.abspath(__file__))
        
        self.main()
            

if __name__ == "__main__":
    load_dotenv()
    isWindows = True
    handlers = [
        logging.FileHandler(filename="trace.log", encoding="utf-8", mode="w+"),
        logging.StreamHandler()
    ]
    if DEBUG is False:
        lvl = logging.INFO
    else:
        lvl = logging.DEBUG
    logging.basicConfig(level=lvl, format="%(asctime)s:%(msecs)d %(levelname)-7s [%(filename)s:%(lineno)d] %(message)s", datefmt='%Y-%m-%d %H:%M:%S', handlers=handlers)
    
    # check host system
    if not any(platform.win32_ver()) and os.name != 'nt':
        logging.info(f"OS Detection: {platform.system()} {platform.release()}")
        isWindows = False
    else:
        logging.info(f"OS Detection: {platform.system()} {platform.release()}")

    startrat = StatRat(isWindows)
