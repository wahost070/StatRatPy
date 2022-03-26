
from contextlib import contextmanager
from tempfile import mkdtemp
from urllib.parse import urlparse
import aiohttp
import asyncio
import hashlib
import json
import logging
import magic
import os
import pefile
import pprint
import re
import requests
import shutil
import yara
import zipfile

"""
https://cuckoo.readthedocs.io/en/latest/usage/submit/
https://developers.virustotal.com/reference/file-behaviour-summary
"""
    
LOCAL = True
SCAN_STRINGS = False


class StatRat():
    
# ------------------------- create temp dir workspace ------------------------ #
    @contextmanager
    def make_temp_directory(self):
        temp_dir = mkdtemp()
        try:
            yield temp_dir
        finally:
            self.pe_file.close()
            shutil.rmtree(temp_dir)

# -------------------------------- unzip file -------------------------------- #
    def unzip_file(self, temp_dir, zip):
        with zipfile.ZipFile(zip, 'r') as zip_f:
            zip_f.extractall(pwd=b'infected', path=temp_dir)
    
        p = [x for x in os.listdir(temp_dir)][0]
        return f"{os.path.abspath(temp_dir)}/{p}"

# ------------------------------ get magic bytes ----------------------------- #
# * https://stackoverflow.com/questions/43580/how-to-find-the-mime-type-of-a-file-in-python
# * https://stackoverflow.com/questions/18374103/exception-valuefailed-to-find-libmagic-check-your-installation-in-windows-7
    """
    pip install python-magic==0.4.15
    pip install python-magic-bin==0.4.14
    pip install libmagic
    """
    
    def get_magic_bytes(self):
        d = {"file_type": magic.from_file(self.malware_path)}
        return d

# ------------------------------- get file size ------------------------------ #
    def get_file_size(self):
        d = {"file_size": os.path.getsize(self.malware_path)}
        return d
        
# ------------------------------- get hash of file ------------------------------- #
# * https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
# * https://brain-upd.com/programming/how-to-use-virustotal-api-with-python/

    def get_file_hash(self):
        x = {}
        if LOCAL is True:
            BUF_SIZE = 65536

            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha1()

            with open(self.malware_path, 'rb') as f:
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
            params = dict(apikey='991c179538d7afed7be9b450dd453cfeacc7e28c39187984d3089e6642171c83')
            with open(self.malware_path, 'rb') as file:
                files = dict(file=(self.malware_path, file))
                response = requests.post(api_url, files=files, params=params)
            if response.status_code == 200:
                result = response.json()

            x["md5"] = result["md5"]
            x["sha1"] = result["sha1"]
            x["sha256"] = result["sha256"]

        d = {"hashes": x}
        return d

# ----------------------------- get imported symbols ---------------------------- #
    def get_imported_symbols(self):
        
        # *https://malwology.com/2018/08/24/python-for-malware-analysis-getting-started/

        imports = {}

        for item in self.pe_file.DIRECTORY_ENTRY_IMPORT:
            for i in item.imports:
                imports[item.dll.decode("utf-8")] = {"address": hex(i.address), "functions": [i.name.decode('utf-8') for i in item.imports]}
        
        d = {"imports": imports}
        return d

# --------------------------- get exported symbols --------------------------- #
    def get_exported_symbols(self):
        exports = {}
        try:
            for exp in self.pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
                exports[exp.name.decode("utf-8")] = {"address": hex(self.pe_file.OPTIONAL_HEADER.ImageBase + exp.address), "ordinal": exp.ordinal}
        except AttributeError as e:
            # no EXPORTS attribute
            logging.info("No export symbols detected or error")
            pass
        d = {"exports": exports}
        return d

# ---------------------- download yara rules --------------------- #
# * https://www.youtube.com/watch?v=ln99aRAcRt0
# * https://isleem.medium.com/detect-malware-packers-and-cryptors-with-python-yara-pefile-65bf3c15be78
    async def get_yars(self, s, url):
        async with s.get(url) as response:
            f_name = urlparse(url).path.split('/')[-1]
            result = await response.text()
            
            return {"f_name": f_name, "result": result}
    
    async def start_async_task(self):
        if not os.path.exists(self.yara_dir):
            os.mkdir(f"{self.yara_dir}")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for v in self.urls:
                task = asyncio.ensure_future(self.get_yars(session, v))
                tasks.append(task)
                
            out = await asyncio.gather(*tasks)
            
            for v in out:
                if len(os.listdir(f"{self.yara_dir}")) != 3:
                    with open(f"{self.yara_dir}/{v['f_name']}", "w") as f:
                        f.write(v["result"])

# ------------------------------ load yara rules ----------------------------- #
# * https://github.com/VirusTotal/yara/issues/499

    def load_yara_rules(self):
        r = {}

        for file in os.listdir(f"{self.yara_dir}\\"):
            if file.lower().endswith(".yar") and os.path.isfile(f"{self.yara_dir}\\{file}"):
                r[file[:-4]] = f"{self.yara_dir}\\{file}"
            else:
                # No valid .yar files
                exit(1)
        
        rules = yara.compile(filepaths=r)

        try:
            # crypto detection
            matches = rules.match(self.malware_path)
            if matches and matches.namespace == "crypto_signatures":
                print(f"Cryptos detected: {matches}")
        
            # packer detection
            matches = rules.match(self.malware_path)
            if matches and matches.namespace == "packer":
                print(f"packer detected: {matches}")
        
            # peid detection
            matches = rules.match(self.malware_path)
            if matches and matches.namespace == "peid":
                for match in matches:
                    for packer in self.packers:
                        if packer.lower() in match.lower():
                            print(f"packer detected: {packer}")

        except Exception as e:
            print(f"Exception: {e}")

# --------------------------- list section adresses -------------------------- #

    def get_section_addresses(self):
        s = {}
        for section in self.pe_file.sections:
            name = section.Name.decode("utf-8").rstrip("\x00")
            s[name] = {"virtual_addr": hex(section.VirtualAddress), "virtual_size": hex(section.Misc_VirtualSize), "raw_data_size": section.SizeOfRawData}

        d = {"sections": s}
        return d
    
# ---------------------------- write to json file ---------------------------- #

    def write_to_json_file(self):
        with open(f"{self.cwd}\\results\\{self.d['hashes']['md5']}_log.json", 'w') as json_f:
            json.dump(self.d, json_f, sort_keys=True, indent=4, separators=(',', ': '))
            
        logging.info(f"Created log at {os.curdir}\\results\\{self.d['hashes']['md5']}_log.json")

# --------------------------- get import table hash -------------------------- #
# * https://malwology.com/2018/08/24/python-for-malware-analysis-getting-started/

    def get_import_table_hash(self):
        x = {"import_table_hash_sha256": self.pe_file.get_imphash()}
        return x
            
# -------------------------- find strings in binary -------------------------- #

    def get_strings(self):
        x = []
        with open(self.malware_path, "rb") as f_binary:
            x = re.findall(b"([a-zA-Z]{4,})", f_binary.read())
            
        d = {"strings": [v.decode("utf-8") for v in x]}
        return d

    def __init__(self):
        
        self.cwd = os.path.dirname(os.path.abspath(__file__))
        self.zip_dir_path = f"{self.cwd}\\malware\\"
        self.yara_dir = f"{self.cwd}\\yara_rules"
        self.urls = [
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/crypto/crypto_signatures.yar",
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/packer.yar",
            "https://raw.githubusercontent.com/Yara-Rules/rules/master/packers/peid.yar"
        ]
        self.packers = [
            'AHTeam', 'Armadillo', 'Stelth', 'yodas', 'ASProtect', 'ACProtect', 'PEnguinCrypt',
            'UPX', 'Safeguard', 'VMProtect', 'Vprotect', 'WinLicense', 'Themida', 'WinZip', 'WWPACK',
            'Y0da', 'Pepack', 'Upack', 'TSULoader'
            'SVKP', 'Simple', 'StarForce', 'SeauSFX', 'RPCrypt', 'Ramnit',
            'RLPack', 'ProCrypt', 'Petite', 'PEShield', 'Perplex',
            'PELock', 'PECompact', 'PEBundle', 'RLPack', 'NsPack', 'Neolite',
            'Mpress', 'MEW', 'MaskPE', 'ImpRec', 'kkrunchy', 'Gentee', 'FSG', 'Epack',
            'DAStub', 'Crunch', 'CCG', 'Boomerang', 'ASPAck', 'Obsidium', 'Ciphator',
            'Phoenix', 'Thoreador', 'QinYingShieldLicense', 'Stones', 'CrypKey', 'VPacker',
            'Turbo', 'codeCrypter', 'Trap', 'beria', 'YZPack', 'crypt', 'crypt', 'pack',
            'protect', 'tect'
        ]
        
        # start async task to download the latest yara rules
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.start_async_task())
        
        # repeat for every zip in the directory
        for zip in os.listdir(self.zip_dir_path):
            if zip.lower().endswith(".zip") and os.path.isfile(f"{self.zip_dir_path}\\{zip}"):
                self.d = {}
                with self.make_temp_directory() as temp_dir:
                    self.malware_path = self.unzip_file(temp_dir, f"{self.zip_dir_path}/{zip}")
                    self.pe_file = pefile.PE(self.malware_path, fast_load=False)
                    self.d.update(self.get_exported_symbols())
                    self.d.update(self.get_file_hash())
                    self.d.update(self.get_file_size())
                    self.d.update(self.get_imported_symbols())
                    self.d.update(self.get_magic_bytes())
                    self.d.update(self.get_section_addresses())
                    self.d.update(self.get_import_table_hash())
                    
                    if SCAN_STRINGS:
                        self.d.update(self.get_strings())
                    
                    self.load_yara_rules()
                
                # write outputs to a file
                self.write_to_json_file()


if __name__ == "__main__":
    handlers = [
        logging.FileHandler(filename="trace.log", encoding="utf-8", mode="w+"),
        logging.StreamHandler()
    ]

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', handlers=handlers)
    startrat = StatRat()