import datetime
import base64
import logging
import argparse
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, utils, padding

chosen_hash = hashes.SHA256()

parser = argparse.ArgumentParser(
    prog='invice-protector', description='A tool used to sign text with digital signatures', epilog='©️ rubeste 2024'
)
parser.add_argument('input', type=str, help='Path to file with contents to sign/veryfy.')
parser.add_argument('-n', '--name', type=str, help='Name for certificate.', required=True)
parser.add_argument('-k', '--key', type=str, help='Path to folder with the key. Default is current directory.')
parser.add_argument('-c', '--crt', type=str, help='Path to folder with the certificate. Default is current directory.')
parser.add_argument('-s', '--signature', type=str, help='The signature to be validated.')
parser.add_argument('-o', '--org', type=str, help='Organization name.')
parser.add_argument('-p', '--pw', type=str, help='A password used by the private key. Can be left empty for no password.')
parser.add_argument('-d', '--debug', action='store_true', help='Verbose logging.')
args = parser.parse_args()

input = Path(args.input)
name = args.name
keyPath = Path(args.key).joinpath('%s.key' % name) if args.key != None else Path('%s.key' % name)
crtPath = Path(args.crt).joinpath('%s.crt' % name) if args.crt != None else Path('%s.crt' % name)
signature = args.signature
verify = args.signature is not None
org = args.org
pw = args.pw
isVerbose = args.debug

if isVerbose:
    logging.basicConfig(level=logging.DEBUG)
else:
    logging.basicConfig(level=logging.INFO)

def genKey():
    _key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return _key

def genCert(name:str, org:str, key:rsa.RSAPrivateKey):
    _subject = _issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org if org != None else name),
        x509.NameAttribute(NameOID.COMMON_NAME, name)
    ])
    _crt = x509.CertificateBuilder().subject_name(
        _subject
    ).issuer_name(
        _issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=730)
    ).add_extension(
        x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
        critical=False
    ).sign(
        key,
        chosen_hash,
        default_backend()
    )
    return _crt

def verifyInvoice(signature:str, data:str, crt:x509.Certificate):
    _decSign = base64.b64decode(signature.encode('utf-8'))
    try:
        crt.public_key().verify(
            signature=_decSign,
            data=hashData(data), 
            padding=padding.PSS(
                mgf=padding.MGF1(chosen_hash),
                salt_length=padding.PSS.MAX_LENGTH
            ), 
            algorithm=utils.Prehashed(chosen_hash)
        )
    except:
        return False
    return True

def hashData(data:str):
    hasher = hashes.Hash(chosen_hash)
    hasher.update(data.encode('utf-8'))
    return hasher.finalize()

def signInvoice(data:str, key:rsa.RSAPrivateKey):
    _signature = key.sign(
        data=hashData(data), 
        padding=padding.PSS(
            mgf=padding.MGF1(chosen_hash),
            salt_length=padding.PSS.MAX_LENGTH
        ), 
        algorithm=utils.Prehashed(chosen_hash)
    )
    return base64.b64encode(_signature).decode('utf-8')

def saveKey(key:rsa.RSAPrivateKey, path:Path, password:str = None):
    with open(path, 'wb') as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8')) if password != None else serialization.NoEncryption()
            )
        )

def saveCrt(crt:x509.Certificate, path:Path):
    with open(path, 'wb') as f:
        f.write(crt.public_bytes(serialization.Encoding.PEM))

def loadKey(path:Path, password:str = None):
    with open(path, 'rb') as f:
        _pemKey = f.read()
    _key = load_pem_private_key(_pemKey, password, default_backend())
    return _key

def loadCrt(path:Path):
    with open(path, 'rb') as f:
        _crtPem = f.read()
    _crt = x509.load_pem_x509_certificate(_crtPem, default_backend())
    return _crt

def getData(dataPath:Path):
    if not dataPath.exists():
        raise FileNotFoundError('Data file does not exist here: %s', dataPath)
    with open(dataPath, 'rt') as f:
        _data = f.read()
    return _data

def signDocument(keyPath:Path, crtPath:Path, name:str, org:str, pw:str, input:Path):
    _key:rsa.RSAPrivateKey
    _crt:x509.Certificate
    if keyPath.exists() and crtPath.exists():
        _key = loadKey(keyPath)
        _crt = loadCrt(crtPath)
    elif keyPath.exists() or crtPath.exists():
        raise FileExistsError('A key or certificate is missing! Please find the missing file or generate a new set.')
    else:
        _key = genKey()
        _crt = genCert(name, org, _key)
        saveKey(_key, keyPath, pw)
        saveCrt(_crt, crtPath)
    return signInvoice(getData(input), _key)

def verifyDocument(crtPath:Path, input:Path, signature:str):
    if not crtPath.exists():
        raise FileNotFoundError('Could not find certificate here: %s', crtPath)
    return verifyInvoice(signature, getData(input), loadCrt(crtPath))

def main():
    if verify:
        try:
            if verifyDocument(crtPath, input, signature):
                logging.info('Validation of the document succeded.')
            else:
                logging.error('Validation of the document failed!')
        except Exception:
            logging.exception('Failed to perform verification.')
    else:
        try:
            _signature = signDocument(keyPath, crtPath, name, org, pw, input)
            logging.info('Created signature:\n%s', _signature)
        except Exception:
            logging.exception('Failed to perform signing.')

if __name__ == "__main__":
    main()