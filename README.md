# invo-protec
A simple Python utility for singing text with a self signed key

## Instalation

1. [Download Python](https://www.python.org/downloads/)
2. [Download Rust](https://www.rust-lang.org/tools/install)
    * You might also need C++ build tools: `https://visualstudio.microsoft.com/visual-cpp-build-tools/`
3. Clone or download and extract the zip of the source code.
4. Go to the source code location with a terminal.
5. Install requirements with the following command: `pip install -r requirements.txt`
6. Install build tools: `pip install wheel setuptools`
7. Run the following command to install the utility: `python setup.py bdist_wheel --universal`
8. Now you can run the command by using `invo-protec -h`

## Usage
In general `invo-protec -h` should be enough. But in case it isn't here is the usage guide.
The `invo-protec` has two features. Signing and Verification.
### Signing
To sign a file you need to run the following: `invo-protec -n NAME /path/to/file/to/sign.txt`

You can add optional arguments like `-p PASSWORD` to add password protection to the private key.
You can also specify with `-k` and `-c` where the key and crt files *will be/are* located.

After the command is ran you will get a base64 encoded signature you can copy for later verification.

### Verification
To verify you will need the following:
* The public key (Certificate) used to sign the document.
* The contents that needs to be verified.
* The signature in base64 encoding.

To verify you need to use the following command: `invo-protec -c /path/to/crt.crt -n NAME_OF_CRT.crt -v "BASE64_ENCODED_SIGNATURE" /path/to/file/to/verify.txt`

To get the crt file you should ask the person that has the crt file to send it to you.