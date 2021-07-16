# encryption algorithms

currently there is only the whole AES algorithm in pure Python, and there is a simple file encryption program that uses the AES algorithm.


# Usage of main.py

### Arguments 

* --help or --h | show help banner
* -e or -encrypt | Encrypt mode
* -d or -decrypt | Decrypt mode
* -k or -key | Hex key is need to start
* -f or -file | input file to start
* -s or -save | output file name and location (Optional)



## Examples

**Encryption**
```
main.py -e -k 00112233445566778899AABBCCDDEEFF -f ~/Desktop/normal.txt
```

**Decryption**
```
main.py -d -k 00112233445566778899AABBCCDDEEFF -f ~/Desktop/encrypted.txt
```

**Decryption with output file location**
```
main.py -d -k 00112233445566778899AABBCCDDEEFF -f ~/Desktop/encrypted.txt -s ~/Desktop/decrypted.txt
```
