##########################IMPORTS############################
import pefile
import binascii
import re
import urllib.request
from arc4 import ARC4

##########################CONSTANTS##########################

#First Payload Settings
RESOURCE_START = 0x60
KEY_START = RESOURCE_START + 0xc
FIRST_KEY_LEN = 0xf

#Second Payload Settings
CRU_STRING_BIN = b"cruloader"
XMM_WORD_SIZE = 16
XOR_KEY_CHAR = 0xc5

#Third Payload Settings
FINAL_PAYLOAD_STRING_LOC = b"redaolurc"
PAYLOAD_XOR_KEY = 0x61

##########################FUNCTIONS##########################

"""
This function accepts a byte sized integers and swaps it

IN num - the byte sized number
OUT - A swapped byte sized number
"""
def swap_int(num):

    """
    The cool thing about rotating a number left 4 times is that it swaps the digits within it
    so ROL(ROL(ROL(ROL(23)))) = 32
    """
    new_hex = f"{num:02x}"
    new_hex = new_hex[1] + new_hex[0]
    return int(new_hex, 16)


"""
This function loads the first stage binary, extracts its payload from the resource section
and then decrypts it and dumps it on disk

OUT key, chipher_text - RC4 key and the encrypted PE
"""
def resource_load():

    
    #Load the PE file into pe
    pe = pefile.PE(r"C:\\Users\\user\\Desktop\\Analysis\\Zero2Auto\\Lesson 3\\Final Test\\First stage\\main_bin.bin")

    section_addr = None

    #Find the resource section
    for section in pe.sections:
        if(".rsrc" in section.Name.decode()):
            section_addr = section
            break


    data = section_addr.get_data()
    print("Physical Location:", hex(section_addr.PointerToRawData))

    #Locate the RC4 Key
    key = data[KEY_START:KEY_START+FIRST_KEY_LEN]

    #Load the cipher text
    cipher_text = data[KEY_START+FIRST_KEY_LEN+1:-1]

    return key, cipher_text

"""
This function extracts the payload URL from the second stage PE, locates the PNG payload and decrypts it
OUT payload_data_decrypted - Decrypted PNG payload
"""
def extract_and_dump_second():

    #Load the PE file into pe
    pe = pefile.PE(r"C:\\Users\\user\\Desktop\\Analysis\\Zero2Auto\\Lesson 3\\Final Test\\Automation\\second_stage.bin")
    section_addr = None

    #Locate the rdata section
    for section in pe.sections:
        if(".rdata" in section.Name.decode()):
            section_addr = section
            break

    print("Physical Location:", hex(section_addr.PointerToRawData))

    data = section_addr.get_data()

    #Locate encrypted website offset by finding "CRULOADER" in string inside PE
    #CRU_STRING_BIN_offset + len(CRU_STRING_BIN) + 3 + XMM_WORD_SIZE * 2 = encrypted string
    string_offset = (data.find(CRU_STRING_BIN)) + len(CRU_STRING_BIN) + 3 + XMM_WORD_SIZE*2

    #Load encrypted website string
    string_encrypted = data[string_offset:string_offset+XMM_WORD_SIZE*2+1]
    string_decrypted = ""

    #For each byte within the encryted string perform decryption
    for byte in string_encrypted:
        byte = swap_int(byte) ^ XOR_KEY_CHAR
        string_decrypted = string_decrypted + chr(byte)

    #Get the URL of the payload PNG file
    with urllib.request.urlopen(string_decrypted) as web_content:
        file_webpage_png = web_content.read().decode('utf-8')

    #Get the contents of the PNG file
    with urllib.request.urlopen(file_webpage_png) as web_content:
        file_content_png_payload = web_content.read()

    #Locate the payload within the PNG file
    payload_offset = file_content_png_payload.find(FINAL_PAYLOAD_STRING_LOC) + len(FINAL_PAYLOAD_STRING_LOC)
    payload_data = file_content_png_payload[payload_offset:-1]

    payload_data_decrypted = b''

    #Decrypt the payload
    for byte in payload_data:
        byte = byte ^ PAYLOAD_XOR_KEY
        payload_data_decrypted = payload_data_decrypted + bytes([byte])

    return payload_data_decrypted


def main():
    key, cipher_text = resource_load()

    print("Decrypting RC4 Encrypted first stage...")
    
    arc4_key = ARC4(key)
    string_decrypt = arc4_key.decrypt(cipher_text)

    print("Loading Second Stage PE")
    with open('second_stage.bin', 'wb') as file_out:
        file_out.write(string_decrypt)

    string_decrypt = extract_and_dump_second()

    print("PNG Payload decrypted! dumping on disk...")

    with open('third_stage.bin', 'wb') as file_out:
        file_out.write(string_decrypt)

    print("Payload dumped! goodbye!")

if __name__ == "__main__":
    main()
