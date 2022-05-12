from time import time
from bitarray import bitarray, frozenbitarray
from heapq import heappush, heappop


def encoding(file_bytes: bytes, dict_cipher: dict) -> bitarray:
    """
    Function to encode original file like file_bytes by dict_cipher and convert it to bitarray
    """
    file_bytes_encode = bitarray()
    for byte in file_bytes: # successively convert original bytes to cipher-code by dict_cipher
        file_bytes_encode += dict_cipher[byte]
    return file_bytes_encode


class Node():
    """
    Class to create node of tree
    """
    def __init__(self, byte = None, freq = None, left = None, right = None):
        self.byte = byte
        self.freq = freq
        self.left = left
        self.right = right
    
    def __lt__(self, node):
        return self.freq < node.freq


def create_root_tree(dict_freq: dict) -> Node:
    """
    Function to create tree by dict_freq of original file. Return root of tree
    """
    heap = []
    for byte, freq in dict_freq.items(): # fill all leafs by data from dict_freq and push them to heap
        leaf = Node(byte, freq)
        heappush(heap, leaf)
    
    while len(heap) > 1: # while we don't reach root we need fetch 2 nodes from the heap and combine them
        left = heappop(heap)
        right = heappop(heap)
        # we combine the nodes to 1 common ancestor and push him to heap
        node = Node(None, left.freq+right.freq, left, right)
        heappush(heap, node)
    
    return heap[0]


def huffman(dict_cipher: dict, node: Node, cipher: bitarray = bitarray()):
    """
    Recursive function to create cipher-code for every byte from root of tree
    """
    if node: # if this node is not None
        if node.byte is not None: # then we are on the leaf and need to add cipher-code for this byte
            dict_cipher[node.byte] = cipher
        else: # then we are on the parent and we need to go to the children: left (0) or right (1)
            huffman(dict_cipher, node.left, cipher + bitarray('0'))
            huffman(dict_cipher, node.right, cipher + bitarray('1'))


def decoding(file_bytes_encode: bytes, dict_cipher: dict) -> list:
    """
    Function to decode encoding file like file_bytes_encode by dict_cipher and convert it to a list of original bytes
    """
    # create new reversed dict from dict_cipher - dict_bytes
    dict_bytes = {frozenbitarray(cipher): byte for byte, cipher in dict_cipher.items()}
    ciphers = set(dict_bytes) # we collect all the ciphers in one set to make it faster to search
    lengths_ciphers = {len(cipher) for cipher in ciphers} # we collect all the len(ciphers) to find faster

    i = 0
    result = []
    while i != len(file_bytes_encode): # start cycle to find cipher-code in bitarray and convert him into orig byte
        for length in lengths_ciphers:
            if (cipher := frozenbitarray(file_bytes_encode[i : i + length])) in ciphers:
                result.append(dict_bytes[cipher])
                i += length
                break
    
    return result

            
def compress(namefile: str):
    """
    Function to compress the file by namefile
    """
    start = time() # start counting time
    with open(namefile, 'rb') as file: # open file by namefile and save bytes from it
        file_bytes = file.read()
    # file bytes looks like:
    # b'\xd0\xbc\xd0\xb0\xd0\xbc\xd0\xb0 \xd0\xbc\xd1\x8b\xd0\xbb\xd0\xb0 \xd1\x80\xd0\xb0\xd0\xbc\xd1\x83'
    
    dict_freq = {} # create a dict of the form {byte: its frequency of occurrence in the file}
    for byte in file_bytes:
        if byte in dict_freq:
            dict_freq[byte] += 1
        else:
            dict_freq[byte] = 1
    # dict_freq looks like:
    # {208: 9, 188: 4, 176: 4, 32: 2, 209: 3, 139: 1, 187: 1, 128: 1, 131: 1}
    
    dict_cipher = {}
    huffman(dict_cipher, create_root_tree(dict_freq)) # create a dict of the form {byte: cipher by huffman}
    # dict_cipher looks like:
    # {188: bitarray('00'), 139: bitarray('0100'), 187: bitarray('0101'), 209: bitarray('011'),
    # 32: bitarray('1000'), 128: bitarray('10010'), 131: bitarray('10011'), 176: bitarray('101'), 208: bitarray('11')}
    
    file_bytes_encode = encoding(file_bytes, dict_cipher) # convert original file to bitarray by dict_cipher
    
    meta = bitarray('000') # create meta information of file. Meta starts from 3 bits - reserved to fill for last byte
    meta += bitarray(format(len(dict_cipher), '09b')[1:]) # append byte with len(dict_cipher) #bytes in original file

    for byte in dict_cipher: # add byte from source file and ciphercode length for each byte as 2 bytes
        meta.frombytes(bytes([byte, len(dict_cipher[byte])]))
        meta.extend(dict_cipher[byte]) # append cipher-code like bitarray
    
    mfbe = meta + file_bytes_encode # append meta to original bitarray file
    fill = mfbe.fill()
    mfbe[:3] = bitarray(format(fill, '03b')) # append information about fill of the last byte
    # file_bytes_encode ~ meta ~ mfbe looks like:
    # bitarray('1100111011100111011000110001101001101011110110000111001011101110001110011')
    
    namefile_zmh = namefile.split('.')[0] + '.zmh' # change extension to .zmh
    with open(namefile_zmh, 'wb') as file_zmh: # save compressed file. Success!
        mfbe.tofile(file_zmh)
    
    print(f'\nThis mode worked during this time(s): {time() - start}')
    print(f'The compressed file was saved with the next name: {namefile_zmh}')


def decompress(namefile_zmh: str, extension: str):
    """
    Function to decompress the file by namefile.zmh and original extension
    """
    start = time()
    with open(namefile_zmh, 'rb') as file_zmh:
        mfbe = bitarray()
        mfbe.fromfile(file_zmh)

    fill = int(mfbe[:3].to01(), 2) # extract the first 3 bits, which store information about the fill of the last byte
    mfbe = mfbe[3 : len(mfbe) - fill] # truncate the source file with respect to the last bits and the first three
    
    len_dict = int.from_bytes(mfbe[:8].tobytes(), 'big') # extract info about len(dict_cipher) from original file 
    if not len_dict:
        len_dict = 256

    i = 8
    dict_cipher = {} # reassembling the dictionary with cipher-codes
    for _ in range(len_dict): # sequentially extract 2 bytes and the number of bits that lies in the second of them
        byte = int.from_bytes(mfbe[i : i + 8].tobytes(), 'big')
        length_cipher = int.from_bytes(mfbe[i + 8 : i + 16].tobytes(), 'big')
        cipher = mfbe[i + 16 : i + 16 + length_cipher]
        dict_cipher[byte] = cipher
        i = i + 16 + length_cipher
    
    
    namefile = namefile_zmh.split('.')[0]
    with open('res_' + namefile + extension, 'wb') as res_file:
        file_bytes_encode = mfbe[i:]
        file_bytes = decoding(file_bytes_encode, dict_cipher) # decompressed file from bitarray by dict_cipher
        res_file.write(bytes(file_bytes))

    print(f'\nThis mode worked during this time(s): {time() - start}')
    print(f'The decompressed file was saved with the next name: res_{namefile + extension}')



mode = input('Enter the mode (c/compress/z/zip or d/decompress/u/unzip or t/test): ')

if mode in {'c', 'compress', 'z', 'zip'}:
    namefile = input('\nEnter the name of the file you want to compress: ')
    compress(namefile)

elif mode in {'d', 'decompress', 'u', 'unzip'}:
    namefile_zmh = input('\nEnter the name of the file you want to decompress (need to .zmh extension): ')
    extension = input('Enter the extension of the file you want to decompress (like .jpeg): ')
    decompress(namefile_zmh, extension)

elif mode in {'t', 'test'}:
    namefile = input('\nEnter the name of the file you want to compress and after decompress: ')
    namefile_zmh = namefile.split('.')[0] + '.zmh'
    extension = '.' + namefile.split('.')[1]

    compress(namefile)
    decompress(namefile_zmh, extension)

    if namefile == namefile_zmh.split('.')[0] + extension:
        with open(namefile, 'rb') as file_1:
            with open('res_' + namefile, 'rb') as file_2:
                print('\nThe sameness of the input file and the resulting:', file_1.read() == file_2.read())

else:
    print('Sorry, incorrect mode')
