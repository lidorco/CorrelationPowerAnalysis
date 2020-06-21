import json
import numpy as np
import requests

USER_NAME = 'test'
DIFFICULTY = 1
VERIFY_URL = "http://aoi.ise.bgu.ac.il/verify?user={user_name}&difficulty={difficulty}&key={key}"
SERVER_URL = "http://aoi.ise.bgu.ac.il/encrypt?user={user_name}&difficulty={difficulty}"

HW = [bin(n).count("1") for n in range(0,256)]

AES_SBOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]


def verify(key):
    response = requests.get(VERIFY_URL.format(user_name=USER_NAME, difficulty=DIFFICULTY, key=key))
    if response.content == b'0':
        return False
    elif response.content == b'1':
        return True
    else:
        raise Exception("verify error")

def pearson_correlation_coefficient(list1, list2):
    return np.corrcoef(list1, list2)[0, 1]


def get_samples_from_file(filename='.\src\\traces.txt'):
    plaintext = []
    traces = []
    with open(filename, 'r') as f:
        data = f.read()
    for line in data.splitlines():
        l = json.loads(line)
        plaintext.append(l["plaintext"])
        traces.append(l["leaks"])
    return plaintext, traces


def numpy_samples():
    pt, traces = get_samples_from_file()

    new_pt = []
    for plaintext in pt:
        plaintext_list = []
        for i in range(int(len(pt[0]) / 2)):
            plaintext_list.append(eval('0x' + plaintext[i * 2:i * 2 + 2]))
        new_pt.append(plaintext_list)

    pt = np.asarray(new_pt)
    traces = np.asarray(traces)
    return pt, traces


def aes_xor_and_sbox(plain, key):
    return AES_SBOX[plain ^ key]


def get_top_n_max(matrix, n=4):
    matrix = abs(matrix)

    flat = matrix.flatten()
    flat.sort()

    for i in range(1, 1 + n):
        indexes = np.where(matrix == flat[-1 * i])
        print(f"   {i}th max is {flat[-1 * i]} in row {indexes[0]} and column {indexes[1]}")

    return int(np.where(matrix == flat[-1])[1])


def calculate_key(plain_text, traces):
    number_of_traces = np.shape(traces)[0]
    samples_in_trace = np.shape(traces)[1]

    result_key = [0] * 16

    for key_index in range(0, 16):

        # Calculate hypothesis matrix
        hypothesis_matrix = np.zeros((number_of_traces, 256)) # Should contains hypothetical power values
        for key_byte_guess in range(0, 256):

            for trace_index in range(0, number_of_traces):
                hypothesis_matrix[trace_index][key_byte_guess] = HW[aes_xor_and_sbox(plain_text[trace_index][key_index], key_byte_guess)]

        # Calculate correlation values
        correlation_matrix = np.zeros((samples_in_trace, 256))
        for key_byte_guess in range(0, 256):
            hypothesis_vector = hypothesis_matrix[:,key_byte_guess]

            for trace_index in range(0, samples_in_trace):
                trace_column = traces[:, trace_index]
                correlation = pearson_correlation_coefficient(trace_column, hypothesis_vector)
                correlation_matrix[trace_index][key_byte_guess] = correlation


        result_key[key_index] = get_top_n_max(correlation_matrix, 6)
        print(f'key in index {key_index} is {result_key[key_index]}')


    print("Key Guess: ")
    key = ''.join([hex(i)[2:] if len(hex(i)[2:]) == 2 else ('0' + hex(i)[2:]) for i in result_key])
    print(key)

    if verify(key):
        print(f"Found key {key} !!!")
        pass
    else:
        print(f"failed")

    return result_key


def brute_force():
    from M1.src.ex02_M1 import get_trace
    amount = 100
    while True:

        plaintext = []
        leaks = []
        current = 0
        while current < amount:
            result = get_trace()
            plaintext.append(result['plaintext'])
            leaks.append(result['leaks'])
            current += 1


        pt = np.asarray(plaintext)
        traces = np.asarray(traces)

        calculate_key(pt, traces)

def get_trace():
    response = requests.get(SERVER_URL.format(user_name=USER_NAME, difficulty=DIFFICULTY))
    result =  json.loads(response.content)

    plaintext_list = []
    for i in range(int(len(result['plaintext']) / 2)):
        plaintext_list.append(eval('0x' + result['plaintext'][i * 2:i * 2 + 2]))

    return plaintext_list, result['leaks']


def check_all_keys_options(keys):
    bytes_per_index = dict()

    for index in range(16):
        bytes = set()
        for key in keys:
            bytes.add(key[index])

        bytes_per_index[index] = dict()

        for byte in list(bytes):
            count = 0
            for key in keys:
                if key[index] == byte:
                    count += 1

            bytes_per_index[index][byte] = count

    print("keys statistics is ")
    for index in bytes_per_index.keys():
        print(f"index {index} values are ")
        for byte in bytes_per_index[index].keys():
            print(f"    {byte} appers {bytes_per_index[index][byte]} times")



def save_all(plain_texts, traces):
    file_name = "good_traces.txt"

    for i in range(len(plain_texts)):
        line = dict()
        line['plaintext'] = "".join([hex(x)[2:] if len(hex(x)[2:]) == 2 else '0'+hex(x)[2:] for x in plain_texts[i]])
        line['leaks'] = list(traces[i])
        l = json.dumps(line) + '\n'
        with open(file_name, 'a') as h:
            h.write(l)

    pass

def main():
    plain_texts, traces = numpy_samples()

    keys = []
    while True:
        optional_key = calculate_key(plain_texts, traces)
        keys.append(optional_key)

        k = ''.join([hex(i)[2:] if len(hex(i)[2:]) == 2 else ('0' + hex(i)[2:]) for i in optional_key])
        if verify(k):
            print("WORKKKKKKK!!!!")
            print(k)
            save_all(plain_texts, traces)
            break

        if len(keys) > 1:
            check_all_keys_options(keys)

        print("increasing samples:")
        for _ in range(100):
            plain_text, trace = get_trace()
            plain_texts = np.append(plain_texts, [plain_text], axis=0)
            traces = np.append(traces, [trace], axis=0)

        print(f"data is : plain text is {len(plain_texts)}  traces is {len(traces)}")




if __name__ == "__main__":
    main()

