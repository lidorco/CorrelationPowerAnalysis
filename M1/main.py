import json
import sys
from statistics import variance, mean

import requests

USER_NAME = 'name'
DIFFICULTY = 1
SERVER_URL = "http://aoi.ise.bgu.ac.il/encrypt?user={user_name}&difficulty={difficulty}/"

NUMBER_OF_TRACE_TO_DOWNLOAD = 100

def get_trace():
    response =  requests.get(SERVER_URL.format(user_name= USER_NAME, difficulty=DIFFICULTY))
    return json.loads(response.content)


def save_to_file(file_name, result):
    with open(file_name, 'w') as f:
        f.write(json.dumps(result).replace('],', '],\n'))


def create_empty_json_file(file_name):
    with open(file_name, 'w') as f:
        f.write('{}')


def main():
    print("file to save trace : {}".format(sys.argv[1]))
    create_empty_json_file(sys.argv[1])
    result = dict()
    while len(result.keys()) < NUMBER_OF_TRACE_TO_DOWNLOAD:
        trace = get_trace()
        result[trace['plaintext']] = trace['leaks']

    save_to_file(sys.argv[1], result)
    print("Mean\tVariance")
    for plain_text, leaks in result.items():
        print("{}\t{}".format(mean(leaks), variance(leaks)))



if __name__ == "__main__":
    main()