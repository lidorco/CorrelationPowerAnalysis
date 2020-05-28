import sys
import requests
import json

USER_NAME = 'name'
DIFFICULTY = 1
SERVER_URL = "http://aoi.ise.bgu.ac.il/encrypt?user={user_name}&difficulty={difficulty}/"

NUMBER_OF_TRACE_TO_DOWNLOAD = 10000

def get_trace():
    response =  requests.get(SERVER_URL.format(user_name= USER_NAME, difficulty=DIFFICULTY))
    return json.loads(response.content)


def save_to_file(file_name, plaintext, leaks):
    with open(file_name, 'rb') as f:
        contents = json.load(f)
    contents[plaintext] = leaks
    with open(file_name, 'w') as f:
        f.write(json.dumps(contents).replace('],', '],\n'))


def create_empty_json_file(file_name):
    with open(file_name, 'w') as f:
        f.write('{}')


def main():
    print("file to save trace : {}".format(sys.argv[1]))
    create_empty_json_file(sys.argv[1])

    for _ in range(NUMBER_OF_TRACE_TO_DOWNLOAD):
        trace = get_trace()
        save_to_file(sys.argv[1], trace['plaintext'], trace['leaks'])


if __name__ == "__main__":
    main()