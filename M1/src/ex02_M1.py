import json
import sys

import numpy as np
import requests

USER_NAME = 'test'
DIFFICULTY = 1
SERVER_URL = "http://aoi.ise.bgu.ac.il/encrypt?user={user_name}&difficulty={difficulty}"

NUMBER_OF_TRACE_TO_DOWNLOAD = 2000


def get_trace():
    response =  requests.get(SERVER_URL.format(user_name= USER_NAME, difficulty=DIFFICULTY))
    return json.loads(response.content)


def append_to_file(file_name, trace):
    with open(file_name, 'a') as f:
        f.write("{}\n".format(trace).replace("'", '"'))


def main():
    out_file = sys.argv[1]
    result = dict()

    while len(result.keys()) < NUMBER_OF_TRACE_TO_DOWNLOAD:
        trace = get_trace()
        result[trace['plaintext']] = trace['leaks']
        append_to_file(out_file, trace)

    print("Mean\tVariance")

    amount_of_samples_per_trace = len(result[list(result.keys())[0]])
    for index in range(amount_of_samples_per_trace):
        samples = np.array([ result[key][index] for key in result.keys()])
        print("%.2f\t%.2f" % (samples.mean(axis=0), samples.var(axis=0)))


if __name__ == "__main__":
    main()
