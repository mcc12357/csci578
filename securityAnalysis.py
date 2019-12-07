import sys
from collections import defaultdict
import json

# weights[0] is the weight of keyword in file name
# weights[1] is the weight of keyword in class
weights = [1, 0.5]
threshold = 1
# key: file name, val: set of classes inside this file which contains keyword
fileClass = {}


def readfileNames(inputFile):
    names = []
    with open(inputFile, 'r') as rf:
        names.append(rf.readline().strip())
    return names


types = {"1": "Access Control", "2": "Threat and Risk Assessment"}
# key: security type, value: list of keywords which are used to match
# key: '1' means "Access Control", '2' means "Threat and risk assessment"
matchRef = {'1': {'auth', 'authenticate', 'authenticator', 'authorization', 'authorize',
                  'identity', 'confidential', 'privacy', 'valid', 'validation', 'validity',
                  'account', 'access control', 'certificate', 'certificator', 'privilege'
},
            '2': {'risk', 'threat', 'danger', 'val', 'evaluate', 'evaluator', 'safe', 'safety'
}
            }


# read source code from file name
def readFile(fileName):
    rf = open(fileName, 'r')
    return rf

# write result to a json file for visualization
def writeFile(securityType, outputFile):
    with open(outputFile, 'w') as wf:
        # for key in fileClass:
        #     wf.write('File name is: ' + key + ', classes are: ')
        #     for fclass in fileClass[key]:
        #         wf.write(fclass + ' ')
        #     wf.write('\n')
        jsonNode = {"name": types[securityType], "parent": "null", "children": [{}]}
        fileNode = jsonNode["children"][0]
        for filename in fileClass:
            fileNode["name"] = fileClass[filename]
            fileNode["parent"] = types[securityType]
            fileNode["children"] = [{}]
            classNode = fileNode["children"][0]
            for classname in fileClass[filename]:
                classNode["name"] = classname
                classNode["parent"] = filename
        json.dump(jsonNode, wf)



def process(filename, securityType, file):
    scores = 0
    keywords = matchRef[securityType]
    # contains all related classes
    classSet = set()
    if filename.lower() in keywords:
        # if filename contains keyword, assign weights[0] and add this class to fileClass
        scores += weights[0]
        classSet.add(filename)
    for line in file.readline():
        words = list(line.split())
        classIndex = words.index('class')
        # if this line doesn't contain 'class' or this is the file name, pass this line
        if classIndex == -1 or words[classIndex+1] == filename:
            continue
        className = words[classIndex+1].lower()
        for keyword in keywords:
            # this class contains one keyword
            if className.find(keyword) != -1:
                classSet.add(className)
                scores += weights[1]
                break
        if scores >= threshold:
            fileClass[filename] = classSet


def main():
    inputFile = sys.argv[1]
    outputFile = sys.argv[2]
    securityType = sys.argv[3]
    filenames = readfileNames(inputFile)
    for filename in filenames:
        file = readFile(filename)
        process(filename, securityType, file)
    writeFile(securityType, outputFile)


if __name__ == "__main__":
    main()
