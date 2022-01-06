import hashlib
import sys
import requests
import os


def calculate_file_hash(filename):
    '''
       This function calculates hash of a given file
       input parameters :
            filename(string): name of file for which hash needs to be calculated
       return:
            readable_hash(string) of the given file
    '''
    try:

        with open(filename, "rb") as f:
            bytes = f.read()  # read file as bytes
            readable_hash = hashlib.md5(bytes).hexdigest() # Convert hash to a readable string format

    except:
        print("Unable to hash file...")
        sys.exit(0)
    return readable_hash


def retrieve_scan_reports(url, api_key, datatype):
    '''
        This function retrieves scan status and reports either by doing hash lookup
        or fetch analysis using dataid which we get by uploading a file.
        input parameters:
            url(string): we send either hash lookup URL or Fetch analysis URL in this parameter
            api_key(string): unique API KEY
            datatype(string): sending hash or dataid to track which url is being run
        return:
            output_data(dic) : Response from the hash lookup API or fetch analysis API calls

    '''
    headers = {'apikey': api_key}
    try:
        #print(url)
        response = requests.request("GET", url, headers=headers)
        output_data = response.json()
    except requests.exceptions.RequestException as req_err:
        print("Request Error:", req_err)
        sys.exit(0)
    except requests.exceptions.HTTPError as http_err:
        print("Http Error:", http_err)
        sys.exit(0)
    except requests.exceptions.ConnectionError as conn_err:
        print("Connection Error:", conn_err)
        sys.exit(0)
    except requests.exceptions.Timeout as time_err:
        print("Timeout Error:", time_err)
        sys.exit(0)
    except:
        print("Error when scanning  {0}".format(datatype))
        sys.exit(0)

    return output_data


def displayoutput(scanresult, fileName):
    '''
        This function is used to pull the fields we need from the API responses and show in the output
        input parameters:
            scanresult(dic): we send either response from hash lookup API
            or response from Fetch analysis API in this parameter
            fileName(string): The name of file you are scanning
    '''
    #print("hashscan output   ", scanresult)
    print("-------------------------------------")
    print("OUTPUT: ")
    print("filename: ", fileName)
    print("overall_status: {}".format(scanresult['scan_results']['scan_all_result_a']))

    for key, value in scanresult['scan_results']['scan_details'].items():
        print("\nengine: {}".format(key))
        print("thread_found: {}".format(value['threat_found'] if value['threat_found'] else 'clean'))
        print("scan_result: {}".format(value['scan_result_i']))
        print("def_time: {}".format(value['def_time']))


def uploadFile(apikey, file):
    '''
        This function uploads a file using POST file API . It supports http multipart and binary uploads.
        input:
            apikey(string): unique API KEY
            file: file to be scanned
            You can pass many other parameters to include in the API POST , using only the required fields here.
        return:
            post_response['data_id'](string): response contains dataid, rest_ip, status, in_queue, queue_priority
            returning only dataid
        '''

    file_api_url = "https://api.metadefender.com/v4/file"
    headers = {'apikey': apikey, 'Content-Type': "application/octet-stream"}
    try:
        # print("Scanning the file...")
        response = requests.request("POST", file_api_url, headers=headers, data=file)
        #print(response.text)
        post_response = response.json()
    except requests.exceptions.RequestException as req_err:
        print("Request Error:", req_err)
        sys.exit(0)
    except requests.exceptions.HTTPError as http_err:
        print("Http Error:", http_err)
        sys.exit(0)
    except requests.exceptions.ConnectionError as conn_err:
        print("Connection Error:", conn_err)
        sys.exit(0)
    except requests.exceptions.Timeout as time_err:
        print("Timeout Error:", time_err)
        sys.exit(0)
    except:
        print("Unable to scan file.")
        sys.exit(0)
    # print("Scanning completed")
    return post_response['data_id']


if __name__ == '__main__':

    wd = os.getcwd()
    print("Your working directory is : " + wd)
    print("Place the file you want to upload in your working directory")


    fileName = input("Enter the name of file you want to upload: ")
    apikey = input("Enter your API Key: ")

    # 1. Calculate the hash of a given file

    file_hash = calculate_file_hash(fileName)
    print(file_hash)

    # 2. Perform hash lookup to see if there are previously cached results for the file

    hash_api_url = "https://api.metadefender.com/v4/hash/" + file_hash  # Appended the calculated hash to the api url
    hashscanresult = retrieve_scan_reports(url=hash_api_url, api_key=apikey, datatype="hash")


    # 3. If results are found, skip to step 6

    if 'error' not in hashscanresult.keys():
        displayoutput(hashscanresult, fileName)
        sys.exit(0)

    # 4. If results are not found, upload the file and receive a "data_id"

    else:
        if ("not found" in hashscanresult['error']['messages'][0]):
            print("No cached results found uploading the file ------")
            with open(fileName, 'rb') as f:
                file = f.read()
                data_id = uploadFile(apikey, file)
                #print(data_id)
        else:
             print("Error while performing hash lookup")
             sys.exit(0)


    # 5. Repeatedly pull on the "data_id" to retrieve results

    dataId_api_url = "https://api.metadefender.com/v4/file/" + data_id
    uploadScanresult = retrieve_scan_reports(url=dataId_api_url, api_key=apikey, datatype="dataId")
    #print('FileUploadscanresult -=====- ', uploadScanresult)
    while uploadScanresult['scan_results']['progress_percentage'] != 100:
        uploadScanresult = retrieve_scan_reports(url=dataId_api_url, api_key=apikey, datatype="dataId")
        #print('hashscanresult inside -=====- ', uploadScanresult)

    # 6. Display results in Required format
    displayoutput(uploadScanresult, fileName)
