from struct import pack
from urllib import response
import requests
from requests.exceptions import HTTPError
import json
import time

FILE_NAME = 'packages2.list'
DPKG_CMD = "sudo dpkg-query -W -f='cpe:2.3:a:*:${Package}:version\n"
API_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0?'
cpes_parameters = {
    'addOns': 'cves',
    'apiKey': '7d7117de-3f10-45ff-967f-5fbd20d57584',
    'cpeMatchString': ''
}

cpes_parameters_no_key = {
    'addOns': 'cves',
    'cpeMatchString': ''
}


def get_packages():
    packages_list = []
    c1 = '-'
    c2 = '+'
    with open(FILE_NAME) as file:
        for line in file:
            package = line.rstrip()
            package = package[:package.rfind(c1)]
            package = package[:package.rfind(c2)]
            packages_list.append(package)
    return packages_list

def get_cpe(cpe_name):
    cpes_results = {}
    cpes_parameters['cpeMatchString'] = cpe_name
    try:
        response = requests.get(API_URL, params=cpes_parameters)
        # If the response was successful, no Exception will be raised
        response.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
        print(f'Other error occurred: {err}')  # Python 3.6
    else:
        print(f'{cpe_name} - Response Success!')
    cpes_results[cpe_name] = response.json()

    return cpes_results

def get_cpes(cpe_names):
    cpes_results = {}
    count = 1
    for cpe_name in cpe_names:
        cpes_parameters_no_key['cpeMatchString'] = cpe_name
        try:
            response = requests.get(API_URL, params=cpes_parameters_no_key)
            # If the response was successful, no Exception will be raised
            response.raise_for_status()
        except HTTPError as http_err:
            print(f'HTTP error occurred: {http_err}')  # Python 3.6
        except Exception as err:
            print(f'Other error occurred: {err}')  # Python 3.6
        else:
            print(f'{count} - {cpe_name} - Response Success!')
            count += 1
        cpes_results[cpe_name] = response.json()
    return cpes_results

if __name__ == '__main__':
    # Measure program start time
    begin = time.time()
    
    # Parse packages from input file
    packages_list = get_packages()
    print(f'Number of CPE Names: {len(packages_list)}')

    # result = get_cpe('cpe:2.3:a:*:accountsservice:0.6.45')
    result = get_cpes(packages_list)

    # Write results to file
    with open('cpes_results.json', 'w') as convert_file:
     convert_file.write(json.dumps(result, indent=4))

    # Print results
    # print(json.dumps(result, indent=4))

    # Total time taken
    end = time.time()
    print(f"Total runtime of the program is {end - begin}")

    


