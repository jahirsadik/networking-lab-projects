import argparse
import codecs
import socket
import ssl
import webbrowser
import re
import os.path
import hashlib
import pickle

# Constants
PORT = 80
WRONG_PROTOCOL = -999
RESPONSE_ERROR = -998
USER_AGENT = 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ' \
             'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99' \
             ' Safari/537.36 Edg/97.0.1072.76'
RFC_2616_REGEX = re.compile(r'(.+?):(.+)')
PARAMS = {
    'Connection': 'close',
}


def main():
    # Parsing user argument url from command line
    parser = argparse.ArgumentParser(description='Parse url from arguments')
    parser.add_argument('url', type=str, help='url for an http website')
    args = parser.parse_args()
    input_url = args.url
    print("Entered HTTP url: " + input_url)
    try:
        domain_and_path_name = '/'.join(parse_url_fields(input_url)[1:]).lower()
    except IndexError as e:
        print("Couldn't process domain and path names.", end='')
        print("Make sure you've entered the url in correct format. Error: " + str(e))
        domain_and_path_name = ''
    # filenames are hash output of their domain & path info (unique)
    hash_code = hashlib.md5(domain_and_path_name.encode())
    file_name = hash_code
    # Create a cached files folder, if not already created
    if not os.path.exists('.\\cache'):
        os.makedirs('.\\cache')
    # Saves cached file info in pickle, a local storage module
    if os.path.exists('.\\cache\\cacheInfo.pkl'):
        infile = open('.\\cache\\cacheInfo.pkl', 'rb')
        cache_info_dict = pickle.load(infile)
        infile.close()
    else:
        infile = open('.\\cache\\cacheInfo.pkl', 'wb')
        cache_info_dict = {}
        pickle.dump(cache_info_dict, infile)
        infile.close()
    # Print Local Saved Cache File Name and Last-Modified Dates
    print("Local Cache Information: " + str(cache_info_dict))
    # Check if this file exists in cache storage
    file_exists = os.path.exists(f'.\\cache\\{file_name.hexdigest()}.html')
    if file_exists:
        inp_protocol, inp_host, inp_path = parse_url_fields(input_url)
        print("Input protocol:" + inp_protocol)
        if inp_protocol == 'http':
            # First check if the link is reachable
            header = fetch('HEAD', inp_host, inp_path)
            status_code, last_modified_date = fetch_info(header)
            if status_code == '200':
                # Conditional GET using saved last-modified value, if it exists
                if str(file_name.hexdigest()) in cache_info_dict:
                    saved_modified_date = cache_info_dict[str(file_name.hexdigest())]
                    response_object = fetch('GET', inp_host, inp_path, if_modified_since=saved_modified_date)
                else:
                    response_object = fetch('GET', inp_host, inp_path)
                html_idx = response_object.upper().find('<HTML')
                header_tuple = parse_header(response_object[:html_idx])
                # Code 304 means no need to update, so saved html file is opened
                if header_tuple[0] == '304':
                    print("Link response is already cached in storage!")
                    webbrowser.open(os.path.join("file://", os.path.abspath(f'.\\cache\\{file_name.hexdigest()}.html')))
                else:
                    # Cache the file only if last-modified date is specified
                    if last_modified_date is not None:
                        cache_and_open(cache_info_dict, header_tuple, file_name, response_object, html_idx)
                    # Else, just open it in browser without caching
                    else:
                        webbrowser.open(input_url)
            else:
                print_error(RESPONSE_ERROR, status_code)
        elif inp_protocol == 'https':
            # First check if the link is reachable
            header = fetch('HEAD', inp_host, inp_path, port=443, protocol='https')
            status_code, last_modified_date = fetch_info(header)
            if status_code == '200':
                # Conditional get, using saved modified value, if it exists
                if str(file_name.hexdigest()) in cache_info_dict:
                    saved_modified_date = cache_info_dict[str(file_name.hexdigest())]
                    response_object = fetch('GET', inp_host, inp_path, port=443, protocol='https',
                                            if_modified_since=saved_modified_date)
                else:
                    response_object = fetch('GET', inp_host, inp_path, protocol='https')
                html_idx = response_object.upper().find('<HTML')
                header_tuple = parse_header(response_object[:html_idx])
                # Code 304 means no need to update, so saved html file is opened
                if header_tuple[0] == '304':
                    print("Link response is already cached in storage!")
                    webbrowser.open(os.path.join("file://", os.path.abspath(f'.\\cache\\{file_name.hexdigest()}.html')))
                else:
                    # Cache the file only if last-modified date is specified
                    if last_modified_date is not None:
                        cache_and_open(cache_info_dict, header_tuple, file_name, response_object, html_idx)
                    # Else, just open it in browser without caching
                    else:
                        webbrowser.open(input_url)
            else:
                print_error(RESPONSE_ERROR, status_code)
        else:
            print_error(WRONG_PROTOCOL, inp_protocol)
    # The file associated with input_url is not present
    else:
        inp_protocol, inp_host, inp_path = parse_url_fields(input_url)
        print("Input protocol:" + inp_protocol)
        if inp_protocol == 'http':
            # First check if the link is reachable
            header = fetch('HEAD', inp_host, inp_path)
            status_code, last_modified_date = fetch_info(header)
            # If status_code == 200, fetch html but Cache only if last-modified is specified
            if status_code == '200':
                response_object = fetch('GET', inp_host, inp_path)
                html_idx = response_object.upper().find('<HTML')
                # Cache the file only if last-modified date is specified
                if last_modified_date is not None:
                    header_tuple = parse_header(response_object[:html_idx])
                    cache_and_open(cache_info_dict, header_tuple, file_name, response_object, html_idx)
                # Else, just open it in browser without caching
                else:
                    webbrowser.open(input_url)
            else:
                print_error(RESPONSE_ERROR, status_code)
        elif inp_protocol == 'https':
            # First check if the link is reachable
            header = fetch('HEAD', inp_host, inp_path, protocol='https')
            status_code, last_modified_date = fetch_info(header)
            if status_code == '200':
                response_object = fetch('GET', inp_host, inp_path, protocol='https')
                html_idx = response_object.upper().find('<HTML')
                # Cache the file only if last-modified date is specified
                if last_modified_date is not None:
                    header_tuple = parse_header(response_object[:html_idx])
                    cache_and_open(cache_info_dict, header_tuple, file_name, response_object, html_idx)
                # Else, just open it in browser without caching
                else:
                    webbrowser.open(input_url)
            else:
                print_error(RESPONSE_ERROR, status_code)
        else:
            print_error(WRONG_PROTOCOL, inp_protocol)


# Utility functions
def fetch_info(header):
    if header is None:
        return "Couldn't connect", None
    header_tuple = parse_header(header)
    status_code = header_tuple[0]
    last_modified_date = None
    if 'Last-Modified' in header_tuple[1]:
        last_modified_date = header_tuple[1]["Last-Modified"]
    return status_code, last_modified_date

# parses Protocol, Hostname & Path from a given url
def parse_url_fields(url):
    url = str(url)
    path = ''
    if url.startswith('http'):
        temp_list = url.lower().split("://")
        protocol = temp_list[0]
        rest = temp_list[-1]
        host_and_path = rest.split("/", maxsplit=1)
        host = host_and_path[0]
        if len(host_and_path) > 1:
            path = host_and_path[1]
    elif url.startswith('www'):
        print(f'LINK HAS NO PROTOCOL DEFINED! ASSUMING " + url + " TO BE http://{url} AND TRYING')
        host_and_path = url.split("/", maxsplit=1)
        host = host_and_path[0]
        if len(host_and_path) > 1:
            path = host_and_path[1]
        # TODO Change impl?
        protocol = 'http'
    else:
        print(f'LINK HAS NO PROTOCOL DEFINED! ASSUMING " + url + " TO BE http://{url} AND TRYING')
        host_and_path = url.split("/", maxsplit=1)
        host = host_and_path[0]
        if len(host_and_path) > 1:
            path = host_and_path[1]
        protocol = 'http'
    return protocol.strip(), host.strip(), path.strip()

# Creates a socket for given method, url, path, protocol etc. And returns response str
def fetch(method, url, path, port=None, protocol='http', if_modified_since=''):
    context = None
    if protocol == 'https':
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

    req = ''
    if if_modified_since != '':
        PARAMS['If-Modified-Since'] = str(if_modified_since)
    if protocol == 'http':
        if port is None:
            port = 80
        req = build_request(method, (url, path), params=PARAMS, port=port)
    elif protocol == 'https':
        if port is None:
            port = 443
        req = build_request(method, (url, path), params=PARAMS, port=port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as skt:
            if protocol == 'https':
                skt = context.wrap_socket(skt, server_hostname=url)
            try:
                skt.connect((url, port))
                skt.sendall(req)
                response_binary = b''
                while True:
                    buffer = skt.recv(1024)
                    if not buffer:
                        break
                    response_binary += buffer
                file_str = response_binary.decode(encoding='utf-8')
                return file_str
            except socket.gaierror as e:
                print(e)
                return None
            except socket.error as ge:
                print(ge)
                return None
    except socket.error as e:
        print('Socket creation failed.' + e)
        return None

# parses the header str to return status code & dict of header objects
def parse_header(header):
    if header is None:
        return "Couldn't connect", None
    header_obj = {}
    fields = header.splitlines()
    status_code = fields[0].split(' ')[1]
    for field in fields:
        reg_match = RFC_2616_REGEX.match(field)
        if reg_match:
            k = reg_match.group(1).strip()
            v = reg_match.group(2).strip()
            header_obj[k] = v
    return status_code, header_obj

# build a request for given method, url etc. info
def build_request(method, url_obj, http_ver='1.1', port=80, params=None):
    req = f'{method.upper()} /{url_obj[1]} HTTP/{http_ver}\r\n' \
          f'Host: {url_obj[0]}:{port}\r\n'
    param_str = ''
    for k in params:
        param_str += f'{k}: {params[k]}\r\n'
    param_str = req + param_str + '\r\n'
    return param_str.encode()


# send header_tuple, file_name, object, html_idx
def cache_and_open(cache_info_dict, header_tuple, file_name, response_object, html_idx):
    outfile = open('.\\cache\\cacheInfo.pkl', 'rb+')
    cache_info_dict[str(file_name.hexdigest())] = header_tuple[1]['Last-Modified']
    pickle.dump(cache_info_dict, outfile)
    outfile.close()
    print("Saving on file: " + file_name.hexdigest() + ".html")
    with codecs.open(f".\\cache\\{file_name.hexdigest()}.html", "w", "utf-8-sig") as file:
        file.write(response_object[html_idx:])
        webbrowser.open(os.path.join("file://", os.path.abspath(f'.\\cache\\{file_name.hexdigest()}.html')))

# prints error, given error type, status code, input protocol
def print_error(error_type, status_code='NOT SPECIFIED', inp_protocol='NOT SPECIFIED'):
    if error_type == RESPONSE_ERROR:
        print("NO OBJECT COULD BE FETCHED. ERROR CODE: " + str(status_code))
    elif error_type == WRONG_PROTOCOL:
        print("LINK NOT SUPPORTED. GIVEN PROTOCOL:" + str(inp_protocol))

if __name__ == "__main__":
    main()
