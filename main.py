import os
import re
import sys
import requests
import threading

as_num = ''
country = ''
provider = ''
regex_host = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
regex_num = re.compile(r'^\s?(\d+)')


def get_traceroute(target_host):
    dictionary = {}
    prev_number = ''
    os.system('traceroute -n -w 1 -m 30 {} > traceroute.txt'.format(target_host))
    with open('traceroute.txt', 'r') as f:
        lines = f.read().split('\n')[:-1]
        threads = []
        for line in lines:
            if line.count('*') == 3:
                continue
            host = regex_host.search(line).group()
            try:
                number = regex_num.search(line).group()
                prev_number = number
            except AttributeError:
                number = prev_number + '.'
            t = threading.Thread(target=get_data, args=(host, dictionary, number))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    print_results(dictionary)


def get_data(ip, dictionary, number):
    global as_num, country, provider
    try:
        data = requests.get('https://stat.ripe.net/data/whois/data.json?resource={}'.format(ip))
        as_num = ''
        for i in data.json()['data']['records']:
            for j in i:
                if j['key'] == 'netname' or j['key'] == 'NetName':
                    provider = j['value']
                elif j['key'] == 'country' or j['key'] == 'Country':
                    country = j['value']
                    break
        for i in data.json()['data']['irr_records']:
            for j in i:
                if j['key'] == 'origin':
                    as_num = j['value']
                    break
        dictionary[number] = [ip, as_num, country, provider]
    except NameError:
        print('Sorry, this address is not in the databases')
    except IndexError:
        pass


def print_results(d):
    print('{0:8} {1:13} {2:5} {3:5} {4:20}'.format('num', 'ip', 'as', 'cntr', 'provider'))
    for i in sorted(d.items()):
        print('{0:4} {1:16} {2:7} {3:4} {4:20}'.format(i[0], i[1][0], i[1][1], i[1][2], i[1][3]))


if __name__ == '__main__':
    get_traceroute(sys.argv[1])
