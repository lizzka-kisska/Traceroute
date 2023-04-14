import os
import re
import sys
import requests

as_num = ''
country = ''
provider = ''
regex_host = re.compile(r'(\d+\.\d+\.\d+\.\d+)')
regex_num = re.compile(r'^\s?(\d+)')


def get_traceroute(target_host):
    dictionary = {'num': ['ip', 'as', 'cntr', 'provider']}
    os.system('traceroute -n -w 1 -m 15 {} > traceroute.txt'.format(target_host))
    with open('traceroute.txt', 'r') as f:
        lines = f.read().split('\n')[:-1]
        for line in lines:
            if line.count('*') >= 3:
                continue
            host = regex_host.search(line).group()
            try:
                number = regex_num.search(line).group()
            except AttributeError:
                number = ' '
            get_data(host)
            if as_num:
                dictionary[number] = host, as_num, country, provider
            else:
                dictionary[number] = host, '-', country, provider
    print_results(dictionary)


def get_data(ip):
    global as_num, country, provider
    try:
        data = requests.get('https://stat.ripe.net/data/whois/data.json?resource={}'.format(ip))
        for i in data.json()['data']['records'][0]:
            if i['key'] == 'netname':
                provider = i['value']
            elif i['key'] == 'country':
                country = i['value']
                break
        for j in data.json()['data']['irr_records'][0]:
            if j['key'] == 'origin':
                as_num = j['value']
                break
    except NameError:
        print('Sorry, this address is not in the RIPE database')
    except IndexError:
        as_num = '-'


def print_results(d):
    for num, data in d.items():
        print('{0:3} {1:16} {2:7} {3:4} {4:20}'.format(num, data[0], data[1], data[2], data[3]))


if __name__ == '__main__':
    get_traceroute(sys.argv[1])
