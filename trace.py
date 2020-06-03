import os
import sys
import argparse

from subprocess import Popen, PIPE
from ipwhois import IPWhois, IPDefinedError


class Tracer:
    @staticmethod
    def trace(address) -> enumerate:
        number = 0
        with Popen(["tracert", "-d", "-w", "500", "-4", address], stdout=PIPE, encoding='cp866') as p:
            while True:
                line = p.stdout.readline()
                if not line:
                    break
                ip = Tracer._get_ip4_from_trace_line(line)
                if ip is not None:
                    number += 1
                    AS, country, provider = Tracer.get_as(ip)
                    yield number, ip, AS, country, provider

    @staticmethod
    def _get_ip4_from_trace_line(line_from_tracert: str):
        ip = line_from_tracert.replace(os.linesep, "").strip().split(' ')[-1]

        parts_ip = ip.split('.')
        if len(parts_ip) == 4 and all(map(lambda part: part.isdigit() and 0 <= int(part) <= 255, parts_ip)):
            return ip

        return None

    @staticmethod
    def get_as(ip: str):
        try:
            result = IPWhois(ip).lookup_rdap(asn_methods=['dns', 'whois', 'http'])
            AS = result['asn'] if result['asn'] != 'NA' else 'Unknown'

            network = result['network']
            country = network['country'] if network['country'] else 'Unknown'

            remarks = network['remarks']
            provider = remarks[0]['description'].replace('\n', ' ').strip() if remarks else 'Unknown'
        except IPDefinedError:
            AS = "Unknown"
            country = "Unknown"
            provider = "Unknown"
        return AS, country, provider

    @staticmethod
    def print_data(number: int, ip: str, AS: str, country: str, provider: str, first: bool = False):
        # | № | ip | AS | country | provider |
        pattern = "|{0:3}|{1:16}|{2:8}|{3:8}|{4:15}|"

        if first:
            first_line = pattern.format('№', 'IP', 'AS', 'Country', 'Provider')
            print(first_line)
            print('-' * len(first_line))
        print(pattern.format(number, ip, AS, country, provider))


def trace(arguments):
    print(f'Трассировка до адреса: {arguments.address}')

    first = True
    for data in Tracer.trace(arguments.address):
        Tracer.print_data(*data, first=first)
        first = False

    print('Конец трассировки')


def get_parser() -> argparse.ArgumentParser:
    parser_ = argparse.ArgumentParser(
        description='Программа для трассировки и определения автономных '
                    'систем, через которые проходит путь к указанному IP',
        epilog='Автор: Шимаев Дмитрий КН203'
    )

    parser_.add_argument('-addr', '--address', help='Адрес до которого будет происходить трассировка')
    parser_.set_defaults(function=trace)

    return parser_


if __name__ == "__main__":
    parser = get_parser()
    if len(sys.argv) == 1:
        parser.parse_args(['-h']).function()
    else:
        args = parser.parse_args()
        args.function(args)
