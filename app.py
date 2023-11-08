#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @2023 - weher.net

import shodan
import yaml
import dns.resolver
import sqlite3
import time
from pysnmp.hlapi import getCmd, CommunityData, SnmpEngine, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
from termcolor import cprint

# Function to read configuration from a YAML file
def read_config(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)

# Function to initialize the SQLite database
def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS resolver_cache (
            ip TEXT PRIMARY KEY,
            is_open_resolver BOOLEAN,
            last_checked INTEGER
        )
    ''')
    conn.commit()
    return conn

# Function to check the cache for a given IP
def check_cache(db_conn, ip, cache_expiry):
    cur = db_conn.cursor()
    cur.execute('SELECT is_open_resolver, last_checked FROM resolver_cache WHERE ip = ?', (ip,))
    result = cur.fetchone()
    if result:
        is_open_resolver, last_checked = result
        if time.time() - last_checked < cache_expiry:
            return is_open_resolver
    return None

# Function to update the cache for a given IP
def update_cache(db_conn, ip, is_open_resolver):
    cur = db_conn.cursor()
    cur.execute('''
        INSERT INTO resolver_cache (ip, is_open_resolver, last_checked)
        VALUES (?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            is_open_resolver = excluded.is_open_resolver,
            last_checked = excluded.last_checked
    ''', (ip, is_open_resolver, int(time.time())))
    db_conn.commit()

# Function to check if an IP is an open resolver by trying to resolve a list of domain names
def is_open_resolver(ip, domains, success_threshold):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [ip]
    successful_resolutions = 0

    for domain in domains:
        try:
            answers = resolver.resolve(domain)
            if answers:
                successful_resolutions += 1
        except (dns.resolver.NoAnswer, dns.resolver.Timeout, dns.resolver.NoNameservers):
            continue
        except Exception as e:
            print(f"An error occurred while checking DNS resolver status for {ip}: {e}")

    success_rate = (successful_resolutions / len(domains)) * 100
    return success_rate >= success_threshold

# Function to check if an IP is an open SNMP server
def is_open_snmp(ip, communities):
    for community in communities:
        try:
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                       CommunityData(community, mpModel=0),
                       UdpTransportTarget((ip, 161), timeout=1, retries=0),
                       ContextData(),
                       ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)))
            )

            if errorIndication:
                print(f"Error with {ip} using community {community}: {errorIndication}")
                continue
            elif errorStatus:
                print(f"Error with {ip} using community {community}: {errorStatus.prettyPrint()}")
                continue
            else:
                for varBind in varBinds:
                    if varBind[0].prettyPrint() == '1.3.6.1.2.1.1.5.0':
                        print(f"SNMP open =( on {ip}, sysName: {varBind[1].prettyPrint()}")
                        return True
        except Exception as e:
            print(f"Exception with {ip}: {e}")
    return False

# Function to search Shodan for open DNS resolvers
def find_open_resolvers(api_key, asn_list, domains, success_threshold, db_conn, cache_expiry):
    api = shodan.Shodan(api_key)

    for asn in asn_list:
        print()
        print(f"Searching for open resolvers with recursion enabled in {asn}...")
        print()
        try:
            results = api.search(f"asn:{asn} port:53 'Recursion: enabled'")

            for result in results['matches']:
                ip = result['ip_str']
                cached_result = check_cache(db_conn, ip, cache_expiry)
                if cached_result is not None:
                    if cached_result:
                        cprint(f"🔥 IP: {ip} is an open DNS resolver (cached).", 'red')
                else:
                    is_resolver = is_open_resolver(ip, domains, success_threshold)
                    update_cache(db_conn, ip, is_resolver)
                    if is_resolver:
                        cprint(f"🔥 IP: {ip} is an open DNS resolver.", 'red')

        except shodan.APIError as e:
            print(f"Error: {e}")

# Function to search Shodan for open SNMP servers
def find_open_snmp_servers(api_key, communities, db_conn, cache_expiry):
    api = shodan.Shodan(api_key)

    print()
    print("Searching for open SNMP servers...")
    print()
    
    try:
        results = api.search("port:161 'public'")

        for result in results['matches']:
            ip = result['ip_str']
            cached_result = check_cache(db_conn, ip, cache_expiry)
            if cached_result is not None:
                cprint(f"🔥 SNMP status for IP: {ip} is OPEN.", 'red')
                update_cache(db_conn, ip, True)

# SNMP Library is broken in Python 3.11
#            else:
#                if is_open_snmp(ip, communities):
#                    update_cache(db_conn, ip, True)
#                else:
#                    update_cache(db_conn, ip, False)

    except shodan.APIError as e:
        print(f"Error: {e}")

# Main execution
if __name__ == "__main__":
    config = read_config('config.yaml')
    db_conn = init_db(config['database']['path'])
    cache_expiry = config['cache_expiry']

    # DNS resolver search
    shodan_api_key = config['shodan_api_key']
    asn_list = config['asns']
    domains_to_test = config['domains_to_test']
    success_threshold = config['success_threshold']
    find_open_resolvers(shodan_api_key, asn_list, domains_to_test, success_threshold, db_conn, cache_expiry)

    # SNMP server search
    snmp_communities = config['snmp_communities']
    find_open_snmp_servers(shodan_api_key, snmp_communities, db_conn, cache_expiry)

    db_conn.close()
