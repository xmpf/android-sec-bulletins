#!/usr/bin/env python3

import os
import csv
import argparse
import requests

from bs4 import BeautifulSoup
from pprint import pprint
from collections import defaultdict

# CONSTANTS
URL = 'https://source.android.com/security/bulletin'

class BulletinEntry(object):
    BASE_URL = 'https://source.android.com'

    def __init__(self, bulletin_url, published_date, patch_level):
        self.bulletin_url = self.BASE_URL + bulletin_url
        self.published_date = published_date
        self.patch_level = patch_level

    def __str__(self):
        out = f'Bulletin URL: {self.bulletin_url}\n'
        out += f'Published date: {self.published_date}\n'
        out += f'Patch Level: {self.patch_level}\n'
        return out

class BulletinEntryDetailed(object):
    pass

def extract_bulletins(html_parser):

    bulletins_table = html_parser.find('table')
    if bulletins_table is None:
        raise Exception("Unable to find bulletins table...")

    bulletin_table_entries = []

    for row in bulletins_table.find_all('tr')[1:]:
        # each row has 4 columns
        columns = row.find_all('td')
        
        try:
            bulletin_url = columns[0].find('a').get('href')
            published_date = columns[2].get_text()
            patch_level = columns[3].get_text().split()

            bulletin_table_entries.append(BulletinEntry(bulletin_url, published_date, patch_level))
        except IndexError:
            pass
    
    return bulletin_table_entries
        
def extract_bulletin_sections(bulletin_entry):
    sess = requests.Session()
    html_page = sess.get(url=bulletin_entry.bulletin_url)
    html_parser = BeautifulSoup(html_page.content, 'html.parser')
    
    print(bulletin_entry)

    table_headers = list(map(lambda x: x.get_text().strip(), html_parser.find_all('h3')))

    n_tables = 0
    sections = defaultdict(list)
    for table in html_parser.find_all('table'):
        
        column_titles = list(map(lambda x: x.get_text().strip(), table.find_all('th')))

        for rows in table.find_all('tr')[1:]:
            entry = []
            n_cols = 0
            for column in rows.find_all('td'):
                entry.append((column_titles[n_cols], column.get_text().strip()))
                n_cols += 1 
            sections[table_headers[n_tables]].append(entry)
        n_tables += 1

    return sections


def main():
    # parser = argparse.ArgumentParser()
    sess = requests.Session()
    html_page = sess.get(url=URL)
    html_parser = BeautifulSoup(html_page.content, 'html.parser')
    
    # entries from main page
    bulletin_table_entries = extract_bulletins(html_parser)

    # sections for each entry
    sections = extract_bulletin_sections(bulletin_table_entries[1])

    pprint(sections)

if __name__ == '__main__':
    main()