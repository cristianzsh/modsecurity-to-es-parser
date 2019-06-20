#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import datetime
import json
import os
import re
import shutil
import time
import zipfile
from elasticsearch import Elasticsearch

__author__ = "Cristian Souza <cristianmsbr@gmail.com>"

class ModSecurityParser():
	def __init__(self):
		self.es = Elasticsearch(["http://ip:9200"], http_auth = ("elastic", "password"))
		self.descriptions_file = open("descriptions.txt", "r").readlines()

		self.dir_count = 0
		self.file_count = 0
		self.zip_path = None
		self.backup_path = os.path.expanduser("~") + "/modsec_logs_backup/"

		self.today = datetime.datetime.now().strftime("%Y/%m/%d")

	def send(self, path_to_directory):
		print("[!] Searching for files...")
		self.zip_path = self.backup_path + str(datetime.datetime.now()) + ".zip"

		for (path, dirs, files) in os.walk(path_to_directory):
			self.dir_count += 1

			for file in files:
				file_obj = open(path + "/" + file, "r")
				text = file_obj.read()

				for item in text.split("\n"):
					if ("ModSecurity" in item):
						data = self.parse(item)

						if (data is not None):
							self.send_to_elasticsearch(data)

				print("[*] File {} sent!".format(path + "/" + file))
				file_obj.close()
				self.file_count += 1

		if (self.file_count < 1):
			print("[*] No files to send!")
			return

		print("[!] Files uploaded successfully. Log directories: {}, log files: {}".format(self.dir_count, self.file_count))
		self.dir_count = 0
		self.file_count = 0
		self.make_backup(path_to_directory)

	def parse(self, item):
		items = {}

		line = item.strip()
		split = re.findall("\[.*?\]", line)

		if ("[\\d.:]" in split):
			split.remove("[\\d.:]")

		for item in split:
			item = item.replace("[", "")
			item = item.replace("]", "")

			tag_name = item.split(" ")[0]
			item = re.findall(r'"(.*?)"', item)
			try:
				items[tag_name] = item[0]
			except:
				return None

		for line in self.descriptions_file:
			line = line.split("|")
			if (line[0] in items["file"]):
				items["type"] = line[1]

		items["backup"] = self.zip_path
		items["date"] = self.today

		return json.dumps(items)

	def send_to_elasticsearch(self, data):
		self.es.index(index = "modsecurity_logs", doc_type = "modsecurity", body = data)

	def make_backup(self, path):
		if not os.path.exists(self.backup_path):
			os.makedirs(self.backup_path)

		self.zip_file = zipfile.ZipFile(self.zip_path, "w", zipfile.ZIP_DEFLATED)

		for root, dirs, files in os.walk(path):
			for file in files:
				self.zip_file.write(os.path.join(root, file))

		self.zip_file.close()
		print("[!] Backup done, file saved in: " + self.zip_path)

		file_list = os.listdir(path)
		for file in file_list:
			shutil.rmtree(path + file)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description = "A script to send ModSecurity logs to Elasticsearch")
	parser.add_argument("-d", "--directory", type = str, help = "informs the log directory", required = True)
	args = parser.parse_args()

	modsec_parser = ModSecurityParser()
	while True:
		modsec_parser.send(args.directory)
		time.sleep(10)
