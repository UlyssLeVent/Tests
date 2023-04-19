#!/usr/bin/env python3

import argparse
import base64
import json
import logging
import re
import ssl
import urllib.parse
import urllib.request


class GithubRepository:

	'''Simple class for accessing Github repository

	members:
	- _owner -- an owner of repository
	- _repo  -- a repository

	methods:
	- get_commit -- returns a commit by the commit hash
	- get_content -- returns a file object in repository by the name

	'''

	def __init__(self, owner: str, repository: str):
		self._owner, self._repo = owner, repository

	@staticmethod
	def from_uri(github_uri: str):
		rc = urllib.parse.urlparse(github_uri)
		tokens = rc.path.split('/')
		return GithubRepository(tokens[1], tokens[2])

	def _github_get(self, uri):
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		return urllib.request.urlopen(uri, context=ctx)

	def get_commit(self, commit_hash: str) -> dict:
		uri = f'https://api.github.com/repos/{self._owner}/{self._repo}/commits/{commit_hash}'
		try:
			return json.load(self._github_get(uri))
		except urllib.error.HTTPError:
			logging.error(f'Cannot load commit {commit_hash}')
			exit(65)
		
	def get_content(self, path: str):
		uri = f'https://api.github.com/repos/{self._owner}/{self._repo}/contents/{path}'
		try:
			rc = json.load(self._github_get(uri))
		except urllib.error.HTTPError:
			logging.error(f'Cannot load file {path}')
			exit(65)
		if 'encoding' in rc and rc['encoding'] == 'base64':
			return base64.b64decode(rc['content'])
		return rc['content']

		
class PatchBlocks:

	'''Class for storing patch blocks region information
	__init__ parses patch block to find '@@ -oldS,oldE +newS,newE @@' string and extract
	newS, newE value

	members:
	- _blocks -- a list of pairs (start, end)

	methods:
	- range_exists -- checks if a given range exists in self._blocks

	'''


	_MATCH_PROG = re.compile('@@ -[0-9]+,[0-9]+ \+([0-9]+),([0-9]+) @@')

	def __init__(self, patch: str):
		self._blocks = []
		for block in self._get_blocks(patch):
			m = self._MATCH_PROG.match(block)
			if m:
				self._blocks.append((int(m.group(1)), int(m.group(2))))
			
	def _get_blocks(self, patch):
		i = 0
		new_line = True
		while i+1 < len(patch):
			if new_line:
				if patch[i] == '@' and patch[i+1] == '@':
					j = i+2
					while j+1 < len(patch):
						if patch[j] == '@' and patch[j+1] == '@':
							yield patch[i:j+2]
							i = j+2
							break
						else:
							j += 1
				else:
					i += 1
				new_line = False
			elif patch[i] == '\n':
				new_line = True
				i += 1
			else:
				i += 1

	def range_exists(self, start, end):
		for block in self._blocks:
			if block[0] <= start and end <= block[1]:
				return True
		return False


def snyk_results(snyk_report: dict):
	'''Helper generator to yield only filenames and regions from snyk reports'''

	for run in snyk_report["runs"]:
		for result in run["results"]:
			for location in result["locations"]:
				filename = location["physicalLocation"]["artifactLocation"]['uri']
				start    = location["physicalLocation"]["region"]['startLine']
				end      = location["physicalLocation"]["region"]['endLine']
				yield (filename, (start, end))

			
def main(repository: str,  commit_hash: str, snyk_report:str) -> bool:

	'''Check if a given report created for a specific commit

	Arguments:
	repository -- Github repository URL
	commit_hash -- commit hash
	snyk_report -- name of a snyk report file in repository

	'''

	gh = GithubRepository.from_uri(repository)
	commit = gh.get_commit(commit_hash)

	# 'patch' in file if it's a text file
	commit_files = {file["filename"]: PatchBlocks(file["patch"]) for file in commit["files"] if 'patch' in file}

	snyk_report = json.loads(gh.get_content(args.snyk_report))

	'''
	report is for given commit iff all run results corresponds to a given commit:
	- all filenames in report exist in commit
	- all regions in a file report exist in commit patches 
	'''

	for filename, region in snyk_results(snyk_report):
		if filename in commit_files:
			if not commit_files[filename].range_exists(region[0], region[1]):
				return False
		else:
			return False
	return True


parser = argparse.ArgumentParser(
                    prog='ProgramName',
                    description='Checks the report was created for this specific GitHub repository and specific commit.')
parser.add_argument('-r', '--repository', required=True, help='Github repository, e.g. https://github.com/OWNER/REPO')
parser.add_argument('--snyk-report', required=True, help='path of a skyn report inside repository')
parser.add_argument('--commit-hash', required=True, help='commit hash')
parser.add_argument('-q', '--quiet', help='no output', action='store_true')

args = parser.parse_args()

rc = main(args.repository, args.commit_hash, args.snyk_report)
if not args.quiet:
	print(rc)
exit({True: 0, False: 1}[rc])

