
#
# Copyright (c) 2019 Nutanix Inc. All rights reserved.
#
# Add gerrit reviewers and give -2 or -1 label based on
# GERRIT_CODEOWNERS file in repo
#

import logging
import re
import subprocess

import argparse
from gerrit_api_util import *
GERRIT_ADMIN_PORT = 29418
GERRIT_ADMIN = "svc.eng.jenkins@nugerrit.ntnxdpro.com"
JENKINS_CR = "jenkins-cr.svc@nugerrit.ntnxdpro.com"
EMAIL_REGEX = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
GERRIT_GROUP = r"^[a-zA-Z0-9_.-]*$"
# Not allow +1 and +2
VALID_FLAGS = ['0', '-1', '-2']


def is_valid_gerrit_group(credentials, recipient):
    group_pattern = re.compile(GERRIT_GROUP)
    if not group_pattern.match(recipient):
        return False

    ret = group_exist(credentials, recipient)
    return ret


def is_valid_recipient(credentials, rec_lst):
    email_pattern = re.compile(EMAIL_REGEX)
    for recipient in rec_lst:
        if not email_pattern.match(recipient) and \
           not is_valid_gerrit_group(credentials, recipient):
            err_msg = ("{} is not a valid email format "
                       "or gerrit group".format(recipient))
            raise Exception(err_msg)


def get_regex_lst(credentials, codeowners_file):
    """
    Generate regex list which contains tuple with regex pattern object
    and corresponding value contains gerrit label and reviewers' email.
    [
        (<_sre.SRE_Pattern object>, '-1',
        ['joseph.chiu@nutanix.com'], 'Require review from Build team')
    ]
    """
    regex_lst = []
    with open(codeowners_file, 'r') as codeowners_f:
        for line in codeowners_f:
            line = line.strip()

            # Skip if line is empty or is commented
            if len(line) == 0 or line[0] == '#':
                continue

            # Allow users to send extra message if this format
            # message<Message Content> is at the end of line

            split_by_message = line.split('message<')
            content_lst = split_by_message[0].strip().split(' ')

            try:
                regex = re.compile(content_lst[0])
            except Exception:
                err_msg = ("'{}' is not a valid python "
                    "regex format".format(content_lst[0]))
                raise Exception(err_msg)

            flag = content_lst[1]
            if flag not in VALID_FLAGS:
                err_msg = ("{} is not a valid review flag "
                    "gerrit".format(flag))
                raise Exception(err_msg )

            mail_list = content_lst[2:]
            is_valid_recipient(credentials, mail_list)

            message = ""
            if len(split_by_message) > 1:
                message = split_by_message[1][:-1]

            regex_lst.append((regex, flag, mail_list, message))
    return regex_lst


def run_cmd(cmd, hidden=False):
    """
    Consume command string and split it as array to
    make it compatible with subprocess.call
    """
    cmd_args = cmd.split(' ')
    if hidden:
        return subprocess.call(cmd_args, stdout=subprocess.PIPE)
    logging.info("Running comamnd '{}'".format(cmd))
    return subprocess.call(cmd_args)


def add_gerrit_reviewers(credentials, change_number, mail_lst):
    """
    Add reviewers by iterating mail loop
    TODO(Joseph): Use Gerrit REST API call
    """
    #for mail in mail_lst:
    add_reviewers(credentials, change_number, mail_lst)


def need_code_review(credentials, patchset_revision, regex, review_flag,
                     mail_lst, message):
    message = ("This patchset changes {0}\n"
               "Need code review from {1}\n"
               "{2}".format(regex.pattern, mail_lst, message))
    update_review(credentials, patchset_revision, message, review_flag)


def handle_code_owners(credentials, codeowners_file, changed_list_file,
                       change_number, patchset_revision):
    """
    Run through changed file list and find out if file paths
    match with regex pattern. If it is, add certain email as
    reviewers and give -2 or -1 label, and only certain
    group of people can remove it
    """
    regex_lst = get_regex_lst(credentials, codeowners_file)

    file_list = []
    with open(changed_list_file, 'r') as changed_file:
        file_list = changed_file.readlines()

    for regex, flag, owners, message in regex_lst:
        if not any(regex.match(file) for file in file_list):
            continue

        logging.info("Send message to {0}, {1}, {2}, {3}".format(
            regex.pattern, flag, owners, message))

        add_gerrit_reviewers(credentials, change_number, owners)
        if flag != '0':
            need_code_review(credentials, patchset_revision, regex, flag,
                             owners, message)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--gerrit-codeowners',
        type=str,
        required=True,
        help='Absolute path of GERRIT_CODEOWNERS file'
    )
    parser.add_argument(
        '--changed-list',
        type=str,
        required=True,
        help=('Path of a file which containing modified '
              'files separated by lines')
    )
    parser.add_argument(
        '--gerrit-change-number',
        type=str,
        required=True,
        help='GERRIT_CHANGE_NUMBER variable from jenkins'
    )
    parser.add_argument(
        '--gerrit-patchset-revision',
        type=str,
        required=True,
        help=("GERRIT_PATCHSET_REVISION variable from jenkins. "
              "It's same as commit hash.")
    )

    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    gerrit_usr, gerrit_pass = JenkinsAgentUtil.FetchGerritCredentials()
    credentials = {'username': gerrit_usr,
                   'password': gerrit_pass}
    handle_code_owners(
        credentials, args.gerrit_codeowners, args.changed_list,
        args.gerrit_change_number, args.gerrit_patchset_revision
    )


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    main()
