#!/usr/bin/python3
# -*- coding: utf-8 -*-


import os
import sys
import re
from datetime import datetime, date
import argparse
import lxml.etree as ET


PARSER = argparse.ArgumentParser(description='Parse Nessus Files')
PARSER.add_argument('-l', '--launch_directory',
                    help="Path to Nessus File Directory", required=True)
PARSER.add_argument('-o', '--report_name',
                    help="Name of report + Extension", required=True)
ARGS = PARSER.parse_args()


TO_BE_PARSED = list()

UNIQUE_HOST = list()

BEGIN_NEW = \
    """<?xml version="1.0" ?>
<NessusClientData_v2>
"""
BEGIN_REPORT = '<Report name="{0}" xmlns:cm="http://www.nessus.org/cm">'.format(
    ARGS.report_name)
END_REPORT = \
    """</Report>
</NessusClientData_v2>"""


def get_attrib_value(currelem, attrib):
    """
        Get element attribute or return emtpy
    """
    if currelem.get(attrib) is not None:
        return currelem.get(attrib)
    return ''


def create_new_report(report_path, context, func, *args, **kwargs):  # pylint: disable=too-many-statements, too-many-locals, too-many-branches, line-too-long
    """
        Paring the nessus file and generating information
    """
    start_tag = None
    for event, elem in context:
        if event == 'start' and elem.tag == 'Policy' and start_tag is None:
            start_tag = elem.tag
            continue
        if event == 'end' and elem.tag == start_tag:
            file = open(report_path, 'ab')
            file.write(ET.tostring(
                elem, pretty_print=True, xml_declaration=False))
            file.close()
            func(elem, *args, **kwargs)
            elem.clear()
            for ancestor in elem.xpath('ancestor-or-self::*'):
                while ancestor.getprevious() is not None:
                    del ancestor.getparent()[0]
            break
    del context


def append_to_report(report_path, initial_context, func, *args, **kwargs):  # pylint: disable=too-many-statements, too-many-locals, too-many-branches, line-too-long
    """
        Paring the nessus file and generating information
    """
    start_tag = None
    for event, elem in initial_context:
        if event == 'start' and elem.tag == 'ReportHost' and start_tag is None:
            start_tag = elem.tag
            continue
        if event == 'end' and elem.tag == start_tag:
            if get_attrib_value(elem, 'name') in UNIQUE_HOST:
                continue
            UNIQUE_HOST.append(get_attrib_value(elem, 'name'))

            file = open(report_path, 'ab')
            file.write(ET.tostring(
                elem, pretty_print=True, xml_declaration=False))
            file.close()
            func(elem, *args, **kwargs)
            elem.clear()
            for ancestor in elem.xpath('ancestor-or-self::*'):
                while ancestor.getprevious() is not None:
                    del ancestor.getparent()[0]
    del initial_context


def begin_parsing():  # pylint: disable=c-extension-no-member
    """
        Provides the initial starting point for validating root tag
        is for a Nessus v2 File. Initiates parsing and then writes to
        the associated workbook sheets.
    """
    initial_report = True
    report_path = os.path.join(ARGS.launch_directory, ARGS.report_name)
    for report in TO_BE_PARSED:
        context = ET.iterparse(report, events=('start', 'end', ))
        context = iter(context)
        event, root = next(context)

        if root.tag in ["NessusClientData_v2"]:
            if initial_report:
                with open(report_path, 'w+') as new_report:
                    new_report.write(BEGIN_NEW)
                    new_report.close()
                create_new_report(report_path, context, lambda elem: None)
                with open(report_path, 'a+') as new_report:
                    new_report.write(BEGIN_REPORT)
                    new_report.close()
                initial_report = False
            context = ET.iterparse(report, events=('start', 'end', ))
            context = iter(context)
            event, root = next(context)
            append_to_report(report_path, context, lambda elem: None)
        del context
    with open(report_path, 'a+') as new_report:
        new_report.write(END_REPORT)
        new_report.close()


if __name__ == "__main__":
    for nessus_report in os.listdir(ARGS.launch_directory):
        if nessus_report.endswith(".nessus") or nessus_report.endswith(".xml"):
            TO_BE_PARSED.append(os.path.join(
                ARGS.launch_directory, nessus_report))
    begin_parsing()
