#
# Copyright (c) 2018 ISP RAS (http://www.ispras.ru)
# Ivannikov Institute for System Programming of the Russian Academy of Sciences
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import re
import xml.etree.ElementTree as ET

from core.vrp.et.error_trace import ErrorTrace


class ErrorTraceParser:
    WITNESS_NS = {'graphml': 'http://graphml.graphdrawing.org/xmlns'}

    def __init__(self, logger, witness):
        self._logger = logger
        self.default_program_file = None  # default source file
        self.global_program_file = None  # ~CIL file
        self.error_trace = ErrorTrace(logger)
        self._parse_witness(witness)
        self._check_given_files()

    def __check_for_default_file(self, name: str, edge: dict):
        try:
            identifier = self.error_trace.add_file(name)
            last_used_file = identifier
            edge['file'] = last_used_file
            return last_used_file
        except FileNotFoundError:
            # File is missing, warning already was generated, parser should continue its work.
            return None

    def _check_given_files(self):
        last_used_file = None
        for edge in self.error_trace.get_edges():
            if 'file' in edge and edge['file'] is not None:
                last_used_file = edge['file']
            elif self.default_program_file:
                tmp_file = self.__check_for_default_file(self.default_program_file, edge)
                if tmp_file:
                    last_used_file = tmp_file
            elif last_used_file is not None:
                edge['file'] = last_used_file
            elif self.global_program_file:
                tmp_file = self.__check_for_default_file(self.global_program_file, edge)
                if tmp_file:
                    last_used_file = tmp_file
            else:
                self._logger.warning("There is no source file for edge {}".format(edge))

    def __check_file_name(self, name: str):
        if os.path.exists(name):
            return name
        # TODO: workaround for some tools.
        name = re.sub(r'^/tmp/vcloud-\S+/worker/working_dir_[^/]+/', '', name)
        if os.path.exists(name):
            return name
        return None

    def _parse_witness(self, witness):
        self._logger.info('Parse witness {!r}'.format(witness))
        if os.stat(witness).st_size == 0:
            raise ET.ParseError("Witness is empty")
        with open(witness, encoding='utf8') as fp:
            tree = ET.parse(fp)
        root = tree.getroot()
        graph = root.find('graphml:graph', self.WITNESS_NS)
        for data in root.findall('graphml:key', self.WITNESS_NS):
            name = data.attrib.get('attr.name')
            if name == "originFileName" or name == "originfile":
                for def_data in data.findall('graphml:default', self.WITNESS_NS):
                    new_name = self.__check_file_name(def_data.text)
                    if new_name:
                        self.default_program_file = new_name
                        break
        for data in graph.findall('graphml:data', self.WITNESS_NS):
            key = data.attrib.get('key')
            if key == 'programfile':
                new_name = self.__check_file_name(data.text)
                if new_name:
                    self.global_program_file = new_name
            elif key == 'witness-type':
                witness_type = data.text
                if witness_type == 'correctness_witness':
                    self.error_trace.witness_type = 'correctness'
                elif witness_type == 'violation_witness':
                    self.error_trace.witness_type = 'violation'
                else:
                    self._logger.warning("Unsupported witness type: {}".format(witness_type))
            elif key == 'specification':
                automaton = data.text
                for line in automaton.split('\n'):
                    note = None
                    match = re.search(r'ERROR\(\"(.+)"\)', line)
                    if match:
                        note = match.group(1)
                    match = re.search(r'MATCH\s*{\S+\s*=(\S+)\(.*\)}', line)
                    if match:
                        func_name = match.group(1)
                        self.error_trace.add_model_function(func_name, note)
                        continue
                    match = re.search(r'MATCH\s*{(\S+)\(.*\)}', line)
                    if match:
                        func_name = match.group(1)
                        self.error_trace.add_model_function(func_name, note)
                        continue
        self.__parse_witness_data(graph)
        sink_nodes_map = self.__parse_witness_nodes(graph)
        self.__parse_witness_edges(graph, sink_nodes_map)

    def __parse_witness_data(self, graph):
        for data in graph.findall('graphml:data', self.WITNESS_NS):
            if 'klever-attrs' in data.attrib and data.attrib['klever-attrs'] == 'true':
                self.error_trace.add_attr(data.attrib.get('key'), data.text,
                                          True if data.attrib.get('associate', "false") == 'true' else False,
                                          True if data.attrib.get('compare', "false") == 'true' else False)

    def __parse_witness_nodes(self, graph):
        sink_nodes_map = dict()
        unsupported_node_data_keys = dict()
        nodes_number = 0

        for node in graph.findall('graphml:node', self.WITNESS_NS):
            is_sink = False

            for data in node.findall('graphml:data', self.WITNESS_NS):
                data_key = data.attrib.get('key')
                if data_key == 'entry':
                    self.error_trace.add_entry_node_id(node.attrib['id'])
                    self._logger.debug('Parse entry node {!r}'.format(node.attrib['id']))
                elif data_key == 'sink':
                    is_sink = True
                    self._logger.debug('Parse sink node {!r}'.format(node.attrib['id']))
                elif data_key == 'violation':
                    pass
                elif data_key not in unsupported_node_data_keys:
                    self._logger.warning('Node data key {!r} is not supported'.format(data_key))
                    unsupported_node_data_keys[data_key] = None

            # Do not track sink nodes as all other nodes. All edges leading to sink nodes will be excluded as well.
            if is_sink:
                sink_nodes_map[node.attrib['id']] = None
            else:
                nodes_number += 1

        self._logger.debug('Parse {0} nodes and {1} sink nodes'.format(nodes_number, len(sink_nodes_map)))
        return sink_nodes_map

    def __parse_witness_edges(self, graph, sink_nodes_map):
        unsupported_edge_data_keys = dict()

        # Use maps for source files and functions as for nodes. Add artificial map to 0 for default file without
        # explicitly specifying its path.
        # The number of edges leading to sink nodes. Such edges will be completely removed.
        sink_edges_num = 0
        edges_num = 0
        is_source_file = False

        for edge in graph.findall('graphml:edge', self.WITNESS_NS):

            source_node_id = edge.attrib.get('source')
            target_node_id = edge.attrib.get('target')

            if target_node_id in sink_nodes_map:
                sink_edges_num += 1
                continue

            # Update lists of input and output edges for source and target nodes.
            _edge = self.error_trace.add_edge(source_node_id, target_node_id)

            for data in edge.findall('graphml:data', self.WITNESS_NS):
                data_key = data.attrib.get('key')
                if data_key == 'originfile':
                    try:
                        identifier = self.error_trace.add_file(data.text)
                        _edge['file'] = identifier
                    except FileNotFoundError:
                        _edge['file'] = None
                elif data_key == 'startline':
                    _edge['start line'] = int(data.text)
                elif data_key == 'endline':
                    _edge['end line'] = int(data.text)
                elif data_key == 'sourcecode':
                    is_source_file = True
                    _edge['source'] = data.text
                elif data_key == 'enterFunction' or data_key == 'returnFrom' or data_key == 'assumption.scope':
                    self.error_trace.add_function(data.text)
                    if data_key == 'enterFunction':
                        func_id = self.error_trace.resolve_function_id(data.text)
                        _edge['enter'] = func_id
                    elif data_key == 'returnFrom':
                        _edge['return'] = self.error_trace.resolve_function_id(data.text)
                    else:
                        _edge['assumption scope'] = self.error_trace.resolve_function_id(data.text)
                elif data_key == 'control':
                    _edge['condition'] = True
                elif data_key == 'assumption':
                    _edge['assumption'] = data.text
                elif data_key == 'threadId':
                    _edge['thread'] = data.text
                    self.error_trace.add_thread(data.text)
                elif data_key in ('startoffset', 'endoffset'):
                    pass
                elif data_key in ('note', 'warning'):
                    _edge[data_key if data_key == 'note' else 'warn'] = self.error_trace.process_comment(data.text)
                elif data_key not in unsupported_edge_data_keys:
                    self._logger.warning('Edge data key {!r} is not supported'.format(data_key))
                    unsupported_edge_data_keys[data_key] = None

            if "source" not in _edge:
                _edge['source'] = ""
                if 'enter' in _edge:
                    _edge['source'] = self.error_trace.get_func_name(_edge['enter'])
                elif 'return' in _edge:
                    _edge['source'] = 'return'
                elif not is_source_file:
                    if 'assumption' in _edge:
                        _edge['source'] = _edge['assumption']
                    elif 'start line' in _edge:
                        if _edge.get('file'):
                            src_file = self.error_trace.get_file_name(_edge['file'])
                        elif self.global_program_file:
                            src_file = self.global_program_file
                        else:
                            src_file = None
                        if src_file:
                            with open(src_file) as fd:
                                counter = 1
                                for line in fd.readlines():
                                    if counter == _edge['start line']:
                                        line = line.rstrip().lstrip()
                                        _edge['source'] = line
                                        break
                                    counter += 1

            if 'thread' not in _edge:
                _edge['thread'] = "0"
            if 'start line' not in _edge:
                _edge['start line'] = 0

            edges_num += 1

        self._logger.debug('Parse {0} edges and {1} sink edges'.format(edges_num, sink_edges_num))
