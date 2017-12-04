#
# Copyright (c) 2014-2016 ISPRAS (http://www.ispras.ru)
# Institute for System Programming of the Russian Academy of Sciences
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

from core.vtg.emg.common import get_conf_property, model_comment
from core.vtg.emg.common.process import Receive, Dispatch
from core.vtg.emg.common.signature import Pointer, Primitive


def action_model_comment(action, text, begin=None, callback=False):
    if action:
        type_comment = type(action).__name__.upper()
        if begin is True:
            type_comment += '_BEGIN'
        elif begin is False:
            type_comment += '_END'

        name_comment = action.name.upper()
    else:
        type_comment = 'ARTIFICIAL'
        name_comment = None

    data = {'action': name_comment}
    if callback:
        data['callback'] = True
    return model_comment(type_comment, text, data)


def control_function_comment_begin(function_name, comment, identifier=None):
    data = {'function': function_name}
    if identifier:
        data['thread'] = identifier
    return model_comment('CONTROL_FUNCTION_BEGIN',
                         comment,
                         data)


def control_function_comment_end(function_name, name):
    data = {'function': function_name}
    return model_comment('CONTROL_FUNCTION_END',
                         "End of control function based on process {!r}".format(name),
                         data)


def extract_relevant_automata(automata, automata_peers, peers, sb_type=None):
    """
    Determine which automata can receive signals from the given instance or send signals to it.

    :param automata_peers: Dictionary {'Automaton.identfier string' -> {'states': ['relevant State objects'],
                                                                        'automaton': 'Automaton object'}
    :param peers: List of relevant Process objects: [{'process': 'Process obj',
                                                     'subprocess': 'Receive or Dispatch obj'}]
    :param sb_type: Receive or Dispatch class to choose only those automata that reseive or send signals to the
                    given one
    :return: None, since it modifies the first argument.
    """
    for peer in peers:
        relevant_automata = [automaton for automaton in automata
                             if automaton.process.identifier == peer["process"].identifier]
        for automaton in relevant_automata:
            if automaton.identifier not in automata_peers:
                automata_peers[automaton.identifier] = {
                    "automaton": automaton,
                    "states": set()
                }
            for state in [node for node in automaton.fsa.states
                          if node.action and node.action.name == peer["subprocess"].name]:
                if not sb_type or isinstance(state.action, sb_type):
                    automata_peers[automaton.identifier]["states"].add(state)


def registration_intf_check(analysis, processes, model_processes, invoke):
    """
    Tries to find relevant automata that can receive signals from model processes of those kernel functions which
    can be called whithin the execution of a provided callback.

    :param analysis: ModuleCategoriesSpecification object
    :param model: ProcessModel object.
    :param invoke: Function name string (Expect explicit function name like 'myfunc' or '(& myfunc)').
    :return: Dictionary {'Automaton.identfier string' -> {'states': ['relevant State objects'],
                                                                     'automaton': 'Automaton object'}
    """
    automata_peers = {}

    # todo: it is replacable with simple code analysis
    name = analysis.refined_name(invoke)
    if name:
        # Caclulate relevant models
        if name in analysis.modules_functions:
            # todo: it is replacable with simple code analysis
            relevant_models = analysis.collect_relevant_models(name)

            # Check relevant state machines for each model
            for model in (m.process for m in model_processes if m.process.name in relevant_models):
                signals = [model.actions[name] for name in sorted(model.actions.keys())
                           if (type(model.actions[name]) is Receive or
                               type(model.actions[name]) is Dispatch) and
                           len(model.actions[name].peers) > 0]

                # Get all peers in total
                peers = []
                for signal in signals:
                    peers.extend(signal.peers)

                # Add relevant state machines
                extract_relevant_automata(processes, automata_peers, peers)

    return automata_peers


def choose_file(cmodel, analysis, automaton):
    # todo: this function should be deprecated
    file = automaton.file
    if file:
        return file

    files = set()
    if automaton.process.category == "kernel models":
        # Calls
        function_obj = analysis.get_kernel_function(automaton.process.name)
        files.update(set(function_obj.files_called_at))
        for caller in (c for c in function_obj.functions_called_at):
            # Caller definitions
            files.update(set(analysis.get_modules_function_files(caller)))

    if len(files) == 0:
        return cmodel.entry_file
    else:
        return sorted(list(files))[0]


def initialize_automaton_variables(conf, automaton):
    initializations = []
    for var in automaton.variables():
        if type(var.declaration) is Pointer and get_conf_property(conf, 'allocate external'):
            initializations.append("{} = external_allocated_data();".format(var.name))
        elif type(var.declaration) is Primitive and var.value:
            initializations.append('{} = {};'.format(var.name, var.value))

    if len(initializations) > 0:
        initializations.insert(0, '/* Initialize automaton variables */')
    return initializations


def model_relevant_files(analysis, cmodel, automaton):
    files = set()
    # Add declarations to files with explicit calls
    kf = analysis.get_kernel_function(automaton.process.name)
    files.update(kf.files_called_at)
    # Then check where we added relevant headers that may contain calls potentially
    if kf.header and len(kf.header) > 0:
        for header in (h for h in kf.header if h in cmodel.extra_headers):
            files.update(cmodel.extra_headers[header])
    return files


def add_model_function(analysis, cmodel, automaton, model):
    files = model_relevant_files(analysis, cmodel, automaton)
    for file in files:
        cmodel.add_function_declaration(file, model, extern=True)

__author__ = 'Ilja Zakharov <ilja.zakharov@ispras.ru>'
