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

import collections

from core.vtg.emg.common import model_comment, get_necessary_conf_property, get_conf_property
from core.vtg.emg.common.c import Function
from core.vtg.emg.common.c.types import import_declaration
from core.vtg.emg.common.process import Process, Condition
from core.vtg.emg.processGenerator.linuxInsmod.tarjan import calculate_load_order


def generate_processes(emg, source, processes, conf):
    """
    This generator generates processes for verifying Linux kernel modules. It generates the main process which calls
    module and kernel initialization functions and then modules exit functions.

    :param emg: EMG Plugin object.
    :param source: Source collection object.
    :param processes: ProcessCollection object.
    :param conf: Configuration dictionary of this generator.
    :return: None
    """

    # Import Specifications
    emg.logger.info("Generate an entry process on base of source analysis of provided Linux kernel files")
    if processes.entry:
        raise ValueError('Do not expect any main process already attached to the model, reorder EMG generators in '
                         'configuration to generate insmod process')

    emg.logger.info("Determine initialization and exit functions")
    inits, exits, kernel_initializations = __import_inits_exits(emg.logger, conf, emg.abstract_task_desc, source)

    emg.logger.info('Generate initializing scenario')
    insmod = __generate_insmod_process(emg.logger, conf, source, inits, exits, kernel_initializations)
    processes.entry = insmod


def __import_inits_exits(logger, conf, avt, source):
    _inits = collections.OrderedDict()
    _exits = collections.OrderedDict()
    deps = {}
    for module, dep in avt['deps'].items():
        deps[module] = list(dep)
    order = calculate_load_order(logger, deps)
    order_c_files = []
    for module in order:
        for module2 in avt['grps']:
            if module2['id'] != module:
                continue
            order_c_files.extend([file['in file'] for file in module2['Extra CCs']])

    init = source.get_macro(get_necessary_conf_property(conf, 'init'))
    if init:
        parameters = dict()
        for path in init.parameters:
            if len(init.parameters[path]) > 1:
                raise ValueError("Cannot set two initialization functions for a file {!r}".format(path))
            elif len(init.parameters[path]) == 1:
                parameters[path] = init.parameters[path][0][0]

        for module in (m for m in order_c_files if m in parameters):
            _inits[module] = parameters[module]
    elif not get_conf_property(conf, 'kernel'):
        raise ValueError('There is no module initialization function provided')

    exitt = source.get_macro(get_necessary_conf_property(conf, 'exit'))
    if exitt:
        parameters = dict()
        for path in exitt.parameters:
            if len(exitt.parameters[path]) > 1:
                raise KeyError("Cannot set two exit functions for a file {!r}".format(path))
            elif len(exitt.parameters[path]) == 1:
                parameters[path] = exitt.parameters[path][0][0]

        for module in (m for m in reversed(order_c_files) if m in parameters):
            _exits[module] = parameters[module]
    if not exitt and not get_conf_property(conf, 'kernel'):
        logger.warning('There is no module exit function provided')

    kernel_initializations = []
    if get_conf_property(conf, 'kernel'):
        if get_necessary_conf_property(conf, "add functions as initialization"):
            extra = get_necessary_conf_property(conf, "add functions as initialization")
        else:
            extra = dict()

        for name in get_necessary_conf_property(conf, 'kernel_initialization'):
            mc = source.get_macro(name)

            same_list = []
            if mc:
                for module in (m for m in order_c_files if m in mc.parameters):
                    for call in mc.parameters[module]:
                        same_list.append((module, call[0]))
            if name in extra:
                for func in (source.get_source_function(f) for f in extra[name] if source.get_source_function(f)):
                    if func.definition_file:
                        file = func.definition_file
                    elif len(func.declaration_files) > 0:
                        file = list(func.declaration_files)[0]
                    else:
                        file = None

                    if file:
                        same_list.append((file, func.name))
                    else:
                        logger.warning("Cannot find file to place alias for {!r}".format(func.name))
            if len(same_list) > 0:
                kernel_initializations.append((name, same_list))

    inits = [(module, _inits[module]) for module in _inits]
    exits = [(module, _exits[module]) for module in _exits]
    return inits, exits, kernel_initializations


def __generate_insmod_process(logger, conf, source, inits, exits, kernel_initializations):
    logger.info("Generate artificial process description to call Init and Exit module functions 'insmod'")
    ep = Process("insmod")
    ep.category = 'linux'
    ep.comment = "Initialize or exit module."
    ep.self_parallelism = False
    ep.identifier = 0
    ep.process = ''
    ep.pretty_id = 'linux/initialization'

    if len(kernel_initializations) > 0:
        body = [
            "int ret;"
        ]
        label_name = 'ldv_kernel_initialization_exit'

        # Generate kernel initializations
        for name, calls in kernel_initializations:
            for filename, func_name in calls:
                func = source.get_source_function(func_name, filename)
                if func:
                    retval = False if func.declaration.return_value.identifier == 'void' else True
                else:
                    raise RuntimeError("Cannot resolve function {!r} in file {!r}".format(name, filename))
                new_name = __generate_alias(ep, func_name, filename, retval)
                statements = [
                    model_comment('callback', func_name, {'call': "{}();".format(func_name)}),
                ]
                if retval:
                    statements.extend([
                        "ret = {}();".format(new_name),
                        "ret = ldv_post_init(ret);",
                        "if (ret)",
                        "\tgoto {};".format(label_name)
                    ])
                else:
                    statements.append("{}();".format(new_name))

                body.extend(statements)
        body.extend([
            "{}:".format(label_name),
            "return ret;"
        ])
        func = Function('ldv_kernel_init', 'int ldv_kernel_init(void)')
        func.body = body
        addon = func.define()
        ep.add_definition('environment model', 'ldv_kernel_init', addon)
        ki_subprocess = ep.add_condition('kernel_initialization', [], ["%ret% = ldv_kernel_init();"],
                                         'Kernel initialization stage.')
        ki_subprocess.trace_relevant = True
        ki_success = ep.add_condition('kerninit_success', ["%ret% == 0"], [], "Kernel initialization is successful.")
        ki_failed = ep.add_condition('kerninit_failed', ["%ret% != 0"], [], "Kernel initialization is unsuccessful.")
    if len(inits) > 0:
        # Generate init subprocess
        for filename, init_name in inits:
            new_name = __generate_alias(ep, init_name, filename, True)
            init_subprocess = Condition(init_name)
            init_subprocess.comment = 'Initialize the module after insmod with {!r} function.'.format(init_name)
            init_subprocess.statements = [
                model_comment('callback', init_name, {'call': "{}();".format(init_name)}),
                "%ret% = {}();".format(new_name),
                "%ret% = ldv_post_init(%ret%);"
            ]
            init_subprocess.trace_relevant = True
            logger.debug("Found init function {}".format(init_name))
            ep.actions[init_subprocess.name] = init_subprocess

    # Add ret label
    ep.add_label('ret', import_declaration("int label"))

    # Generate exit subprocess
    if len(exits) == 0:
        logger.debug("There is no exit function found")
    else:
        for filename, exit_name in exits:
            new_name = __generate_alias(ep, exit_name, filename, False)
            exit_subprocess = Condition(exit_name)
            exit_subprocess.comment = 'Exit the module before its unloading with {!r} function.'.format(exit_name)
            exit_subprocess.statements = [
                model_comment('callback', exit_name, {'call': "{}();".format(exit_name)}),
                "{}();".format(new_name)
            ]
            exit_subprocess.trace_relevant = True
            logger.debug("Found exit function {}".format(exit_name))
            ep.actions[exit_subprocess.name] = exit_subprocess

    # Generate conditions
    success = ep.add_condition('init_success', ["%ret% == 0"], [], "Module has been initialized.")
    ep.actions[success.name] = success
    # Generate else branch
    failed = ep.add_condition('init_failed', ["%ret% != 0"], [], "Failed to initialize the module.")
    ep.actions[failed.name] = failed

    # Add subprocesses finally
    process = ''
    for i, pair in enumerate(inits):
        process += "<{0}>.(<init_failed>".format(pair[1])
        for j, pair2 in enumerate(exits[::-1]):
            if pair2[0] == pair[0]:
                break
        j = 1
        for _, exit_name in exits[:j - 1:-1]:
            process += ".<{}>".format(exit_name)
        process += "|<init_success>."

    for _, exit_name in exits:
        process += "<{}>.".format(exit_name)
    # Remove the last dot
    process = process[:-1]

    process += ")" * len(inits)

    if len(kernel_initializations) > 0 and len(inits) > 0:
        ep.process += "<{}>.(<{}> | <{}>.({}))".format(ki_subprocess.name, ki_failed.name, ki_success.name, process)
    elif len(kernel_initializations) == 0 and len(inits) > 0:
        ep.process += process
    elif len(kernel_initializations) > 0 and len(inits) == 0:
        ep.process += "<{}>.(<{}> | <{}>)".format(ki_subprocess.name, ki_failed.name, ki_success.name, process)
    else:
        raise NotImplementedError("There is no both kernel initilization functions and module initialization functions")
    return ep


def __generate_alias(process, name, file, int_retval=False):
    new_name = "ldv_emg_{}".format(name)
    code = [
        "{}();".format("return {}".format(name) if int_retval else name)
    ]
    # Add definition
    func = Function(new_name,
                    "{}(void)".format("int {}".format(new_name) if int_retval else "void {}".format(new_name)))
    func.body = code
    process.add_definition(file, name, func.define())
    process.add_declaration('environment model', name,
                            'extern {} {}(void);\n'.format("int" if int_retval else "void", new_name))

    return new_name
