# Multiple Error Analysis (MEA) library.
# This library presents functions for processing several error traces,
# including traces parsing, caching, converting and comparison in accordance with MEA theory.


import json
import operator
import re
from io import BytesIO

from django.utils.translation import ugettext as _

from bridge.utils import ArchiveFileContent, BridgeException, file_get_or_create
from bridge.vars import ERROR_TRACE_FILE
from marks.models import ErrorTraceConvertionCache, ConvertedTraces, MarkUnsafe, MarkUnsafeReport
from reports.models import ReportUnsafe

CONVERSION_FUNCTION_CALL_TREE = "call tree"
CONVERSION_FUNCTION_MODEL_FUNCTIONS = "model functions"
CONVERSION_FUNCTION_CONDITIONS = "conditions"
CONVERSION_FUNCTION_ASSIGNMENTS = "assignments"
CONVERSION_FUNCTION_NOTES = "error descriptions"
CONVERSION_FUNCTION_FULL = "full"
CONVERSION_FUNCTIONS = [
    {'name': CONVERSION_FUNCTION_MODEL_FUNCTIONS, 'id': 1,
     'desc': _('Functions call tree, in which each leaf is a model function')},
    {'name': CONVERSION_FUNCTION_CALL_TREE, 'id': 2, 'desc': _('Functions call tree')},
    {'name': CONVERSION_FUNCTION_CONDITIONS, 'id': 3, 'desc': _('Error trace conditions')},
    {'name': CONVERSION_FUNCTION_ASSIGNMENTS, 'id': 4, 'desc': _('Error trace assignments')},
    {'name': CONVERSION_FUNCTION_NOTES, 'id': 5, 'desc': _('Added by the verifier description of error locations')},
    {'name': CONVERSION_FUNCTION_FULL, 'id': 6, 'desc': _('Full error trace')}
]
DEFAULT_CONVERSION_FUNCTION = CONVERSION_FUNCTION_MODEL_FUNCTIONS

COMPARISON_FUNCTION_EQUAL = "equal"
COMPARISON_FUNCTION_INCLUDE = "include"
COMPARISON_FUNCTION_INCLUDE_PARTIAL = "partial include"
COMPARISON_FUNCTIONS = [
    {'name': COMPARISON_FUNCTION_EQUAL, 'id': 1, 'desc': _('Converted error traces are the same')},
    {'name': COMPARISON_FUNCTION_INCLUDE, 'id': 2, 'desc': _('First converted trace is included into the second')},
    {'name': COMPARISON_FUNCTION_INCLUDE_PARTIAL, 'id': 3,
     'desc': _('All elements of the first converted trace are included into the second')}
]
DEFAULT_COMPARISON_FUNCTION = COMPARISON_FUNCTION_EQUAL

ET_FILE_NAME = 'converted-error-trace.json'

CET_OP = "op"
CET_OP_CALL = "CALL"
CET_OP_RETURN = "RET"
CET_OP_ASSUME = "ASSUME"
CET_OP_ASSIGN = "ASSIGN"
CET_OP_NOTE = "NOTE"
CET_OP_WARN = "WARN"

CET_THREAD = "thread"
CET_SOURCE = "source"
CET_DISPLAY_NAME = "name"
CET_ID = "id"
CET_LINE = "line"

TAG_CONVERSION_FUNCTION = "conversion_function"
TAG_COMPARISON_FUNCTION = "comparison_function"
TAG_EDITED_ERROR_TRACE = "edited_error_trace"

CODE_LINE_SEPARATOR = "|"
CODE_LINE_SEPARATOR_FOR_REGEXP = "\|"
FUNCTION_CALL_SEPARATOR = " "
CET_END = "__ERROR__"
ASSIGN_MARK = " = "


def get_or_convert_error_trace(unsafe, conversion_function: str, args: dict) -> list:
    """
    Convert error trace for unsafe report and cache results, so the result can be reused later.
    """
    if isinstance(unsafe, ReportUnsafe):
        report_unsafe = unsafe
    elif isinstance(unsafe, MarkUnsafe):
        report_unsafe = unsafe.report
        if not report_unsafe:
            most_likely_report_id = MarkUnsafeReport.objects.filter(mark__id=unsafe.id).values_list('report')
            if most_likely_report_id:
                report_unsafe = ReportUnsafe.objects.get(id=most_likely_report_id[0][0])
                unsafe.report = report_unsafe
                unsafe.save()
    else:
        raise BridgeException("Unknown type of unsafe: {}".format(unsafe))

    if not report_unsafe:
        raise BridgeException("There is no unsafe report for this mark")

    args_str = json.dumps(args, sort_keys=True)

    try:
        with ErrorTraceConvertionCache.objects.filter(
                unsafe=report_unsafe, function=conversion_function, args=args_str).last().converted.file as fp:
            converted_error_trace = fp.read().decode('utf8')
    except:
        parsed_trace = json.loads(
            ArchiveFileContent(report_unsafe, 'error_trace', ERROR_TRACE_FILE).content.decode('utf8'))
        converted_error_trace = __convert_error_trace(parsed_trace, conversion_function, args)
        et_file = dump_converted_error_trace(converted_error_trace)
        ErrorTraceConvertionCache.objects.create(unsafe=report_unsafe, function=conversion_function, converted=et_file,
                                                 args=args_str)
    return converted_error_trace


def compare_error_traces(edited_error_trace: list, compared_error_trace: list, comparison_function: str) -> float:
    """
    Compare two error traces by means of specified function and return Jaccard index for their threads equivalence
    (in case of a single thread function returns True/False).
    """
    edited_error_trace = __load_json(edited_error_trace)
    compared_error_trace = error_trace_pretty_parse(error_trace_pretty_print(__load_json(compared_error_trace)))
    et1_threaded, et2_threaded = __transfrom_to_threads(edited_error_trace, compared_error_trace)
    if not et1_threaded and not et2_threaded:
        # Return true for empty converted error traces (so they will be applied to all unsafes with the same attributes)
        return 1.0
    functions = {
        COMPARISON_FUNCTION_EQUAL: __compare_equal,
        COMPARISON_FUNCTION_INCLUDE: __compare_include,
        COMPARISON_FUNCTION_INCLUDE_PARTIAL: __compare_include_partial,
    }
    if comparison_function not in functions.keys():
        comparison_function = DEFAULT_COMPARISON_FUNCTION
    equal_threads = functions[comparison_function](et1_threaded, et2_threaded)
    return __get_jaccard(et1_threaded, et2_threaded, equal_threads)


def obtain_pretty_error_trace(converted_error_trace: list, unsafe, conversion_function: str, args: dict) -> str:
    try:
        # If trace is in new format, then just process it.
        return error_trace_pretty_print(converted_error_trace)
    except:
        # In case of old format create new converted error trace.
        converted_error_trace = get_or_convert_error_trace(unsafe, conversion_function, args)
        return error_trace_pretty_print(converted_error_trace)


def error_trace_pretty_print(converted_error_trace: list) -> str:
    """
    Print converted error trace (list of elements) for the user.
    """
    result = ""
    level = 0
    cur_thread = -1
    stack = list()
    if isinstance(converted_error_trace, str):
        converted_error_trace = json.loads(converted_error_trace)

    # Thread '0' is a normal thread.
    for elem in converted_error_trace:
        elem['thread'] = str(elem['thread'])

    for elem in converted_error_trace:
        op = elem[CET_OP]
        thread = elem[CET_THREAD]
        if cur_thread == -1:
            cur_thread = str(thread)
        elif not cur_thread == thread:
            cur_thread = str(thread)
            result += "{}\t{}{}{}\n".format("    0", CODE_LINE_SEPARATOR, FUNCTION_CALL_SEPARATOR * level, CET_END)
            level = 0
        name = elem[CET_DISPLAY_NAME]
        source = elem[CET_SOURCE]
        line = elem[CET_LINE]
        str_line_len = len(str(line))
        if str_line_len == 2:
            line = "   {}".format(line)
        elif str_line_len == 1:
            line = "    {}".format(line)
        elif str_line_len == 3:
            line = "  {}".format(line)
        elif str_line_len == 4:
            line = " {}".format(line)

        if op == CET_OP_RETURN:
            last_call = stack.pop()
            if name == last_call:
                level -= 1
            else:
                print("Warning: there was no call for function {}. Last called function is {}. "
                      "Current id is {}".format(name, last_call, elem[CET_ID]))
                stack.append(last_call)
                continue
        # Pretty print.
        if op == CET_OP_CALL:
            result += "{}\t{}{}{}\n".format(line, CODE_LINE_SEPARATOR, FUNCTION_CALL_SEPARATOR * level, name)
        elif op in [CET_OP_ASSIGN, CET_OP_ASSUME, CET_OP_NOTE, CET_OP_WARN]:
            if level > 0:
                # with function calls
                spaces = " " * level
            else:
                spaces = " " * int(cur_thread)
            if op == CET_OP_ASSUME:
                if name:
                    result += "{}\t{}{}{}({})\n".format(line, CODE_LINE_SEPARATOR, spaces, op, source)
                else:
                    result += "{}\t{}{}{}(!({}))\n".format(line, CODE_LINE_SEPARATOR, spaces, op, source)
            elif op == CET_OP_ASSIGN:
                result += "{}\t{}{}{}: '{}'\n".format(line, CODE_LINE_SEPARATOR, spaces, op, source)
            else:
                result += "{}\t{}{}{}: '{}'\n".format(line, CODE_LINE_SEPARATOR, spaces, op, name)
        if op == CET_OP_CALL:
            level += 1
            stack.append(name)
    result += "{}\t{}{}{}\n".format("    0", CODE_LINE_SEPARATOR, FUNCTION_CALL_SEPARATOR * level, CET_END)
    return result


def error_trace_pretty_parse(pretty_error_trace: str) -> list:
    """
    Parse input string (result of error_trace_pretty_print() plus user changes) into converted error trace.
    """
    converted_error_trace = []
    cur_thread = 0
    cur_level = -1
    stack = list()
    for line in pretty_error_trace.splitlines():
        line = line.strip()
        m = re.match(r'^\s*(\d+)\s*{}({}*)(\w+)$'.format(CODE_LINE_SEPARATOR_FOR_REGEXP, FUNCTION_CALL_SEPARATOR), line)
        if m:
            line = m.group(1)
            level = len(m.group(2))
            func = m.group(3)
            if level == 0 and cur_level != -1:
                cur_level = -1
            if level == cur_level:
                ret_func = stack.pop()
                converted_error_trace.append({
                    CET_OP: CET_OP_RETURN,
                    CET_THREAD: cur_thread,
                    CET_SOURCE: None,
                    CET_DISPLAY_NAME: ret_func,
                    CET_ID: 0,
                    CET_LINE: line
                })
            elif level < cur_level:
                for i in range(cur_level - level + 1):
                    ret_func = stack.pop()
                    converted_error_trace.append({
                        CET_OP: CET_OP_RETURN,
                        CET_THREAD: cur_thread,
                        CET_SOURCE: None,
                        CET_DISPLAY_NAME: ret_func,
                        CET_ID: 0,
                        CET_LINE: line
                    })
            if func == CET_END:
                cur_thread += 1
            if not func == CET_END:
                converted_error_trace.append({
                    CET_OP: CET_OP_CALL,
                    CET_THREAD: cur_thread,
                    CET_SOURCE: None,
                    CET_DISPLAY_NAME: func,
                    CET_ID: 0,
                    CET_LINE: line
                })
            cur_level = level
            stack.append(func)
            continue
        m = re.match(r'^\s*(\d+)\s*{}({}*){}\((!?)(.+)\)$'.format(CODE_LINE_SEPARATOR_FOR_REGEXP,
                                                                  FUNCTION_CALL_SEPARATOR, CET_OP_ASSUME), line)
        if m:
            line = m.group(1)
            level = len(m.group(2))
            is_false = bool(m.group(3))
            assume = m.group(4)
            converted_error_trace.append({
                CET_OP: CET_OP_ASSUME,
                CET_THREAD: cur_thread,
                CET_SOURCE: assume,
                CET_DISPLAY_NAME: not is_false,
                CET_ID: 0,
                CET_LINE: line
            })
            continue
        m = re.match(r'^\s*(\d+)\s*{}({}*)(\w+): \'(.+)\'$'.format(CODE_LINE_SEPARATOR_FOR_REGEXP,
                                                                   FUNCTION_CALL_SEPARATOR), line)
        if m:
            line = m.group(1)
            level = len(m.group(2))
            op = m.group(3)
            text = m.group(4)
            converted_error_trace.append({
                CET_OP: op,
                CET_THREAD: cur_thread,
                CET_SOURCE: text,
                CET_DISPLAY_NAME: text,
                CET_ID: 0,
                CET_LINE: line
            })
            continue
        raise ValueError("Cannot parse line '{}' in edited error trace".format(line))
    return converted_error_trace


def dump_converted_error_trace(converted_error_trace):
    """
    Print converted error trace into file.
    """
    return file_get_or_create(
        BytesIO(
            json.dumps(converted_error_trace, ensure_ascii=False, sort_keys=True, indent=4).encode('utf8')),
        ET_FILE_NAME, ConvertedTraces)[0]


def __convert_error_trace(error_trace: dict, conversion_function: str, args: dict=dict) -> list:
    """
    Convert json error trace into list of elements.
    Do not call this function itself, use wrapper function get_or_convert_error_trace
    """
    functions = {
        CONVERSION_FUNCTION_MODEL_FUNCTIONS: __convert_model_functions,
        CONVERSION_FUNCTION_CALL_TREE: __convert_call_tree_filter,
        CONVERSION_FUNCTION_CONDITIONS: __convert_conditions,
        CONVERSION_FUNCTION_FULL: __convert_full,
        CONVERSION_FUNCTION_ASSIGNMENTS: __convert_assignments,
        CONVERSION_FUNCTION_NOTES: __convert_notes
    }
    if conversion_function not in functions.keys():
        conversion_function = DEFAULT_CONVERSION_FUNCTION
    result = functions[conversion_function](error_trace, args)
    return result


def __convert_call_tree_filter(error_trace: dict, args: dict=dict) -> list:
    converted_error_trace = list()
    counter = 0
    # TODO: should be fixed in core.
    double_funcs = {}
    for edge in error_trace['edges']:
        if 'enter' in edge and 'return' in edge:
            double_funcs[edge['enter']] = edge['return']
        if 'enter' in edge:
            function_call = error_trace['funcs'][edge['enter']]
            converted_error_trace.append({
                CET_OP: CET_OP_CALL,
                CET_THREAD: edge['thread'],
                CET_SOURCE: edge['source'],
                CET_LINE: edge['start line'],
                CET_DISPLAY_NAME: function_call,
                CET_ID: counter
            })
        elif 'return' in edge:
            function_return = error_trace['funcs'][edge['return']]
            converted_error_trace.append({
                CET_OP: CET_OP_RETURN,
                CET_THREAD: edge['thread'],
                CET_LINE: edge['start line'],
                CET_SOURCE: edge['source'],
                CET_DISPLAY_NAME: function_return,
                CET_ID: counter
            })
            double_return = edge['return']
            while True:
                if double_return in double_funcs.keys():
                    converted_error_trace.append({
                        CET_OP: CET_OP_RETURN,
                        CET_THREAD: edge['thread'],
                        CET_LINE: edge['start line'],
                        CET_SOURCE: edge['source'],
                        CET_DISPLAY_NAME: error_trace['funcs'][double_funcs[double_return]],
                        CET_ID: counter
                    })
                    tmp = double_return
                    double_return = double_funcs[double_return]
                    del double_funcs[tmp]
                else:
                    break
        counter += 1
    return converted_error_trace


def __convert_model_functions(error_trace: dict, args: dict=dict) -> list:
    model_functions = __get_model_functions(error_trace)
    converted_error_trace = __convert_call_tree_filter(error_trace)
    while True:
        counter = 0
        is_break = False
        for item in converted_error_trace:
            op = item[CET_OP]
            thread = item[CET_THREAD]
            name = item[CET_DISPLAY_NAME]
            if op == CET_OP_CALL:
                is_save = False
                remove_items = 0
                for checking_elem in converted_error_trace[counter:]:
                    remove_items += 1
                    checking_op = checking_elem[CET_OP]
                    checking_name = checking_elem[CET_DISPLAY_NAME]
                    checking_thread = checking_elem[CET_THREAD]
                    if checking_op == CET_OP_RETURN and checking_name == name or checking_thread != thread:
                        break
                    elif checking_op == CET_OP_CALL:
                        if checking_name in model_functions:
                            is_save = True
                if not is_save:
                    del converted_error_trace[counter:(counter + remove_items)]
                    is_break = True
                    break
            counter += 1
        if not is_break:
            break
    return converted_error_trace


def __convert_conditions(error_trace: dict, args: dict=dict) -> list:
    converted_error_trace = list()
    counter = 0
    for edge in error_trace['edges']:
        if 'condition' in edge:
            assume = edge['condition']
            converted_error_trace.append({
                CET_OP: CET_OP_ASSUME,
                CET_THREAD: edge['thread'],
                CET_SOURCE: edge['source'],
                CET_LINE: edge['start line'],
                CET_DISPLAY_NAME: assume,
                CET_ID: counter
            })
        counter += 1
    return converted_error_trace


def __convert_assignments(error_trace: dict, args: dict=dict) -> list:
    converted_error_trace = list()
    counter = 0
    for edge in error_trace['edges']:
        if 'source' in edge:
            source = edge['source']
            if ASSIGN_MARK in source:
                converted_error_trace.append({
                    CET_OP: CET_OP_ASSIGN,
                    CET_THREAD: edge['thread'],
                    CET_SOURCE: edge['source'],
                    CET_LINE: edge['start line'],
                    CET_DISPLAY_NAME: source,
                    CET_ID: counter
                })
        counter += 1
    return converted_error_trace


def __convert_notes(error_trace: dict, args: dict=dict) -> list:
    converted_error_trace = list()
    counter = 0
    for edge in error_trace['edges']:
        if 'note' in edge:
            converted_error_trace.append({
                CET_OP: CET_OP_NOTE,
                CET_THREAD: edge['thread'],
                CET_SOURCE: edge['source'],
                CET_LINE: edge['start line'],
                CET_DISPLAY_NAME: edge['note'],
                CET_ID: counter
            })
        elif 'warn' in edge:
            converted_error_trace.append({
                CET_OP: CET_OP_WARN,
                CET_THREAD: edge['thread'],
                CET_SOURCE: edge['source'],
                CET_LINE: edge['start line'],
                CET_DISPLAY_NAME: edge['warn'],
                CET_ID: counter
            })
        counter += 1
    return converted_error_trace


def __convert_full(error_trace: dict, args: dict=dict) -> list:
    converted_error_trace = __convert_call_tree_filter(error_trace) + \
                            __convert_conditions(error_trace) + \
                            __convert_assignments(error_trace) + \
                            __convert_notes(error_trace)
    converted_error_trace = sorted(converted_error_trace, key=operator.itemgetter(CET_ID))
    return converted_error_trace


def __get_model_functions(error_trace: dict) -> set:
    """
    Extract model functions from error trace.
    """
    stack = list()
    model_functions = set()
    for edge in error_trace['edges']:
        if 'enter' in edge:
            func = error_trace['funcs'][edge['enter']]
            stack.append(func)
        if 'return' in edge:
            # func = error_trace['funcs'][edge['return']]
            stack.pop()
        if 'warn' in edge or 'note' in edge:
            if len(stack) > 0:
                model_functions.add(stack[len(stack) - 1])
    return model_functions


def __prep_elem_for_cmp(elem: dict, et: dict) -> None:
    op = elem[CET_OP]
    thread = elem[CET_THREAD]
    if thread not in et:
        et[thread] = list()
    if op in [CET_OP_RETURN, CET_OP_CALL]:
        et[thread].append((op, elem[CET_DISPLAY_NAME]))
    elif op == CET_OP_ASSUME:
        thread_aux = "{}_aux".format(thread)
        if thread_aux not in et:
            et[thread_aux] = list()
        et[thread_aux].append((op, elem[CET_DISPLAY_NAME], elem[CET_SOURCE]))
    elif op in [CET_OP_WARN, CET_OP_NOTE, CET_OP_ASSIGN]:
        thread_aux = "{}_aux".format(thread)
        if thread_aux not in et:
            et[thread_aux] = list()
        et[thread_aux].append((op, elem[CET_DISPLAY_NAME]))


def __load_json(et):
    if isinstance(et, str):
        et = json.loads(et)
    return et


def __transfrom_to_threads(edited_error_trace: list, compared_error_trace: list) -> (dict, dict):
    et1 = dict()
    et2 = dict()
    for i in range(len(edited_error_trace)):
        __prep_elem_for_cmp(edited_error_trace[i], et1)
    for i in range(len(compared_error_trace)):
        __prep_elem_for_cmp(compared_error_trace[i], et2)
    et1_threaded = dict()
    et2_threaded = dict()
    for thread, trace in et1.items():
        if trace:
            et1_threaded[thread] = tuple(trace)
    for thread, trace in et2.items():
        if trace:
            et2_threaded[thread] = tuple(trace)
    return et1_threaded, et2_threaded


def __sublist(sublist: tuple, biglist: tuple) -> bool:
    """
    Check that list lst1 is included into the list lst2.
    """
    sublist = list(sublist)
    common_part = [element for element in biglist if element in sublist]
    return sublist and sublist == common_part


def __compare_equal(edited_error_trace: dict, compared_error_trace: dict) -> int:
    equal_threads = len(set(edited_error_trace.values()) & set(compared_error_trace.values()))
    return equal_threads


def __compare_include(edited_error_trace: dict, compared_error_trace: dict) -> int:
    equal_threads = 0
    for thread_1 in edited_error_trace.values():
        result = False
        for thread_2 in compared_error_trace.values():
            if __sublist(thread_1, thread_2):
                result = True
                break
        if result:
            equal_threads += 1
    return equal_threads


def __compare_include_partial(edited_error_trace: dict, compared_error_trace: dict) -> int:
    equal_threads = 0
    for thread_1 in edited_error_trace.values():
        result = False
        for thread_2 in compared_error_trace.values():
            if all(elem in thread_2 for elem in thread_1):
                result = True
                break
        if result:
            equal_threads += 1
    return equal_threads


def __get_jaccard(l1: dict, l2: dict, common_elements: int) -> float:
    diff_elements = len(l1) + len(l2) - common_elements
    if diff_elements:
        return round(common_elements / diff_elements, 2)
    else:
        return 0.0
