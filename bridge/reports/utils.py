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

import json
import os
import tempfile
import uuid
from collections import Counter
from wsgiref.util import FileWrapper

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.core.files import File
from django.db.models import Count
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.translation import ugettext_lazy as _

from bridge.ZipGenerator import ZipStream
from bridge.tableHead import Header
from bridge.utils import ArchiveFileContent, logger, extract_archive, BridgeException
from bridge.vars import ERROR_TRACE_FILE, UNSAFE_VERDICTS, SAFE_VERDICTS, MARK_STATUS
from jobs.utils import get_resource_data, get_user_time, get_user_memory
from marks.models import UnknownProblem, SafeTag, UnsafeTag, MarkUnsafeReport
from marks.utils import SAFE_COLOR, UNSAFE_COLOR, SAFE_LINK_CLASS, UNSAFE_LINK_CLASS, STATUS_COLOR
from reports.etv import save_zip_trace
from reports.models import ReportComponent, AttrFile, Attr, AttrName, ReportAttr, ReportUnsafe, ReportSafe, \
    ReportUnknown, ReportRoot
from reports.querysets import LeavesQuery
from users.utils import ALL_ATTRS

REP_MARK_TITLES = {
    'mark_num': _('Mark'),
    'mark_verdict': _("Verdict"),
    'mark_result': _('Similarity'),
    'mark_status': _('Status'),
    'number': _('#'),
    'component': _('Component'),
    'marks_number': _("Number of associated marks"),
    'report_verdict': _("Total verdict"),
    'tags': _('Tags'),
    'verifiers': _('Verifiers'),
    'verifiers:cpu': _('CPU time'),
    'verifiers:wall': _('Wall time'),
    'verifiers:memory': _('RAM'),
    'problems': _('Problems'),
    'total_similarity': _('Total similarity')
}

MARK_COLUMNS = ['mark_verdict', 'mark_result', 'mark_status']

EDITED_ERROR_TRACE_SUFFIX = "_edited.json"


def computer_description(computer):
    computer = json.loads(computer)
    data = []
    comp_name = _('Unknown')
    for comp_data in computer:
        if isinstance(comp_data, dict):
            data_name = str(next(iter(comp_data)))
            if data_name == 'node name':
                comp_name = str(comp_data[data_name])
            else:
                data.append([data_name, str(comp_data[data_name])])
    return {
        'name': comp_name,
        'data': data
    }


def get_column_title(column):
    col_parts = column.split(':')
    column_starts = []
    for i in range(0, len(col_parts)):
        column_starts.append(':'.join(col_parts[:(i + 1)]))
    titles = []
    for col_st in column_starts:
        titles.append(REP_MARK_TITLES.get(col_st, col_st))
    concated_title = titles[0]
    for i in range(1, len(titles)):
        concated_title = '{0}/{1}'.format(concated_title, titles[i])
        # concated_title = string_concat(concated_title, '/', titles[i])
    return concated_title


def get_parents(report):
    parents_data = []
    try:
        parent = ReportComponent.objects.get(id=report.parent_id)
    except ObjectDoesNotExist:
        parent = None
    while parent is not None:
        parent_attrs = []
        for rep_attr in parent.attrs.order_by('attr__name__name').values_list('attr__name__name', 'attr__value'):
            parent_attrs.append(rep_attr)
        parents_data.insert(0, {
            'title': parent.component.name,
            'href': reverse('reports:component', args=[parent.id]),
            'attrs': parent_attrs,
            'has_coverage': (parent.covnum > 0),
            'id': parent.id
        })
        try:
            parent = ReportComponent.objects.get(id=parent.parent_id)
        except ObjectDoesNotExist:
            parent = None
    return parents_data


def get_leaf_resources(user, report):
    if all(x is not None for x in [report.wall_time, report.cpu_time, report.memory]):
        rd = get_resource_data(user.extended.data_format, user.extended.accuracy, report)
        return {'wall_time': rd[0], 'cpu_time': rd[1], 'memory': rd[2]}
    return None


def report_resources(report, user):
    if all(x is not None for x in [report.wall_time, report.cpu_time, report.memory]):
        rd = get_resource_data(user.extended.data_format, user.extended.accuracy, report)
        return {'wall_time': rd[0], 'cpu_time': rd[1], 'memory': rd[2]}
    return None


def get_attr_vals(ids: str) -> dict:
    result = dict()
    for attr_id in ids.split(','):
        try:
            attr = Attr.objects.get(id=attr_id)
            name = attr.name.name
            if name not in result:
                result[name] = list()
            result[name].append(attr_id)
        except ObjectDoesNotExist:
            logger.exception("Attribute with identifier {} is not found".format(attr_id), stack_info=True)
        except ValueError:
            logger.exception("Cannot parse integer {}".format(attr_id), stack_info=True)
    return result


def get_edited_error_trace(report) -> str:
    if isinstance(report, ReportUnsafe):
        original_error_trace_arch = os.path.join(settings.MEDIA_ROOT, report.error_trace.name)
    elif isinstance(report, ReportSafe):
        original_error_trace_arch = os.path.join(settings.MEDIA_ROOT, report.proof.name)
    else:
        raise ValueError('Unsupported report type: {}'.format(type(report)))
    edited_error_trace = original_error_trace_arch[:-4] + EDITED_ERROR_TRACE_SUFFIX
    return edited_error_trace


def get_error_trace_content(report) -> str:
    edited_error_trace = get_edited_error_trace(report)
    if os.path.exists(edited_error_trace):
        with open(edited_error_trace) as fd:
            error_trace = fd.read()
    else:
        if isinstance(report, ReportUnsafe):
            error_trace = ArchiveFileContent(report, 'error_trace', ERROR_TRACE_FILE).content.decode('utf8')
        elif isinstance(report, ReportSafe):
            error_trace = ArchiveFileContent(report, 'proof', ERROR_TRACE_FILE).content.decode('utf8')
        else:
            raise ValueError('Unsupported report type: {}'.format(type(report)))

    return error_trace


def get_html_error_trace(etv, src, assumptions):
    zip_trace_tmp = os.path.join(tempfile.gettempdir(), uuid.uuid4().hex + ".zip")
    save_zip_trace(zip_trace_tmp, etv, src, assumptions)
    data = FileWrapper(open(zip_trace_tmp, "rb"))
    os.remove(zip_trace_tmp)
    return data


def __apply_comments_changes(edges: list, comments: dict, comment_type: str):
    # Sort comments, so they can be applied in correct order.
    sorted_comments = dict()
    for identifier, new_comment in comments.items():
        sorted_comments[int(identifier)] = new_comment
    for identifier in sorted(sorted_comments):
        edge = edges[identifier]
        new_comment = sorted_comments[identifier]
        if new_comment:
            edge[comment_type] = new_comment
        elif comment_type in edge:
            del edge[comment_type]
            # Remove comments recursively.
            recursive_comments = set()
            is_remove_comments = False
            if 'enter' in edge:
                enter_function_id = edge['enter']
                for i in range(identifier + 1, len(edges)):
                    cur_edge = edges[i]
                    if comment_type in cur_edge:
                        recursive_comments.add(i)
                    if cur_edge.get('return') == enter_function_id:
                        is_remove_comments = True
                        break
            if is_remove_comments:
                for edge_id in recursive_comments:
                    del edges[edge_id][comment_type]


def modify_error_trace(unsafe_report: ReportUnsafe, notes: dict, warns: dict, is_modifiable: bool):
    error_trace = json.loads(get_error_trace_content(unsafe_report))
    edges = error_trace['edges']
    error_trace['is_modifiable'] = is_modifiable
    __apply_comments_changes(edges, notes, 'note')
    __apply_comments_changes(edges, warns, 'warn')
    edited_error_trace = get_edited_error_trace(unsafe_report)
    with open(edited_error_trace, "w") as fd:
        json.dump(error_trace, fd, ensure_ascii=False, sort_keys=True, indent=4)


class ReportAttrsTable:
    def __init__(self, report):
        self.report = report
        columns, values = self.__self_data()
        self.table_data = {'header': Header(columns, REP_MARK_TITLES).struct, 'values': values}

    def __self_data(self):
        columns = []
        values = []
        for ra in self.report.attrs.order_by('id').select_related('attr', 'attr__name'):
            columns.append(ra.attr.name.name)
            values.append((ra.attr.value, ra.id if ra.data is not None else None))
        return columns, values


class SafesTable:
    columns_list = ['marks_number', 'report_verdict', 'tags', 'verifiers:cpu', 'verifiers:wall', 'verifiers:memory']
    columns_set = set(columns_list)

    def __init__(self, user, report, view, data):
        self.title = _('Safes')
        self.user = user
        self.view = view
        self._kwargs = self.__get_kwargs(report, data)
        self.parents = get_parents(report)
        self.report = report

        self.verdicts = SAFE_VERDICTS

        self.page = None
        columns, values = self.__safes_data()
        self.table_data = {'header': Header(columns, REP_MARK_TITLES).struct, 'values': values}

    def __get_kwargs(self, report, data):
        kwargs = {'page': int(data.get('page', 1)), 'report': report}
        if 'confirmed' in data:
            kwargs['confirmed'] = True
            self.title = '{0}: {1}'.format(_("Safes"), _('confirmed'))

        # Either verdict, tag or attr is supported in kwargs
        if 'verdict' in data:
            verdict_title = ReportSafe(verdict=data['verdict']).get_verdict_display()
            if 'confirmed' in data:
                self.title = '{0}: {1} {2}'.format(_("Safes"), _('confirmed'), verdict_title)
            else:
                self.title = '{0}: {1}'.format(_("Safes"), verdict_title)
            kwargs['verdict'] = data['verdict']
        if 'tag' in data:
            tag_id = data['tag']
            if tag_id == '-1':
                self.title = '{0}: {1}'.format(_("Safes"), _("Without tags"))
                kwargs['tag'] = -1
            else:
                try:
                    tag = SafeTag.objects.get(id=data['tag'])
                except ObjectDoesNotExist:
                    raise BridgeException(_("The tag was not found"))
                self.title = '{0}: {1}'.format(_("Safes"), tag.tag)
                kwargs['tag'] = tag
        if 'attr' in data:
            kwargs['attr'] = get_attr_vals(data['attr'])
        return kwargs

    @cached_property
    def selected_columns(self):
        columns = []
        for col in self.view['columns']:
            if col == ALL_ATTRS:
                continue
            if ':' in col:
                col_title = get_column_title(col)
            else:
                col_title = REP_MARK_TITLES.get(col, col)
            columns.append({'value': col, 'title': col_title})
        return columns

    @cached_property
    def available_columns(self):
        self.__is_not_used()
        columns = []
        for col in self.columns_list:
            if ':' in col:
                col_title = get_column_title(col)
            else:
                col_title = REP_MARK_TITLES.get(col, col)
            columns.append({'value': col, 'title': col_title})
        return columns

    def __paginate_objects(self, objects):
        return objects, 1

    def __safes_data(self):
        columns = ['number']
        columns.extend(self.view['columns'])
        if ALL_ATTRS in columns:
            columns.remove(ALL_ATTRS)

        query = LeavesQuery(ReportSafe, self.view, **self._kwargs)
        objects, cnt = self.__paginate_objects(query.get_objects())

        safes = {}
        ordered_ids = []
        for safe_data in objects:
            ordered_ids.append(safe_data['id'])
            safes[safe_data['id']] = safe_data

        if 'tag' in self._kwargs and self._kwargs['tag'] == -1:
            new_ids = []
            for identifier in list(self.report.leaves.exclude(safe=None).filter(
                    safe__tags__tag=None, safe__id__in=ordered_ids).order_by('safe__id').
                                           values_list("safe__id")):
                new_ids.extend(identifier)
            ordered_ids = new_ids

        attributes = {}
        for r_id, a_name, a_value in ReportAttr.objects.filter(report_id__in=ordered_ids).order_by('id')\
                .values_list('report_id', 'attr__name__name', 'attr__value'):
            if a_name not in attributes:
                self.available_columns.append({'value': a_name, 'title': a_name})
                if ALL_ATTRS in self.view['columns']:
                    self.selected_columns.append({'value': a_name, 'title': a_name})
                    columns.append(a_name)
                attributes[a_name] = {}
            attributes[a_name][r_id] = a_value

        values_data = []
        for rep_id in ordered_ids:
            values_row = []
            for col in columns:
                val = '-'
                href = None
                color = None
                style = None
                if col in attributes:
                    val = attributes[col].get(rep_id, '-')
                elif col == 'number':
                    val = cnt
                    href = reverse('reports:safe', args=[rep_id])
                elif col == 'marks_number':
                    if 'confirmed' in safes[rep_id]:
                        val = '%s (%s)' % (safes[rep_id]['confirmed'], safes[rep_id]['marks_number'])
                    else:
                        val = str(safes[rep_id]['marks_number'])
                elif col == 'report_verdict':
                    for s in SAFE_VERDICTS:
                        if s[0] == safes[rep_id]['verdict']:
                            val = s[1]
                            break
                    verdict = safes[rep_id]['verdict']
                    color = SAFE_COLOR[verdict]
                    style = SAFE_LINK_CLASS[verdict]
                elif col == 'tags':
                    if 'tags' in safes[rep_id] and safes[rep_id]['tags']:
                        if isinstance(safes[rep_id]['tags'], str):
                            safes[rep_id]['tags'] = safes[rep_id]['tags'].split(',')
                        tags_numbers = Counter(safes[rep_id]['tags'])
                        val = '; '.join([
                            '{0} ({1})'.format(t, tags_numbers[t]) if tags_numbers[t] > 1 else t
                            for t in sorted(tags_numbers)
                        ])
                elif col == 'verifiers:cpu':
                    val = get_user_time(self.user, safes[rep_id]['cpu_time'])
                elif col == 'verifiers:wall':
                    val = get_user_time(self.user, safes[rep_id]['wall_time'])
                elif col == 'verifiers:memory':
                    val = get_user_memory(self.user, safes[rep_id]['memory'])
                values_row.append({'value': val, 'color': color, 'href': href, 'style': style})
            values_data.append(values_row)
            cnt += 1

        self.available_columns = [item for item in self.available_columns if item.get('value') not in columns]
        return columns, values_data

    def __is_not_used(self):
        pass


class UnsafesTable:
    columns_list = ['marks_number', 'report_verdict', 'mark_status',
                    'tags', 'verifiers:cpu', 'verifiers:wall', 'verifiers:memory']
    columns_set = set(columns_list)

    def __init__(self, user, report, view, data):
        self.title = _('Unsafes')
        self.user = user
        self.view = view
        self._kwargs = self.__get_kwargs(report, data)
        self.parents = get_parents(report)
        self.page = None
        self.report = report

        self.selected_columns = self.__selected()
        self.available_columns = self.__available()
        self.verdicts = UNSAFE_VERDICTS

        columns, values = self.__unsafes_data()
        self.table_data = {'header': Header(columns, REP_MARK_TITLES).struct, 'values': values}

    def __get_kwargs(self, report, data):
        kwargs = {'page': int(data.get('page', 1)), 'report': report}
        if 'confirmed' in data:
            kwargs['confirmed'] = True
            self.title = '{0}: {1}'.format(_("Unsafes"), _('confirmed'))

        # Either verdict, tag or attr is supported in kwargs
        if 'verdict' in data:
            verdict_title = ReportUnsafe(verdict=data['verdict']).get_verdict_display()
            if 'confirmed' in data:
                self.title = '{0}: {1} {2}'.format(_("Unsafes"), _('confirmed'), verdict_title)
            else:
                self.title = '{0}: {1}'.format(_("Unsafes"), verdict_title)
            kwargs['verdict'] = data['verdict']
        if 'tag' in data:
            tag_id = data['tag']
            if tag_id == '-1':
                self.title = '{0}: {1}'.format(_("Unsafes"), _("Without tags"))
                kwargs['tag'] = -1
            else:
                try:
                    tag = UnsafeTag.objects.get(id=data['tag'])
                except ObjectDoesNotExist:
                    raise BridgeException(_("The tag was not found"))
                self.title = '{0}: {1}'.format(_("Unsafes"), tag.tag)
                kwargs['tag'] = tag
        if 'attr' in data:
            kwargs['attr'] = get_attr_vals(data['attr'])
        return kwargs

    def __selected(self):
        columns = []
        for col in self.view['columns']:
            if col == ALL_ATTRS:
                continue
            if ':' in col:
                col_title = get_column_title(col)
            else:
                col_title = REP_MARK_TITLES.get(col, col)
            columns.append({'value': col, 'title': col_title})
        return columns

    def __available(self):
        columns = []
        for col in self.columns_list:
            if ':' in col:
                col_title = get_column_title(col)
            else:
                col_title = REP_MARK_TITLES.get(col, col)
            columns.append({'value': col, 'title': col_title})
        return columns

    def __paginate_objects(self, objects):
        return objects, 1

    def __unsafes_data(self):
        columns = ['number']
        columns.extend(self.view['columns'])
        if ALL_ATTRS in columns:
            columns.remove(ALL_ATTRS)

        query = LeavesQuery(ReportUnsafe, self.view, **self._kwargs)
        objects, cnt = self.__paginate_objects(query.get_objects())

        unsafes = {}
        ordered_ids = []
        for unsafe_data in objects:
            ordered_ids.append(unsafe_data['id'])
            unsafes[unsafe_data['id']] = unsafe_data
            if unsafe_data.get('tags'):
                if isinstance(unsafe_data['tags'], str):
                    unsafe_data['tags'] = unsafe_data['tags'].split(',')
                unsafe_data['tags'] = '; '.join(sorted(unsafe_data['tags']))
            if 'marks_number' in unsafe_data and unsafe_data['marks_number'] is None:
                unsafe_data['marks_number'] = 0
            if 'confirmed' in unsafe_data and unsafe_data['confirmed'] is None:
                unsafe_data['confirmed'] = 0
            if 'mark_status' in columns:
                marks = list(set(v_id for v_id, in MarkUnsafeReport.objects.filter(
                    report__id=unsafe_data['id']).values_list("mark__status")))
                number_of_applied_marks = len(marks)
                if number_of_applied_marks == 0:
                    unsafe_data['mark_status'] = '-'
                elif number_of_applied_marks == 1:
                    unsafe_data['mark_status'] = marks[0]
                else:
                    unsafe_data['mark_status'] = _('Multiple')

        if 'tag' in self._kwargs and self._kwargs['tag'] == -1:
            new_ids = []
            for identifier in list(self.report.leaves.exclude(unsafe=None).filter(
                    unsafe__tags__tag=None, unsafe__id__in=ordered_ids).order_by('unsafe__id').
                                           values_list("unsafe__id")):
                new_ids.extend(identifier)
            ordered_ids = new_ids

        attributes = {}
        for r_id, a_name, a_value in ReportAttr.objects.filter(report_id__in=ordered_ids).order_by('id')\
                .values_list('report_id', 'attr__name__name', 'attr__value'):
            if a_name not in attributes:
                self.available_columns.append({'value': a_name, 'title': a_name})
                if ALL_ATTRS in self.view['columns']:
                    self.selected_columns.append({'value': a_name, 'title': a_name})
                    columns.append(a_name)
                attributes[a_name] = {}
            attributes[a_name][r_id] = a_value

        values_data = []
        for rep_id in ordered_ids:
            values_row = []
            for col in columns:
                val = '-'
                href = None
                color = None
                style = None
                if col in attributes:
                    val = attributes[col].get(rep_id, '-')
                elif col == 'number':
                    val = cnt
                    href = reverse('reports:unsafe', args=[unsafes[rep_id]['trace_id']])
                elif col == 'marks_number':
                    if 'confirmed' in unsafes[rep_id]:
                        val = '%s (%s)' % (unsafes[rep_id]['confirmed'], unsafes[rep_id]['marks_number'])
                    else:
                        val = str(unsafes[rep_id]['marks_number'])
                elif col == 'mark_status':
                    val = unsafes[rep_id]['mark_status']
                    for u in MARK_STATUS:
                        if u[0] == val:
                            val = u[1]
                            color = STATUS_COLOR[u[0]]
                            break
                elif col == 'total_similarity':
                    val = '%d%%' % (unsafes[rep_id]['total_similarity'] * 100)
                elif col == 'report_verdict':
                    for u in UNSAFE_VERDICTS:
                        if u[0] == unsafes[rep_id]['verdict']:
                            val = u[1]
                            break
                    verict = unsafes[rep_id]['verdict']
                    color = UNSAFE_COLOR[verict]
                    style = UNSAFE_LINK_CLASS[verict]
                elif col == 'tags':
                    if 'tags' in unsafes[rep_id] and unsafes[rep_id]['tags']:
                        val = unsafes[rep_id]['tags']
                elif col == 'verifiers:cpu':
                    val = get_user_time(self.user, unsafes[rep_id]['cpu_time'])
                elif col == 'verifiers:wall':
                    val = get_user_time(self.user, unsafes[rep_id]['wall_time'])
                elif col == 'verifiers:memory':
                    val = get_user_memory(self.user, unsafes[rep_id]['memory'])
                values_row.append({'value': val, 'color': color, 'href': href, 'style': style})
            values_data.append(values_row)
            cnt += 1

        self.available_columns = [item for item in self.available_columns if item.get('value') not in columns]
        return columns, values_data

    def __is_not_used(self):
        pass


class UnknownsTable:
    columns_list = ['component', 'marks_number', 'problems', 'verifiers:cpu', 'verifiers:wall', 'verifiers:memory']
    columns_set = set(columns_list)

    def __init__(self, user, report, view, data):
        self.title = _('Unknowns')
        self.user = user
        self.view = view
        self._kwargs = self.__get_kwargs(report, data)
        self.parents = get_parents(report)
        self.page = None

        self.selected_columns = self.__selected()
        self.available_columns = self.__available()

        columns, values = self.__unknowns_data()
        if isinstance(values, str):
            self.table_data = values
        else:
            self.table_data = {'header': Header(columns, REP_MARK_TITLES).struct, 'values': values}

    def __get_kwargs(self, report, data):
        kwargs = {'page': int(data.get('page', 1)), 'report': report}
        if 'component' in data:
            kwargs['component'] = data['component']
        if 'problem' in data:
            problem_id = int(data['problem'])
            if problem_id == 0:
                self.title = _("Unknowns without marks")
                kwargs['problem'] = 0
            else:
                try:
                    problem = UnknownProblem.objects.get(id=problem_id)
                except ObjectDoesNotExist:
                    raise BridgeException(_("The problem was not found"))
                self.title = '{0}: {1}'.format(_("Unknowns"), problem.name)
                kwargs['problem'] = problem
        if 'attr' in data:
            kwargs['attr'] = get_attr_vals(data['attr'])
        return kwargs

    def __selected(self):
        columns = []
        for col in self.view['columns']:
            if col == ALL_ATTRS:
                continue
            if ':' in col:
                col_title = get_column_title(col)
            else:
                col_title = REP_MARK_TITLES.get(col, col)
            columns.append({'value': col, 'title': col_title})
        return columns

    def __available(self):
        columns = []
        for col in self.columns_list:
            if ':' in col:
                col_title = get_column_title(col)
            else:
                col_title = REP_MARK_TITLES.get(col, col)
            columns.append({'value': col, 'title': col_title})
        return columns

    def __paginate_objects(self, objects):
        return objects, 1

    def __unknowns_data(self):
        columns = ['number']
        columns.extend(self.view['columns'])
        if ALL_ATTRS in columns:
            columns.remove(ALL_ATTRS)

        query = LeavesQuery(ReportUnknown, self.view, **self._kwargs)
        objects, cnt = self.__paginate_objects(query.get_objects())

        unknowns = {}
        ordered_ids = []
        for unknown_data in objects:
            ordered_ids.append(unknown_data['id'])
            unknowns[unknown_data['id']] = unknown_data
            if unknown_data.get('problems'):
                pass
            if 'marks_number' in unknown_data and unknown_data['marks_number'] is None:
                unknown_data['marks_number'] = 0
            if 'confirmed' in unknown_data and unknown_data['confirmed'] is None:
                unknown_data['confirmed'] = 0

        attributes = {}
        for r_id, a_name, a_value in ReportAttr.objects.filter(report_id__in=ordered_ids).order_by('id')\
                .values_list('report_id', 'attr__name__name', 'attr__value'):
            if a_name not in attributes:
                self.available_columns.append({'value': a_name, 'title': a_name})
                if ALL_ATTRS in self.view['columns']:
                    self.selected_columns.append({'value': a_name, 'title': a_name})
                    columns.append(a_name)
                attributes[a_name] = {}
            attributes[a_name][r_id] = a_value

        values_data = []
        for rep_id in ordered_ids:
            values_row = []
            for col in columns:
                val = '-'
                href = None
                color = None
                if col in attributes:
                    val = attributes[col].get(rep_id, '-')
                elif col == 'number':
                    val = cnt
                    href = reverse('reports:unknown', args=[rep_id])
                elif col == 'component':
                    val = unknowns[rep_id]['component']
                elif col == 'marks_number':
                    if 'confirmed' in unknowns[rep_id]:
                        val = '%s (%s)' % (unknowns[rep_id]['confirmed'], unknowns[rep_id]['marks_number'])
                    else:
                        val = str(unknowns[rep_id]['marks_number'])
                elif col == 'problems':
                    if 'problems' in unknowns[rep_id]:
                        if isinstance(unknowns[rep_id]['problems'], str):
                            unknowns[rep_id]['problems'] = unknowns[rep_id]['problems'].split(",")
                    if unknowns[rep_id].get('problems'):
                        pr_numbers = Counter(unknowns[rep_id]['problems'])
                        val = ', '.join(['{0} ({1})'.format(p, pr_numbers[p]) if pr_numbers[p] > 1 else str(p)
                                         for p in sorted(pr_numbers)])
                elif col == 'verifiers:cpu':
                    if unknowns[rep_id]['cpu_time']:
                        val = get_user_time(self.user, unknowns[rep_id]['cpu_time'])
                elif col == 'verifiers:wall':
                    if unknowns[rep_id]['wall_time']:
                        val = get_user_time(self.user, unknowns[rep_id]['wall_time'])
                elif col == 'verifiers:memory':
                    if unknowns[rep_id]['memory']:
                        val = get_user_memory(self.user, unknowns[rep_id]['memory'])
                values_row.append({'value': val, 'color': color, 'href': href})
            values_data.append(values_row)
            cnt += 1

        self.available_columns = [item for item in self.available_columns if item.get('value') not in columns]
        return columns, values_data

    def __get_problems(self, problems):
        if problems is None:
            return ''

    def __is_not_used(self):
        pass


class ReportChildrenTable:
    def __init__(self, user, report, view):
        self.user = user
        self.report = report
        self.view = view

        self.columns = []
        columns, values = self.__component_data()
        self.paginator = None
        self.table_data = {'header': Header(columns, REP_MARK_TITLES).struct, 'values': values}

    def __component_data(self):
        data = {}
        components = {}
        columns = []
        component_filters = {'parent': self.report}
        if 'component' in self.view:
            component_filters['component__name__' + self.view['component'][0]] = self.view['component'][1]

        finish_dates = {}
        report_ids = set()
        for report in ReportComponent.objects.filter(**component_filters).select_related('component'):
            report_ids.add(report.id)
            components[report.id] = report.component
            if 'order' in self.view and self.view['order'][1] == 'date' and report.finish_date is not None:
                finish_dates[report.id] = report.finish_date

        for ra in ReportAttr.objects.filter(report_id__in=report_ids).order_by('id') \
                .values_list('report_id', 'attr__name__name', 'attr__value'):
            if ra[1] not in data:
                columns.append(ra[1])
                data[ra[1]] = {}
            data[ra[1]][ra[0]] = ra[2]

        comp_data = []
        for pk in components:
            if self.view['order'][1] == 'component':
                comp_data.append((components[pk].name, {'pk': pk, 'component': components[pk]}))
            elif self.view['order'][1] == 'date':
                if pk in finish_dates:
                    comp_data.append((finish_dates[pk], {'pk': pk, 'component': components[pk]}))
            elif self.view['order'][1] == 'attr':
                attr_val = '-'
                if self.view['order'][2] in data and pk in data[self.view['order'][2]]:
                    attr_val = data[self.view['order'][2]][pk]
                comp_data.append((attr_val, {'pk': pk, 'component': components[pk]}))

        sorted_components = []
        for name, dt in sorted(comp_data, key=lambda x: x[0]):
            sorted_components.append(dt)
        if self.view['order'] is not None and self.view['order'][0] == 'up':
            sorted_components = list(reversed(sorted_components))

        values_data = []
        for comp_data in sorted_components:
            values_row = []
            for col in columns:
                cell_val = '-'
                if comp_data['pk'] in data[col]:
                    cell_val = data[col][comp_data['pk']]
                values_row.append(cell_val)
                if not self.__filter_attr(col, cell_val):
                    break
            else:
                values_data.append({
                    'pk': comp_data['pk'],
                    'component': comp_data['component'],
                    'attrs': values_row
                })
        columns.insert(0, 'component')
        return columns, values_data

    def __filter_attr(self, attribute, value):
        if 'attr' in self.view:
            attr_name = self.view['attr'][0]
            ftype = self.view['attr'][1]
            attr_val = self.view['attr'][2]
            if attr_name is not None and attr_name.lower() == attribute.lower():
                if ftype == 'iexact' and attr_val.lower() != value.lower():
                    return False
                elif ftype == 'istartswith' and not value.lower().startswith(attr_val.lower()):
                    return False
        return True


class AttrData:
    def __init__(self, root_id, archive):
        self._root_id = root_id
        self._data = []
        self._name = {}
        self._attrs = {}
        self._files = {}
        if archive is not None:
            self.__get_files(archive)

    def __get_files(self, archive):
        archive.seek(0)
        try:
            files_dir = extract_archive(archive)
        except Exception as e:
            logger.exception("Archive extraction failed: %s" % e, stack_info=True)
            raise ValueError('Archive "%s" with attributes data is corrupted' % archive.name)
        for dir_path, dir_names, file_names in os.walk(files_dir.name):
            for file_name in file_names:
                full_path = os.path.join(dir_path, file_name)
                rel_path = os.path.relpath(full_path, files_dir.name).replace('\\', '/')
                newfile = AttrFile(root_id=self._root_id)
                with open(full_path, mode='rb') as fp:
                    newfile.file.save(os.path.basename(rel_path), File(fp), True)
                self._files[rel_path] = newfile.id

    def add(self, report_id, name, value, compare, associate, data):
        self._data.append((report_id, name, value, compare, associate, self._files.get(data)))
        if name not in self._name:
            self._name[name] = None
        if (name, value) not in self._attrs:
            self._attrs[(name, value)] = None

    def upload(self):
        self.__upload_names()
        self.__upload_attrs()
        ReportAttr.objects.bulk_create(list(ReportAttr(
            report_id=d[0], attr_id=self._attrs[(d[1], d[2])], compare=d[3], associate=d[4], data_id=d[5]
        ) for d in self._data))
        self.__init__(self._root_id, None)

    def __upload_names(self):
        names_to_create = set(self._name) - set(n.name for n in AttrName.objects.filter(name__in=self._name))
        AttrName.objects.bulk_create(list(AttrName(name=name) for name in names_to_create))
        for n in AttrName.objects.filter(name__in=self._name):
            self._name[n.name] = n.id

    def __upload_attrs(self):
        for a in Attr.objects.filter(value__in=list(attr[1] for attr in self._attrs)).select_related('name'):
            if (a.name.name, a.value) in self._attrs:
                self._attrs[(a.name.name, a.value)] = a.id
        attrs_to_create = []
        for attr in self._attrs:
            if self._attrs[attr] is None and attr[0] in self._name:
                attrs_to_create.append(Attr(name_id=self._name[attr[0]], value=attr[1]))
        Attr.objects.bulk_create(attrs_to_create)
        for a in Attr.objects.filter(value__in=list(attr[1] for attr in self._attrs)).select_related('name'):
            if (a.name.name, a.value) in self._attrs:
                self._attrs[(a.name.name, a.value)] = a.id


class FilesForCompetitionArchive:
    obj_attr = 'Program fragment'
    requirement_attr = 'Requirement'

    def __init__(self, job, filters):
        try:
            self.root = ReportRoot.objects.get(job=job)
        except ObjectDoesNotExist:
            raise BridgeException(_('The job is not decided'))
        self._attrs = self.__get_attrs()
        self._archives = self.__get_archives()
        self.filters = filters
        self._archives_to_upload = []
        self.__get_archives_to_upload()
        self.stream = ZipStream()

    def __iter__(self):
        cnt = 0
        names_in_use = set()
        for arch_path, name_pattern in self._archives_to_upload:

            # TODO: original extension (currently it's supposed that verification files are zip archives)
            if name_pattern in names_in_use:
                cnt += 1
                arch_name = '%s_%s.zip' % (name_pattern, cnt)
            else:
                arch_name = '%s.zip' % name_pattern

            for data in self.stream.compress_file(arch_path, arch_name):
                yield data

        yield self.stream.close_stream()

    def __get_archives(self):
        archives = {}
        for c in ReportComponent.objects.filter(root=self.root, verification=True).exclude(verifier_input='')\
                .only('id', 'verifier_input'):
            if c.verifier_input:
                archives[c.id] = c.verifier_input.path
        return archives

    def __get_attrs(self):
        names = {}
        for a_name in AttrName.objects.filter(name__in=[self.obj_attr, self.requirement_attr]):
            names[a_name.id] = a_name.name

        attrs = {}
        # Select attributes for all safes, unsafes and unknowns
        for r_id, n_id, a_val in ReportAttr.objects.filter(report__root=self.root, attr__name_id__in=names)\
                .exclude(report__reportunsafe=None, report__reportsafe=None, report__reportunknown=None)\
                .values_list('report_id', 'attr__name_id', 'attr__value'):
            if r_id not in attrs:
                attrs[r_id] = {}
            attrs[r_id][names[n_id]] = a_val

        return attrs

    def __add_archive(self, r_type, r_id, p_id):
        if p_id in self._archives and r_id in self._attrs \
                and self.obj_attr in self._attrs[r_id] \
                and self.requirement_attr in self._attrs[r_id]:

            ver_obj = self._attrs[r_id][self.obj_attr].replace('~', 'HOME').replace('/', '---')
            ver_requirement = self._attrs[r_id][self.requirement_attr].replace(':', '-')
            dirname = 'Unknowns' if r_type == 'f' else 'Unsafes' if r_type == 'u' else 'Safes'

            self._archives_to_upload.append(
                (self._archives[p_id], '{0}/{1}__{2}__{3}'.format(dirname, r_type, ver_requirement, ver_obj))
            )

    def __get_archives_to_upload(self):
        for f_t in self.filters:
            if isinstance(f_t, list) and f_t:
                for problem in f_t:
                    comp_id, problem_id = problem.split('_')[0:2]
                    if comp_id == problem_id == '0':
                        queryset = ReportUnknown.objects.annotate(mr_len=Count('markreport_set'))\
                            .filter(root=self.root, mr_len=0).exclude(parent__parent=None)\
                            .values_list('id', 'parent_id')
                    else:
                        queryset = ReportUnknown.objects \
                            .filter(root=self.root, markreport_set__problem_id=problem_id, component_id=comp_id)\
                            .exclude(parent__parent=None).values_list('id', 'parent_id')
                    for args in queryset:
                        self.__add_archive('f', *args)
            else:
                model = ReportUnsafe if f_t == 'u' else ReportSafe if f_t == 's' else ReportUnknown
                for args in model.objects.filter(root=self.root).exclude(parent__parent=None)\
                        .values_list('id', 'parent_id'):
                    self.__add_archive('f' if isinstance(f_t, list) else f_t, *args)


def report_attibutes(report):
    return report.attrs.order_by('id').values_list('id', 'attr__name__name', 'attr__value', 'data')


def report_attributes_with_parents(report):
    attrs = []
    parent = report
    while parent is not None:
        attrs = list(parent.attrs.order_by('id').values_list('attr__name__name', 'attr__value')) + attrs
        parent = parent.parent
    return attrs


def remove_verification_files(job):
    for report in ReportComponent.objects.filter(root=job.reportroot, verification=True).exclude(verifier_input=''):
        report.verifier_input.delete()


def get_report_data_type(component, data):
    if component == 'Core' and isinstance(data, dict) and all(isinstance(res, dict) for res in data.values()):
        if all(x in res for x in ['ideal verdict', 'verdict'] for res in data.values()):
            return 'Core:testing'
        elif all(x in res for x in ['before fix', 'after fix'] for res in data.values()) \
                and all('verdict' in data[mod]['before fix'] and 'verdict' in data[mod]['after fix'] for mod in data):
            return 'Core:validation'
    elif component == 'LKVOG' and isinstance(data, dict):
        return 'LKVOG:lines'
    return 'Unknown'


class ReportStatus:
    def __init__(self, report):
        self._report = report
        self.name = _('In progress')
        self.color = '#a4e9eb'
        self.href = None
        self.duration = None
        self.__get_status()

    def __get_status(self):
        if self._report.finish_date is not None:
            self.duration = self._report.finish_date - self._report.start_date
            self.name = _('Finished')
            self.color = '#4ce215'
        try:
            self.href = reverse('reports:unknown', args=[
                ReportUnknown.objects.get(parent=self._report, component=self._report.component).id
            ])
            self.name = _('Failed')
            self.color = None
        except ObjectDoesNotExist:
            pass
        except MultipleObjectsReturned:
            self.name = None


class ReportData:
    def __init__(self, report):
        self._report = report
        self.data = self.__get_data()
        self.type = self.__get_type()

    def __get_type(self):
        component = self._report.component.name
        if component == 'Core' and isinstance(self.data, dict) \
                and all(isinstance(res, dict) for res in self.data.values()):
            if all(x in res for x in ['ideal verdict', 'verdict'] for res in self.data.values()):
                return 'Core:testing'
            elif all(any(x in res for x in ['before fix', 'after fix']) for res in self.data.values()) \
                    and all(('verdict' in self.data[bug]['before fix'] if 'before fix' in self.data[bug] else True)
                            or ('verdict' in self.data[bug]['after fix'] if 'after fix' in self.data[bug] else True)
                            for bug in self.data):
                return 'Core:validation'
        elif component == 'LKVOG' and isinstance(self.data, dict):
            return 'LKVOG:lines'
        return 'Unknown'

    def __get_data(self):
        if self._report.data:
            with self._report.data.file as fp:
                return json.loads(fp.read().decode('utf8'))
        return None
