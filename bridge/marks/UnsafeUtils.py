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
import time

from django.db import transaction
from django.db.models import F
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from bridge.utils import logger, BridgeException
from bridge.utils import unique_id
from bridge.vars import UNKNOWN_ERROR, UNSAFE_VERDICTS
from bridge.vars import USER_ROLES, MARK_STATUS, MARK_UNSAFE, MARK_TYPE, ASSOCIATION_TYPE
from marks.models import ConvertedTraces
from marks.models import MarkUnsafe, MarkUnsafeHistory, MarkUnsafeReport, MarkUnsafeAttr, \
    MarkUnsafeTag, UnsafeTag, UnsafeReportTag, ReportUnsafeTag
from reports.mea import error_trace_pretty_parse, \
    compare_error_traces, TAG_CONVERSION_FUNCTION, TAG_COMPARISON_FUNCTION, TAG_EDITED_ERROR_TRACE, \
    get_or_convert_error_trace, dump_converted_error_trace, DEFAULT_CONVERSION_FUNCTION, DEFAULT_COMPARISON_FUNCTION, \
    is_equivalent
from reports.models import ReportComponentLeaf, ReportAttr, ReportUnsafe, Attr, AttrName
from users.models import User


class NewMark:
    def __init__(self, user, args, mark_unsafe=None):
        self._user = user
        self._args = args

        # Specific information
        self.edited_error_trace = args.get(TAG_EDITED_ERROR_TRACE, "")
        self.conversion_function = args.get(TAG_CONVERSION_FUNCTION, DEFAULT_CONVERSION_FUNCTION)
        self.comparison_function = args.get(TAG_COMPARISON_FUNCTION, DEFAULT_COMPARISON_FUNCTION)
        self.similarity_threshold = round(int(args.get('similarity_threshold', 0)))
        self.initial_error_trace = args.get('initial_error_trace')
        self.conversion_function_args = json.loads(args.get('conversion_function_args', "{}"))
        self.apply_for_current = args.get('apply_for_current', False)

        if mark_unsafe:
            self.__check_mark_applicability(mark_unsafe)

        self.changes = {}
        self._comparison = None
        self.__check_args()

    def __check_mark_applicability(self, mark_unsafe):
        if not self.edited_error_trace:
            self.edited_error_trace = get_or_convert_error_trace(mark_unsafe, self.conversion_function,
                                                                 self.conversion_function_args)
        else:
            self.edited_error_trace = error_trace_pretty_parse(self.edited_error_trace)
        # Check that mark is applicable to the error trace itself.
        if self.initial_error_trace:
            new_report = ReportUnsafe.objects.get(id=self.initial_error_trace)
            mark_unsafe.report = new_report
            mark_unsafe.save()
        converted_error_trace = get_or_convert_error_trace(mark_unsafe, self.conversion_function,
                                                           self.conversion_function_args)
        if not is_equivalent(compare_error_traces(self.edited_error_trace, converted_error_trace,
                                                  self.comparison_function), self.similarity_threshold):
            raise BridgeException(_("Mark cannot be applied to the initial error trace"), response_type='json')
        self.error_trace_id = dump_converted_error_trace(self.edited_error_trace)

    def __check_args(self):
        if not isinstance(self._args, dict):
            raise ValueError('Wrong type: args (%s)' % type(self._args))
        if not isinstance(self._user, User):
            raise ValueError('Wrong type: user (%s)' % type(self._user))
        if self._args.get('verdict') not in set(x[0] for x in MARK_UNSAFE):
            raise ValueError('Unsupported verdict: %s' % self._args.get('verdict'))
        if self._args.get('status') not in set(x[0] for x in MARK_STATUS):
            raise ValueError('Unsupported status: %s' % self._args.get('status'))
        if not isinstance(self._args.get('comment'), str):
            self._args['comment'] = ''

        if self._user.extended.role != USER_ROLES[2][0]:
            self._args['is_modifiable'] = MarkUnsafe._meta.get_field('is_modifiable').default
        elif not isinstance(self._args.get('is_modifiable'), bool):
            raise ValueError('Wrong type: is_modifiable (%s)' % type(self._args.get('is_modifiable')))

        if 'tags' not in self._args or not isinstance(self._args['tags'], list):
            raise ValueError('Unsupported tags: %s' % self._args.get('tags'))

        if 'autoconfirm' in self._args and not isinstance(self._args['autoconfirm'], bool):
            raise ValueError('Wrong type: autoconfirm (%s)' % type(self._args['autoconfirm']))

        tags = set(int(t) for t in self._args['tags'])
        if len(tags) > 0:
            tags_in_db = {}
            for tid, pid in UnsafeTag.objects.all().values_list('id', 'parent_id'):
                tags_in_db[tid] = pid
            if any(t not in tags_in_db for t in tags):
                raise BridgeException(_('One of tags was not found'))
            tags_parents = set()
            for t in tags:
                while tags_in_db[t] is not None:
                    tags_parents.add(tags_in_db[t])
                    t = tags_in_db[t]
            tags |= tags_parents
        self._args['tags'] = tags

    def create_mark(self, report):
        mark = MarkUnsafe.objects.create(
            identifier=unique_id(), author=self._user, change_date=now(), format=report.root.job.format,
            job=report.root.job, description=str(self._args.get('description', '')),
            verdict=self._args['verdict'], status=self._args['status'], is_modifiable=self._args['is_modifiable'],
            comparison_function=self.comparison_function, conversion_function=self.conversion_function,
            report=report
        )

        try:
            markversion = self.__create_version(mark, self.error_trace_id)
            self.__create_attributes(markversion.id, report)
        except Exception:
            mark.delete()
            raise
        self.changes = ConnectMarks([mark], self.similarity_threshold, self.conversion_function_args,
                                    prime_id=report.id, apply_for_current=self.apply_for_current).\
            changes.get(mark.id, {})
        self.__get_tags_changes(RecalculateTags(list(self.changes)).changes)
        update_confirmed_cache([report])
        return mark

    def change_mark(self, mark, recalculate_cache=True):
        last_v = MarkUnsafeHistory.objects.get(mark=mark, version=F('mark__version'))

        mark.author = self._user
        mark.change_date = now()
        mark.status = self._args['status']
        mark.description = str(self._args.get('description', ''))
        mark.version += 1
        mark.is_modifiable = self._args['is_modifiable']

        recalc_verdicts = False
        if mark.verdict != self._args['verdict']:
            mark.verdict = self._args['verdict']
            recalc_verdicts = True

        do_recalc = False
        if mark.conversion_function != self.conversion_function:
            mark.conversion_function = self.conversion_function
            do_recalc = True

        if mark.comparison_function != self.comparison_function:
            mark.comparison_function = self.comparison_function
            do_recalc = True

        with last_v.error_trace.file as fp:
            old_trace = json.loads(fp.read().decode('utf8'))
        if self.edited_error_trace != old_trace:
            do_recalc = True
        if not last_v.similarity == self.similarity_threshold:
            do_recalc = True

        markversion = self.__create_version(mark, self.error_trace_id)

        try:
            do_recalc |= self.__create_attributes(markversion.id, last_v)
        except Exception:
            markversion.delete()
            raise
        mark.save()

        if recalculate_cache:
            if do_recalc:
                changes = ConnectMarks([mark], self.similarity_threshold, self.conversion_function_args,
                                       apply_for_current=self.apply_for_current).changes
            else:
                changes = self.__create_changes(mark)
                if recalc_verdicts:
                    changes = UpdateVerdicts(changes).changes
            self.changes = changes.get(mark.id, {})
            self.__get_tags_changes(RecalculateTags(list(self.changes)).changes)
            update_confirmed_cache(list(self.changes))
        return mark

    def upload_mark(self):
        if 'error_trace' not in self._args and not isinstance(self._args['error_trace'], str):
            raise ValueError('Unsafe mark error_trace is required')
        if 'format' not in self._args:
            raise BridgeException(_('Unsafe mark format is required'))
        if isinstance(self._args.get('identifier'), str) and 0 < len(self._args['identifier']) < 255:
            if MarkUnsafe.objects.filter(identifier=self._args['identifier']).count() > 0:
                raise BridgeException(_("The mark with identifier specified in the archive already exists"))
        else:
            self._args['identifier'] = unique_id()
        self.error_trace_id = dump_converted_error_trace(self._args['error_trace'])
        mark = MarkUnsafe.objects.create(
            identifier=self._args['identifier'], author=self._user, change_date=now(), format=self._args['format'],
            type=MARK_TYPE[2][0], description=str(self._args.get('description', '')),
            verdict=self._args['verdict'], status=self._args['status'], is_modifiable=self._args['is_modifiable'],
            comparison_function=self.comparison_function, conversion_function=self.conversion_function
        )

        try:
            markversion = self.__create_version(mark, self.error_trace_id)
            self.__create_attributes(markversion.id)
        except Exception:
            mark.delete()
            raise
        return mark

    def __create_changes(self, mark):
        self.__is_not_used()
        changes = {mark.id: {}}
        for mr in mark.markreport_set.all().select_related('report'):
            changes[mark.id][mr.report] = {'kind': '=', 'verdict1': mr.report.verdict}
        return changes

    def __create_version(self, mark, error_trace):
        markversion = MarkUnsafeHistory.objects.create(
            mark=mark, version=mark.version, status=mark.status, verdict=mark.verdict,
            author=mark.author, change_date=mark.change_date, comment=self._args['comment'],
            error_trace=error_trace, description=mark.description, comparison_function=self.comparison_function,
            conversion_function=self.conversion_function, similarity=self.similarity_threshold,
            args=json.dumps(self.conversion_function_args, sort_keys=True)
        )
        MarkUnsafeTag.objects.bulk_create(
            list(MarkUnsafeTag(tag_id=t_id, mark_version=markversion) for t_id in self._args['tags'])
        )
        return markversion

    def __create_attributes(self, markversion_id, inst=None):
        if 'attrs' in self._args and (not isinstance(self._args['attrs'], list) or len(self._args['attrs']) == 0):
            del self._args['attrs']
        if 'attrs' in self._args:
            for a in self._args['attrs']:
                if not isinstance(a, dict) or not isinstance(a.get('attr'), str) \
                        or not isinstance(a.get('is_compare'), bool):
                    raise ValueError('Wrong attribute found: %s' % a)
                if inst is None and not isinstance(a.get('value'), str):
                    raise ValueError('Wrong attribute found: %s' % a)

        need_recalc = False
        new_attrs = []
        if isinstance(inst, ReportUnsafe):
            for a_id, a_name, associate in inst.attrs.order_by('id')\
                    .values_list('attr_id', 'attr__name__name', 'associate'):
                if 'attrs' in self._args:
                    for a in self._args['attrs']:
                        if a['attr'] == a_name:
                            new_attrs.append(MarkUnsafeAttr(
                                mark_id=markversion_id, attr_id=a_id, is_compare=a['is_compare']
                            ))
                            break
                    else:
                        raise ValueError('Not enough attributes in args')
                else:
                    new_attrs.append(MarkUnsafeAttr(mark_id=markversion_id, attr_id=a_id, is_compare=associate))
        elif isinstance(inst, MarkUnsafeHistory):
            for a_id, a_name, is_compare in inst.attrs.order_by('id')\
                    .values_list('attr_id', 'attr__name__name', 'is_compare'):
                if 'attrs' in self._args:
                    for a in self._args['attrs']:
                        if a['attr'] == a_name:
                            new_attrs.append(MarkUnsafeAttr(
                                mark_id=markversion_id, attr_id=a_id, is_compare=a['is_compare']
                            ))
                            if a['is_compare'] != is_compare:
                                need_recalc = True
                            break
                    else:
                        raise ValueError('Not enough attributes in args')
                else:
                    new_attrs.append(MarkUnsafeAttr(mark_id=markversion_id, attr_id=a_id, is_compare=is_compare))
        else:
            if 'attrs' not in self._args:
                raise ValueError('Attributes are required')
            for a in self._args['attrs']:
                attr = Attr.objects.get_or_create(
                    name=AttrName.objects.get_or_create(name=a['attr'])[0], value=a['value']
                )[0]
                new_attrs.append(MarkUnsafeAttr(mark_id=markversion_id, attr=attr, is_compare=a['is_compare']))
        MarkUnsafeAttr.objects.bulk_create(new_attrs)
        return need_recalc

    def __get_tags_changes(self, data):
        for report in self.changes:
            if report.id in data and len(data[report.id]) > 0:
                self.changes[report]['tags'] = list(sorted(data[report.id]))

    def __is_not_used(self):
        pass


class ConnectMarks:
    def __init__(self, marks, similarity_threshold, conversion_function_args: dict, prime_id=None,
                 apply_for_current=False):
        self._marks = marks
        self._prime_id = prime_id
        self.changes = {}
        self.similarity_threshold = similarity_threshold
        self.conversion_function_args = conversion_function_args
        self.conversion_functions = {}
        self.comparison_functions = {}
        self.edited_error_trace = {}
        self.apply_for_current = apply_for_current

        self._marks_attrs = self.__get_marks_attrs()
        self._unsafes_attrs = self.__get_unsafes_attrs()
        if len(self._unsafes_attrs) == 0:
            return
        self.__clear_connections()
        self._author = dict((m.id, m.author) for m in self._marks)

        self.__connect()
        self.__update_verdicts()

    def __get_unsafes_attrs(self):
        self.__is_not_used()
        attrs_ids = set()
        for m_id in self._marks_attrs:
            attrs_ids |= self._marks_attrs[m_id]

        unsafes_attrs = {}
        for r_id, a_id in ReportAttr.objects.exclude(report__reportunsafe=None).filter(attr_id__in=attrs_ids)\
                .values_list('report_id', 'attr_id'):
            if r_id not in unsafes_attrs:
                unsafes_attrs[r_id] = set()
            unsafes_attrs[r_id].add(a_id)
        return unsafes_attrs

    def __get_marks_attrs(self):
        attr_filters = {
            'mark__mark__in': self._marks, 'is_compare': True,
            'mark__version': F('mark__mark__version')
        }
        marks_attrs = {}
        for attr_id, mark_id in MarkUnsafeAttr.objects.filter(**attr_filters).values_list('attr_id', 'mark__mark_id'):
            if mark_id not in marks_attrs:
                marks_attrs[mark_id] = set()
            marks_attrs[mark_id].add(attr_id)
        for m_id, comparison_name, conversion_name, pattern_id in MarkUnsafeHistory.objects\
                .filter(mark_id__in=marks_attrs, version=F('mark__version'))\
                .values_list('mark_id', 'comparison_function', 'conversion_function', 'error_trace_id'):
            self.comparison_functions[m_id] = comparison_name
            self.conversion_functions[m_id] = conversion_name
            self.edited_error_trace[m_id] = pattern_id
        return marks_attrs

    def __clear_connections(self):
        for mr in MarkUnsafeReport.objects.filter(mark__in=self._marks).select_related('report'):
            if mr.mark_id not in self.changes:
                self.changes[mr.mark_id] = {}
            self.changes[mr.mark_id][mr.report] = {'kind': '-', 'result1': mr.result, 'verdict1': mr.report.verdict}
        MarkUnsafeReport.objects.filter(mark__in=self._marks).delete()

    def __connect(self):
        marks_reports = {}
        unsafes_ids = set()
        for mark_id in self._marks_attrs:
            marks_reports[mark_id] = set()
            for unsafe_id in self._unsafes_attrs:
                if self._marks_attrs[mark_id].issubset(self._unsafes_attrs[unsafe_id]):
                    marks_reports[mark_id].add(unsafe_id)
                    unsafes_ids.add(unsafe_id)
            if len(marks_reports[mark_id]) == 0:
                del self.edited_error_trace[mark_id]
                del self.comparison_functions[mark_id]
                del self.conversion_functions[mark_id]
        patterns = {}
        for converted in ConvertedTraces.objects.filter(id__in=set(self.edited_error_trace.values())):
            with converted.file as fp:
                patterns[converted.id] = json.loads(fp.read().decode('utf8'))
        for m_id in self.edited_error_trace:
            self.edited_error_trace[m_id] = patterns[self.edited_error_trace[m_id]]

        new_markreports = []

        time_start = time.process_time()
        for unsafe in ReportUnsafe.objects.filter(id__in=unsafes_ids):
            for mark_id in self.edited_error_trace:
                if unsafe.id not in marks_reports[mark_id]:
                    continue
                if self.apply_for_current:
                    try:
                        current_job_id = MarkUnsafe.objects.get(id=mark_id).report.root.job.id
                        compared_job_id = unsafe.root.job.id
                        if not current_job_id == compared_job_id:
                            # Skip comparison for other reports for faster results.
                            continue
                    except:
                        # Do not process old format (report was not saved, so we cannot use this heuristic).
                        pass
                compare_error = None
                compare_result = 0
                try:
                    converted_error_trace = get_or_convert_error_trace(unsafe, self.conversion_functions[mark_id],
                                                                       self.conversion_function_args)
                    compare_result = compare_error_traces(self.edited_error_trace[mark_id], converted_error_trace,
                                                          self.comparison_functions[mark_id])
                    if not is_equivalent(compare_result, self.similarity_threshold):
                        continue

                except BridgeException as e:
                    compare_error = str(e)
                except Exception as e:
                    logger.exception("Error traces comparison failed: %s" % e, exc_info=e)
                    compare_error = str(UNKNOWN_ERROR)

                ass_type = ASSOCIATION_TYPE[0][0]
                if self._prime_id == unsafe.id:
                    ass_type = ASSOCIATION_TYPE[1][0]
                new_markreports.append(MarkUnsafeReport(
                    mark_id=mark_id, report=unsafe, result=compare_result, error=compare_error,
                    type=ass_type, author=self._author[mark_id]
                ))
                if mark_id not in self.changes:
                    self.changes[mark_id] = {}
                if unsafe in self.changes[mark_id]:
                    self.changes[mark_id][unsafe]['kind'] = '='
                    self.changes[mark_id][unsafe]['result2'] = compare_result
                else:
                    self.changes[mark_id][unsafe] = {
                        'kind': '+', 'result2': compare_result, 'verdict1': unsafe.verdict
                    }
        MarkUnsafeReport.objects.bulk_create(new_markreports)
        time_start = time.process_time() - time_start
        print("Filtering time is {}".format(time_start))

    def __update_verdicts(self):
        unsafe_verdicts = {}
        for mark_id in self.changes:
            for unsafe in self.changes[mark_id]:
                unsafe_verdicts[unsafe] = set()
        for mr in MarkUnsafeReport.objects.filter(report__in=unsafe_verdicts, error=None, result__gt=0)\
                .exclude(type=ASSOCIATION_TYPE[2][0]).select_related('mark'):
            unsafe_verdicts[mr.report].add(mr.mark.verdict)

        unsafes_to_update = {}
        for unsafe in unsafe_verdicts:
            old_verdict = unsafe.verdict
            new_verdict = self.__calc_verdict(unsafe_verdicts[unsafe])
            if old_verdict != new_verdict:
                if new_verdict not in unsafes_to_update:
                    unsafes_to_update[new_verdict] = set()
                unsafes_to_update[new_verdict].add(unsafe.id)
                for mark_id in self.changes:
                    if unsafe in self.changes[mark_id]:
                        self.changes[mark_id][unsafe]['verdict2'] = new_verdict
        self.__new_verdicts(unsafes_to_update)

    @transaction.atomic
    def __new_verdicts(self, unsafes_to_update):
        self.__is_not_used()
        for v in unsafes_to_update:
            ReportUnsafe.objects.filter(id__in=unsafes_to_update[v]).update(verdict=v)

    def __calc_verdict(self, verdicts):
        self.__is_not_used()
        assert isinstance(verdicts, set), 'Set expected'
        if len(verdicts) == 0:
            return UNSAFE_VERDICTS[5][0]
        elif len(verdicts) == 1:
            return verdicts.pop()
        return UNSAFE_VERDICTS[4][0]

    def __is_not_used(self):
        pass


class ConnectReport:
    def __init__(self, unsafe):
        self._unsafe = unsafe
        self._marks = {}

        MarkUnsafeReport.objects.filter(report=self._unsafe).delete()
        self._unsafe_attrs = set(a_id for a_id, in self._unsafe.attrs.values_list('attr_id'))
        self._marks_attrs = self.__get_marks_attrs()

        self.__connect()

    def __get_marks_attrs(self):
        attr_filters = {'is_compare': True, 'mark__version': F('mark__mark__version')}
        marks_attrs = {}
        for attr_id, mark_id in MarkUnsafeAttr.objects.filter(**attr_filters).values_list('attr_id', 'mark__mark_id'):
            if mark_id not in marks_attrs:
                marks_attrs[mark_id] = set()
            marks_attrs[mark_id].add(attr_id)
        for m_id, f_comparison, f_conversion, edited_error_trace, verdict, report, similarity, args in MarkUnsafeHistory.objects\
                .filter(mark_id__in=marks_attrs, version=F('mark__version'))\
                .values_list('mark_id', 'comparison_function', 'conversion_function', 'error_trace_id', 'verdict',
                             'mark__report', 'similarity', 'args'):
            self._marks[m_id] = {'comparison_functions': f_comparison, 'conversion_functions': f_conversion,
                                 'edited_error_trace': edited_error_trace, 'verdict': verdict, 'report': report,
                                 'similarity_threshold': similarity, 'args': args}
        return marks_attrs

    def __connect(self):
        new_markreports = []
        for mark_id in self._marks_attrs:
            if not self._marks_attrs[mark_id].issubset(self._unsafe_attrs):
                del self._marks[mark_id]
                continue
        patterns = {}
        for converted in ConvertedTraces.objects.filter(
                id__in=set(self._marks[mid]['edited_error_trace'] for mid in self._marks)):
            with converted.file as fp:
                patterns[converted.id] = fp.read().decode('utf8')
        for m_id in self._marks:
            self._marks[m_id]['edited_error_trace'] = patterns[self._marks[m_id]['edited_error_trace']]

        for mark_id in self._marks:
            compare_result = 0
            compare_error = None
            try:
                converted_error_trace = get_or_convert_error_trace(self._unsafe,
                                                                   self._marks[mark_id]['conversion_functions'],
                                                                   json.loads(self._marks[mark_id]['args'] or "{}"))
                compare_result = compare_error_traces(self._marks[mark_id]['edited_error_trace'], converted_error_trace,
                                                      self._marks[mark_id]['comparison_functions'])
                if not is_equivalent(compare_result, self._marks[mark_id]['similarity_threshold']):
                    continue
            except BridgeException as e:
                compare_error = str(e)
            except Exception as e:
                logger.exception("Error traces comparison failed: %s" % e)
                compare_error = str(UNKNOWN_ERROR)
            new_markreports.append(MarkUnsafeReport(
                mark_id=mark_id, report=self._unsafe, result=compare_result, error=compare_error
            ))
        MarkUnsafeReport.objects.bulk_create(new_markreports)

        verdicts = set(self._marks[m_id]['verdict'] for m_id in
                       list(mr.mark_id for mr in new_markreports if mr.error is None and mr.result > 0))
        if len(verdicts) == 0:
            new_verdict = UNSAFE_VERDICTS[5][0]
        elif len(verdicts) == 1:
            new_verdict = verdicts.pop()
        else:
            new_verdict = UNSAFE_VERDICTS[4][0]

        if self._unsafe.verdict != new_verdict:
            self._unsafe.verdict = new_verdict
            self._unsafe.save()


class RecalculateTags:
    def __init__(self, reports):
        self.reports = reports
        self.changes = {}
        self.__fill_leaves_cache()
        self.__fill_reports_cache()

    def __fill_leaves_cache(self):
        old_numbers = {}
        tags_names = {}
        for urt in UnsafeReportTag.objects.filter(report__in=self.reports).select_related('tag'):
            old_numbers[(urt.tag_id, urt.report_id)] = urt.number
            tags_names[urt.tag_id] = urt.tag.tag
        UnsafeReportTag.objects.filter(report__in=self.reports).delete()
        marks = {}
        for m_id, r_id in MarkUnsafeReport.objects.filter(report__in=self.reports, error=None, result__gt=0) \
                .exclude(type=ASSOCIATION_TYPE[2][0]).values_list('mark_id', 'report_id'):
            if m_id not in marks:
                marks[m_id] = set()
            marks[m_id].add(r_id)
        tags = {}
        for t_id, m_id, t_name in MarkUnsafeTag.objects.filter(
            mark_version__mark_id__in=marks, mark_version__version=F('mark_version__mark__version')
        ).values_list('tag_id', 'mark_version__mark_id', 'tag__tag'):
            tags_names[t_id] = t_name
            for r_id in marks[m_id]:
                if (t_id, r_id) not in tags:
                    tags[(t_id, r_id)] = 0
                tags[(t_id, r_id)] += 1
        for tr_id in set(tags) | set(old_numbers):
            old_n = old_numbers.get(tr_id, 0)
            new_n = tags.get(tr_id, 0)
            if tr_id[1] not in self.changes:
                self.changes[tr_id[1]] = []
            self.changes[tr_id[1]].append((tags_names[tr_id[0]], old_n, new_n))
        UnsafeReportTag.objects.bulk_create(list(
            UnsafeReportTag(report_id=r_id, tag_id=t_id, number=tags[(t_id, r_id)]) for t_id, r_id in tags)
        )

    def __fill_reports_cache(self):
        reports = set(leaf['report_id']
                      for leaf in ReportComponentLeaf.objects.filter(unsafe__in=self.reports).values('report_id'))
        ReportUnsafeTag.objects.filter(report_id__in=reports).delete()
        reports_data = {}
        all_unsafes = set()
        for leaf in ReportComponentLeaf.objects.filter(report_id__in=reports).exclude(unsafe=None):
            if leaf.report_id not in reports_data:
                reports_data[leaf.report_id] = {'leaves': set(), 'numbers': {}}
            reports_data[leaf.report_id]['leaves'].add(leaf.unsafe_id)
            all_unsafes.add(leaf.unsafe_id)
        for rt in UnsafeReportTag.objects.filter(report_id__in=all_unsafes):
            for rc_id in reports_data:
                if rt.report_id in reports_data[rc_id]['leaves']:
                    if rt.tag_id in reports_data[rc_id]['numbers']:
                        reports_data[rc_id]['numbers'][rt.tag_id] += rt.number
                    else:
                        reports_data[rc_id]['numbers'][rt.tag_id] = rt.number
        new_reporttags = []
        for rc_id in reports_data:
            for t_id in reports_data[rc_id]['numbers']:
                if reports_data[rc_id]['numbers'][t_id] > 0:
                    new_reporttags.append(ReportUnsafeTag(
                        report_id=rc_id, tag_id=t_id, number=reports_data[rc_id]['numbers'][t_id]
                    ))
        ReportUnsafeTag.objects.bulk_create(new_reporttags)


class UpdateVerdicts:
    def __init__(self, changes):
        self.changes = changes
        if len(self.changes) > 0:
            self.__update_verdicts()

    def __update_verdicts(self):
        unsafe_verdicts = {}
        for mark_id in self.changes:
            for unsafe in self.changes[mark_id]:
                unsafe_verdicts[unsafe] = set()
        for mr in MarkUnsafeReport.objects.filter(report__in=unsafe_verdicts, error=None, result__gt=0)\
                .exclude(type=ASSOCIATION_TYPE[2][0]).select_related('mark'):
            unsafe_verdicts[mr.report].add(mr.mark.verdict)

        unsafes_to_update = {}
        for unsafe in unsafe_verdicts:
            new_verdict = self.__calc_verdict(unsafe_verdicts[unsafe])
            if unsafe.verdict == new_verdict:
                # Verdict wasn't changed
                continue
            if new_verdict not in unsafes_to_update:
                unsafes_to_update[new_verdict] = set()
            unsafes_to_update[new_verdict].add(unsafe.id)

            for mark_id in self.changes:
                if unsafe in self.changes[mark_id]:
                    self.changes[mark_id][unsafe]['verdict2'] = new_verdict
        self.__new_verdicts(unsafes_to_update)

    @transaction.atomic
    def __new_verdicts(self, unsafes_to_update):
        self.__is_not_used()
        for v in unsafes_to_update:
            ReportUnsafe.objects.filter(id__in=unsafes_to_update[v]).update(verdict=v)

    def __calc_verdict(self, verdicts):
        self.__is_not_used()
        # verdicts is set (otherwise there is bug here)
        v_num = len(verdicts)
        if v_num == 0:
            # No marks
            return UNSAFE_VERDICTS[5][0]
        elif v_num == 1:
            return verdicts.pop()
        # Several different verdicts
        return UNSAFE_VERDICTS[4][0]

    def __is_not_used(self):
        pass


class RecalculateConnections:
    def __init__(self, roots):
        self._roots = roots
        self.__recalc()

    def __recalc(self):
        ReportUnsafeTag.objects.filter(report__root__in=self._roots).delete()
        UnsafeReportTag.objects.filter(report__root__in=self._roots).delete()
        MarkUnsafeReport.objects.filter(report__root__in=self._roots).delete()
        ReportUnsafe.objects.filter(root__in=self._roots).update(verdict=UNSAFE_VERDICTS[5][0], has_confirmed=False)
        unsafes = []
        for unsafe in ReportUnsafe.objects.filter(root__in=self._roots):
            ConnectReport(unsafe)
            unsafes.append(unsafe)
        RecalculateTags(unsafes)


def delete_marks(marks):
    changes = {}
    for mark in marks:
        changes[mark.id] = {}
    MarkUnsafe.objects.filter(id__in=changes).update(version=0)
    for mr in MarkUnsafeReport.objects.filter(mark__in=marks, error=None).select_related('report'):
        changes[mr.mark_id][mr.report] = {'kind': '-', 'verdict1': mr.report.verdict}
    MarkUnsafe.objects.filter(id__in=changes).delete()
    changes = UpdateVerdicts(changes).changes
    unsafes_changes = {}
    for m_id in changes:
        for report in changes[m_id]:
            unsafes_changes[report] = changes[m_id][report]
    RecalculateTags(unsafes_changes)
    update_confirmed_cache(list(unsafes_changes))
    return unsafes_changes


def update_confirmed_cache(unsafes):
    unsafes_set= set(unsafe.id for unsafe in unsafes)
    with_confirmed = set(MarkUnsafeReport.objects.filter(
        report_id__in=unsafes_set, type=ASSOCIATION_TYPE[1][0], error=None, result__gt=0
    ).values_list('report_id', flat=True))

    ReportUnsafe.objects.filter(id__in=unsafes_set - with_confirmed).update(has_confirmed=False)
    ReportUnsafe.objects.filter(id__in=with_confirmed).update(has_confirmed=True)
