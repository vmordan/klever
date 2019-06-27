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

from bridge.utils import logger, BridgeException, unique_id
from bridge.vars import UNKNOWN_ERROR, UNSAFE_VERDICTS, USER_ROLES, MARK_STATUS, MARK_UNSAFE, MARK_TYPE, \
    ASSOCIATION_TYPE
from marks.attributes import create_attributes, get_marks_attributes, get_reports_by_attributes, get_user_attrs, \
    get_basic_attributes
from marks.models import ConvertedTraces, MarkUnsafe, MarkUnsafeHistory, MarkUnsafeReport, MarkUnsafeAttr, \
    MarkUnsafeTag, UnsafeTag, UnsafeReportTag, ReportUnsafeTag
from reports.mea.wrapper import error_trace_pretty_parse, TAG_CONVERSION_FUNCTION, TAG_COMPARISON_FUNCTION, \
    TAG_EDITED_ERROR_TRACE, get_or_convert_error_trace, dump_converted_error_trace, DEFAULT_CONVERSION_FUNCTION, \
    DEFAULT_COMPARISON_FUNCTION, is_trace_equal, automatic_error_trace_editing
from reports.models import ReportComponentLeaf, ReportUnsafe
from users.models import User

UNSAFE_MARK_TIME_THRESHOLD = 1  # sec

OPTIMIZATION_APPLY_FOR_CURRENT = 'apply_for_current'
OPTIMIZATION_DO_NOT_RECALC = 'do_not_recalc'
OPTIMIZATIONS = [OPTIMIZATION_APPLY_FOR_CURRENT, OPTIMIZATION_DO_NOT_RECALC]

CONVERSION_FUNCTION_DO_NOT_USE = "*DO NOT CHANGE*"


def decode_optimizations(encoded) -> set:
    counter = 0
    decoded = set()
    for name in OPTIMIZATIONS:
        if (encoded >> counter) & 1:
            decoded.add(name)
        counter += 1
    return decoded


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
        self.conversion_function_args = self.__get_conversion_function_args(mark_unsafe)
        self.use_edited_error_trace = args.get("use_edited_error_trace", False)

        # Optimizations.
        self.optimizations = set()
        for optimization in OPTIMIZATIONS:
            if args.get(optimization, False):
                self.optimizations.add(optimization)

        if mark_unsafe:
            self.__check_mark_applicability(mark_unsafe)

        self.changes = {}
        self._comparison = None
        self.__check_args()

    def __get_conversion_function_args(self, mark_unsafe) -> dict:
        result = {}
        cfa = self._args.get('conversion_function_args')
        if isinstance(cfa, str):
            if cfa == CONVERSION_FUNCTION_DO_NOT_USE:
                if isinstance(mark_unsafe, MarkUnsafe):
                    last_v = MarkUnsafeHistory.objects.get(mark=mark_unsafe, version=F('mark__version'))
                    result = json.loads(last_v.args)
            else:
                for arg, value in json.loads(cfa).items():
                    if value:
                        result[arg] = value
        return result

    def __check_mark_applicability(self, mark_unsafe):
        is_auto_edit_success = False
        if self.use_edited_error_trace:
            is_auto_edit_success, edited_error_trace, conversion_function, conversion_function_args, comparison_function = \
                automatic_error_trace_editing(mark_unsafe)
            if is_auto_edit_success:
                self.edited_error_trace = edited_error_trace
                self.conversion_function = conversion_function
                self.conversion_function_args = conversion_function_args
                self.comparison_function = comparison_function
            else:
                logger.warning("Automatic editing of error trace failed, using none-edited error trace")
        if not is_auto_edit_success:
            if not self.edited_error_trace:
                self.edited_error_trace = get_or_convert_error_trace(mark_unsafe, self.conversion_function,
                                                                     self.conversion_function_args)
            else:
                self.edited_error_trace = error_trace_pretty_parse(self.edited_error_trace)

        # Check attributes.
        if isinstance(mark_unsafe, ReportUnsafe):
            report = mark_unsafe
        else:
            report = mark_unsafe.report

        if 'attrs' not in self._args:
            self._args['attrs'] = get_basic_attributes(mark_unsafe)

        marks_attrs = get_user_attrs(self._args)
        mark_reports = get_reports_by_attributes('unsafe', marks_attrs, {'report': report})
        if not mark_reports:
            raise BridgeException(_("Mark cannot be applied to the selected attributes"), response_type='json')

        # Check that mark is applicable to the error trace itself.
        if self.initial_error_trace:
            new_report = ReportUnsafe.objects.get(id=self.initial_error_trace)
            mark_unsafe.report = new_report
            mark_unsafe.save()
        converted_error_trace = get_or_convert_error_trace(mark_unsafe, self.conversion_function,
                                                           self.conversion_function_args)
        if not is_trace_equal(self.edited_error_trace, converted_error_trace, self.comparison_function,
                              self.similarity_threshold)[0]:
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

    def __encode_optimizations(self) -> int:
        encoded = 0
        counter = 0
        for name in OPTIMIZATIONS:
            encoded += (int(name in self.optimizations) & 1) << counter
            counter += 1
        return encoded

    def create_mark(self, report):
        mark = MarkUnsafe.objects.create(
            identifier=unique_id(), author=self._user, change_date=now(), format=report.root.job.format,
            job=report.root.job, description=str(self._args.get('description', '')),
            verdict=self._args['verdict'], status=self._args['status'], is_modifiable=self._args['is_modifiable'],
            comparison_function=self.comparison_function, conversion_function=self.conversion_function,
            report=report, optimizations=self.__encode_optimizations()
        )

        try:
            markversion = self.__create_version(mark, self.error_trace_id)
            self.__create_attributes(markversion.id, report)
        except Exception:
            mark.delete()
            raise
        self.changes = ConnectMarks([mark], self.similarity_threshold, self.conversion_function_args,
                                    prime_id=report.id, optimizations=self.optimizations).\
            changes.get(mark.id, {})
        self.__get_tags_changes(RecalculateTags(list(self.changes)).changes)
        update_confirmed_cache([report])
        return mark

    def change_mark(self, mark, recalculate_cache=True):
        last_v = MarkUnsafeHistory.objects.get(mark=mark, version=F('mark__version'))

        old_optimizations = decode_optimizations(mark.optimizations)
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

        if old_optimizations != self.optimizations:
            mark.optimizations = self.__encode_optimizations()
            do_recalc = True

        markversion = self.__create_version(mark, self.error_trace_id)

        try:
            do_recalc |= self.__create_attributes(markversion.id, last_v)
        except Exception:
            markversion.delete()
            raise
        mark.save()

        if OPTIMIZATION_DO_NOT_RECALC in self.optimizations:
            do_recalc = False

        if recalculate_cache:
            if do_recalc:
                changes = ConnectMarks([mark], self.similarity_threshold, self.conversion_function_args,
                                       optimizations=self.optimizations).changes
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
            comparison_function=self.comparison_function, conversion_function=self.conversion_function,
            optimizations=self.__encode_optimizations()
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
        return create_attributes(MarkUnsafeAttr, self._args, markversion_id, inst)

    def __get_tags_changes(self, data):
        for report in self.changes:
            if report.id in data and len(data[report.id]) > 0:
                self.changes[report]['tags'] = list(sorted(data[report.id]))

    def __is_not_used(self):
        pass


class ConnectMarks:
    def __init__(self, marks, similarity_threshold, conversion_function_args: dict, prime_id=None,
                 optimizations=set()):
        self._marks = marks
        self._prime_id = prime_id
        self.changes = {}
        self.similarity_threshold = similarity_threshold
        self.conversion_function_args = conversion_function_args
        self.conversion_functions = {}
        self.comparison_functions = {}
        self.edited_error_trace = {}
        self.optimizations = optimizations

        self._marks_attrs = self.__get_marks_attrs()
        self.marks_reports = get_reports_by_attributes('unsafe', self._marks_attrs)

        if len(self.marks_reports) == 0:
            return
        self.__clear_connections()
        self._author = dict((m.id, m.author) for m in self._marks)

        self.__connect()
        self.__update_verdicts()

    def __get_marks_attrs(self):
        attr_filters = {
            'mark__mark__in': self._marks, 'is_compare': True,
            'mark__version': F('mark__mark__version')
        }
        marks_attrs = get_marks_attributes(MarkUnsafeAttr, attr_filters)
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

    def __update_progress(self, mark, counter_all, counter_applied, number_of_target_unsafes, time_previous):
        if time.time() - time_previous > UNSAFE_MARK_TIME_THRESHOLD:
            try:
                cur_progress = round(100.0 * counter_all / number_of_target_unsafes)
                mes = (counter_applied << 8) | cur_progress
                mark.format = mes
                mark.save()
            except:
                # Since this is aux action, do not stop the whole process only because of it.
                pass
            time_previous = time.time()
        return time_previous

    def __connect(self):
        unsafes_ids = set()
        for mark_id, report_ids in self.marks_reports.items():
            unsafes_ids.update(report_ids)

        patterns = {}
        for converted in ConvertedTraces.objects.filter(id__in=set(self.edited_error_trace.values())):
            with converted.file as fp:
                patterns[converted.id] = json.loads(fp.read().decode('utf8'))
        marks = {}
        for m_id in self.edited_error_trace:
            self.edited_error_trace[m_id] = patterns[self.edited_error_trace[m_id]]
            marks[m_id] = MarkUnsafe.objects.get(id=m_id)

        new_markreports = []

        time_previous = time.time()
        counter_all = 0
        counter_applied = 0

        if OPTIMIZATION_APPLY_FOR_CURRENT in self.optimizations:
            # Optimizations.
            target_job_ids = []
            for mark_id in self.edited_error_trace:
                try:
                    target_job_ids.append(marks[mark_id].report.root.job.id)
                except:
                    # Do not process old format (report was not saved, so we cannot use this optimization).
                    pass
            target_unsafes = None
            if target_job_ids:
                target_unsafes = ReportUnsafe.objects.filter(id__in=unsafes_ids, root__job__id__in=target_job_ids)
            if not target_unsafes:
                target_unsafes = ReportUnsafe.objects.filter(id__in=unsafes_ids)
        else:
            target_unsafes = ReportUnsafe.objects.filter(id__in=unsafes_ids)

        number_of_target_unsafes = target_unsafes.count()

        for unsafe in target_unsafes:
            for mark_id in self.edited_error_trace:
                if unsafe.id not in self.marks_reports[mark_id]:
                    continue
                compare_error = None
                compare_result = 0
                try:
                    converted_error_trace = get_or_convert_error_trace(unsafe, self.conversion_functions[mark_id],
                                                                       self.conversion_function_args)
                    is_equal, compare_result = is_trace_equal(self.edited_error_trace[mark_id], converted_error_trace,
                                                              self.comparison_functions[mark_id],
                                                              self.similarity_threshold)
                    counter_all += 1

                    time_previous = self.__update_progress(marks[mark_id], counter_all, counter_applied,
                                                           number_of_target_unsafes, time_previous)
                    if not is_equal:
                        continue
                    counter_applied += 1
                    time_previous = self.__update_progress(marks[mark_id], counter_all, counter_applied,
                                                           number_of_target_unsafes, time_previous)

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
        for mark_id in marks:
            marks[mark_id].format = 1
            marks[mark_id].save()

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
        self._marks_attrs = self.__get_marks_attrs()
        self.marks_reports = get_reports_by_attributes('unsafe', self._marks_attrs, {'report': unsafe})
        self.__connect()

    def __get_marks_attrs(self):
        attr_filters = {'is_compare': True, 'mark__version': F('mark__mark__version')}
        marks_attrs = get_marks_attributes(MarkUnsafeAttr, attr_filters)
        for m_id, f_comparison, f_conversion, edited_error_trace, verdict, report, similarity, args in \
                MarkUnsafeHistory.objects.filter(mark_id__in=marks_attrs, version=F('mark__version'))\
                        .values_list('mark_id', 'comparison_function', 'conversion_function', 'error_trace_id',
                                     'verdict','mark__report', 'similarity', 'args'):
            self._marks[m_id] = {'comparison_functions': f_comparison, 'conversion_functions': f_conversion,
                                 'edited_error_trace': edited_error_trace, 'verdict': verdict, 'report': report,
                                 'similarity_threshold': similarity, 'args': args}
        return marks_attrs

    def __connect(self):
        new_markreports = []
        for mark_id in self._marks_attrs:
            if not self.marks_reports.get(mark_id, None):
                del self._marks[mark_id]
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
                is_equal, compare_result = is_trace_equal(self._marks[mark_id]['edited_error_trace'],
                                                          converted_error_trace,
                                                          self._marks[mark_id]['comparison_functions'],
                                                          self._marks[mark_id]['similarity_threshold'])
                if not is_equal:
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
