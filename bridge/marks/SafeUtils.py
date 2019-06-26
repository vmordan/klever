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

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models import F, Q
from django.utils.timezone import now
from django.utils.translation import ugettext_lazy as _

from bridge.utils import unique_id, BridgeException
from bridge.vars import USER_ROLES, SAFE_VERDICTS, MARK_SAFE, MARK_STATUS, MARK_TYPE, ASSOCIATION_TYPE
from marks.attributes import create_attributes, get_marks_attributes, get_reports_by_attributes
from marks.models import MarkSafe, MarkSafeHistory, MarkSafeReport, MarkSafeAttr, \
    SafeTag, MarkSafeTag, SafeReportTag, ReportSafeTag, SafeAssociationLike
from reports.models import ReportComponentLeaf, ReportSafe, Attr, AttrName
from users.models import User


class NewMark:
    def __init__(self, user, args):
        self._user = user
        self._args = args
        self.changes = {}
        self.__check_args()

    def __check_args(self):
        if not isinstance(self._args, dict):
            raise ValueError('Wrong type: args (%s)' % type(self._args))
        if not isinstance(self._user, User):
            raise ValueError('Wrong type: user (%s)' % type(self._user))
        if self._args.get('verdict') not in set(x[0] for x in MARK_SAFE):
            raise ValueError('Unsupported verdict: %s' % self._args.get('verdict'))
        if self._args.get('status') not in set(x[0] for x in MARK_STATUS):
            raise ValueError('Unsupported status: %s' % self._args.get('status'))
        if not isinstance(self._args.get('comment'), str):
            self._args['comment'] = ''

        if self._user.extended.role != USER_ROLES[2][0]:
            self._args['is_modifiable'] = MarkSafe._meta.get_field('is_modifiable').default
        elif not isinstance(self._args.get('is_modifiable'), bool):
            raise ValueError('Wrong type: is_modifiable (%s)' % type(self._args.get('is_modifiable')))

        if 'tags' not in self._args or not isinstance(self._args['tags'], list):
            raise ValueError('Unsupported tags: %s' % self._args.get('tags'))

        if 'autoconfirm' in self._args and not isinstance(self._args['autoconfirm'], bool):
            raise ValueError('Wrong type: autoconfirm (%s)' % type(self._args['autoconfirm']))

        tags = set(int(t) for t in self._args['tags'])
        if len(tags) > 0:
            tags_in_db = {}
            for tid, pid in SafeTag.objects.all().values_list('id', 'parent_id'):
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
        mark = MarkSafe.objects.create(
            identifier=unique_id(), author=self._user, change_date=now(), format=report.root.job.format,
            job=report.root.job, status=self._args['status'], description=str(self._args.get('description', '')),
            is_modifiable=self._args['is_modifiable'], verdict=self._args['verdict']
        )

        try:
            markversion = self.__create_version(mark)
            self.__create_attributes(markversion.id, report)
        except Exception:
            mark.delete()
            raise
        self.changes = ConnectMarks([mark], prime_id=report.id).changes.get(mark.id, {})
        self.__get_tags_changes(RecalculateTags(list(self.changes)).changes)
        update_confirmed_cache([report])
        return mark

    def change_mark(self, mark, recalculate_cache=True):
        last_v = MarkSafeHistory.objects.get(mark=mark, version=F('mark__version'))

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

        markversion = self.__create_version(mark)
        try:
            do_recalc = self.__create_attributes(markversion.id, last_v)
        except Exception:
            markversion.delete()
            raise
        mark.save()

        if recalculate_cache:
            if do_recalc or not self._args.get('autoconfirm', False):
                MarkSafeReport.objects.filter(mark_id=mark.id).update(type=ASSOCIATION_TYPE[0][0])
                SafeAssociationLike.objects.filter(association__mark=mark).delete()
            if do_recalc:
                changes = ConnectMarks([mark]).changes
            else:
                changes = self.__create_changes(mark)
                if recalc_verdicts:
                    changes = UpdateVerdicts(changes).changes
            self.changes = changes.get(mark.id, {})
            self.__get_tags_changes(RecalculateTags(list(self.changes)).changes)
            update_confirmed_cache(list(self.changes))
        return mark

    def upload_mark(self):
        if 'format' not in self._args:
            raise BridgeException(_('Safe mark format is required'))
        if isinstance(self._args.get('identifier'), str) and 0 < len(self._args['identifier']) < 255:
            if MarkSafe.objects.filter(identifier=self._args['identifier']).count() > 0:
                raise BridgeException(_("The mark with identifier specified in the archive already exists"))
        else:
            self._args['identifier'] = unique_id()
        mark = MarkSafe.objects.create(
            identifier=self._args['identifier'], author=self._user, change_date=now(), format=self._args['format'],
            type=MARK_TYPE[2][0], status=self._args['status'], description=str(self._args.get('description', '')),
            is_modifiable=self._args['is_modifiable'], verdict=self._args['verdict']
        )

        try:
            markversion = self.__create_version(mark)
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

    def __create_version(self, mark):
        markversion = MarkSafeHistory.objects.create(
            mark=mark, version=mark.version, status=mark.status, verdict=mark.verdict, description=mark.description,
            author=mark.author, change_date=mark.change_date, comment=self._args['comment']
        )
        MarkSafeTag.objects.bulk_create(
            list(MarkSafeTag(tag_id=t_id, mark_version=markversion) for t_id in self._args['tags'])
        )
        return markversion

    def __create_attributes(self, markversion_id, inst=None):
        return create_attributes(MarkSafeAttr, self._args, markversion_id, inst)

    def __get_tags_changes(self, data):
        for report in self.changes:
            if report.id in data and len(data[report.id]) > 0:
                self.changes[report]['tags'] = list(sorted(data[report.id]))

    def __is_not_used(self):
        pass


class ConnectMarks:
    def __init__(self, marks, prime_id=None):
        self._marks = marks
        self._prime_id = prime_id
        self.changes = {}

        self._marks_attrs = self.__get_marks_attrs()
        self.marks_reports = get_reports_by_attributes('safe', self._marks_attrs)
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
        marks_attrs = get_marks_attributes(MarkSafeAttr, attr_filters)
        return marks_attrs

    def __clear_connections(self):
        for mr in MarkSafeReport.objects.filter(mark__in=self._marks)\
                .select_related('report'):
            if mr.mark_id not in self.changes:
                self.changes[mr.mark_id] = {}
            self.changes[mr.mark_id][mr.report] = {'kind': '-', 'verdict1': mr.report.verdict}
        MarkSafeReport.objects.filter(mark__in=self._marks).delete()

    def __connect(self):
        safes_ids = set()
        for mark_id, report_ids in self.marks_reports.items():
            safes_ids.update(report_ids)

        new_markreports = []
        for safe in ReportSafe.objects.filter(id__in=safes_ids):
            for mark_id in self._marks_attrs:
                if safe.id not in self.marks_reports[mark_id]:
                    continue
                ass_type = ASSOCIATION_TYPE[0][0]
                if self._prime_id == safe.id:
                    ass_type = ASSOCIATION_TYPE[1][0]
                new_markreports.append(MarkSafeReport(
                    mark_id=mark_id, report=safe, type=ass_type, author=self._author[mark_id]
                ))
                if mark_id not in self.changes:
                    self.changes[mark_id] = {}
                if safe in self.changes[mark_id]:
                    self.changes[mark_id][safe]['kind'] = '='
                else:
                    self.changes[mark_id][safe] = {'kind': '+', 'verdict1': safe.verdict}
        MarkSafeReport.objects.bulk_create(new_markreports)

    def __update_verdicts(self):
        safe_verdicts = {}
        for mark_id in self.changes:
            for safe in self.changes[mark_id]:
                safe_verdicts[safe] = set()
        for mr in MarkSafeReport.objects.filter(report__in=safe_verdicts).select_related('mark'):
            safe_verdicts[mr.report].add(mr.mark.verdict)

        safes_to_update = {}
        for safe in safe_verdicts:
            old_verdict = safe.verdict
            new_verdict = self.__calc_verdict(safe_verdicts[safe])
            if old_verdict != new_verdict:
                if new_verdict not in safes_to_update:
                    safes_to_update[new_verdict] = set()
                safes_to_update[new_verdict].add(safe.id)
                for mark_id in self.changes:
                    if safe in self.changes[mark_id]:
                        self.changes[mark_id][safe]['verdict2'] = new_verdict
        self.__new_verdicts(safes_to_update)

    @transaction.atomic
    def __new_verdicts(self, safes_to_update):
        self.__is_not_used()
        for v in safes_to_update:
            ReportSafe.objects.filter(id__in=safes_to_update[v]).update(verdict=v)

    def __calc_verdict(self, verdicts):
        self.__is_not_used()
        assert isinstance(verdicts, set), 'Set expected'
        if len(verdicts) == 0:
            return SAFE_VERDICTS[4][0]
        elif len(verdicts) == 1:
            return verdicts.pop()
        return SAFE_VERDICTS[3][0]

    def __is_not_used(self):
        pass


class ConnectReport:
    def __init__(self, safe):
        self.report = safe
        self.__connect()
        RecalculateTags([self.report])

    def __connect(self):
        self.report.markreport_set.all().delete()
        attr_filters = {'is_compare': True, 'mark__version': F('mark__mark__version')}
        marks_attrs = {}
        verdicts = {}
        for mark_id, value, name, op, verdict in MarkSafeAttr.objects.filter(**attr_filters). \
                values_list('mark__mark_id', 'attr__value', 'attr__name__name', 'operator', 'mark__verdict'):
            if mark_id not in marks_attrs:
                marks_attrs[mark_id] = set()
                verdicts[mark_id] = set()
            verdicts[mark_id].add(verdict)
            marks_attrs[mark_id].add((name, value, op))
        marks_reports = get_reports_by_attributes('safe', marks_attrs, {'report': self.report})

        new_markreports = []
        verdicts_set = set()
        for mark_id, report_ids in marks_reports.items():
            if report_ids:
                new_markreports.append(MarkSafeReport(mark_id=mark_id, report=self.report))
                verdicts_set.update(verdicts[mark_id])
        MarkSafeReport.objects.bulk_create(new_markreports)

        if len(verdicts_set) == 0:
            new_verdict = SAFE_VERDICTS[4][0]
        elif len(verdicts_set) == 1:
            new_verdict = verdicts_set.pop()
        else:
            new_verdict = SAFE_VERDICTS[3][0]

        if new_verdict != self.report.verdict:
            self.report.verdict = new_verdict
            self.report.save()


class RecalculateTags:
    def __init__(self, reports):
        self.reports = reports
        self.changes = {}
        if len(self.reports) > 0:
            self.__fill_leaves_cache()
            self.__fill_reports_cache()

    def __fill_leaves_cache(self):
        old_numbers = {}
        tags_names = {}
        for srt in SafeReportTag.objects.filter(report__in=self.reports).select_related('tag'):
            old_numbers[(srt.tag_id, srt.report_id)] = srt.number
            tags_names[srt.tag_id] = srt.tag.tag
        SafeReportTag.objects.filter(report__in=self.reports).delete()

        # Get marks that are connected with reprots
        marks = {}
        for m_id, r_id in MarkSafeReport.objects.filter(report__in=self.reports).exclude(type=ASSOCIATION_TYPE[2][0])\
                .values_list('mark_id', 'report_id'):
            if m_id not in marks:
                marks[m_id] = set()
            marks[m_id].add(r_id)

        # Calculate number of tags
        tags = {}
        for t_id, m_id, t_name in MarkSafeTag.objects.filter(
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

        # Fill the cache
        SafeReportTag.objects.bulk_create(list(
            SafeReportTag(report_id=r_id, tag_id=t_id, number=tags[(t_id, r_id)]) for t_id, r_id in tags)
        )

    def __fill_reports_cache(self):
        # Affected components' reports
        reports = set(leaf['report_id']
                      for leaf in ReportComponentLeaf.objects.filter(safe__in=self.reports).values('report_id'))

        # Clear cache
        ReportSafeTag.objects.filter(report_id__in=reports).delete()

        # Get all safes for each affected report
        reports_data = {}
        all_safes = set()
        for leaf in ReportComponentLeaf.objects.filter(report_id__in=reports).exclude(safe=None):
            if leaf.report_id not in reports_data:
                reports_data[leaf.report_id] = {'leaves': set(), 'numbers': {}}
            reports_data[leaf.report_id]['leaves'].add(leaf.safe_id)
            all_safes.add(leaf.safe_id)
        for rt in SafeReportTag.objects.filter(report_id__in=all_safes):
            for rc_id in reports_data:
                if rt.report_id in reports_data[rc_id]['leaves']:
                    if rt.tag_id in reports_data[rc_id]['numbers']:
                        reports_data[rc_id]['numbers'][rt.tag_id] += rt.number
                    else:
                        reports_data[rc_id]['numbers'][rt.tag_id] = rt.number

        # Fill new cache
        new_reporttags = []
        for rc_id in reports_data:
            for t_id in reports_data[rc_id]['numbers']:
                if reports_data[rc_id]['numbers'][t_id] > 0:
                    new_reporttags.append(ReportSafeTag(
                        report_id=rc_id, tag_id=t_id, number=reports_data[rc_id]['numbers'][t_id]
                    ))
        ReportSafeTag.objects.bulk_create(new_reporttags)


class UpdateVerdicts:
    def __init__(self, changes):
        self.changes = changes
        if len(self.changes) > 0:
            self.__update_verdicts()

    def __update_verdicts(self):
        safe_verdicts = {}
        for mark_id in self.changes:
            for safe in self.changes[mark_id]:
                safe_verdicts[safe] = set()
        for mr in MarkSafeReport.objects.filter(Q(report__in=safe_verdicts) & ~Q(type=ASSOCIATION_TYPE[2][0]))\
                .select_related('mark'):
            safe_verdicts[mr.report].add(mr.mark.verdict)

        safes_to_update = {}
        for safe in safe_verdicts:
            old_verdict = safe.verdict
            new_verdict = self.__calc_verdict(safe_verdicts[safe])
            if old_verdict != new_verdict:
                if new_verdict not in safes_to_update:
                    safes_to_update[new_verdict] = set()
                safes_to_update[new_verdict].add(safe.id)
                for mark_id in self.changes:
                    if safe in self.changes[mark_id]:
                        self.changes[mark_id][safe]['verdict2'] = new_verdict
        self.__new_verdicts(safes_to_update)

    @transaction.atomic
    def __new_verdicts(self, safes_to_update):
        self.__is_not_used()
        for v in safes_to_update:
            ReportSafe.objects.filter(id__in=safes_to_update[v]).update(verdict=v)

    def __calc_verdict(self, verdicts):
        self.__is_not_used()
        # verdicts is set (otherwise there is bug here)
        v_num = len(verdicts)
        if v_num == 0:
            # No marks
            return SAFE_VERDICTS[4][0]
        elif v_num == 1:
            return verdicts.pop()
        # Several different verdicts
        return SAFE_VERDICTS[3][0]

    def __is_not_used(self):
        pass


class RecalculateConnections:
    def __init__(self, roots):
        self._roots = roots
        self.__recalc()

    def __recalc(self):
        ReportSafeTag.objects.filter(report__root__in=self._roots).delete()
        SafeReportTag.objects.filter(report__root__in=self._roots).delete()
        MarkSafeReport.objects.filter(report__root__in=self._roots).delete()
        ReportSafe.objects.filter(root__in=self._roots).update(verdict=SAFE_VERDICTS[4][0], has_confirmed=False)
        safes = []
        for safe in ReportSafe.objects.filter(root__in=self._roots):
            ConnectReport(safe)
            safes.append(safe)
        RecalculateTags(safes)


class PopulateMarks:
    def __init__(self, manager):
        self.total = 0
        self._author = manager
        self._dbtags = {}
        self._tagnames = {}
        self._marktags = {}
        self._markattrs = {}
        self.__current_tags()
        self._marks = self.__get_data()
        self.__get_attrnames()
        self.__get_attrs()
        self.created = self.__create_marks()
        self.__create_related()
        changes = ConnectMarks(self.created.values()).changes
        reports = []
        for m_id in changes:
            reports.extend(changes[m_id])
        RecalculateTags(reports)

    def __current_tags(self):
        for t_id, parent_id, t_name in SafeTag.objects.values_list('id', 'parent_id', 'tag'):
            self._dbtags[t_id] = parent_id
            self._tagnames[t_name] = t_id

    def __get_tags(self, tags_data):
        tags = set()
        for t in tags_data:
            if t not in self._tagnames:
                raise BridgeException(_('Corrupted preset safe mark: not enough tags in the system'))
            t_id = self._tagnames[t]
            tags.add(t_id)
            while self._dbtags[t_id] is not None:
                t_id = self._dbtags[t_id]
                tags.add(t_id)
        return tags

    def __get_attrnames(self):
        attrnames = {}
        for a in AttrName.objects.all():
            attrnames[a.name] = a.id
        for mid in self._markattrs:
            for a in self._markattrs[mid]:
                if a['attr'] in attrnames:
                    a['attr'] = attrnames[a['attr']]
                else:
                    newname = AttrName.objects.get_or_create(name=a['attr'])[0]
                    a['attr'] = newname.id
                    attrnames[newname.name] = newname.id

    def __get_attrs(self):
        attrs_in_db = {}
        for a in Attr.objects.all():
            attrs_in_db[(a.name_id, a.value)] = a.id
        attrs_to_create = []
        for mid in self._markattrs:
            for a in self._markattrs[mid]:
                if (a['attr'], a['value']) not in attrs_in_db:
                    attrs_to_create.append(Attr(name_id=a['attr'], value=a['value']))
                    attrs_in_db[(a['attr'], a['value'])] = None
        if len(attrs_to_create) > 0:
            Attr.objects.bulk_create(attrs_to_create)
            self.__get_attrs()
        else:
            for mid in self._markattrs:
                for a in self._markattrs[mid]:
                    a['attr'] = attrs_in_db[(a['attr'], a['value'])]
                    del a['value']

    def __create_marks(self):
        marks_in_db = {}
        for ma in MarkSafeAttr.objects.values('mark_id', 'attr_id', 'is_compare'):
            if ma['mark_id'] not in marks_in_db:
                marks_in_db[ma['mark_id']] = set()
            marks_in_db[ma['mark_id']].add((ma['attr_id'], ma['is_compare']))
        marks_to_create = []
        for mark in self._marks:
            attr_set = set((a['attr'], a['is_compare']) for a in self._markattrs[mark.identifier])
            if any(attr_set == marks_in_db[x] for x in marks_in_db):
                del self._markattrs[mark.identifier]
                del self._marktags[mark.identifier]
                continue
            marks_to_create.append(mark)
        MarkSafe.objects.bulk_create(marks_to_create)

        created_marks = {}
        marks_versions = []
        for mark in MarkSafe.objects.filter(versions=None):
            created_marks[mark.identifier] = mark
            marks_versions.append(MarkSafeHistory(
                mark=mark, verdict=mark.verdict, status=mark.status, description=mark.description,
                version=mark.version, author=mark.author, change_date=mark.change_date, comment=''
            ))
        MarkSafeHistory.objects.bulk_create(marks_versions)
        return created_marks

    def __create_related(self):
        versions = {}
        for mh in MarkSafeHistory.objects.filter(mark__in=self.created.values()).select_related('mark'):
            versions[mh.mark.identifier] = mh.id

        new_tags = []
        for mid in self._marktags:
            for tid in self._marktags[mid]:
                new_tags.append(MarkSafeTag(tag_id=tid, mark_version_id=versions[mid]))
        MarkSafeTag.objects.bulk_create(new_tags)
        new_attrs = []
        for mid in self._markattrs:
            for a in self._markattrs[mid]:
                new_attrs.append(MarkSafeAttr(mark_id=versions[mid], attr_id=a['attr'], is_compare=a['is_compare']))
        MarkSafeAttr.objects.bulk_create(new_attrs)

    def __get_data(self):
        presets_dir = os.path.join(settings.BASE_DIR, 'marks', 'presets', 'safes')
        new_marks = []
        for mark_settings in [os.path.join(presets_dir, x) for x in os.listdir(presets_dir)]:
            identifier = os.path.splitext(os.path.basename(mark_settings))[0]
            try:
                MarkSafe.objects.get(identifier=identifier)
                # The mark was already uploaded
                continue
            except ObjectDoesNotExist:
                pass

            with open(mark_settings, encoding='utf8') as fp:
                data = json.load(fp)
            if not isinstance(data, dict):
                raise BridgeException(_('Corrupted preset safe mark: wrong format'))

            if settings.POPULATE_JUST_PRODUCTION_PRESETS and not data.get('production'):
                # Do not populate non-production marks
                continue

            if any(x not in data for x in ['status', 'verdict', 'is_modifiable', 'description', 'attrs', 'tags']):
                raise BridgeException(_('Corrupted preset safe mark: not enough data'))
            if not isinstance(data['attrs'], list) or not isinstance(data['tags'], list):
                raise BridgeException(_('Corrupted preset safe mark: attributes or tags is not a list'))
            if any(not isinstance(x, dict) for x in data['attrs']):
                raise BridgeException(_('Corrupted preset safe mark: one of attributes has wrong format'))
            if any(x not in y for x in ['attr', 'value', 'is_compare'] for y in data['attrs']):
                raise BridgeException(_('Corrupted preset safe mark: one of attributes does not have enough data'))
            if data['status'] not in list(x[0] for x in MARK_STATUS):
                raise BridgeException(_('Corrupted preset safe mark: wrong mark status'))
            if data['verdict'] not in list(x[0] for x in SAFE_VERDICTS):
                raise BridgeException(_('Corrupted preset safe mark: wrong mark verdict'))
            if not isinstance(data['description'], str):
                raise BridgeException(_('Corrupted preset safe mark: wrong description'))
            if not isinstance(data['is_modifiable'], bool):
                raise BridgeException(_('Corrupted preset safe mark: is_modifiable must be bool'))

            new_marks.append(MarkSafe(
                identifier=identifier, author=self._author, change_date=now(), is_modifiable=data['is_modifiable'],
                status=data['status'], verdict=data['verdict'], description=data['description'], type=MARK_TYPE[1][0]
            ))
            self._marktags[identifier] = self.__get_tags(data['tags'])
            self._markattrs[identifier] = data['attrs']
            self.total += 1
        return new_marks


def delete_marks(marks):
    changes = {}
    for mark in marks:
        changes[mark.id] = {}
    MarkSafe.objects.filter(id__in=changes).update(version=0)
    for mr in MarkSafeReport.objects.filter(mark__in=marks).select_related('report'):
        changes[mr.mark_id][mr.report] = {'kind': '-', 'verdict1': mr.report.verdict}
    MarkSafe.objects.filter(id__in=changes).delete()
    changes = UpdateVerdicts(changes).changes
    safes_changes = {}
    for m_id in changes:
        for report in changes[m_id]:
            safes_changes[report] = changes[m_id][report]
    RecalculateTags(safes_changes)
    update_confirmed_cache(list(safes_changes))
    return safes_changes


def update_confirmed_cache(safes):
    safes_set = set(safe.id for safe in safes)
    with_confirmed = set(MarkSafeReport.objects.filter(
        report_id__in=safes_set, type=ASSOCIATION_TYPE[1][0]
    ).values_list('report_id', flat=True))
    ReportSafe.objects.filter(id__in=safes_set).update(has_confirmed=False)
    ReportSafe.objects.filter(id__in=with_confirmed).update(has_confirmed=True)
