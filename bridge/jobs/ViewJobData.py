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

import operator
import re

from django.db.models import Q, Count, Case, When, BooleanField, Value
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

from bridge.utils import logger, BridgeException
from bridge.vars import SAFE_VERDICTS, UNSAFE_VERDICTS, ASSOCIATION_TYPE
from jobs.utils import SAFES, UNSAFES, TITLES, get_resource_data
from marks.models import MarkUnknownReport
from marks.utils import UNSAFE_LINK_CLASS, SAFE_LINK_CLASS
from reports.models import Attr, JobViewAttrs, ReportAttr, ComponentInstances, ReportUnknown, VerifierConfig

COLORS = {
    'red': '#C70646',
    'orange': '#D05A00',
    'purple': '#930BBD',
}


def update_job_view_attrs(raw_attrs: dict, user, job) -> bool:
    saved_attrs = set()
    for view in JobViewAttrs.objects.filter(job=job, user=user).only('attr'):
        saved_attrs.add(view.attr)

    new_attrs = set()
    for raw_name, value in raw_attrs.items():
        m = re.match('attr_(.+)_{}'.format(value), raw_name)
        if m:
            name = m.group(1)
            new_attrs.add(Attr.objects.get(name__name=name, value=value))
        else:
            logger.exception("Cannot parse attribute name '{}' with value '{}'".format(raw_name, value))
    add_attrs = new_attrs - saved_attrs
    delete_attrs = saved_attrs - new_attrs

    # Delete attrs from job view.
    JobViewAttrs.objects.filter(job=job, user=user, attr__in=delete_attrs).delete()

    # Add attrs to job view.
    job_view_attrs = list()
    for attr in add_attrs:
        job_view_attrs.append(JobViewAttrs(job=job, user=user, attr=attr))
    JobViewAttrs.objects.bulk_create(job_view_attrs)
    return bool(add_attrs) or bool(delete_attrs)


class ViewJobData:
    def __init__(self, user, view, report):
        self.user = user
        self.report = report
        self.view = view

        if self.report is None:
            return

        self.attrs = self.__get_attrs()
        self.totals = self.__get_totals()
        self.problems = self.__get_problems()
        self.data = self.__get_view_data()
        self.config = self.__get_config()

    def __get_config(self) -> dict:
        res = dict()
        for name, val in VerifierConfig.objects.filter(report=self.report).values_list('name', 'value'):
            res[name] = val
        return res

    def __get_attrs(self) -> dict:
        result = dict()
        self.__attrs_href = set()
        for view in JobViewAttrs.objects.filter(job=self.report.root.job, user=self.user).only('attr'):
            attr = view.attr
            name = attr.name.name
            if name not in result:
                result[name] = list()
            result[name].append(attr)
            self.__attrs_href.add(str(attr.id))
        self.__attrs_href = ','.join(self.__attrs_href)
        return result

    def __get_view_data(self):
        if 'data' not in self.view:
            return {}
        data = {}
        actions = {
            'safes': self.__safes_info,
            'unsafes': self.__unsafes_info,
            'unknowns': self.__unknowns_info,
            'resources': self.__resource_info,
            'safes_attr_stat': self.__safes_attrs_statistic,
            'unsafes_attr_stat': self.__unsafes_attrs_statistic,
            'unknowns_attr_stat': self.__unknowns_attrs_statistic
        }
        for d in self.view['data']:
            if d in actions:
                data[d] = actions[d]()
        return data

    def __get_total_href(self, href_type: str) -> str:
        href = reverse('reports:{}'.format(href_type), args=[self.report.pk])
        if self.__attrs_href:
            href += "?attr={}".format(self.__attrs_href)
        return href

    def __get_totals(self):
        self.__safes = self.report.leaves.exclude(safe=None)
        self.__unsafes = self.report.leaves.exclude(unsafe=None)
        self.__unknowns = self.report.leaves.exclude(unknown=None)

        for name, values in self.attrs.items():
            self.__safes = self.__safes.filter(safe__attrs__attr__in=values)
            self.__unsafes = self.__unsafes.filter(unsafe__attrs__attr__in=values)
            self.__unknowns = self.__unknowns.filter(unknown__attrs__attr__in=values)

        return {
            'safes': {'number': self.__safes.count(), 'href': self.__get_total_href('safes')},
            'unsafes': {'number': self.__unsafes.count(), 'href': self.__get_total_href('unsafes')},
            'unknowns': {'number': self.__unknowns.count(), 'href': self.__get_total_href('unknowns')}
        }

    def __get_problems(self):
        queryset = MarkUnknownReport.objects.filter(Q(report__root=self.report.root) & ~Q(type=ASSOCIATION_TYPE[2][0]))\
            .values_list('problem_id', 'problem__name', 'report__component_id', 'report__component__name')\
            .distinct().order_by('report__component__name', 'problem__name')

        problems = []
        for p_id, p_name, c_id, c_name in queryset:
            problems.append(('{0}/{1}'.format(c_name, p_name), '{0}_{1}'.format(c_id, p_id)))
        if len(problems) > 0:
            problems.append((_('Without marks'), '0_0'))
        return problems

    def __safe_tags_info(self):
        safe_tag_filter = {}
        if 'safe_tag' in self.view:
            safe_tag_filter['tag__tag__%s' % self.view['safe_tag'][0]] = self.view['safe_tag'][1]

        tree_data = []
        for st in self.report.safe_tags.filter(**safe_tag_filter).order_by('tag__tag').select_related('tag'):
            tree_data.append({
                'id': st.tag_id,
                'parent': st.tag.parent_id,
                'name': st.tag.tag,
                'number': st.number,
                'href': '%s?tag=%s' % (reverse('reports:safes', args=[st.report_id]), st.tag_id),
                'description': st.tag.description
            })

        def get_children(parent, padding):
            children = []
            if parent['id'] is not None:
                parent['padding'] = padding * 13
                children.append(parent)
            for t in tree_data:
                if t['parent'] == parent['id']:
                    children.extend(get_children(t, padding + 1))
            return children

        return get_children({'id': None}, -1)

    def __unsafe_tags_info(self):
        unsafe_tag_filter = {}
        if 'unsafe_tag' in self.view:
            unsafe_tag_filter['tag__tag__%s' % self.view['unsafe_tag'][0]] = self.view['unsafe_tag'][1]

        tree_data = []
        for ut in self.report.unsafe_tags.filter(**unsafe_tag_filter).order_by('tag__tag').select_related('tag'):
            tree_data.append({
                'id': ut.tag_id,
                'parent': ut.tag.parent_id,
                'name': ut.tag.tag,
                'number': ut.number,
                'href': '%s?tag=%s' % (reverse('reports:unsafes', args=[ut.report_id]), ut.tag_id),
                'description': ut.tag.description
            })

        def get_children(parent, padding):
            children = []
            if parent['id'] is not None:
                parent['padding'] = padding * 13
                children.append(parent)
            for t in tree_data:
                if t['parent'] == parent['id']:
                    children.extend(get_children(t, padding + 1))
            return children

        return get_children({'id': None}, -1)

    def __resource_info(self):
        instances = {}
        for c_name, total, in_progress in ComponentInstances.objects.filter(report=self.report)\
                .order_by('component__name').values_list('component__name', 'total', 'in_progress'):
            instances[c_name] = str(total)

        cpu_time = {}
        memory = {}
        wall_time = {}
        resource_filters = {}

        if 'resource_component' in self.view:
            resource_filters['component__name__%s' % self.view['resource_component'][0]] = \
                self.view['resource_component'][1]

        for cr in self.report.resources_cache.filter(~Q(component=None) & Q(**resource_filters))\
                .select_related('component'):
            if cr.component.name not in cpu_time:
                cpu_time[cr.component.name] = {}
                memory[cr.component.name] = {}
                wall_time[cr.component.name] = {}
            rd = get_resource_data(self.user.extended.data_format, self.user.extended.accuracy, cr)

            wall_time[cr.component.name] = rd[0]
            cpu_time[cr.component.name] = rd[1]
            memory[cr.component.name] = rd[2]

        def prepare_component_resources(component: str) -> dict:
            return {
                'component': component,
                'instances': instances[component],
                'cpu': cpu_time[component],
                'mem': memory[component],
                'wall': wall_time[component]
            }

        resource_data = [prepare_component_resources(component) for component in sorted(cpu_time)
                         if not component == self.report.component.name]
        if self.report.component.name in cpu_time:
            resource_data.append(prepare_component_resources(self.report.component.name))

        return resource_data

    def __unknowns_info(self):
        url = reverse('reports:unknowns', args=[self.report.pk])
        attrs_href = ""
        if self.__attrs_href:
            attrs_href = '&attr={}'.format(self.__attrs_href)
        no_mark_hidden = 'hidden' in self.view and 'unknowns_nomark' in self.view['hidden']
        total_hidden = 'hidden' in self.view and 'unknowns_total' in self.view['hidden']

        # ==========================
        # Get querysets for unknowns
        queryset_fields = ['component_id', 'component__name', 'markreport_set__problem_id',
                           'markreport_set__problem__name', 'number', 'unconfirmed']
        order_by_fields = ['component__name', 'markreport_set__problem__name']
        queryset = ReportUnknown.objects.filter(leaves__in=self.__unknowns)
        if 'unknown_component' in self.view:
            queryset = queryset.filter(**{
                'component__name__' + self.view['unknown_component'][0]: self.view['unknown_component'][1]
            })
        queryset_total = queryset.values('component_id').annotate(number=Count('id'))\
            .values_list('component_id', 'component__name', 'number')

        if no_mark_hidden:
            queryset = queryset.filter(markreport_set__type__in=[ASSOCIATION_TYPE[0][0], ASSOCIATION_TYPE[1][0]])
            unconfirmed = Value(False, output_field=BooleanField())
        else:
            unconfirmed = Case(When(markreport_set__type=ASSOCIATION_TYPE[2][0], then=True),
                               default=False, output_field=BooleanField())

        queryset = queryset.values('component_id', 'markreport_set__problem_id')\
            .annotate(number=Count('id', distinct=True), unconfirmed=unconfirmed)

        if 'unknown_problem' in self.view:
            queryset = queryset.filter(**{
                'markreport_set__problem__name__' + self.view['unknown_problem'][0]: self.view['unknown_problem'][1]
            })
        queryset = queryset.values_list(*queryset_fields).order_by(*order_by_fields)
        # ==========================

        unknowns_data = {}
        unmarked = {}
        # Get marked unknowns
        for c_id, c_name, p_id, p_name, number, unconfirmed in queryset:
            if p_id is None or unconfirmed:
                if c_name not in unmarked:
                    unmarked[c_name] = [0, c_id]
                unmarked[c_name][0] += number
            else:
                if c_name not in unknowns_data:
                    unknowns_data[c_name] = []
                unknowns_data[c_name].append({'num': number, 'problem': p_name,
                                              'href': '{0}?component={1}&problem={2}{3}'.
                                             format(url, c_id, p_id, attrs_href)})

        # Get unmarked unknowns
        for c_name in unmarked:
            if c_name not in unknowns_data:
                unknowns_data[c_name] = []
            unknowns_data[c_name].append({
                'num': unmarked[c_name][0], 'problem': _('Without marks'),
                'href': '{0}?component={1}&problem=0&{2}'.format(url, unmarked[c_name][1], attrs_href)
            })

        if not total_hidden:
            # Get total unknowns for each component
            for c_id, c_name, number in queryset_total:
                if c_name not in unknowns_data:
                    unknowns_data[c_name] = []
                unknowns_data[c_name].append({
                    'num': number, 'problem': 'total', 'href': '{0}?component={1}{2}'.
                        format(url, c_id, attrs_href)
                })
        return list({'component': c_name, 'problems': unknowns_data[c_name]} for c_name in sorted(unknowns_data))

    def __safes_info(self):
        safes_numbers = {}
        tags = self.__obtain_tags('safe')
        for verdict, total in self.__safes.exclude(safe=None).values('safe__verdict').annotate(
                total=Count('id')
        ).values_list('safe__verdict', 'total'):
            href = None
            if total > 0:
                href = '%s?verdict=%s' % (reverse('reports:safes', args=[self.report.pk]), verdict)
            if self.__attrs_href:
                href += "&attr={}".format(self.__attrs_href)

            value = total

            color = None
            safe_name = 'safe:'
            style = SAFE_LINK_CLASS[verdict]
            if verdict == SAFE_VERDICTS[0][0]:
                safe_name += SAFES[2]
                color = COLORS['purple']
            elif verdict == SAFE_VERDICTS[1][0]:
                safe_name += SAFES[1]
                color = COLORS['orange']
            elif verdict == SAFE_VERDICTS[2][0]:
                safe_name += SAFES[0]
                color = COLORS['red']
            elif verdict == SAFE_VERDICTS[3][0]:
                safe_name += SAFES[3]
                color = COLORS['red']
            elif verdict == SAFE_VERDICTS[4][0]:
                safe_name += SAFES[4]

            if verdict in tags:
                if not verdict == SAFE_VERDICTS[4][0]:
                    self.postprocess_tags(tags, verdict, href)
                else:
                    del tags[verdict]

            if total > 0:
                safes_numbers[safe_name] = {
                    'id': verdict,
                    'title': TITLES[safe_name],
                    'value': value,
                    'color': color,
                    'href': href,
                    'style': style,
                    'tags': tags.get(verdict, None)
                }

        safes_data = []
        for safe_name in SAFES:
            safe_name = 'safe:' + safe_name
            if safe_name in safes_numbers:
                safes_data.append(safes_numbers[safe_name])
        return safes_data

    def __sort_tree(self, parent_id, padding, raw_data: dict):
        children = []
        if parent_id is not None:
            parent = raw_data[parent_id]
            parent['padding'] = padding * 13
            children.append(parent)
        for tag_id, tag_desc in sorted(raw_data.items(), key=operator.itemgetter(0)):
            if tag_desc['parent'] == parent_id:
                children.extend(self.__sort_tree(tag_id, padding + 1, raw_data))
        return children

    def __obtain_tags(self, leaf_type: str) -> dict:
        tags = {}
        if leaf_type == 'unsafe':
            leaves = self.__unsafes
        elif leaf_type == 'safe':
            leaves = self.__safes
        else:
            return {}
        for leaf in leaves.values(leaf_type + '__verdict', leaf_type + '__tags__tag', leaf_type + '__tags__tag__tag',
                                  leaf_type + '__tags__tag__description', leaf_type + '__tags__tag__parent_id'):
            verdict_id = leaf[leaf_type + '__verdict']
            tag_id = leaf[leaf_type + '__tags__tag']
            if verdict_id not in tags:
                tags[verdict_id] = {}
            if not tag_id:
                tag_id = -1
                leaf[leaf_type + '__tags__tag__description'] = ''
                leaf[leaf_type + '__tags__tag__tag'] = _('Without tags')

            if tag_id not in tags[verdict_id].keys():
                tags[verdict_id][tag_id] = {'number': 1, 'name': leaf[leaf_type + '__tags__tag__tag'],
                                            'desc': leaf[leaf_type + '__tags__tag__description'],
                                            'parent': leaf[leaf_type + '__tags__tag__parent_id']}
            else:
                tags[verdict_id][tag_id]['number'] += 1
        return tags

    def postprocess_tags(self, tags: dict, verdict: str, href: str):
        for tag_id, tag_desc in tags[verdict].items():
            tag_desc['href'] = "{}&tag={}".format(href, tag_id)
        tags[verdict] = self.__sort_tree(None, -1, tags[verdict])

    def __unsafes_info(self):
        unsafes_numbers = {}

        tags = self.__obtain_tags('unsafe')

        for verdict, total in self.__unsafes.values('unsafe__verdict').annotate(
                total=Count('id')
        ).values_list('unsafe__verdict', 'total'):
            href = None
            if total > 0:
                href = '%s?verdict=%s' % (reverse('reports:unsafes', args=[self.report.pk]), verdict)
            if self.__attrs_href:
                href += "&attr={}".format(self.__attrs_href)

            value = total

            color = None
            unsafe_name = 'unsafe:'
            style = UNSAFE_LINK_CLASS[verdict]
            if verdict == UNSAFE_VERDICTS[0][0]:
                unsafe_name += UNSAFES[3]
                color = COLORS['purple']
            elif verdict == UNSAFE_VERDICTS[1][0]:
                unsafe_name += UNSAFES[0]
                color = COLORS['red']
            elif verdict == UNSAFE_VERDICTS[2][0]:
                unsafe_name += UNSAFES[1]
                color = COLORS['red']
            elif verdict == UNSAFE_VERDICTS[3][0]:
                unsafe_name += UNSAFES[2]
                color = COLORS['orange']
            elif verdict == UNSAFE_VERDICTS[4][0]:
                unsafe_name += UNSAFES[4]
                color = COLORS['red']
            elif verdict == UNSAFE_VERDICTS[5][0]:
                unsafe_name += UNSAFES[5]

            if verdict in tags:
                if not verdict == UNSAFE_VERDICTS[5][0]:
                    self.postprocess_tags(tags, verdict, href)
                else:
                    del tags[verdict]

            if total > 0:
                unsafes_numbers[unsafe_name] = {
                    'id': verdict,
                    'title': TITLES[unsafe_name],
                    'value': value,
                    'color': color,
                    'href': href,
                    'style': style,
                    'tags': tags.get(verdict, None)
                }
        unsafes_data = []
        for unsafe_name in UNSAFES:
            unsafe_name = 'unsafe:' + unsafe_name
            if unsafe_name in unsafes_numbers:
                unsafes_data.append(unsafes_numbers[unsafe_name])
        return unsafes_data

    def __safes_attrs_statistic(self):
        try:
            return self.__attr_statistic('safe')
        except Exception as e:
            logger.exception(e)
            raise BridgeException()

    def __unsafes_attrs_statistic(self):
        try:
            return self.__attr_statistic('unsafe')
        except Exception as e:
            logger.exception(e)
            raise BridgeException()

    def __unknowns_attrs_statistic(self):
        try:
            return self.__attr_statistic('unknown')
        except Exception as e:
            logger.exception(e)
            raise BridgeException()

    def __attr_statistic(self, report_type):
        if report_type not in {'safe', 'unsafe', 'unknown'}:
            return []
        leaf_column = '"cache_report_component_leaf"."{0}_id"'.format(report_type)
        queryset = ReportAttr.objects.raw("""
SELECT "report_attrs"."id", "report_attrs"."attr_id" as "a_id",
       "attr"."value" as "a_val", "attr_name"."name" as "a_name"
  FROM "report_attrs"
  INNER JOIN "cache_report_component_leaf" ON ("report_attrs"."report_id" = {0})
  INNER JOIN "attr" ON ("report_attrs"."attr_id" = "attr"."id")
  INNER JOIN "attr_name" ON ("attr"."name_id" = "attr_name"."id")
  WHERE "cache_report_component_leaf"."report_id" = {1};""".format(leaf_column, self.report.id))

        if 'attr_stat' not in self.view or len(self.view['attr_stat']) != 1 or len(self.view['attr_stat'][0]) == 0:
            return []
        attr_name = self.view['attr_stat'][0]

        a_tmpl = None
        if 'attr_stat_filter' in self.view:
            a_tmpl = self.view['attr_stat_filter'][1].lower()

        attr_stat_data = {}
        for ra in queryset:
            if ra.a_name != attr_name:
                continue
            if 'attr_stat_filter' in self.view:
                a_low = ra.a_val.lower()
                if self.view['attr_stat_filter'][0] == 'iexact' and a_low != a_tmpl \
                        or self.view['attr_stat_filter'][0] == 'istartswith' and not a_low.startswith(a_tmpl) \
                        or self.view['attr_stat_filter'][0] == 'icontains' and not a_low.__contains__(a_tmpl):
                    continue

            if ra.a_val not in attr_stat_data:
                attr_stat_data[ra.a_val] = {'num': 0, 'href': '{0}?attr={1}'.format(
                    reverse('reports:%ss' % report_type, args=[self.report.pk]), ra.a_id)}
            attr_stat_data[ra.a_val]['num'] += 1
        return list((val, attr_stat_data[val]['num'], attr_stat_data[val]['href']) for val in sorted(attr_stat_data))
