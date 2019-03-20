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
import re
import sys
from difflib import SequenceMatcher

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Count
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

from bridge.utils import BridgeException
from bridge.vars import COMPARE_VERDICT
from jobs.models import Job
from jobs.utils import JobAccess, get_resource_data
from marks.models import MarkUnsafeReport, MarkSafeReport, MarkUnknownReport
from marks.utils import UNSAFE_COLOR, SAFE_COLOR
from reports.mea.wrapper import COMPARISON_FUNCTIONS, CONVERSION_FUNCTIONS, DEFAULT_SIMILARITY_THRESHOLD, \
    DEFAULT_COMPARISON_FUNCTION, DEFAULT_CONVERSION_FUNCTION, get_or_convert_error_trace_auto, is_trace_equal
from reports.models import AttrName, Attr, ReportAttr, ReportComponentLeaf, CompareJobsInfo, CompareJobsCache, \
    Report, ReportSafe, ReportUnsafe, ReportUnknown, ReportComponent, ReportRoot, ComponentResource
from users.models import User

VERDICT_SAFE = 'safe'
VERDICT_UNSAFE = 'unsafe'
VERDICT_UNSAFE_INCOMPLETE = 'unsafe-incomplete'
VERDICT_UNKNOWN = 'unknown'

VERDICTS_SAFE = 'safes'
VERDICTS_UNSAFE = 'unsafes'
VERDICTS_UNSAFE_INCOMPLETE = 'unsafe_incompletes'
VERDICTS_UNKNOWN = 'unknowns'
VERDICTS_ALL = [VERDICTS_SAFE, VERDICTS_UNSAFE, VERDICTS_UNSAFE_INCOMPLETE, VERDICTS_UNKNOWN]

FILTERED_ATTRS = ['Coverage:Functions', 'Coverage:Lines', 'Filtering time', 'Found all traces', 'Traces:Filtered',
                  'Traces:Initial']

CLUSTERING_ORIGIN_MARK = "mark"
CLUSTERING_ORIGIN_AUTO = "auto"

CLUSTERING_TYPE_DIFF_CLUSTERS = "diff_clusters"
CLUSTERING_TYPE_DIFF_TRACES = "diff_traces"
CLUSTERING_TYPE_ALL = "all"

TAG_AUTO_ID = "id"
TAG_MARK = "mark"
TAG_ORIGIN = "origin"
TAG_ATTRS = "attrs"
TAG_REPORTS = "reports"
TAG_CET = "cet"
TAG_COLOR = "color"
TAG_HIDE = "hide"

CLUSTERING_COLORS = ["#dd7777", "#77dd77"]


class InternalLeaf:
    def __init__(self, verdict: str, cpu_time: int, parent_report_id: int):
        self.verdict = verdict
        self.cpu_time = cpu_time
        if not cpu_time:
            self.cpu_time = 0
        self.parent_report_id = parent_report_id
        self.attrs_vals = dict()
        self.attrs_ids = set()

    def add_attrs(self, name: str, val: str, attr_id: int):
        if name not in self.attrs_vals:
            self.attrs_vals[name] = set()
        self.attrs_vals[name].add(val)
        self.attrs_ids.add(attr_id)

    def serialize_attrs(self, core_attrs: set = set()) -> tuple:
        tmp_res = list()
        tmp_res_core = list()
        for name, vals in sorted(self.attrs_vals.items()):
            for val in sorted(vals):
                tmp_res.append(str(val))
                if name in core_attrs:
                    tmp_res_core.append(str(val))
        return "/".join(tmp_res), "/".join(tmp_res_core)

    def is_attr(self, filtered: dict):
        for name in set(self.attrs_vals.keys()).intersection(filtered.keys()):
            if set(self.attrs_vals[name]).issubset(filtered[name]):
                return True
        return False

    def __str__(self):
        return "[{}, {}, {}]".format(self.verdict, self.cpu_time, self.serialize_attrs()[0])


class JobsComparison:
    def __init__(self, root_reports: list, args: dict = dict):
        self.__init_args(args)

        common_attrs = dict()
        common_attrs_ids = set()
        common_attrs_vals = dict()

        self.internals = list()

        self.comparison = list()
        for root in root_reports:
            attrs, attrs_vals, attrs_ids, cdata = self.init_internals(root)
            if common_attrs:
                common_attrs, common_attrs_vals = \
                    self.get_common_attrs(attrs, attrs_vals, common_attrs, common_attrs_vals)
                common_attrs_ids.intersection_update(attrs_ids)
            else:
                common_attrs, common_attrs_vals = attrs, attrs_vals
                common_attrs_ids = attrs_ids

            if self.comparison:
                cdata['launches_comp'] = self.comparison[0]['launches'] >= cdata['launches']
                cdata['launches_diff'] = abs(self.comparison[0]['launches'] - cdata['launches'])

            self.comparison.append(cdata)

        self.common_attrs_as_dict = common_attrs
        self.common_attrs, self.common_attrs_vals = self.sort_attrs(common_attrs, common_attrs_vals)

        # 2nd iteration.
        counter = 0
        clusters = list()
        for cmp in self.comparison:
            marked_attrs = list()

            safes, unsafes, unsafe_incompletes, unknowns, cpu_time = self.sort_internals_by_attrs(counter, common_attrs_ids)
            cmp['compared_cpu'] = get_resource_data('hum', 2, ComponentResource(report=None, cpu_time=cpu_time))[1]

            cmp['{}_len'.format(VERDICTS_SAFE)] = len(safes)
            cmp['{}_len'.format(VERDICTS_UNSAFE)] = len(unsafes)
            cmp['{}_len'.format(VERDICTS_UNSAFE_INCOMPLETE)] = len(unsafe_incompletes)
            cmp['{}_len'.format(VERDICTS_UNKNOWN)] = len(unknowns)
            if counter == 0:
                cmp[VERDICTS_UNSAFE] = unsafes
                cmp[VERDICTS_UNSAFE_INCOMPLETE] = unsafe_incompletes
                cmp[VERDICTS_UNKNOWN] = unknowns
                cmp[VERDICTS_SAFE] = safes
            else:
                for verdicts_type in VERDICTS_ALL:
                    self.__process_verdicts_transitions(verdicts_type, safes, unsafes, unsafe_incompletes, unknowns,
                                                        cmp)
                    if not self.show_same_transitions[verdicts_type]:
                        cmp['{0}_{0}'.format(verdicts_type)] = []

            if self.enable_clustering:
                clusters.append(self.perform_clustering(unsafes, unsafe_incompletes, cmp))

            for name, vals in cmp['attrs_vals']:
                marked_vals = list()
                for val in vals:
                    if name in common_attrs_vals and val in common_attrs_vals[name]:
                        marked_vals.append((val, True))
                    else:
                        marked_vals.append((val, False))
                marked_attrs.append((name, marked_vals))
            cmp['attrs_vals'] = marked_attrs
            counter += 1

        if clusters:
            # TODO: support for more than 2 reports comparison
            assert len(clusters) == 2
            clusters_1 = clusters[0]
            clusters_2 = clusters[1]

            desc_1 = self.__pre_process_cluster(clusters_1)
            desc_2 = self.__pre_process_cluster(clusters_2)

            common_marks = desc_1.get(CLUSTERING_ORIGIN_MARK, set()).\
                intersection(desc_2.get(CLUSTERING_ORIGIN_MARK, set()))

            if self.clustering_type == CLUSTERING_TYPE_DIFF_TRACES:
                for cluster_1 in clusters_1:
                    if cluster_1[TAG_ORIGIN] == CLUSTERING_ORIGIN_MARK and cluster_1[TAG_MARK] in common_marks:
                        for cluster_2 in clusters_2:
                            if cluster_2[TAG_ORIGIN] == CLUSTERING_ORIGIN_MARK and \
                                    cluster_2[TAG_MARK] == cluster_1[TAG_MARK]:
                                if len(cluster_1[TAG_REPORTS]) == len(cluster_2[TAG_REPORTS]):
                                    cluster_1[TAG_HIDE] = True
                                    cluster_2[TAG_HIDE] = True

            common_compared_attrs = desc_1.get(CLUSTERING_ORIGIN_AUTO, set()). \
                intersection(desc_2.get(CLUSTERING_ORIGIN_AUTO, set()))

            common_ama_counter = 0
            for cluster_1 in clusters_1:
                if cluster_1[TAG_ORIGIN] == CLUSTERING_ORIGIN_AUTO and cluster_1[TAG_ATTRS] in common_compared_attrs:
                    compared_attrs = cluster_1[TAG_ATTRS]
                    cet_1 = cluster_1[TAG_CET]
                    for cluster_2 in clusters_2:
                        if cluster_2[TAG_ORIGIN] == CLUSTERING_ORIGIN_AUTO and cluster_2[TAG_ATTRS] == compared_attrs \
                                and TAG_AUTO_ID not in cluster_2:
                            cet_2 = cluster_2[TAG_CET]
                            if is_trace_equal(cet_1, cet_2, self.comparison_function, self.similarity)[0]:
                                common_ama_counter += 1
                                cluster_1[TAG_AUTO_ID] = common_ama_counter
                                cluster_2[TAG_AUTO_ID] = common_ama_counter
                                if self.clustering_type == CLUSTERING_TYPE_DIFF_TRACES:
                                    if len(cluster_1[TAG_REPORTS]) == len(cluster_2[TAG_REPORTS]):
                                        cluster_1[TAG_HIDE] = True
                                        cluster_2[TAG_HIDE] = True
                                break

            counter = 0
            for cluster in clusters:
                self.comparison[counter]['clusters_len'] = len(cluster)
                common_clusters = len(common_marks) + common_ama_counter
                if counter:
                    self.__post_process_cluster(clusters, common_marks)
                    all_new = 0
                    all_lost = 0
                    am_new = 0
                    am_lost = 0
                    ama_new = 0
                    ama_lost = 0
                    if len(cluster) > common_clusters:
                        all_new = len(cluster) - common_clusters
                    if len(clusters[0]) > common_clusters:
                        all_lost = len(clusters[0]) - common_clusters
                    if len(desc_2.get(CLUSTERING_ORIGIN_MARK, set())) > len(common_marks):
                        am_new = len(desc_2.get(CLUSTERING_ORIGIN_MARK, set())) - len(common_marks)
                    if len(desc_1.get(CLUSTERING_ORIGIN_MARK, set())) > len(common_marks):
                        am_lost = len(desc_1.get(CLUSTERING_ORIGIN_MARK, set())) - len(common_marks)
                    if all_new > am_new:
                        ama_new = all_new - am_new
                    if all_lost > am_lost:
                        ama_lost = all_lost - am_lost
                    self.comparison[counter]['clusters_new'] = all_new
                    self.comparison[counter]['clusters_lost'] = all_lost
                    self.comparison[counter]['clusters_am_new'] = am_new
                    self.comparison[counter]['clusters_am_lost'] = am_lost
                    self.comparison[counter]['clusters_ama_new'] = ama_new
                    self.comparison[counter]['clusters_ama_lost'] = ama_lost

                counter += 1

    def __pre_process_cluster(self, clusters: list) -> dict:
        res = dict()
        for cluster in clusters:
            cluster_origin = cluster[TAG_ORIGIN]
            if cluster_origin not in res:
                res[cluster_origin] = set()
            if cluster_origin == CLUSTERING_ORIGIN_MARK:
                res[cluster_origin].add(cluster[TAG_MARK])
            elif cluster_origin == CLUSTERING_ORIGIN_AUTO:
                res[cluster_origin].add(cluster[TAG_ATTRS])
            else:
                raise Exception("Unknown cluster origin {}".format(cluster_origin))
        return res

    def __post_process_cluster(self, clusters_list: list, common_marks: set):
        common_clusters = list()
        diff_clusters = list()
        counter = 0
        for clusters in clusters_list:
            common_counter = 0
            diff_clusters.append(list())
            for cluster in sorted(clusters,
                                  key=lambda x: (x.get(TAG_MARK, sys.maxsize), x[TAG_ATTRS], x.get(TAG_AUTO_ID, 0))):
                cluster_origin = cluster[TAG_ORIGIN]
                if cluster_origin == CLUSTERING_ORIGIN_MARK:
                    if cluster[TAG_MARK] not in common_marks:
                        self.__change_reports_tag(cluster, counter)
                        #cluster[TAG_COLOR] = CLUSTERING_COLORS[counter]
                        diff_clusters[counter].append(cluster)
                    else:
                        self.__process_common_cluster(cluster, common_clusters, counter, common_counter)
                        common_counter += 1
                elif cluster_origin == CLUSTERING_ORIGIN_AUTO:
                    if cluster.get(TAG_AUTO_ID, 0):
                        self.__process_common_cluster(cluster, common_clusters, counter, common_counter)
                        common_counter += 1
                    else:
                        self.__change_reports_tag(cluster, counter)
                        #cluster[TAG_COLOR] = CLUSTERING_COLORS[counter]
                        diff_clusters[counter].append(cluster)
                else:
                    raise Exception("Unknown cluster origin {}".format(cluster_origin))
            counter += 1
        self.comparison[counter - 1]['clusters'] = common_clusters + sum(diff_clusters, list())

    def __change_reports_tag(self, cluster: dict, counter: int):
        cluster[TAG_REPORTS + "_{}".format(counter)] = cluster[TAG_REPORTS]
        del cluster[TAG_REPORTS]

    def __process_common_cluster(self, cluster: dict, common_clusters: list, counter: int, common_counter: int):
        if counter:
            common_clusters[common_counter][TAG_REPORTS + "_{}".format(counter)] = cluster[TAG_REPORTS]
            return
        self.__change_reports_tag(cluster, counter)
        if self.clustering_type == CLUSTERING_TYPE_DIFF_CLUSTERS:
            cluster[TAG_HIDE] = True
        common_clusters.append(cluster)

    def perform_clustering(self, unsafes: dict, unsafe_incompletes: dict, cmp) -> list:
        clusters_by_attrs = dict()
        clusters_by_attrs_reverse = dict()
        traces = set()
        clusters = list()
        for attrs, reports in unsafes.items():
            clusters_by_attrs[attrs] = set(reports)
            for report_id in reports:
                clusters_by_attrs_reverse[report_id] = attrs
            traces.update(reports)
        for attrs, reports in unsafe_incompletes.items():
            unsafe_reports = set()
            for report_id, report_type in reports:
                if report_type == VERDICT_UNSAFE:
                    unsafe_reports.add(report_id)
                    clusters_by_attrs_reverse[report_id] = attrs
            clusters_by_attrs[attrs] = set(unsafe_reports)
            traces.update(unsafe_reports)
        cmp['error_traces'] = len(traces)

        mark_to_reports = dict()
        for mark_id, report_id in MarkUnsafeReport.objects.filter(report__id__in=traces). \
                values_list('mark__id', 'report__id'):
            if mark_id not in mark_to_reports:
                mark_to_reports[mark_id] = set()
            mark_to_reports[mark_id].add(report_id)
            if report_id in traces:
                traces.remove(report_id)

        for mark_id, report_ids in mark_to_reports.items():
            attrs = ""
            for report_id in report_ids:
                report_attrs = clusters_by_attrs_reverse[report_id]
                if attrs:
                    attrs = SequenceMatcher(None, attrs, report_attrs).\
                        find_longest_match(0, len(attrs), 0, len(report_attrs))
                else:
                    attrs = report_attrs
            clusters.append({
                TAG_ATTRS: attrs,
                TAG_ORIGIN: CLUSTERING_ORIGIN_MARK,
                TAG_MARK: mark_id,
                TAG_REPORTS: sorted(report_ids)
            })
        cmp['cluster_marks'] = len(mark_to_reports)

        auto_clusters_counter = 0
        for attrs, reports in clusters_by_attrs.items():
            converted_error_traces = dict()
            for report_id in sorted(reports):
                if report_id not in traces:
                    # There is a mark for this trace.
                    continue
                converted_error_trace = get_or_convert_error_trace_auto(report_id, self.conversion_function, {})
                if not converted_error_traces:
                    converted_error_traces[converted_error_trace] = {report_id}
                else:
                    is_equal = False
                    for processed_cet in converted_error_traces.keys():
                        if is_trace_equal(converted_error_trace, processed_cet, self.comparison_function,
                                          self.similarity)[0]:
                            is_equal = True
                            converted_error_traces[processed_cet].add(report_id)
                            break
                    if not is_equal:
                        converted_error_traces[converted_error_trace] = {report_id}
            if converted_error_traces:
                for cet, report_ids in converted_error_traces.items():
                    clusters.append({
                        TAG_ATTRS: attrs,
                        TAG_ORIGIN: CLUSTERING_ORIGIN_AUTO,
                        TAG_CET: cet,
                        TAG_REPORTS: sorted(report_ids)
                    })
                    auto_clusters_counter += 1

        cmp['cluster_ama'] = auto_clusters_counter
        return clusters

    def __init_args(self, args: dict):
        # Default values.
        self.show_same_transitions = {
            VERDICTS_SAFE: False,
            VERDICTS_UNSAFE: False,
            VERDICTS_UNSAFE_INCOMPLETE: False,
            VERDICTS_UNKNOWN: False
        }
        self.show_lost_transitions = {
            VERDICT_SAFE: False,
            VERDICT_UNSAFE: False,
            VERDICT_UNKNOWN: False
        }
        self.comparison_attrs = set()
        self.filtered_values = dict()
        self.is_modified = False
        self.core_attrs = set()
        self.core_keys = dict()
        self.core_keys_inverse = dict()

        # MEA.
        self.enable_clustering = False
        self.conversion_functions = CONVERSION_FUNCTIONS
        self.comparison_functions = COMPARISON_FUNCTIONS
        self.similarity = DEFAULT_SIMILARITY_THRESHOLD
        self.conversion_function = DEFAULT_CONVERSION_FUNCTION
        self.comparison_function = DEFAULT_COMPARISON_FUNCTION
        self.clustering_type = CLUSTERING_TYPE_ALL

        if args:
            self.is_modified = True
            if 'same_transitions' in args:
                same_transitions = args.get('same_transitions', [])
                for verdicts in self.show_same_transitions:
                    self.show_same_transitions[verdicts] = verdicts in same_transitions
            if 'lost_transitions' in args:
                lost_transitions = args.get('lost_transitions', [])
                for verdicts in self.show_lost_transitions:
                    self.show_lost_transitions[verdicts] = verdicts in lost_transitions
            self.comparison_attrs = set(args.get('comparison_attrs', set()))
            for arg in args.get('filtered_values', {}):
                name, value = str(arg).split("<::>")
                if name not in self.filtered_values:
                    self.filtered_values[name] = set()
                self.filtered_values[name].add(value)
            if 'mea_config' in args:
                mea_config = args.get('mea_config', {})
                self.enable_clustering = mea_config.get('enable', self.enable_clustering)
                self.conversion_function = mea_config.get('conversion', self.conversion_function)
                self.comparison_function = mea_config.get('comparison', self.comparison_function)
                self.similarity = int(mea_config.get('similarity', self.similarity))
                self.clustering_type = mea_config.get('clustering_type', self.clustering_type)

    def __process_verdicts_transitions(self, verdicts_type: str, safes: dict, unsafes: dict, unsafe_incompletes: dict,
                                       unknowns: dict, cmp: dict) -> None:
        to_safes = list()
        to_unsafes = list()
        to_unsafe_incompletes = list()
        to_unknowns = list()
        first_reports = self.comparison[0].get(verdicts_type)
        old_reports_number = len(first_reports)
        for cur_attrs, old_reports in first_reports.items():
            if cur_attrs in safes:
                to_safes.append((old_reports, cur_attrs, safes[cur_attrs]))
            elif cur_attrs in unsafes:
                to_unsafes.append((old_reports, cur_attrs, unsafes[cur_attrs]))
            elif cur_attrs in unsafe_incompletes:
                to_unsafe_incompletes.append((old_reports, cur_attrs, unsafe_incompletes[cur_attrs]))
            elif cur_attrs in unknowns:
                to_unknowns.append((old_reports, cur_attrs, unknowns[cur_attrs]))
            else:
                core_cur_attrs = self.core_keys[cur_attrs]
                if core_cur_attrs in safes:
                    to_safes.append((old_reports, cur_attrs, safes[core_cur_attrs]))
                elif core_cur_attrs in unsafes:
                    to_unsafes.append((old_reports, cur_attrs, unsafes[core_cur_attrs]))
                elif core_cur_attrs in unsafe_incompletes:
                    to_unsafe_incompletes.append((old_reports, cur_attrs, unsafe_incompletes[core_cur_attrs]))
                elif core_cur_attrs in unknowns:
                    to_unknowns.append((old_reports, cur_attrs, unknowns[core_cur_attrs]))
                else:
                    core_cur_attrs = self.core_keys_inverse.get(cur_attrs)
                    if core_cur_attrs in safes:
                        to_safes.append((old_reports, cur_attrs, safes[core_cur_attrs]))
                    elif core_cur_attrs in unsafes:
                        to_unsafes.append((old_reports, cur_attrs, unsafes[core_cur_attrs]))
                    elif core_cur_attrs in unsafe_incompletes:
                        to_unsafe_incompletes.append((old_reports, cur_attrs, unsafe_incompletes[core_cur_attrs]))
                    elif core_cur_attrs in unknowns:
                        to_unknowns.append((old_reports, cur_attrs, unknowns[core_cur_attrs]))
                    else:
                        print("Warning: lost transition from reports {} for attrs {} (core attrs are {})".
                              format(old_reports, cur_attrs, core_cur_attrs))

        cmp['{}_safes'.format(verdicts_type)] = sorted(to_safes, key=lambda x: x[1])
        cmp['{}_unsafes'.format(verdicts_type)] = sorted(to_unsafes, key=lambda x: x[1])
        cmp['{}_unsafe_incompletes'.format(verdicts_type)] = sorted(to_unsafe_incompletes, key=lambda x: x[1])
        cmp['{}_unknowns'.format(verdicts_type)] = sorted(to_unknowns, key=lambda x: x[1])
        if verdicts_type == VERDICTS_SAFE:
            lost_verdicts = old_reports_number - len(to_safes)
            new_reports = len(safes)
        elif verdicts_type == VERDICTS_UNSAFE:
            lost_verdicts = old_reports_number - len(to_unsafes)
            new_reports = len(unsafes)
        elif verdicts_type == VERDICTS_UNSAFE_INCOMPLETE:
            lost_verdicts = old_reports_number - len(to_unsafe_incompletes)
            new_reports = len(unsafe_incompletes)
        else:
            lost_verdicts = old_reports_number - len(to_unknowns)
            new_reports = len(unknowns)
        cmp['{}_lost'.format(verdicts_type)] = lost_verdicts
        diff = abs(old_reports_number - new_reports)
        # TODO: shit!
        if lost_verdicts >= diff:
            new_verdicts = lost_verdicts - diff
        else:
            new_verdicts = lost_verdicts + diff
        cmp['{}_new'.format(verdicts_type)] = new_verdicts

    def sort_internals_by_attrs(self, number: int, common_attrs_ids: set) -> tuple:
        safes = dict()
        unsafes = dict()
        unsafe_incompletes = dict()
        unknowns = dict()
        cpu_sum = dict()

        verdicts_by_attrs = dict()
        ids_by_attrs = dict()
        lost = set()
        for report_id, internal in self.internals[number].items():

            if self.filtered_values:
                if internal.is_attr(self.filtered_values):
                    continue

            key, key_core = internal.serialize_attrs(self.core_attrs)
            self.core_keys[key] = key_core
            self.core_keys_inverse[key_core] = key
            if not internal.attrs_ids:
                continue
            verdict = internal.verdict
            if not set(internal.attrs_ids).issubset(common_attrs_ids):
                if self.show_lost_transitions[verdict]:
                    lost.add(report_id)
                continue
            if key not in verdicts_by_attrs:
                verdicts_by_attrs[key] = verdict
                ids_by_attrs[key] = {report_id: verdict}
                cpu_sum[internal.parent_report_id] = internal.cpu_time
            else:
                ids_by_attrs[key][report_id] = verdict
                old_verdict = verdicts_by_attrs[key]
                if old_verdict == VERDICT_UNSAFE and verdict == VERDICT_UNKNOWN or \
                        verdict == VERDICT_UNSAFE and old_verdict == VERDICT_UNKNOWN:
                    verdicts_by_attrs[key] = VERDICT_UNSAFE_INCOMPLETE
                elif old_verdict in [VERDICT_UNSAFE, VERDICT_UNSAFE_INCOMPLETE] and verdict == VERDICT_UNSAFE:
                    pass
                else:
                    print("Warning: strange verdicts: {} and {} for attrs {}: {}".format(old_verdict, verdict, key,
                                                                                         internal))

        self.comparison[number]['elems_by_attrs'] = len(verdicts_by_attrs)

        for key, verdict in verdicts_by_attrs.items():
            result = ids_by_attrs[key]
            if verdict == VERDICT_SAFE:
                safes[key] = sorted(result.keys())
            elif verdict == VERDICT_UNSAFE:
                unsafes[key] = sorted(result.keys())
            elif verdict == VERDICT_UNSAFE_INCOMPLETE:
                unsafe_incompletes[key] = sorted(result.items())
            elif verdict == VERDICT_UNKNOWN:
                unknowns[key] = sorted(result.keys())
            else:
                raise Exception("Broken verdict: {}".format(verdict))

        if lost:
            lost_prepared = dict()
            for report_id in sorted(lost):
                internal = self.internals[number][report_id]
                verdict = internal.verdict
                key = internal.serialize_attrs()[0]
                if verdict not in lost_prepared:
                    lost_prepared[verdict] = list()
                lost_prepared[verdict].append({
                    'id': report_id,
                    'attrs': key
                })
            self.comparison[number]['lost'] = lost_prepared

        return safes, unsafes, unsafe_incompletes, unknowns, sum(cpu_sum.values())

    def sort_attrs(self, attrs: dict, attrs_vals: dict) -> tuple:
        attrs_selected = list()
        attrs_others = list()
        attrs_vals_selected = list()
        attrs_vals_others = list()
        for name, compare in sorted(attrs.items()):
            if compare:
                attrs_selected.append((name, True))
                attrs_vals_selected.append((name, attrs_vals[name]))
            else:
                attrs_others.append((name, False))
                attrs_vals_others.append((name, attrs_vals[name]))
        sorted_attrs = attrs_selected + attrs_others
        sorted_attrs_vals = attrs_vals_selected + attrs_vals_others
        return sorted_attrs, sorted_attrs_vals

    def get_common_attrs(self, attrs1: dict, attrs_vals1: dict, attrs2: dict, attrs_vals2: dict) -> tuple:
        attrs = dict()
        attrs_vals = dict()
        for attr in set(attrs1.keys()).intersection(attrs2.keys()):
            attrs[attr] = attrs1[attr]
        for attr in attrs.keys():
            attrs_vals[attr] = sorted(set(attrs_vals1[attr]).intersection(set(attrs_vals2[attr])))
        return attrs, attrs_vals

    def init_internals(self, root: ReportRoot) -> tuple:
        """
        Get all required information about the given report from the database.
        """

        comparison_data = {
            'job': root.job,
            'other_components_unknowns': list(),
        }
        wall, cpu, mem = ComponentResource.objects.filter(report__root=root, report__parent=None, component__name="Core").\
            values_list('wall_time', 'cpu_time', 'memory').first()
        comparison_data['overall_wall'], comparison_data['overall_cpu'], comparison_data['overall_mem'] = \
            get_resource_data('hum', 2, ComponentResource(wall_time=wall, cpu_time=cpu, memory=mem))

        internals = dict()
        verifier_components = set()
        other_components_unknowns = dict()
        for report_id, cpu_time, parent_report_id in ReportUnsafe.objects.filter(root=root).\
                values_list('id', 'cpu_time', 'parent__id'):
            internals[report_id] = InternalLeaf(VERDICT_UNSAFE, cpu_time, parent_report_id)
            verifier_components.add(parent_report_id)
        for report_id, cpu_time, parent_report_id in ReportSafe.objects.filter(root=root).\
                values_list('id', 'cpu_time', 'parent__id'):
            internals[report_id] = InternalLeaf(VERDICT_SAFE, cpu_time, parent_report_id)
            verifier_components.add(parent_report_id)
        for report_id, cpu_time, parent_report_id, component, verification in ReportUnknown.objects.filter(root=root).\
                values_list('id', 'cpu_time', 'parent__id', 'component__name', 'parent__reportcomponent__verification'):
            if verification:
                verifier_components.add(parent_report_id)
                internals[report_id] = InternalLeaf(VERDICT_UNKNOWN, cpu_time, parent_report_id)
            else:
                other_components_unknowns[report_id] = component

        comparison_data['launches'] = len(verifier_components)
        other_components_problems = dict()
        for problem, report_id in MarkUnknownReport.objects.filter(report__id__in=other_components_unknowns.keys()).\
                values_list('problem__name', 'report_id'):
            if report_id not in other_components_problems:
                other_components_problems[report_id] = set()
            other_components_problems[report_id].add(problem)

        for report_id, component in sorted(other_components_unknowns.items()):
            if report_id in other_components_problems:
                problem = ", ".join(sorted(other_components_problems[report_id]))
            else:
                problem = "-"
            comparison_data['other_components_unknowns'].append({
                "id": report_id,
                "component": component,
                "problem": problem
            })

        attrs = dict()
        attrs_vals = dict()
        attrs_ids = set()
        for report_id, attr_id, name, val, compare in ReportAttr.objects.filter(report__in=internals.keys()). \
                values_list('report__id', 'attr_id', 'attr__name__name', 'attr__value', 'associate'):
            if name in FILTERED_ATTRS:
                continue

            if compare:
                self.core_attrs.add(name)

            if self.comparison_attrs:
                compare = name in self.comparison_attrs

            if name not in attrs:
                attrs[name] = compare
            if name not in attrs_vals:
                attrs_vals[name] = set()
            attrs_vals[name].add(val)
            if compare:
                attrs_ids.add(attr_id)
                internals[report_id].add_attrs(name, val, attr_id)
        self.internals.append(internals)
        for attr in attrs.keys():
            attrs_vals[attr] = sorted(attrs_vals[attr])

        comparison_data['attrs_vals'] = self.sort_attrs(attrs, attrs_vals)[1]

        return attrs, attrs_vals, attrs_ids, comparison_data


# *** Outdated / not supported anymore ***


def can_compare(user, job1, job2):
    if not isinstance(job1, Job) or not isinstance(job2, Job) or not isinstance(user, User):
        return False
    if not JobAccess(user, job1).can_view() or not JobAccess(user, job2).can_view():
        return False
    return True


class ReportTree:
    def __init__(self, root, name_ids):
        self._name_ids = name_ids
        self.attr_values = {}
        self._report_tree = {}
        self._leaves = {'u': set(), 's': set(), 'f': set()}
        self.__get_tree(root)

    def __get_tree(self, root):
        core_id = None
        for r_id, p_id in Report.objects.filter(root=root).values_list('id', 'parent_id'):
            self._report_tree[r_id] = p_id
            if p_id is None:
                core_id = r_id

        leaves_fields = {'u': 'unsafe_id', 's': 'safe_id', 'f': 'unknown_id'}
        # core has all leaves of the job
        for leaf in ReportComponentLeaf.objects.filter(report_id=core_id).values('safe_id', 'unsafe_id', 'unknown_id'):
            # There is often number of safes > unknowns > unsafes
            for l_type in 'sfu':
                l_id = leaf[leaves_fields[l_type]]
                if l_id is not None:
                    self._leaves[l_type].add(l_id)
                    break

        # The order is important
        for l_type in 'usf':
            self.__fill_leaves_vals(l_type)

    def __fill_leaves_vals(self, l_type):
        leaves_attrs = {}
        for ra in ReportAttr.objects.filter(report_id__in=self._leaves[l_type], attr__name_id__in=self._name_ids)\
                .select_related('attr').only('report_id', 'attr__name_id', 'attr__value'):
            if ra.report_id not in leaves_attrs:
                leaves_attrs[ra.report_id] = {}
            leaves_attrs[ra.report_id][ra.attr.name_id] = ra.attr_id

        for l_id in self._leaves[l_type]:
            if l_id in leaves_attrs:
                attrs_id = '|'.join(
                    str(leaves_attrs[l_id][n_id]) if n_id in leaves_attrs[l_id] else '-' for n_id in self._name_ids
                )
            else:
                attrs_id = '|'.join(['-'] * len(self._name_ids))

            branch_ids = [(l_type, l_id)]
            parent = self._report_tree[l_id]
            while parent is not None:
                branch_ids.insert(0, ('c', parent))
                parent = self._report_tree[parent]

            if attrs_id in self.attr_values:
                if l_type == 's':
                    self.attr_values[attrs_id]['verdict'] = COMPARE_VERDICT[5][0]
                elif l_type == 'f':
                    for branch in self.attr_values[attrs_id]['branches']:
                        if branch[-1][0] != 'u':
                            self.attr_values[attrs_id]['verdict'] = COMPARE_VERDICT[5][0]
                            break
                    else:
                        self.attr_values[attrs_id]['verdict'] = COMPARE_VERDICT[2][0]
                self.attr_values[attrs_id]['branches'].append(branch_ids)
            else:
                if l_type == 'u':
                    verdict = COMPARE_VERDICT[1][0]
                elif l_type == 's':
                    verdict = COMPARE_VERDICT[0][0]
                else:
                    verdict = COMPARE_VERDICT[3][0]
                self.attr_values[attrs_id] = {'branches': [branch_ids], 'verdict': verdict}


class CompareTree:
    def __init__(self, user, root1, root2):
        self.user = user
        self._root1 = root1
        self._root2 = root2

        self._name_ids = self.__get_attr_names()
        self.tree1 = ReportTree(self._root1, self._name_ids)
        self.tree2 = ReportTree(self._root2, self._name_ids)

        self.attr_values = {}
        self.__compare_values()
        self.__fill_cache()

    def __get_attr_names(self):
        names1 = set(aname for aname, in ReportAttr.objects.filter(report__root=self._root1, compare=True)
                     .values_list('attr__name_id'))
        names2 = set(aname for aname, in ReportAttr.objects.filter(report__root=self._root2, compare=True)
                     .values_list('attr__name_id'))
        if names1 != names2:
            raise BridgeException(_("Jobs with different sets of attributes to compare can't be compared"))
        return sorted(names1)

    def __compare_values(self):
        for a_id in self.tree1.attr_values:
            self.attr_values[a_id] = {
                'v1': self.tree1.attr_values[a_id]['verdict'],
                'v2': COMPARE_VERDICT[4][0],
                'branches1': self.tree1.attr_values[a_id]['branches'],
                'branches2': []
            }
            if a_id in self.tree2.attr_values:
                self.attr_values[a_id]['v2'] = self.tree2.attr_values[a_id]['verdict']
                self.attr_values[a_id]['branches2'] = self.tree2.attr_values[a_id]['branches']
        for a_id in self.tree2.attr_values:
            if a_id not in self.tree1.attr_values:
                self.attr_values[a_id] = {
                    'v1': COMPARE_VERDICT[4][0],
                    'v2': self.tree2.attr_values[a_id]['verdict'],
                    'branches1': [],
                    'branches2': self.tree2.attr_values[a_id]['branches']
                }

    def __fill_cache(self):
        info = CompareJobsInfo.objects.create(
            user=self.user, root1=self._root1, root2=self._root2,
            attr_names='|'.join(str(nid) for nid in self._name_ids)
        )
        CompareJobsCache.objects.bulk_create(list(CompareJobsCache(
            info=info, attr_values=x,
            verdict1=self.attr_values[x]['v1'], verdict2=self.attr_values[x]['v2'],
            reports1=json.dumps(self.attr_values[x]['branches1'], ensure_ascii=False),
            reports2=json.dumps(self.attr_values[x]['branches2'], ensure_ascii=False)
        ) for x in self.attr_values))


class ComparisonTableData:
    def __init__(self, user, root1, root2):
        self.data = []
        self.info = 0
        self.attrs = []
        self.__get_data(user, root1, root2)

    def __get_data(self, user, root1, root2):
        try:
            info = CompareJobsInfo.objects.get(user=user, root1=root1, root2=root2)
        except ObjectDoesNotExist:
            raise BridgeException(_('The comparison cache was not found'))
        self.info = info.pk

        numbers = {}
        for v1, v2, num in CompareJobsCache.objects.filter(info=info).values('verdict1', 'verdict2')\
                .annotate(number=Count('id')).values_list('verdict1', 'verdict2', 'number'):
            numbers[(v1, v2)] = num

        for v1 in COMPARE_VERDICT:
            row_data = []
            for v2 in COMPARE_VERDICT:
                num = '-'
                if (v1[0], v2[0]) in numbers:
                    num = (numbers[(v1[0], v2[0])], v2[0])
                row_data.append(num)
            self.data.append(row_data)

        all_attrs = {}
        names_ids = list(int(x) for x in info.attr_names.split('|'))
        for aname in AttrName.objects.filter(id__in=names_ids):
            all_attrs[aname.id] = {'values': set(), 'name': aname.name}
        if len(all_attrs) != len(names_ids):
            raise BridgeException(_('The comparison cache was corrupted'))

        for compare in info.comparejobscache_set.all():
            attr_values = compare.attr_values.split('|')
            if len(attr_values) != len(names_ids):
                raise BridgeException(_('The comparison cache was corrupted'))
            for i in range(len(attr_values)):
                if attr_values[i] == '-':
                    continue
                all_attrs[names_ids[i]]['values'].add(attr_values[i])

        for an_id in names_ids:
            values = []
            if len(all_attrs[an_id]['values']) > 0:
                values = list(Attr.objects.filter(id__in=all_attrs[an_id]['values'])
                              .order_by('value').values_list('id', 'value'))
            self.attrs.append({'name': all_attrs[an_id]['name'], 'values': values})


class ComparisonData:
    def __init__(self, info, page_num, hide_attrs, hide_components, verdict=None, attrs=None):
        self.info = info
        self._attr_names = list(int(x) for x in self.info.attr_names.split('|'))
        self.v1 = self.v2 = None
        self.hide_attrs = bool(int(hide_attrs))
        self.hide_components = bool(int(hide_components))
        self.attr_search = False
        self.pages = {
            'backward': True,
            'forward': True,
            'num': page_num,
            'total': 0
        }
        self.data = self.__get_data(verdict, attrs)

    def __get_verdicts(self, verdict):
        self.__is_not_used()
        m = re.match('^(\d)_(\d)$', verdict)
        if m is None:
            raise BridgeException()
        v1 = m.group(1)
        v2 = m.group(2)
        if any(v not in list(x[0] for x in COMPARE_VERDICT) for v in [v1, v2]):
            raise BridgeException()
        return v1, v2

    def __get_data(self, verdict=None, search_attrs=None):
        if search_attrs is not None:
            try:
                search_attrs = '|'.join(json.loads(search_attrs))
            except ValueError:
                raise BridgeException()
            if '__REGEXP_ANY__' in search_attrs:
                search_attrs = re.escape(search_attrs)
                search_attrs = search_attrs.replace('__REGEXP_ANY__', '\d+')
                search_attrs = '^' + search_attrs + '$'
                data = self.info.comparejobscache_set.filter(attr_values__regex=search_attrs).order_by('id')
            else:
                data = self.info.comparejobscache_set.filter(attr_values=search_attrs).order_by('id')
            self.attr_search = True
        elif verdict is not None:
            (v1, v2) = self.__get_verdicts(verdict)
            data = self.info.comparejobscache_set.filter(verdict1=v1, verdict2=v2).order_by('id')
        else:
            raise BridgeException()
        self.pages['total'] = len(data)
        if self.pages['total'] < self.pages['num']:
            raise BridgeException(_('Required reports were not found'))
        self.pages['backward'] = (self.pages['num'] > 1)
        self.pages['forward'] = (self.pages['num'] < self.pages['total'])
        data = data[self.pages['num'] - 1]
        for v in COMPARE_VERDICT:
            if data.verdict1 == v[0]:
                self.v1 = v[1]
            if data.verdict2 == v[0]:
                self.v2 = v[1]

        try:
            branches = self.__compare_reports(data)
        except ObjectDoesNotExist:
            raise BridgeException(_('The report was not found, please recalculate the comparison cache'))
        if branches is None:
            raise BridgeException()

        final_data = []
        for branch in branches:
            ordered = []
            for i in sorted(list(branch)):
                if len(branch[i]) > 0:
                    ordered.append(branch[i])
            final_data.append(ordered)
        return final_data

    def __compare_reports(self, c):
        data1 = self.__get_reports_data(json.loads(c.reports1))
        data2 = self.__get_reports_data(json.loads(c.reports2))
        for i in sorted(list(data1)):
            if i not in data2:
                break
            blocks = self.__compare_lists(data1[i], data2[i])
            if isinstance(blocks, list) and len(blocks) == 2:
                data1[i] = blocks[0]
                data2[i] = blocks[1]
        return [data1, data2]

    def __compare_lists(self, blocks1, blocks2):
        for b1 in blocks1:
            for b2 in blocks2:
                if b1.block_class != b2.block_class or b1.type == 'm':
                    continue
                for a1 in b1.list:
                    if a1['name'] not in list(x['name'] for x in b2.list):
                        a1['color'] = '#c60806'
                    for a2 in b2.list:
                        if a2['name'] not in list(x['name'] for x in b1.list):
                            a2['color'] = '#c60806'
                        if a1['name'] == a2['name'] and a1['value'] != a2['value']:
                            a1['color'] = a2['color'] = '#af49bd'
        if self.hide_attrs:
            for b1 in blocks1:
                for b2 in blocks2:
                    if b1.block_class != b2.block_class or b1.type == 'm':
                        continue
                    for b in [b1, b2]:
                        new_list = []
                        for a in b.list:
                            if 'color' in a:
                                new_list.append(a)
                        b.list = new_list
        if self.hide_components:
            for_del = {
                'b1': [],
                'b2': []
            }
            for i in range(len(blocks1)):
                for j in range(len(blocks2)):
                    if blocks1[i].block_class != blocks2[j].block_class or blocks1[i].type != 'c':
                        continue
                    if blocks1[i].list == blocks2[j].list and blocks1[i].add_info == blocks2[j].add_info:
                        for_del['b1'].append(i)
                        for_del['b2'].append(j)
            new_blocks1 = []
            for i in range(0, len(blocks1)):
                if i not in for_del['b1']:
                    new_blocks1.append(blocks1[i])
            new_blocks2 = []
            for i in range(0, len(blocks2)):
                if i not in for_del['b2']:
                    new_blocks2.append(blocks2[i])
            return [new_blocks1, new_blocks2]
        return None

    def __get_reports_data(self, reports):
        branch_data = {}
        get_block = {
            'u': (self.__unsafe_data, self.__unsafe_mark_data),
            's': (self.__safe_data, self.__safe_mark_data),
            'f': (self.__unknown_data, self.__unknown_mark_data)
        }
        added_ids = set()
        for branch in reports:
            cnt = 1
            parent = None
            for rdata in branch:
                if cnt not in branch_data:
                    branch_data[cnt] = []
                if rdata[1] in added_ids:
                    pass
                elif rdata[0] == 'c':
                    branch_data[cnt].append(
                        self.__component_data(rdata[1], parent)
                    )
                elif rdata[0] in 'usf':
                    branch_data[cnt].append(
                        get_block[rdata[0]][0](rdata[1], parent)
                    )
                    cnt += 1
                    for b in get_block[rdata[0]][1](rdata[1]):
                        if cnt not in branch_data:
                            branch_data[cnt] = []
                        if b.id not in list(x.id for x in branch_data[cnt]):
                            branch_data[cnt].append(b)
                        else:
                            for i in range(len(branch_data[cnt])):
                                if b.id == branch_data[cnt][i].id:
                                    if rdata[0] == 'f' \
                                            and b.add_info[0]['value'] != branch_data[cnt][i].add_info[0]['value']:
                                        branch_data[cnt].append(b)
                                    else:
                                        branch_data[cnt][i].parents.extend(b.parents)
                                    break
                    break
                parent = rdata[1]
                cnt += 1
                added_ids.add(rdata[1])
        return branch_data

    def __component_data(self, report_id, parent_id):
        report = ReportComponent.objects.get(pk=report_id)
        block = CompareBlock('c_%s' % report_id, 'c', report.component.name, 'comp_%s' % report.component_id)
        if parent_id is not None:
            block.parents.append('c_%s' % parent_id)
        block.list = self.__get_attrs_list(report)
        block.href = reverse('reports:component', args=[report.pk])
        return block

    def __unsafe_data(self, report_id, parent_id):
        report = ReportUnsafe.objects.get(pk=report_id)
        block = CompareBlock('u_%s' % report_id, 'u', _('Unsafe'), 'unsafe')
        block.parents.append('c_%s' % parent_id)
        block.add_info = {'value': report.get_verdict_display(), 'color': UNSAFE_COLOR[report.verdict]}
        block.list = self.__get_attrs_list(report)
        block.href = reverse('reports:unsafe', args=[report.trace_id])
        return block

    def __safe_data(self, report_id, parent_id):
        report = ReportSafe.objects.get(pk=report_id)
        block = CompareBlock('s_%s' % report_id, 's', _('Safe'), 'safe')
        block.parents.append('c_%s' % parent_id)
        block.add_info = {'value': report.get_verdict_display(), 'color': SAFE_COLOR[report.verdict]}
        block.list = self.__get_attrs_list(report)
        block.href = reverse('reports:safe', args=[report.pk])
        return block

    def __unknown_data(self, report_id, parent_id):
        report = ReportUnknown.objects.get(pk=report_id)
        block = CompareBlock('f_%s' % report_id, 'f', _('Unknown'), 'unknown-%s' % report.component.name)
        block.parents.append('c_%s' % parent_id)
        problems = list(x.problem.name for x in report.markreport_set.select_related('problem').order_by('id'))
        if len(problems) > 0:
            block.add_info = {'value': '; '.join(problems), 'color': '#c60806'}
        else:
            block.add_info = {'value': _('Without marks')}
        block.list = self.__get_attrs_list(report)
        block.href = reverse('reports:unknown', args=[report.pk])
        return block

    def __get_attrs_list(self, report):
        attrs_list = []
        for an_id, a_name, a_val in report.attrs.values_list('attr__name_id', 'attr__name__name', 'attr__value')\
                .order_by('attr__name__name'):
            attr_data = {'name': a_name, 'value': a_val}
            if an_id in self._attr_names:
                attr_data['color'] = '#8bb72c'
            attrs_list.append(attr_data)
        return attrs_list

    def __unsafe_mark_data(self, report_id):
        self.__is_not_used()
        blocks = []
        for mark in MarkUnsafeReport.objects.filter(report_id=report_id, result__gt=0, type__in='01')\
                .select_related('mark'):
            block = CompareBlock('um_%s' % mark.mark_id, 'm', _('Unsafes mark'))
            block.parents.append('u_%s' % report_id)
            block.add_info = {'value': mark.mark.get_verdict_display(), 'color': UNSAFE_COLOR[mark.mark.verdict]}
            block.href = reverse('marks:mark', args=['unsafe', mark.mark_id])
            for t in mark.mark.versions.order_by('-version').first().tags.all():
                block.list.append({'name': None, 'value': t.tag.tag})
            blocks.append(block)
        return blocks

    def __safe_mark_data(self, report_id):
        self.__is_not_used()
        blocks = []
        for mark in MarkSafeReport.objects.filter(report_id=report_id).select_related('mark'):
            block = CompareBlock('sm_%s' % mark.mark_id, 'm', _('Safes mark'))
            block.parents.append('s_%s' % report_id)
            block.add_info = {'value': mark.mark.get_verdict_display(), 'color': SAFE_COLOR[mark.mark.verdict]}
            block.href = reverse('marks:mark', args=['safe', mark.mark_id])
            for t in mark.mark.versions.order_by('-version').first().tags.all():
                block.list.append({'name': None, 'value': t.tag.tag})
            blocks.append(block)
        return blocks

    def __unknown_mark_data(self, report_id):
        self.__is_not_used()
        blocks = []
        for mark in MarkUnknownReport.objects.filter(report_id=report_id).select_related('problem'):
            block = CompareBlock("fm_%s" % mark.mark_id, 'm', _('Unknowns mark'))
            block.parents.append('f_%s' % report_id)
            block.add_info = {'value': mark.problem.name}
            block.href = reverse('marks:mark', args=['unknown', mark.mark_id])
            blocks.append(block)
        return blocks

    def __is_not_used(self):
        pass


class CompareBlock:
    def __init__(self, block_id, block_type, title, block_class=None):
        self.id = block_id
        self.block_class = block_class if block_class is not None else self.id
        self.type = block_type
        self.title = title
        self.parents = []
        self.list = []
        self.add_info = None
        self.href = None
