#
# Copyright (c) 2019 ISP RAS (http://www.ispras.ru)
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

from django.db.models import FloatField
from django.db.models import Q
from django.db.models.functions import Cast

from bridge.utils import logger
from bridge.vars import ATTRIBUTES_OPERATOR_EQ, ATTRIBUTES_OPERATOR_RE, ATTRIBUTES_OPERATOR_GE, ATTRIBUTES_OPERATOR_GT, \
    ATTRIBUTES_OPERATOR_LE, ATTRIBUTES_OPERATOR_LT, ATTRIBUTES_OPERATOR_NE
from marks.models import MarkUnsafeHistory, MarkSafeHistory, MarkUnknownHistory
from reports.models import ReportAttr, ReportUnsafe, Attr, AttrName, ReportSafe, ReportUnknown

VALUES_SEPARATOR = ","


def __get_or_create_attrs(name: str, val: str) -> Attr:
    attr = Attr.objects.get_or_create(
        name=AttrName.objects.get_or_create(name=name)[0], value=val
    )[0]
    return attr


def __get_internal_attrs_desc(attr_desc: dict) -> tuple:
    a_val = attr_desc['value']
    a_cmp = attr_desc['is_compare']
    a_op = attr_desc.get('op', ATTRIBUTES_OPERATOR_EQ)  # This is required for backward compatibility.
    return a_val, a_cmp, a_op


def create_attributes(mark_attr_type, args, markversion_id, inst=None) -> bool:
    if 'attrs' in args and (not isinstance(args['attrs'], list) or len(args['attrs']) == 0):
        del args['attrs']
    if 'attrs' in args:
        for a in args['attrs']:
            if not isinstance(a, dict) or not isinstance(a.get('attr'), str) \
                    or not isinstance(a.get('is_compare'), bool):
                raise ValueError('Wrong attribute found: %s' % a)
            if inst is None and not isinstance(a.get('value'), str):
                raise ValueError('Wrong attribute found: %s' % a)

    need_recalc = False
    new_attrs = []
    if isinstance(inst, ReportUnsafe) or isinstance(inst, ReportSafe) or isinstance(inst, ReportUnknown):
        for a_id, a_name, associate in inst.attrs.order_by('id') \
                .values_list('attr_id', 'attr__name__name', 'associate'):
            if 'attrs' in args:
                for a in args['attrs']:
                    if a['attr'] == a_name:
                        a_val, a_cmp, a_op = __get_internal_attrs_desc(a)
                        attr = __get_or_create_attrs(a_name, a_val)
                        new_attrs.append(mark_attr_type(
                            mark_id=markversion_id, attr=attr, is_compare=a_cmp, operator=a_op
                        ))
                        break
                else:
                    raise ValueError('Not enough attributes in args')
            else:
                new_attrs.append(mark_attr_type(mark_id=markversion_id, attr_id=a_id, is_compare=associate))
    elif isinstance(inst, MarkUnsafeHistory) or isinstance(inst, MarkSafeHistory) or \
            isinstance(inst, MarkUnknownHistory):
        for a_id, a_name, is_compare, op in inst.attrs.order_by('id') \
                .values_list('attr_id', 'attr__name__name', 'is_compare', 'operator'):
            if 'attrs' in args:
                for a in args['attrs']:
                    if a['attr'] == a_name:
                        a_val, a_cmp, a_op = __get_internal_attrs_desc(a)
                        attr = __get_or_create_attrs(a_name, a_val)
                        new_attrs.append(mark_attr_type(
                            mark_id=markversion_id, attr=attr, is_compare=a_cmp, operator=a_op
                        ))
                        if a_cmp != is_compare or attr.id != a_id or a_op != op:
                            need_recalc = True
                        break
                else:
                    raise ValueError('Not enough attributes in args')
            else:
                new_attrs.append(mark_attr_type(mark_id=markversion_id, attr_id=a_id, is_compare=is_compare))
    else:
        if 'attrs' not in args:
            raise ValueError('Attributes are required')
        for a in args['attrs']:
            a_val, a_cmp, a_op = __get_internal_attrs_desc(a)
            attr = __get_or_create_attrs(a['attr'], a_val)
            new_attrs.append(mark_attr_type(mark_id=markversion_id, attr=attr, is_compare=a_cmp, operator=a_op))
    mark_attr_type.objects.bulk_create(new_attrs)
    return need_recalc


def get_marks_attributes(mark_attr_type, attr_filters: dict) -> dict:
    marks_attrs = {}
    for mark_id, value, name, op in mark_attr_type.objects.filter(**attr_filters). \
            values_list('mark__mark_id', 'attr__value', 'attr__name__name', 'operator'):
        if mark_id not in marks_attrs:
            marks_attrs[mark_id] = set()
        marks_attrs[mark_id].add((name, value, op))
    return marks_attrs


def get_user_attrs(args: dict) -> dict:
    marks_attrs = {1: set()}
    if 'attrs' in args:
        for a in args['attrs']:
            a_name = a['attr']
            a_val, a_cmp, a_op = __get_internal_attrs_desc(a)
            if a_cmp:
                marks_attrs[1].add((a_name, a_val, a_op))
    return marks_attrs


def get_reports_by_attributes(mark_type: str, marks_attrs: dict, attr_filters: dict = None):
    marks_reports = dict()

    for m_id, attrs_desc in marks_attrs.items():
        attrs = dict()
        for attr_desc in attrs_desc:
            name = attr_desc[0]
            value = str(attr_desc[1])
            op = attr_desc[2]

            if op == ATTRIBUTES_OPERATOR_EQ and VALUES_SEPARATOR not in value:
                tmp_attrs = Attr.objects.filter(name__name=name, value=value).values_list('id')
                if tmp_attrs:
                    attrs[name] = {value}
            else:
                values = value.split(VALUES_SEPARATOR)
                tmp_attrs = tuple()
                if op == ATTRIBUTES_OPERATOR_EQ:
                    tmp_attrs = Attr.objects.filter(name__name=name, value__in=values).values_list('id', 'value')
                elif op == ATTRIBUTES_OPERATOR_RE:
                    for val in values:
                        tmp_attrs += tuple(Attr.objects.filter(name__name=name, value__regex=val).
                                           values_list('id', 'value'))
                elif op == ATTRIBUTES_OPERATOR_NE:
                    tmp_attrs = Attr.objects.filter(~Q(value__in=values), name__name=name).values_list('id', 'value')
                else:  # numbers
                    if len(values) == 1:
                        try:
                            number = float(values[0])
                            if op == ATTRIBUTES_OPERATOR_LE:
                                tmp_attrs = Attr.objects.annotate(value_float=Cast('value', FloatField())). \
                                    filter(name__name=name, value_float__lte=number). \
                                    values_list('id', 'value')
                            elif op == ATTRIBUTES_OPERATOR_LT:
                                tmp_attrs = Attr.objects.annotate(value_float=Cast('value', FloatField())). \
                                    filter(name__name=name, value_float__lt=number). \
                                    values_list('id', 'value')
                            elif op == ATTRIBUTES_OPERATOR_GE:
                                tmp_attrs = Attr.objects.annotate(value_float=Cast('value', FloatField())). \
                                    filter(name__name=name, value_float__gte=number). \
                                    values_list('id', 'value')
                            elif op == ATTRIBUTES_OPERATOR_GT:
                                tmp_attrs = Attr.objects.annotate(value_float=Cast('value', FloatField())). \
                                    filter(name__name=name, value_float__gt=number). \
                                    values_list('id', 'value')
                        except Exception as e:
                            logger.warning("Cannot parse number {}: {}".format(values[0], e))
                    else:
                        logger.warning("Only one number can be specified {}".format(values))
                for attr_id, attr_value in tmp_attrs:
                    if name not in attrs:
                        attrs[name] = set()
                    attrs[name].add(attr_value)

        if mark_type == 'unsafe':
            report_attrs = ReportAttr.objects.exclude(report__reportunsafe=None)
        elif mark_type == 'safe':
            report_attrs = ReportAttr.objects.exclude(report__reportsafe=None)
        else:
            report_attrs = ReportAttr.objects.exclude(report__reportunknown=None)
        if attr_filters:
            report_attrs = report_attrs.filter(**attr_filters)
        report_ids = set()
        for a_name, a_val in attrs.items():
            cur_ids = set(x[0] for x in report_attrs.filter(attr__name__name=a_name, attr__value__in=a_val).
                          values_list('report_id'))
            if not report_ids:
                report_ids = cur_ids
            else:
                report_ids = report_ids.intersection(cur_ids)
            if not report_ids:
                break
        if report_ids:
            marks_reports[m_id] = report_ids

    return marks_reports
