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

from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist, PermissionDenied
from django.db.models import F, Q
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render
from django.utils.translation import ugettext as _, activate

from bridge.utils import BridgeException, logger
from bridge.vars import USER_ROLES, JOB_STATUS, UNKNOWN_ERROR
from jobs.models import Job, JobFile
from marks.UnsafeUtils import ConnectMarks, RecalculateTags
from marks.models import MarkUnsafe, MarkUnsafeHistory, UnknownProblem, ConvertedTraces
from reports.models import Component, Computer, JobViewAttrs
from service.models import Task
from tools.models import LockTable
from tools.profiling import unparallel_group, ProfileData, clear_old_logs, ExecLocker
from tools.utils import objects_without_relations, ClearFiles, Recalculation
from marks.models import ErrorTraceConvertionCache
from reports.mea.core import CACHED_CONVERSION_FUNCTIONS


@login_required
def manager_tools(request):
    activate(request.user.extended.language)
    return render(request, "tools/ManagerPanel.html", {
        'components': Component.objects.all(),
        'problems': UnknownProblem.objects.all(),
        'jobs': Job.objects.exclude(reportroot=None).exclude(
            status__in=[JOB_STATUS[0][0], JOB_STATUS[1][0], JOB_STATUS[2][0]]
        )
    })


@login_required
@unparallel_group([Component])
def rename_component(request):
    activate(request.user.extended.language)
    if request.method != 'POST':
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    if request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': _("No access")})
    try:
        component = Component.objects.get(pk=int(request.POST.get('component_id', 0)))
    except ObjectDoesNotExist:
        return JsonResponse({'error': _("The component was not found")})
    new_name = request.POST.get('name', '')
    if len(new_name) == 0 or len(new_name) > 15:
        return JsonResponse({'error': _("The component name should be greater than 0 and less than 16 symbols")})
    if Component.objects.filter(name=new_name).exclude(pk=component.pk).count() > 0:
        return JsonResponse({'error': _("The specified component name is used already")})
    component.name = new_name
    component.save()
    return JsonResponse({'message': _("The component was successfully renamed")})


@login_required
@unparallel_group([Component])
def clear_components(request):
    activate(request.user.extended.language)
    if request.method != 'POST':
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    if request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': _("No access")})
    objects_without_relations(Component).delete()
    return JsonResponse({'message': _("All unused components were deleted, please reload the page")})


@login_required
@unparallel_group([UnknownProblem])
def clear_problems(request):
    activate(request.user.extended.language)
    if request.method != 'POST':
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    if request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': _("No access")})
    objects_without_relations(UnknownProblem).delete()
    return JsonResponse({'message': _("All unused problems were deleted, please reload the page")})


@login_required
@unparallel_group([JobFile, ConvertedTraces, Computer, Component, UnknownProblem])
def clear_system(request):
    activate(request.user.extended.language)
    if request.method != 'POST':
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    if request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': _("No access")})
    ClearFiles()
    objects_without_relations(Computer).delete()
    objects_without_relations(Component).delete()
    objects_without_relations(UnknownProblem).delete()
    return JsonResponse({'message': _("All unused files and DB rows were deleted")})


@login_required
@unparallel_group([JobFile, ConvertedTraces, Computer, Component, UnknownProblem])
def resolve_marks(request):
    activate(request.user.extended.language)
    if request.method != 'POST':
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    if request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': _("No access")})
    marks = MarkUnsafe.objects.filter(~Q(optimizations=0))
    for mark in marks:
        try:
            last_v = MarkUnsafeHistory.objects.get(mark=mark, version=F('mark__version'))
            changes = ConnectMarks([mark], last_v.similarity, json.loads(last_v.args)).changes.get(mark.id, [])
            RecalculateTags(list(changes))
            mark.optimizations = 0
            mark.save()
        except Exception as e:
            logger.exception(e)

    return JsonResponse({'message': _("Optimizations for all marks were resolved")})


@login_required
@unparallel_group([Job])
def recalculation(request):
    activate(request.user.extended.language)
    if request.method != 'POST':
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    if request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': _("No access")})
    if 'type' not in request.POST:
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    try:
        Recalculation(request.POST['type'], request.POST.get('jobs', None))
    except BridgeException as e:
        return JsonResponse({'error': str(e)})
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'error': str(UNKNOWN_ERROR)})
    return JsonResponse({'message': _("Caches were successfully recalculated")})


@login_required
def view_call_logs(request):
    activate(request.user.extended.language)
    return render(request, "tools/CallLogs.html", {})


def call_list(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.method != 'POST' or request.user.extended.role != USER_ROLES[2][0]:
        return HttpResponse('<h1>Unknown error</h1>')
    action = request.POST.get('action')
    if action == 'between':
        date1 = None
        if 'date1' in request.POST:
            date1 = float(request.POST['date1'])
        date2 = None
        if 'date2' in request.POST:
            date2 = float(request.POST['date2'])
        data = ProfileData().get_log(date1, date2, request.POST.get('name'))
    elif action == 'around' and 'date' in request.POST:
        if 'interval' in request.POST:
            data = ProfileData().get_log_around(float(request.POST['date']), int(request.POST['interval']))
        else:
            data = ProfileData().get_log_around(float(request.POST['date']))
    else:
        return HttpResponse('<h1>Unknown error</h1>')
    return render(request, "tools/LogList.html", {'data': data})


def call_statistic(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.method != 'POST' or request.user.extended.role != USER_ROLES[2][0]:
        return HttpResponse('<h1>Unknown error</h1>')
    action = request.POST.get('action')
    data = None
    if action == 'between':
        date1 = None
        if 'date1' in request.POST:
            date1 = float(request.POST['date1'])
        date2 = None
        if 'date2' in request.POST:
            date2 = float(request.POST['date2'])
        data = ProfileData().get_statistic(date1, date2, request.POST.get('name'))
    elif action == 'around' and 'date' in request.POST:
        if 'interval' in request.POST:
            data = ProfileData().get_statistic_around(float(request.POST['date']), int(request.POST['interval']))
        else:
            data = ProfileData().get_statistic_around(float(request.POST['date']))
    return render(request, "tools/CallStatistic.html", {'data': data})


def processing_list(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.user.extended.role != USER_ROLES[2][0]:
        return HttpResponse('<h1>Unknown error</h1>')
    return render(request, "tools/ProcessingRequests.html", {
        'data': ProfileData().processing(), 'locked': LockTable.objects.filter(locked=True)
    })


def clear_call_logs(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.method != 'POST' or request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': 'Unknown error'})
    clear_old_logs()
    return JsonResponse({'message': _('Logs were successfully cleared')})


def clear_cet(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.method != 'POST' or request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': 'Unknown error'})

    data = dict()

    for cet_f, cet_args in ErrorTraceConvertionCache.objects.values_list('function', 'args'):
        key = (cet_f, cet_args)
        if key not in data:
            data[key] = 1
        else:
            data[key] += 1

    removed_records = 0
    all_records = ErrorTraceConvertionCache.objects.count()
    for key, num in data.items():
        cet_f = key[0]
        cet_args = key[1]
        counter = MarkUnsafeHistory.objects.filter(conversion_function=cet_f, args=cet_args).count()
        if not counter:
            if not (cet_f in CACHED_CONVERSION_FUNCTIONS and cet_args == "{}"):
                removed_records += num
                ErrorTraceConvertionCache.objects.filter(function=cet_f, args=cet_args).delete()

    return JsonResponse({'message': str(removed_records) + _(' unused converted error traces of ') +
                                    str(all_records) + _(' have been deleted')})


def clear_all_cet(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.method != 'POST' or request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': 'Unknown error'})

    all_records = ErrorTraceConvertionCache.objects.count()
    ErrorTraceConvertionCache.objects.all().delete()

    return JsonResponse({'message': str(all_records) + _(' converted error traces have been deleted')})


def clear_jobs_view(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.method != 'POST' or request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': 'Unknown error'})

    number_of_attrs = JobViewAttrs.objects.count()
    if not number_of_attrs:
        return JsonResponse({'message': _('Job attributes view cache is empty')})
    JobViewAttrs.objects.all().delete()
    return JsonResponse({'message': str(number_of_attrs) + _(' cached records were successfully deleted')})


def clear_tasks(request):
    activate(request.user.extended.language)
    if not request.user.is_authenticated or request.method != 'POST' or request.user.extended.role != USER_ROLES[2][0]:
        return JsonResponse({'error': 'Unknown error'})
    Task.objects.exclude(progress__job__status=JOB_STATUS[2][0]).delete()
    return JsonResponse({'message': _('Tasks were successfully deleted')})


def manual_unlock(request):
    if not request.user.is_staff:
        raise PermissionDenied()
    LockTable.objects.all().delete()
    try:
        os.remove(ExecLocker.lockfile)
    except FileNotFoundError:
        pass
    return HttpResponse('<h1>Success!</h1>')
