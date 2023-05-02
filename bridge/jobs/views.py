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
from difflib import unified_diff
from urllib.parse import unquote
from wsgiref.util import FileWrapper

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.template.defaulttags import register
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _, override
from django.views.generic.base import TemplateView
from django.views.generic.detail import SingleObjectMixin, DetailView

import bridge.CustomViews as Bview
import jobs.utils
from bridge.utils import logger, file_get_or_create, extract_archive, BridgeException
from bridge.vars import VIEW_TYPES, JOB_STATUS, PRIORITY, JOB_WEIGHT, USER_ROLES
from jobs.Download import UploadJob, JobArchiveGenerator, KleverCoreArchiveGen, JobsArchivesGen, \
    UploadReportsWithoutDecision, JobsTreesGen, UploadTree
from jobs.JobTableProperties import TableTree
from jobs.ViewJobData import ViewJobData, update_job_view_attrs
from jobs.configuration import get_configuration_value, GetConfiguration, StartDecisionData
from jobs.jobForm import JobForm, role_info, LoadFilesTree, UserRolesForm
from jobs.models import Job, RunHistory, JobHistory, JobFile, FileSystem
from reports.UploadReport import UploadReport, CollapseReports
from reports.comparison import can_compare
from reports.models import ReportComponent, ReportAttr
from reports.utils import FilesForCompetitionArchive
from service.utils import StartJobDecision, StopDecision, GetJobsProgresses
from tools.profiling import LoggedCallMixin
from users.models import User


@register.filter
def get(dictionary, key):
    if dictionary:
        return dictionary.get(key)
    else:
        return None


@method_decorator(login_required, name='dispatch')
class JobsTree(LoggedCallMixin, Bview.DataViewMixin, TemplateView):
    template_name = 'jobs/tree.html'

    def get_context_data(self, **kwargs):
        return {
            'users': User.objects.all(),
            'statuses': JOB_STATUS, 'weights': JOB_WEIGHT, 'priorities': list(reversed(PRIORITY)),
            'months': jobs.utils.months_choices(), 'years': jobs.utils.years_choices(),
            'TableData': TableTree(self.request.user, self.get_view(VIEW_TYPES[1]))
        }


@method_decorator(login_required, name='dispatch')
class JobPage(LoggedCallMixin, Bview.DataViewMixin, DetailView):
    model = Job
    template_name = 'jobs/viewJob.html'

    def get_context_data(self, **kwargs):
        job_access = jobs.utils.JobAccess(self.request.user, self.object)
        if not job_access.can_view():
            raise BridgeException(code=400)
        versions = jobs.utils.JobVersionsData(self.object, self.request.user)
        if versions.first_version is None:
            logger.error("There is a job without versions")
            raise BridgeException()
        report = ReportComponent.objects.filter(root__job=self.object, parent=None).first()
        attrs = {}
        coverage = dict()
        if report:
            for identifier, functions, lines in report.coverages.\
                    values_list('identifier', 'lines_percent', 'functions_percent'):
                coverage[identifier] = functions, lines
        for name, val, associate in ReportAttr.objects.filter(report__root__job=self.object).\
                values_list('attr__name__name', 'attr__value', 'associate'):
            if not associate:
                continue
            if name not in attrs:
                attrs[name] = set()
            attrs[name].add(val)

        return {
            'job': self.object, 'job_access': job_access, 'created_by': versions.first_version.change_author,
            'versions': versions.versions, 'last_version': versions.last_version,
            'roles': role_info(versions.last_version, self.request.user),
            'parents': jobs.utils.get_job_parents(self.request.user, self.object),
            'children': jobs.utils.get_job_children(self.request.user, self.object),
            'progress': GetJobsProgresses(self.request.user, [self.object.id]).data[self.object.id],
            'reportdata': ViewJobData(self.request.user, self.get_view(VIEW_TYPES[2]), report),
            'attrs': attrs, 'coverage': coverage
        }


@method_decorator(login_required, name='dispatch')
class JobsScatterPage(LoggedCallMixin, TemplateView):
    template_name = 'jobs/scatter.html'

    def get_context_data(self, **kwargs):
        args = json.loads(self.request.GET.get('args', '{}'))
        try:
            job1 = Job.objects.get(id=self.kwargs['job1_id'])
            job2 = Job.objects.get(id=self.kwargs['job2_id'])
        except ObjectDoesNotExist:
            raise BridgeException(code=405)
        if not jobs.utils.JobAccess(self.request.user, job1).can_view() \
                or not jobs.utils.JobAccess(self.request.user, job2).can_view():
            raise BridgeException(code=401)
        plot, res_names, tasks = jobs.utils.get_scatter_plot(job1.id, job2.id, args)
        return {
            'job1': job1,
            'job2': job2,
            'resources': plot,
            'res_names': res_names,
            'args': args,
            'tasks': tasks
        }


@method_decorator(login_required, name='dispatch')
class JobQuantilePage(LoggedCallMixin, Bview.DataViewMixin, DetailView):
    model = Job
    template_name = 'jobs/quantile.html'

    def get_context_data(self, **kwargs):
        args = json.loads(self.request.GET.get('args', '{}'))
        job_access = jobs.utils.JobAccess(self.request.user, self.object)
        if not job_access.can_view():
            raise BridgeException(code=400)
        plot, res_names = jobs.utils.get_quantile_plot([self.object.id], args)
        return {
            'job': self.object,
            'job_ids': [(self.object.id, self.object.name)],
            'res_names': res_names,
            'resources': plot,
            'args': args
        }


@method_decorator(login_required, name='dispatch')
class JobQuantileSeveralPage(LoggedCallMixin, TemplateView):
    template_name = 'jobs/quantile.html'

    def get_context_data(self, **kwargs):
        args = json.loads(self.request.GET.get('args', '{}'))
        job_ids = json.loads(str(self.request.GET['jobs']).replace('{', '[').replace('}', ']'))
        selected_jobs = list()
        for job_id in job_ids:
            try:
                job = Job.objects.get(id=job_id)
                selected_jobs.append((job.id, job.name))
            except ObjectDoesNotExist:
                raise BridgeException(code=405)
            if not jobs.utils.JobAccess(self.request.user, job).can_view():
                raise BridgeException(code=401)
        plot, res_names = jobs.utils.get_quantile_plot(job_ids, args)
        return {
            'job_ids': selected_jobs,
            'res_names': res_names,
            'resources': plot,
            'args': args
        }


class DecisionResults(LoggedCallMixin, Bview.DataViewMixin, Bview.DetailPostView):
    model = Job
    template_name = 'jobs/DecisionResults.html'

    def get_context_data(self, **kwargs):
        report = ReportComponent.objects.filter(root__job=self.object, parent=None).first()
        return {'reportdata': ViewJobData(self.request.user, self.get_view(VIEW_TYPES[2]), report)}


class JobProgress(LoggedCallMixin, Bview.JSONResponseMixin, DetailView):
    model = Job
    template_name = 'jobs/jobProgress.html'

    def get_context_data(self, **kwargs):
        return {'progress': GetJobsProgresses(self.request.user, [self.object.id]).data[self.object.id]}


class JobStatus(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job

    def get_context_data(self, **kwargs):
        return {'status': self.object.status}


@method_decorator(login_required, name='dispatch')
class JobsFilesComparison(LoggedCallMixin, TemplateView):
    template_name = 'jobs/comparison.html'

    def get_context_data(self, **kwargs):
        try:
            job1 = Job.objects.get(id=self.kwargs['job1_id'])
            job2 = Job.objects.get(id=self.kwargs['job2_id'])
        except ObjectDoesNotExist:
            raise BridgeException(code=405)
        if not jobs.utils.JobAccess(self.request.user, job1).can_view() \
                or not jobs.utils.JobAccess(self.request.user, job2).can_view():
            raise BridgeException(code=401)
        return {'job1': job1, 'job2': job2, 'data': jobs.utils.CompareFileSet(job1, job2).data}


class RemoveJobsView(LoggedCallMixin, Bview.JsonView):
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        jobs.utils.remove_jobs_by_id(self.request.user, json.loads(self.request.POST.get('jobs', '[]')))
        return {}


class ClearJobsView(LoggedCallMixin, Bview.JsonView):
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        jobs.utils.clear_jobs_by_id(self.request.user, json.loads(self.request.POST.get('jobs', '[]')))
        return {}


class SaveJobCopyView(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        newjob = jobs.utils.save_job_copy(self.request.user, self.object, self.request.POST.get('name'))
        return {'identifier': newjob.identifier, 'id': newjob.id}


class DecisionResultsJson(LoggedCallMixin, Bview.JsonDetailView):
    model = Job

    def get_context_data(self, **kwargs):
        res = jobs.utils.GetJobDecisionResults(self.object)
        return {'data': json.dumps({
            'name': res.job.name, 'status': res.job.status,
            'start_date': res.start_date.timestamp() if res.start_date else None,
            'finish_date': res.finish_date.timestamp() if res.finish_date else None,
            'verdicts': res.verdicts, 'resources': res.resources,
            'safes': res.safes, 'unsafes': res.unsafes, 'unknowns': res.unknowns
        }, indent=2, sort_keys=True, ensure_ascii=False)}


@method_decorator(login_required, name='dispatch')
class JobFormPage(LoggedCallMixin, DetailView):
    model = Job
    template_name = 'jobs/jobForm.html'

    def get_unparallel(self):
        if self.request.method == 'POST':
            return [Job]
        return []

    def post(self, *args, **kwargs):
        self.is_not_used(*args, **kwargs)
        try:
            return JsonResponse({'job_id': JobForm(self.request.user, self.get_object(),
                                                   self.kwargs['action']).save(self.request.POST).id})
        except BridgeException as e:
            raise BridgeException(str(e), response_type='json')
        except Exception as e:
            logger.exception(e)
            raise BridgeException(response_type='json')

    def get_context_data(self, **kwargs):
        if not jobs.utils.JobAccess(self.request.user, self.object).can_view():
            raise BridgeException(code=400)
        return JobForm(self.request.user, self.object, self.kwargs['action']).get_context()


class GetJobHistoryData(LoggedCallMixin, Bview.JsonDetailView):
    model = JobHistory

    def get_object(self, queryset=None):
        try:
            obj = self.get_queryset().get(job_id=self.kwargs['job_id'], version=self.kwargs['version'])
        except ObjectDoesNotExist:
            raise BridgeException(_("The job version was not found"))
        if not jobs.utils.JobAccess(self.request.user, obj.job).can_view():
            raise BridgeException(code=400)
        return obj

    def get_context_data(self, **kwargs):
        return {'description': self.object.description}


class GetJobHistoryRoles(LoggedCallMixin, Bview.JSONResponseMixin, DetailView):
    model = JobHistory
    template_name = 'jobs/userRolesForm.html'

    def get_object(self, queryset=None):
        try:
            obj = self.get_queryset().get(job_id=self.kwargs['job_id'], version=self.kwargs['version'])
        except ObjectDoesNotExist:
            raise BridgeException(_('Job version was not found'))
        if not jobs.utils.JobAccess(self.request.user, obj.job).can_view():
            raise BridgeException(code=400)
        return obj

    def get_context_data(self, **kwargs):
        return UserRolesForm(self.request.user, self.object).get_context()


class GetJobHistoryFiles(LoggedCallMixin, Bview.JsonView):
    def get_context_data(self, **kwargs):
        opened = 'opened' not in self.request.POST or json.loads(self.request.POST['opened'])
        return LoadFilesTree(self.kwargs['job_id'], self.kwargs['version'], opened).as_json()


@method_decorator(login_required, name='dispatch')
class DownloadJobFileView(LoggedCallMixin, SingleObjectMixin, Bview.StreamingResponseView):
    model = JobFile
    slug_url_kwarg = 'hash_sum'
    slug_field = 'hash_sum'

    def get_filename(self):
        return unquote(self.request.GET.get('name', 'filename'))

    def get_generator(self):
        self.object = self.get_object()
        self.file_size = len(self.object.file)
        return FileWrapper(self.object.file, 8192)


class UploadJobFileView(LoggedCallMixin, Bview.JsonView):
    unparallel = [JobFile]

    def get_context_data(self, **kwargs):
        fname = self.request.FILES['file'].name
        if not all(ord(c) < 128 for c in fname):
            title_size = len(fname)
            if title_size > 30:
                fname = fname[(title_size - 30):]
        return {'hashsum': file_get_or_create(self.request.FILES['file'], fname, JobFile, True)[1]}


class GetFileContentView(LoggedCallMixin, Bview.JsonDetailView):
    model = JobFile
    slug_url_kwarg = 'hashsum'
    slug_field = 'hash_sum'

    def get_context_data(self, **kwargs):
        return {'content': self.object.file.read().decode('utf8')}


class GetFilesDiffView(LoggedCallMixin, Bview.JsonView):
    def get_context_data(self, **kwargs):
        try:
            f1 = jobs.utils.JobFile.objects.get(hash_sum=self.kwargs['hashsum1'])
            f2 = jobs.utils.JobFile.objects.get(hash_sum=self.kwargs['hashsum2'])
        except ObjectDoesNotExist:
            raise BridgeException(_("The file was not found"))
        with f1.file as fp1, f2.file as fp2:
            lines1 = fp1.read().decode('utf8').split('\n')
            lines2 = fp2.read().decode('utf8').split('\n')
            name1 = self.request.POST.get('name1', 'Old')
            name2 = self.request.POST.get('name2', 'Old')
            return {'content': '\n'.join(list(unified_diff(lines1, lines2, fromfile=name1, tofile=name2)))}


class ReplaceJobFileView(LoggedCallMixin, Bview.JsonView):
    unparallel = [FileSystem]

    def get_context_data(self, **kwargs):
        jobs.utils.ReplaceJobFile(self.kwargs['job_id'], self.request.POST['name'], self.request.FILES['file'])
        return {}


@method_decorator(login_required, name='dispatch')
class DownloadFilesForCompetition(LoggedCallMixin, SingleObjectMixin, Bview.StreamingResponsePostView):
    model = Job
    file_name = 'svcomp.zip'

    def get_generator(self):
        self.object = self.get_object()
        if not jobs.utils.JobAccess(self.request.user, self.object).can_dfc():
            raise BridgeException(code=400)
        return FilesForCompetitionArchive(self.object, json.loads(self.request.POST['filters']))


@method_decorator(login_required, name='dispatch')
class DownloadJobView(LoggedCallMixin, SingleObjectMixin, Bview.StreamingResponseView):
    model = Job

    def get_generator(self):
        self.object = self.get_object()
        if not jobs.utils.JobAccess(self.request.user, self.object).can_download():
            raise BridgeException(code=400)
        generator = JobArchiveGenerator(self.object)
        self.file_name = generator.arcname
        return generator


@method_decorator(login_required, name='dispatch')
class DownloadJobsListView(LoggedCallMixin, Bview.StreamingResponsePostView):
    def get_generator(self):
        jobs_list = Job.objects.filter(pk__in=json.loads(self.request.POST['job_ids']))
        for job in jobs_list:
            if not jobs.utils.JobAccess(self.request.user, job).can_download():
                raise BridgeException(
                    _("You don't have an access to one of the selected jobs"), back=reverse('jobs:tree'))
        self.file_name = 'KleverJobs.zip'
        return JobsArchivesGen(jobs_list)


@method_decorator(login_required, name='dispatch')
class DownloadJobsTreeView(LoggedCallMixin, Bview.StreamingResponsePostView):
    def get_generator(self):
        if self.request.user.extended.role != USER_ROLES[2][0]:
            raise BridgeException(_("Only managers can download jobs trees"), back=reverse('jobs:tree'))
        self.file_name = 'KleverJobs.zip'
        return JobsTreesGen(json.loads(self.request.POST['job_ids']))


class UploadJobsView(LoggedCallMixin, Bview.JsonView):
    unparallel = [Job, 'AttrName']

    def get_context_data(self, **kwargs):
        if not jobs.utils.JobAccess(self.request.user).can_create():
            raise BridgeException(_("You don't have an access to upload jobs"))
        for f in self.request.FILES.getlist('file'):
            try:
                job_dir = extract_archive(f)
            except Exception as e:
                logger.exception(e)
                raise BridgeException(_('Extraction of the archive "%(arcname)s" has failed') % {'arcname': f.name})
            try:
                UploadJob(self.kwargs['parent_id'], self.request.user, job_dir.name)
            except BridgeException as e:
                raise BridgeException(_('Creating the job from archive "%(arcname)s" failed: %(message)s') % {
                    'arcname': f.name, 'message': str(e)
                })
            except Exception as e:
                logger.exception(e)
                raise BridgeException(_('Creating the job from archive "%(arcname)s" failed: %(message)s') % {
                    'arcname': f.name, 'message': _('The job archive is corrupted')
                })
        return {}


class UploadJobsTreeView(LoggedCallMixin, Bview.JsonView):
    unparallel = [Job, 'AttrName']

    def get_context_data(self, **kwargs):
        if self.request.user.extended.role != USER_ROLES[2][0]:
            raise BridgeException(_("You don't have an access to upload jobs tree"))
        if Job.objects.filter(status__in=[JOB_STATUS[1][0], JOB_STATUS[2][0]]).count() > 0:
            raise BridgeException(_("There are jobs in progress right now, uploading may corrupt it results. "
                                    "Please wait until it will be finished."))

        jobs_dir = extract_archive(self.request.FILES['file'])
        UploadTree(self.request.POST['parent_id'], self.request.user, jobs_dir.name)
        return {}


class RemoveJobVersions(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job
    unparallel = ['Job', JobHistory]

    def get_context_data(self, **kwargs):
        if not jobs.utils.JobAccess(self.request.user, self.object).can_edit():
            raise BridgeException(code=400)
        jobs.utils.delete_versions(self.object, json.loads(self.request.POST.get('versions', '[]')))
        return {'message': _('Selected versions were successfully deleted')}


class CompareJobVersionsView(LoggedCallMixin, Bview.DetailPostView):
    model = Job
    template_name = 'jobs/jobVCmp.html'

    def get_context_data(self, **kwargs):
        versions = [int(self.request.POST['v1']), int(self.request.POST['v2'])]
        job_versions = JobHistory.objects.filter(job=self.object, version__in=versions).order_by('change_date')
        if job_versions.count() != 2:
            raise BridgeException(_('The page is outdated, reload it please'))
        return {'data': jobs.utils.CompareJobVersions(*list(job_versions))}


class CopyJobVersionView(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        if not jobs.utils.JobAccess(self.request.user, self.object).can_edit():
            raise BridgeException(code=400)
        jobs.utils.copy_job_version(self.request.user, self.object)
        return {}


class PrepareDecisionView(LoggedCallMixin, DetailView):
    template_name = 'jobs/startDecision.html'
    model = Job

    def post(self, *args, **kwargs):
        self.is_not_used(*args, **kwargs)
        self.object = self.get_object()
        try:
            return self.render_to_response(self.get_context_data(object=self.object))
        except BridgeException as e:
            raise BridgeException(e, back=reverse('jobs:prepare_run', args=[self.object.pk]))
        except Exception as e:
            logger.exception(e)
            raise BridgeException(back=reverse('jobs:prepare_run', args=[self.object.pk]))

    def get_context_data(self, **kwargs):
        context = {'job': self.object}
        conf_args = {}
        if self.request.method == 'POST':
            context['current_conf'] = self.request.POST['conf_name']

            if context['current_conf'] == 'file_conf':
                conf_args = {'file_conf': self.request.FILES['file_conf']}
            else:
                conf_args = {'conf_name': context['current_conf']}
        else:
            # Default configuration will be used by default
            context['current_conf'] = settings.DEF_KLEVER_CORE_MODE

        context['data'] = StartDecisionData(self.request.user, **conf_args)
        return context


@method_decorator(login_required, name='dispatch')
class DownloadRunConfigurationView(LoggedCallMixin, SingleObjectMixin, Bview.StreamingResponseView):
    model = RunHistory

    def get_generator(self):
        self.object = self.get_object()
        if not jobs.utils.JobAccess(self.request.user, self.object.job).can_view():
            raise BridgeException(code=400)
        self.file_name = "job-%s.conf" % self.object.job.identifier[:5]
        self.file_size = len(self.object.configuration.file)
        return FileWrapper(self.object.configuration.file, 8192)


class GetDefStartJobValue(LoggedCallMixin, Bview.JsonView):
    def get_context_data(self, **kwargs):
        return get_configuration_value(self.request.POST['name'], self.request.POST['value'])


class StartDecision(LoggedCallMixin, Bview.JsonView):
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        getconf_kwargs = {}

        # If self.request.POST['mode'] == 'fast' or any other then default configuration is used
        if self.request.POST['mode'] == 'data':
            getconf_kwargs['user_conf'] = json.loads(self.request.POST['data'])
        elif self.request.POST['mode'] == 'file_conf':
            getconf_kwargs['file_conf'] = self.request.FILES['file_conf']
        elif self.request.POST['mode'] == 'lastconf':
            last_run = RunHistory.objects.filter(job_id=self.kwargs['job_id']).order_by('date').last()
            if last_run is None:
                raise BridgeException(_('The job was not decided before'))
            getconf_kwargs['last_run'] = last_run
        elif self.request.POST['mode'] == 'default':
            getconf_kwargs['conf_name'] = self.request.POST['conf_name']

        StartJobDecision(self.request.user, self.kwargs['job_id'], GetConfiguration(**getconf_kwargs).configuration)
        return {}


class SetJobViewAttrs(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job

    def get_context_data(self, **kwargs):
        raw_attrs = json.loads(self.request.POST.get('data', '{}'))
        is_reload = update_job_view_attrs(raw_attrs, self.request.user, self.object)
        return {"is_reload": is_reload}


class StopDecisionView(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        if not jobs.utils.JobAccess(self.request.user, self.object).can_stop():
            raise BridgeException(_("You don't have an access to stop decision of this job"))
        StopDecision(self.object)
        return {}


class DecideJobServiceView(LoggedCallMixin, SingleObjectMixin,
                           Bview.JSONResponseMixin, Bview.StreamingResponsePostView):
    model = Job
    unparallel = [Job, 'AttrName']

    def dispatch(self, request, *args, **kwargs):
        with override(settings.DEFAULT_LANGUAGE):
            return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()
        return queryset.get(id=int(self.request.session['job id']), format=int(self.request.POST['job format']))

    def get_generator(self):
        self.object = self.get_object()

        if 'job format' not in self.request.POST:
            raise BridgeException('Job format is not specified')
        if 'report' not in self.request.POST:
            raise BridgeException('Start report is not specified')

        attempt = int(self.request.POST.get('attempt', 0))
        if not jobs.utils.JobAccess(self.request.user, self.object).klever_core_access():
            raise BridgeException('User "{0}" doesn\'t have access to decide the job "{1}"'
                                  .format(self.request.user, self.object.identifier))
        if attempt == 0:
            if self.object.status != JOB_STATUS[1][0]:
                raise BridgeException('Only pending jobs can be decided')
            jobs.utils.change_job_status(self.object, JOB_STATUS[2][0])

        err = UploadReport(self.object, json.loads(self.request.POST.get('report', '{}')), attempt=attempt).error
        if err is not None:
            raise BridgeException(err)

        generator = KleverCoreArchiveGen(self.object)
        self.file_name = generator.arcname
        return generator


class GetJobFieldView(LoggedCallMixin, Bview.JsonView):
    def get_context_data(self, **kwargs):
        job = jobs.utils.get_job_by_name_or_id(self.request.POST['job'])
        return {self.request.POST['field']: getattr(job, self.request.POST['field'])}


class DoJobHasChildrenView(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job

    def get_context_data(self, **kwargs):
        return {'children': (self.object.children.count() > 0)}


class CheckDownloadAccessView(LoggedCallMixin, Bview.JsonView):
    def get_context_data(self, **kwargs):
        for job_id in json.loads(self.request.POST.get('jobs', '[]')):
            try:
                job = Job.objects.get(id=int(job_id))
            except ObjectDoesNotExist:
                raise BridgeException(code=405)
            if not jobs.utils.JobAccess(self.request.user, job).can_download():
                raise BridgeException(code=401)
        return {}


class CheckCompareAccessView(LoggedCallMixin, Bview.JsonView):
    def get_context_data(self, **kwargs):
        try:
            j1 = Job.objects.get(id=self.request.POST.get('job1', 0))
            j2 = Job.objects.get(id=self.request.POST.get('job2', 0))
        except ObjectDoesNotExist:
            raise BridgeException(code=405)
        if not can_compare(self.request.user, j1, j2):
            raise BridgeException(code=401)
        return {}


class JobProgressJson(LoggedCallMixin, Bview.JsonDetailView):
    model = Job

    def get_context_data(self, **kwargs):
        try:
            progress = self.object.jobprogress
            solving = self.object.solvingprogress
        except ObjectDoesNotExist:
            return {'data': json.dumps({'status': self.object.status})}

        return {'data': json.dumps({
            'status': self.object.status,
            'subjobs': {
                'total': progress.total_sj, 'failed': progress.failed_sj, 'solved': progress.solved_sj,
                'expected_time': progress.expected_time_sj, 'gag_text': progress.gag_text_sj,
                'start': progress.start_sj.timestamp() if progress.start_sj else None,
                'finish': progress.finish_sj.timestamp() if progress.finish_sj else None
            },
            'tasks': {
                'total': progress.total_ts, 'failed': progress.failed_ts, 'solved': progress.solved_ts,
                'expected_time': progress.expected_time_ts, 'gag_text': progress.gag_text_ts,
                'start': progress.start_ts.timestamp() if progress.start_ts else None,
                'finish': progress.finish_ts.timestamp() if progress.finish_ts else None
            },
            'start_date': solving.start_date.timestamp() if solving.start_date else None,
            'finish_date': solving.finish_date.timestamp() if solving.finish_date else None
        }, indent=2, sort_keys=True, ensure_ascii=False)}


class UploadReportsView(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        if not jobs.utils.JobAccess(self.request.user, self.object).can_decide():
            raise BridgeException(_("You don't have an access to upload reports for this job"))

        try:
            reports_dir = extract_archive(self.request.FILES['archive'])
        except Exception as e:
            logger.exception(e)
            raise BridgeException(_('Extraction of the archive has failed'))

        UploadReportsWithoutDecision(self.object, self.request.user, reports_dir.name)
        return {}


class CollapseReportsView(LoggedCallMixin, Bview.JsonDetailPostView):
    model = Job
    unparallel = [Job]

    def get_context_data(self, **kwargs):
        if not jobs.utils.JobAccess(self.request.user, self.object).can_collapse():
            raise BridgeException(_("You don't have an access to collapse reports"))
        CollapseReports(self.object)
        return {}
