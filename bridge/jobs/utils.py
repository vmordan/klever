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

import hashlib
import operator
import os
from datetime import datetime

from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Count, Case, When, IntegerField, F, BooleanField
from django.utils.text import format_lazy
from django.utils.timezone import now, pytz
from django.utils.translation import ugettext_lazy as _

from bridge.utils import logger, BridgeException, file_get_or_create, get_templated_text
from bridge.vars import JOB_STATUS, USER_ROLES, JOB_ROLES, JOB_WEIGHT, SAFE_VERDICTS, UNSAFE_VERDICTS, \
    ASSOCIATION_TYPE, RESOURCE_CPU_TIME, RESOURCE_MEMORY_USAGE, RESOURCE_WALL_TIME
from jobs.models import Job, JobHistory, FileSystem, UserRole, JobFile
from marks.models import MarkSafeReport, MarkSafeTag, MarkUnsafeReport, MarkUnsafeTag, MarkUnknownReport
from reports.models import ComponentResource, ReportComponent, ReportSafe, ReportUnsafe, ReportUnknown, ReportAttr, \
    Resources, ReportRoot
from users.notifications import Notify

# List of available types of 'safe' column class.
SAFES = [
    'missed_bug',
    'incorrect',
    'unknown',
    'inconclusive',
    'unassociated',
    'total'
]

# List of available types of 'unsafe' column class.
UNSAFES = [
    'bug',
    'target_bug',
    'false_positive',
    'unknown',
    'inconclusive',
    'unassociated',
    'total'
]

# Dictionary of titles of static columns
TITLES = {
    'name': _('Title'),
    'author': _('Last change author'),
    'date': _('Last change date'),
    'status': _('Decision status'),

    'safe': _('Safes'),
    'safe:missed_bug': _('Missed target bugs'),
    'safe:incorrect': _('Incorrect proof'),
    'safe:unknown': _('Unknown'),
    'safe:inconclusive': _('Incompatible marks'),
    'safe:unassociated': _('Without marks'),
    'safe:total': _('Total'),

    'unsafe': _('Unsafes'),
    'unsafe:bug': _('Bugs'),
    'unsafe:target_bug': _('Target bugs'),
    'unsafe:false_positive': _('False positives'),
    'unsafe:unknown': _('Unknown'),
    'unsafe:inconclusive': _('Incompatible marks'),
    'unsafe:unassociated': _('Without marks'),
    'unsafe:total': _('Total'),

    'problem': _('Unknowns'),
    'problem:total': _('Total'),

    'resource': _('Consumed resources'),
    'resource:total': _('Total'),
    'tag': _('Tags'),
    'tag:safe': _('Safes'),
    'tag:unsafe': _('Unsafes'),
    'identifier': _('Identifier'),
    'format': _('Format'),
    'version': _('Version'),
    'parent_id': format_lazy('{0}/{1}', _('Parent'), _('Identifier')),
    'role': _('Your role'),
    'priority': _('Priority'),
    'start_date': _('Decision start date'),
    'finish_date': _('Decision finish date'),
    'solution_wall_time': _('Decision wall time'),
    'operator': _('Operator'),

    'tasks': _('Verification tasks'),
    'tasks:pending': _('Pending'),
    'tasks:processing': _('Processing'),
    'tasks:finished': _('Finished'),
    'tasks:error': _('Error'),
    'tasks:cancelled': _('Cancelled'),
    'tasks:total': _('Total'),
    'tasks:solutions': _('Number of decisions'),
    'tasks:total_ts': _('Total to be solved'),
    'tasks:start_ts': _('Start solution date'),
    'tasks:finish_ts': _('Finish solution date'),
    'tasks:progress_ts': _('Solution progress'),
    'tasks:expected_time_ts': _('Expected solution time'),

    'subjobs': _('Subjobs'),
    'subjobs:total_sj': _('Total to be solved'),
    'subjobs:start_sj': _('Start solution date'),
    'subjobs:finish_sj': _('Finish solution date'),
    'subjobs:progress_sj': _('Solution progress'),
    'subjobs:expected_time_sj': _('Expected solution time'),
}


def months_choices():
    months = []
    for i in range(1, 13):
        months.append((i, datetime(2016, i, 1).strftime('%B')))
    return months


def years_choices():
    curr_year = datetime.now().year
    return list(range(curr_year - 3, curr_year + 1))


def is_readable(filename):
    ext = os.path.splitext(filename)[1]
    return len(ext) > 0 and ext[1:] in {'txt', 'json', 'xml', 'c', 'aspect', 'i', 'h', 'tmpl'}


def get_job_parents(user, job):
    parent_set = []
    next_parent = job.parent
    while next_parent is not None:
        parent_set.append(next_parent)
        next_parent = next_parent.parent
    parent_set.reverse()
    parents = []
    for parent in parent_set:
        if JobAccess(user, parent).can_view():
            job_id = parent.pk
        else:
            job_id = None
        parents.append({'pk': job_id, 'name': parent.name})
    return parents


def get_job_children(user, job):
    children = []
    for child in job.children.order_by('-id'):
        if JobAccess(user, child).can_view():
            report = ReportComponent.objects.filter(root__job=child, parent=None).first()
            if report:
                res = ComponentResource.objects.filter(report__root=report.root, report__parent=None, component__name="Core") \
                    .annotate(root_id=F('report__root_id')).first()
                start_date = report.start_date
                (wall, cpu, mem) = get_resource_data('hum', 2, res)
                unsafes = ReportUnsafe.objects.filter(root=report.root).count()
                safes = ReportSafe.objects.filter(root=report.root).count()
                unknowns = ReportUnknown.objects.filter(root=report.root).count()
            else:
                (wall, cpu, mem, unsafes, safes, unknowns, start_date) = ('-', '-', '-', '-', '-', '-', '-')
            children.append({'pk': child.pk, 'name': child.name, 'wall': wall, 'cpu': cpu, 'mem': mem,
                             'safes': safes, 'unsafes': unsafes, 'unknowns': unknowns, 'start_date': start_date})
    return children


class JobAccess:

    def __init__(self, user, job=None):
        self.user = user
        self.job = job
        self._is_author = False
        self._job_role = None
        self._user_role = user.extended.role
        self._is_manager = (self._user_role == USER_ROLES[2][0])
        self._is_expert = (self._user_role == USER_ROLES[3][0])
        self._is_service = (self._user_role == USER_ROLES[4][0])
        self._is_operator = False
        try:
            if self.job is not None:
                self._is_operator = (user == self.job.reportroot.user)
        except ObjectDoesNotExist:
            pass
        self.__get_prop(user)

    def klever_core_access(self):
        if self.job is None:
            return False
        return self._is_manager or self._is_service

    def can_decide(self):
        return self._is_manager or self._is_service or \
               self._is_author or self._job_role in [JOB_ROLES[3][0], JOB_ROLES[4][0]]

    def can_upload_reports(self):
        if self.job is None or self.job.status in [JOB_STATUS[1][0], JOB_STATUS[2][0], JOB_STATUS[6][0]]:
            return False
        return self._is_manager or self._is_author or self._job_role in [JOB_ROLES[3][0], JOB_ROLES[4][0]]

    def can_view(self):
        if self.job is None:
            return False
        return self._is_manager or self._is_author or self._job_role != JOB_ROLES[0][0] or self._is_expert

    def can_view_jobs(self, filters=None):
        queryset = Job.objects.all()
        if isinstance(filters, dict):
            queryset = queryset.filter(**filters)
        elif filters is not None:
            queryset = queryset.filter(filters)
        queryset = queryset.only('id')

        all_jobs = set(j_id for j_id, in queryset.values_list('id'))

        if self._is_manager or self._is_expert:
            return all_jobs
        author_of = set(jh.job_id for jh in JobHistory.objects.filter(version=1, change_author=self.user))
        jobs_with_no_access = self.__get_jobs_with_roles([JOB_ROLES[0][0]])
        return all_jobs - (jobs_with_no_access - author_of)

    def can_create(self):
        return self._user_role not in [USER_ROLES[0][0], USER_ROLES[4][0]]

    def can_edit(self):
        if self.job is None:
            return False
        return self.job.status not in [JOB_STATUS[1][0], JOB_STATUS[2][0], JOB_STATUS[6][0]] \
            and (self._is_author or self._is_manager)

    def can_stop(self):
        if self.job is None:
            return False
        if self.job.status in [JOB_STATUS[1][0], JOB_STATUS[2][0]] and (self._is_operator or self._is_manager):
            return True
        return False

    def can_delete(self):
        if self.job is None:
            return False
        for ch in self.job.children.all():
            if not JobAccess(self.user, ch).can_delete():
                return False
        if self._is_manager:
            return True
        if self.job.status in [JOB_STATUS[1][0], JOB_STATUS[2][0]]:
            return False
        return self._is_author or self._is_manager

    def can_download(self):
        return self.job is not None and self.job.status != JOB_STATUS[2][0]

    def can_collapse(self):
        if self.job is None:
            return False
        return self.job.status not in {JOB_STATUS[1][0], JOB_STATUS[2][0], JOB_STATUS[6][0]} \
            and (self._is_author or self._is_manager) and self.job.weight == JOB_WEIGHT[0][0]

    def can_clear_verifications(self):
        if self.job is None or self.job.status in {JOB_STATUS[1][0], JOB_STATUS[2][0], JOB_STATUS[6][0]}:
            return False
        if not (self._is_author or self._is_manager):
            return False
        try:
            return ReportComponent.objects.filter(root=self.job.reportroot, verification=True)\
                .exclude(verifier_input='').count() > 0
        except ObjectDoesNotExist:
            return False

    def can_dfc(self):
        return self.job is not None and self.job.status not in [JOB_STATUS[0][0], JOB_STATUS[1][0]]

    def __get_jobs_with_roles(self, roles):
        jobs = set()
        for j_id, in UserRole.objects.filter(user=self.user, job__version=F('job__job__version'), role__in=roles) \
                .values_list('job__job_id'):
            jobs.add(j_id)
        for j_id, role in JobHistory.objects.exclude(job_id__in=jobs)\
                .filter(version=F('job__version'), global_role__in=roles) \
                .values_list('job_id', 'global_role'):
            jobs.add(j_id)
        return jobs

    def __get_prop(self, user):
        if self.job is not None:
            try:
                first_version = self.job.versions.get(version=1)
                last_version = self.job.versions.get(version=self.job.version)
            except ObjectDoesNotExist:
                return
            self._is_author = (first_version.change_author == user)
            last_v_role = last_version.userrole_set.filter(user=user)
            if len(last_v_role) > 0:
                self._job_role = last_v_role[0].role
            else:
                self._job_role = last_version.global_role


def get_job_by_identifier(identifier):
    found_jobs = Job.objects.filter(identifier__startswith=identifier)
    if len(found_jobs) == 0:
        raise BridgeException(_('The job with specified identifier was not found'))
    elif len(found_jobs) > 1:
        raise BridgeException(_('Several jobs match the specified identifier, '
                              'please increase the length of the job identifier'))
    return found_jobs[0]


def get_job_by_name_or_id(name_or_id):
    try:
        if name_or_id.isdigit():
            return Job.objects.get(id=name_or_id)
        else:
            return Job.objects.get(name=name_or_id)
    except ObjectDoesNotExist:
        found_jobs = Job.objects.filter(identifier__startswith=name_or_id)
        if len(found_jobs) == 0:
            raise BridgeException(_('The job with specified identifier or name was not found'))
        elif len(found_jobs) > 1:
            raise BridgeException(_('Several jobs match the specified identifier, '
                                    'please increase the length of the job identifier'))
        return found_jobs[0]


class FileData:
    def __init__(self, job):
        self.filedata = []
        self.__get_filedata(job)
        self.__order_by_lvl()

    def __get_filedata(self, job):
        for f in job.filesystem_set\
                .annotate(is_file=Case(When(file=None, then=0), default=1, output_field=IntegerField()))\
                .order_by('is_file', 'name').select_related('file'):
            self.filedata.append({
                'id': f.pk,
                'title': f.name,
                'parent': f.parent_id,
                'type': f.is_file,
                'hash_sum': f.file.hash_sum if f.is_file else None
            })

    def __order_by_lvl(self):
        ordered_data = []
        first_lvl = []
        other_data = []
        for fd in self.filedata:
            if fd['parent'] is None:
                first_lvl.append(fd)
            else:
                other_data.append(fd)

        def __get_all_children(file_info):
            children = []
            if file_info['type'] == 1:
                return children
            for fi in other_data:
                if fi['parent'] == file_info['id']:
                    children.append(fi)
                    children.extend(__get_all_children(fi))
            return children

        for fd in first_lvl:
            ordered_data.append(fd)
            ordered_data.extend(__get_all_children(fd))
        self.filedata = ordered_data


class SaveFileData:
    def __init__(self, filedata, job):
        self.filedata = filedata
        self.job = job
        self.filedata_by_lvl = []
        self.__check_data()
        self._files = self.__get_files()
        self.__save_file_data()

    def __save_file_data(self):
        saved_files = {}
        for lvl in self.filedata_by_lvl:
            for lvl_elem in lvl:
                fs_elem = FileSystem(job=self.job)
                if lvl_elem['parent']:
                    fs_elem.parent = saved_files[lvl_elem['parent']]
                if lvl_elem['type'] == '1':
                    if lvl_elem['hash_sum'] not in self._files:
                        raise ValueError('The file was not uploaded before')
                    fs_elem.file = self._files[lvl_elem['hash_sum']]
                if not all(ord(c) < 128 for c in lvl_elem['title']):
                    t_size = len(lvl_elem['title'])
                    if t_size > 30:
                        lvl_elem['title'] = lvl_elem['title'][(t_size - 30):]
                fs_elem.name = lvl_elem['title']
                fs_elem.save()
                saved_files[lvl_elem['id']] = fs_elem
        return None

    def __check_data(self):
        num_of_elements = 0
        element_of_lvl = []
        cnt = 0
        while num_of_elements < len(self.filedata):
            cnt += 1
            if cnt > 1000:
                raise ValueError('The file is too deep, maybe there is a loop in the files tree')
            num_of_elements += len(element_of_lvl)
            element_of_lvl = self.__get_lower_level(element_of_lvl)
            if len(element_of_lvl):
                self.filedata_by_lvl.append(element_of_lvl)
        for lvl in self.filedata_by_lvl:
            names_with_parents = set()
            for fd in lvl:
                if len(fd['title']) == 0:
                    raise ValueError("The file/folder name can't be empty")
                if not all(ord(c) < 128 for c in fd['title']):
                    title_size = len(fd['title'])
                    if title_size > 30:
                        fd['title'] = fd['title'][(title_size - 30):]
                if fd['type'] == '1' and fd['hash_sum'] is None:
                    raise ValueError('The file was not uploaded before')
                if fd['parent'] is not None:
                    rel_path = "%s/%s" % (fd['parent'], fd['title'])
                else:
                    rel_path = fd['title']
                if rel_path in names_with_parents:
                    raise ValueError("The same names in one folder found")
                names_with_parents.add(rel_path)

    def __get_lower_level(self, data):
        if len(data) == 0:
            return list(fd for fd in self.filedata if fd['parent'] is None)
        parents = set(fd['id'] for fd in data)
        return list(fd for fd in self.filedata if fd['parent'] in parents)

    def __get_files(self):
        files_data = {}
        hash_sums = set(fd['hash_sum'] for fd in self.filedata if fd['hash_sum'] is not None)
        for f in JobFile.objects.filter(hash_sum__in=list(hash_sums)):
            files_data[f.hash_sum] = f
        return files_data


class ReplaceJobFile:
    def __init__(self, job_id, name, file):
        try:
            self._job = Job.objects.get(id=job_id)
        except ObjectDoesNotExist:
            raise BridgeException(_('The job was not found'))

        self._file_to_replace = self.__get_file(name)
        self.__replace_file(file)

    def __get_file(self, name):
        path = name.split('/')

        filetree = {}
        for fs in FileSystem.objects.filter(job__job=self._job, job__version=self._job.version):
            filetree[fs.id] = {'parent': fs.parent_id, 'name': fs.name, 'file': fs.file}

        for f_id in filetree:
            if filetree[f_id]['name'] == path[-1]:
                parent = filetree[f_id]['parent']
                parents_branch = list(reversed(path))[1:]
                if len(parents_branch) > 0:
                    for n in parents_branch:
                        if parent is not None and filetree[parent]['name'] == n:
                            parent = filetree[parent]['parent']
                        else:
                            break
                    else:
                        return f_id
                else:
                    return f_id
        raise ValueError("The file wasn't found")

    def __replace_file(self, fp):
        if self._file_to_replace is None:
            raise ValueError("The file wasn't found")

        fp.seek(0)
        db_file = file_get_or_create(fp, fp.name, JobFile, True)[0]
        fs = FileSystem.objects.get(id=self._file_to_replace)
        fs.file = db_file
        fs.save()


def convert_time(val, acc):
    def final_value(time, postfix):
        fpart_len = len(str(round(time)))
        if fpart_len > int(acc):
            tmp_div = 10**(fpart_len - int(acc))
            rounded_value = round(time/tmp_div) * tmp_div
        elif fpart_len == int(acc):
            rounded_value = round(time)
        else:
            rounded_value = round(time, int(acc) - fpart_len)
        return get_templated_text('{% load l10n %}{{ val }} {{ postfix }}', val=rounded_value, postfix=postfix)

    new_time = int(val)
    try_div = new_time / 1000
    if try_div < 1:
        return final_value(new_time, _('ms'))
    new_time = try_div
    try_div = new_time / 60
    if try_div < 1:
        return final_value(new_time, _('s'))
    new_time = try_div
    try_div = new_time / 60
    if try_div < 1:
        return final_value(new_time, _('min'))
    return final_value(try_div, _('h'))


def convert_memory(val, acc):
    def final_value(memory, postfix):
        fpart_len = len(str(round(memory)))
        if fpart_len > int(acc):
            tmp_div = 10 ** (fpart_len - int(acc))
            rounded_value = round(memory / tmp_div) * tmp_div
        elif fpart_len == int(acc):
            rounded_value = round(memory)
        else:
            rounded_value = round(memory, int(acc) - fpart_len)
        return get_templated_text('{% load l10n %}{{ val }} {{ postfix }}', val=rounded_value, postfix=postfix)

    new_mem = int(val)
    try_div = new_mem / 10**3
    if try_div < 1:
        return final_value(new_mem, _('B'))
    new_mem = try_div
    try_div = new_mem / 10**3
    if try_div < 1:
        return final_value(new_mem, _('KB'))
    new_mem = try_div
    try_div = new_mem / 10**3
    if try_div < 1:
        return final_value(new_mem, _('MB'))
    return final_value(try_div, _('GB'))


def create_version(job, kwargs):
    new_version = JobHistory(
        job=job, version=job.version,
        change_author=job.change_author, change_date=job.change_date,
        comment=kwargs.get('comment', ''), description=kwargs.get('description', '')
    )
    if 'global_role' in kwargs and kwargs['global_role'] in set(x[0] for x in JOB_ROLES):
        new_version.global_role = kwargs['global_role']
    new_version.save()
    if 'user_roles' in kwargs:
        user_roles = dict((int(ur['user']), ur['role']) for ur in kwargs['user_roles'])
        user_roles_to_create = []
        for u in User.objects.filter(id__in=list(user_roles)).only('id'):
            user_roles_to_create.append(UserRole(job=new_version, user=u, role=user_roles[u.id]))
        if len(user_roles_to_create) > 0:
            UserRole.objects.bulk_create(user_roles_to_create)
    return new_version


def create_job(kwargs):
    if 'name' not in kwargs or len(kwargs['name']) == 0:
        logger.error('The job name was not got')
        raise BridgeException()
    try:
        Job.objects.get(name=kwargs['name'])
    except ObjectDoesNotExist:
        pass
    else:
        raise BridgeException(_('The job name is already used'))

    if 'author' not in kwargs or not isinstance(kwargs['author'], User):
        logger.error('The job author was not got')
        raise BridgeException()
    newjob = Job(name=kwargs['name'], change_date=now(), change_author=kwargs['author'], parent=kwargs.get('parent'))

    if 'identifier' in kwargs and kwargs['identifier'] is not None:
        if Job.objects.filter(identifier=kwargs['identifier']).count() > 0:
            # This exception will be occurred only on jobs population (if for preset jobs identifier would be set)
            # or jobs uploading
            raise BridgeException(_('The job with specified identifier already exists'))
        newjob.identifier = kwargs['identifier']
    else:
        time_encoded = now().strftime("%Y%m%d%H%M%S%f%z").encode('utf-8')
        newjob.identifier = hashlib.md5(time_encoded).hexdigest()
    newjob.save()

    new_version = create_version(newjob, kwargs)

    if 'filedata' in kwargs:
        try:
            SaveFileData(kwargs['filedata'], new_version)
        except Exception as e:
            logger.exception(e)
            newjob.delete()
            raise BridgeException()
    if 'absolute_url' in kwargs:
        # newjob_url = reverse('jobs:job', args=[newjob.pk])
        # Notify(newjob, 0, {'absurl': kwargs['absolute_url'] + newjob_url})
        pass
    else:
        # Notify(newjob, 0)
        pass
    return newjob


def update_job(kwargs):
    if 'job' not in kwargs or not isinstance(kwargs['job'], Job):
        raise ValueError('The job is required')
    if 'author' not in kwargs or not isinstance(kwargs['author'], User):
        raise ValueError('Change author is required')
    if 'comment' not in kwargs:
        kwargs['comment'] = ''
    if 'parent' in kwargs:
        kwargs['job'].parent = kwargs['parent']
    if 'name' in kwargs and len(kwargs['name']) > 0:
        try:
            job = Job.objects.get(name=kwargs['name'])
        except ObjectDoesNotExist:
            pass
        else:
            if job.id != kwargs['job'].id:
                raise BridgeException(_('The job name is already used'))
        kwargs['job'].name = kwargs['name']
    kwargs['job'].change_author = kwargs['author']
    kwargs['job'].change_date = now()
    kwargs['job'].version += 1
    kwargs['job'].save()

    newversion = create_version(kwargs['job'], kwargs)

    if 'filedata' in kwargs:
        try:
            SaveFileData(kwargs['filedata'], newversion)
        except Exception:
            newversion.delete()
            kwargs['job'].version -= 1
            kwargs['job'].save()
            raise
    if 'absolute_url' in kwargs:
        try:
            Notify(kwargs['job'], 1, {'absurl': kwargs['absolute_url']})
        except Exception as e:
            logger.exception("Can't notify users: %s" % e)
    else:
        try:
            Notify(kwargs['job'], 1)
        except Exception as e:
            logger.exception("Can't notify users: %s" % e)


def copy_job_version(user, job):
    last_version = JobHistory.objects.get(job=job, version=job.version)
    job.version += 1

    new_version = JobHistory.objects.create(
        job=job, version=job.version, change_author=user, comment='',
        description=last_version.description, global_role=last_version.global_role
    )

    roles = []
    for ur in UserRole.objects.filter(job=last_version):
        roles.append(UserRole(job=new_version, user=ur.user, role=ur.role))
    UserRole.objects.bulk_create(roles)

    try:
        fdata = FileData(last_version).filedata
        for i in range(len(fdata)):
            fdata[i]['type'] = str(fdata[i]['type'])
        SaveFileData(fdata, new_version)
    except Exception:
        new_version.delete()
        raise
    job.change_date = new_version.change_date
    job.change_author = user
    job.save()


def save_job_copy(user, job, name=None):
    last_version = JobHistory.objects.get(job=job, version=job.version)

    if isinstance(name, str) and len(name) > 0:
        job_name = name
        try:
            Job.objects.get(name=job_name)
        except ObjectDoesNotExist:
            pass
        else:
            raise BridgeException('The job name is used already.')
    else:
        cnt = 1
        while True:
            job_name = "%s #COPY-%s" % (job.name, cnt)
            try:
                Job.objects.get(name=job_name)
            except ObjectDoesNotExist:
                break
            cnt += 1

    newjob = Job.objects.create(
        identifier=hashlib.md5(now().strftime("%Y%m%d%H%M%S%f%z").encode('utf-8')).hexdigest(),
        name=job_name, change_date=now(), change_author=user, parent=job
    )

    new_version = JobHistory.objects.create(
        job=newjob, version=newjob.version,
        change_author=user, change_date=newjob.change_date, comment='',
        description=last_version.description, global_role=last_version.global_role
    )

    roles = []
    for ur in UserRole.objects.filter(job=last_version):
        roles.append(UserRole(job=new_version, user=ur.user, role=ur.role))
    UserRole.objects.bulk_create(roles)

    try:
        fdata = FileData(last_version).filedata
        for i in range(len(fdata)):
            fdata[i]['type'] = str(fdata[i]['type'])
        SaveFileData(fdata, new_version)
    except Exception:
        new_version.delete()
        job.version -= 1
        job.save()
        raise
    return newjob


def clear_jobs_by_id(user, job_ids):
    for job_id in job_ids:
        job_id = int(job_id)
        ReportRoot.objects.filter(job__id=job_id).delete()


def remove_jobs_by_id(user, job_ids):
    job_struct = {}
    all_jobs = {}
    for j in Job.objects.only('id', 'parent_id'):
        if j.parent_id not in job_struct:
            job_struct[j.parent_id] = set()
        job_struct[j.parent_id].add(j.id)
        all_jobs[j.id] = j

    def remove_job_with_children(j_id):
        j_id = int(j_id)
        if j_id not in all_jobs:
            return
        if j_id in list(job_struct):
            for ch_id in job_struct[j_id]:
                remove_job_with_children(ch_id)
            del job_struct[j_id]
        if not JobAccess(user, all_jobs[j_id]).can_delete():
            raise BridgeException(_("You don't have an access to delete one of the children"))
        try:
            Notify(all_jobs[j_id], 2)
        except Exception as e:
            logger.exception("Can't notify users: %s" % e)
        all_jobs[j_id].delete()
        del all_jobs[j_id]

    for job_id in job_ids:
        job_id = int(job_id)
        if job_id in job_struct:
            raise BridgeException(_("Cannot remove none-leaf element from the jobs tree with children. "
                                    "Please remove all element children first."))
    for job_id in job_ids:
        remove_job_with_children(job_id)


class JobVersionsData:
    def __init__(self, job, user):
        self._job = job
        self._user = user
        self.first_version = None
        self.last_version = None
        self.versions = self.__get_versions()

    def __get_versions(self):
        versions = []
        for j in self._job.versions.order_by('-version'):
            if self.first_version is None:
                self.first_version = j
            if j.version == self._job.version:
                self.last_version = j

            title = j.change_date.astimezone(pytz.timezone(self._user.extended.timezone)).strftime("%d.%m.%Y %H:%M:%S")
            if j.change_author:
                title += ' ({0})'.format(j.change_author.get_full_name())
            if j.comment:
                title += ': %s' % j.comment
            versions.append({'version': j.version, 'title': title})
        return versions


def delete_versions(job, versions):
    versions = list(int(v) for v in versions)
    if any(v in {1, job.version} for v in versions):
        raise BridgeException(_("You don't have an access to remove one of the selected version"))
    checked_versions = job.versions.filter(version__in=versions)
    checked_versions.delete()


def check_new_parent(job, parent):
    if job.parent == parent:
        return True
    while parent is not None:
        if parent == job:
            return False
        parent = parent.parent
    return True


def get_resource_data(data_format, accuracy, resource):
    if not resource:
        return [0, 0, 0]
    if data_format == 'hum':
        wall = convert_time(resource.wall_time, accuracy)
        # Make big numbers look actually human readable.
        cpu_time_in_seconds = round(resource.cpu_time / 1000)
        cpu_time_human_readable = ""
        if cpu_time_in_seconds == 0:
            cpu_time_human_readable = "0"
        while cpu_time_in_seconds > 0:
            # Add thousand separator.
            three_digits = cpu_time_in_seconds % 1000
            cpu_time_in_seconds //= 1000
            if cpu_time_in_seconds > 0:
                if int(three_digits) < 100:
                    three_digits = "0{0}".format(three_digits)
                if int(three_digits) < 10:
                    three_digits = "0{0}".format(three_digits)
            cpu_time_human_readable = "{1} {0}".format(cpu_time_human_readable, three_digits)
        cpu_time_human_readable = "{0} {1}".format(cpu_time_human_readable, _('s'))
        cpu = cpu_time_human_readable

        mem = convert_memory(resource.memory, accuracy)
    else:
        wall = "%s %s" % (resource.wall_time, _('ms'))
        cpu = "%s %s" % (resource.cpu_time, _('ms'))
        mem = "%s %s" % (resource.memory, _('B'))
    return [wall, cpu, mem]


def get_user_time(user, milliseconds):
    if user.extended.data_format == 'hum':
        converted = convert_time(int(milliseconds), user.extended.accuracy)
    else:
        converted = "%s %s" % (int(milliseconds), _('ms'))
    return converted


def get_user_memory(user, bytes_val):
    if user.extended.data_format == 'hum':
        converted = convert_memory(int(bytes_val), user.extended.accuracy)
    else:
        converted = "%s %s" % (int(bytes_val), _('B'))
    return converted


class CompareFileSet:
    def __init__(self, job1, job2):
        self.j1 = job1
        self.j2 = job2
        self.data = {
            'same': [],
            'diff': [],
            'unmatched1': [],
            'unmatched2': []
        }
        self.__get_comparison()

    def __get_comparison(self):

        def get_files(job):
            files = []
            last_v = job.versions.order_by('-version').first()
            files_data = {}
            for f in last_v.filesystem_set.only('parent_id', 'name'):
                files_data[f.pk] = (f.parent_id, f.name)
            for f in last_v.filesystem_set.exclude(file=None).select_related('file')\
                    .only('name', 'parent_id', 'file__hash_sum'):
                f_name = f.name
                parent = f.parent_id
                while parent is not None:
                    f_name = files_data[parent][1] + '/' + f_name
                    parent = files_data[parent][0]
                files.append([f_name, f.file.hash_sum])
            return files

        files1 = get_files(self.j1)
        files2 = get_files(self.j2)
        for f1 in files1:
            if f1[0] not in list(x[0] for x in files2):
                if is_readable(f1[0]):
                    self.data['unmatched1'].insert(0, [f1[0], f1[1]])
                else:
                    self.data['unmatched1'].append([f1[0]])
            else:
                for f2 in files2:
                    if f2[0] == f1[0]:
                        is_rdb = is_readable(f1[0])
                        if f2[1] == f1[1]:
                            if is_rdb:
                                self.data['same'].insert(0, [f1[0], f1[1]])
                            else:
                                self.data['same'].append([f1[0]])
                        else:
                            if is_rdb:
                                self.data['diff'].insert(0, [f1[0], f1[1], f2[1]])
                            else:
                                self.data['diff'].append([f1[0]])
                        break
        for f2 in files2:
            if f2[0] not in list(x[0] for x in files1):
                if is_readable(f2[0]):
                    self.data['unmatched2'].insert(0, [f2[0], f2[1]])
                else:
                    self.data['unmatched2'].append([f2[0]])


def change_job_status(job, status):
    if not isinstance(job, Job) or status not in set(x[0] for x in JOB_STATUS):
        return
    job.status = status
    job.save()
    try:
        run_data = job.runhistory_set.latest('date')
        run_data.status = status
        run_data.save()
    except ObjectDoesNotExist:
        pass


class CompareJobVersions:
    def __init__(self, v1, v2):
        self.v1 = v1
        self.v2 = v2
        self.files_map = {}
        self.roles = self.__user_roles()
        self.paths, self.files = self.__compare_files()

    def __user_roles(self):
        set1 = set(uid for uid, in UserRole.objects.filter(job=self.v1).values_list('user_id'))
        set2 = set(uid for uid, in UserRole.objects.filter(job=self.v2).values_list('user_id'))
        if set1 != set2:
            return [
                UserRole.objects.filter(job=self.v1).order_by('user__last_name').select_related('user'),
                UserRole.objects.filter(job=self.v2).order_by('user__last_name').select_related('user')
            ]
        return None

    def __get_files(self, version):
        self.__is_not_used()
        tree = {}
        for f in FileSystem.objects.filter(job=version).order_by('id').select_related('file'):
            tree[f.id] = {'parent': f.parent_id, 'name': f.name, 'hashsum': f.file.hash_sum if f.file else None}
        files = {}
        for f_id in tree:
            if tree[f_id]['hashsum'] is None:
                continue
            parent = tree[f_id]['parent']
            path_list = [tree[f_id]['name']]
            while parent is not None:
                path_list.insert(0, tree[parent]['name'])
                parent = tree[parent]['parent']
            files['/'.join(path_list)] = {'hashsum': tree[f_id]['hashsum'], 'name': tree[f_id]['name']}
        return files

    def __compare_files(self):
        files1 = self.__get_files(self.v1)
        files2 = self.__get_files(self.v2)
        changed_files = []
        changed_paths = []
        for fp1 in list(files1):
            if fp1 in files2:
                if files1[fp1]['hashsum'] != files2[fp1]['hashsum']:
                    # The file was changed
                    changed_files.append([is_readable(fp1), fp1, files1[fp1]['hashsum'], files2[fp1]['hashsum']])

                # Files are not changed deleted here too
                del files2[fp1]
            else:
                for fp2 in list(files2):
                    if files2[fp2]['hashsum'] == files1[fp1]['hashsum']:
                        # The file was moved
                        changed_paths.append([files1[fp1]['hashsum'], files2[fp2]['hashsum'], fp1, fp2])
                        del files2[fp2]
                        break
                else:
                    # The file was deleted
                    changed_paths.append([files1[fp1]['hashsum'], None, fp1, None])

        # files2 contains now only created files (or moved+changed at the same time)
        for fp2 in list(files2):
            changed_paths.append([None, files2[fp2]['hashsum'], None, fp2])
        return changed_paths, changed_files

    def __is_not_used(self):
        pass


class GetJobDecisionResults:
    no_mark = 'Without marks'
    total = 'Total'

    def __init__(self, job):
        self.job = job
        try:
            self.start_date = self.job.solvingprogress.start_date
            self.finish_date = self.job.solvingprogress.finish_date
        except ObjectDoesNotExist:
            raise BridgeException('The job was not solved')
        try:
            self._report = ReportComponent.objects.get(root__job=self.job, parent=None)
        except ObjectDoesNotExist:
            raise BridgeException('The job was not solved')

        self.verdicts = self.__get_verdicts()
        self.resources = self.__get_resources()

        self.safes = self.__get_safes()
        self.unsafes = self.__get_unsafes()
        self.unknowns = self.__get_unknowns()

    def __get_verdicts(self):
        data = {'safes': {}, 'unsafes': {}, 'unknowns': {}}

        # Obtaining safes information
        total_safes = 0
        confirmed_safes = 0
        for verdict, total, confirmed in ReportSafe.objects.filter(root=self._report.root).values('verdict')\
                .annotate(total=Count('id'), confirmed=Count(Case(When(has_confirmed=True, then=1))))\
                .values_list('verdict', 'total', 'confirmed'):
            data['safes'][verdict] = [confirmed, total]
            confirmed_safes += confirmed
            total_safes += total
        data['safes']['total'] = [confirmed_safes, total_safes]

        # Obtaining unsafes information
        total_unsafes = 0
        confirmed_unsafes = 0
        for verdict, total, confirmed in ReportUnsafe.objects.filter(root=self._report.root).values('verdict')\
                .annotate(total=Count('id'), confirmed=Count(Case(When(has_confirmed=True, then=1))))\
                .values_list('verdict', 'total', 'confirmed'):
            data['unsafes'][verdict] = [confirmed, total]
            confirmed_unsafes += confirmed
            total_unsafes += total
        data['unsafes']['total'] = [confirmed_unsafes, total_unsafes]

        # Marked/Unmarked unknowns
        unconfirmed = Case(When(markreport_set__type=ASSOCIATION_TYPE[2][0], then=True),
                           default=False, output_field=BooleanField())
        queryset = ReportUnknown.objects.filter(root=self._report.root)\
            .values('component_id', 'markreport_set__problem_id')\
            .annotate(number=Count('id', distinct=True), unconfirmed=unconfirmed)\
            .values_list('component__name', 'markreport_set__problem__name', 'number', 'unconfirmed')
        for c_name, p_name, number, unconfirmed in queryset:
            if p_name is None or unconfirmed:
                p_name = self.no_mark
            if c_name not in data['unknowns']:
                data['unknowns'][c_name] = {}
            if p_name not in data['unknowns'][c_name]:
                data['unknowns'][c_name][p_name] = 0
            data['unknowns'][c_name][p_name] += number

        # Total unknowns for each component
        for component, number in ReportUnknown.objects.filter(root=self._report.root) \
                .values('component_id').annotate(number=Count('id')).values_list('component__name', 'number'):
            if component not in data['unknowns']:
                data['unknowns'][component] = {}
            data['unknowns'][component][self.total] = number
        return data

    def __get_resources(self):
        res_total = self._report.resources_cache.filter(component=None).first()
        if res_total is None:
            return None
        return {'CPU time': res_total.cpu_time, 'memory': res_total.memory}

    def __get_safes(self):
        marks = {}
        reports = {}

        for mr in MarkSafeReport.objects.filter(report__root=self.job.reportroot).select_related('mark'):
            if mr.report_id not in reports:
                reports[mr.report_id] = {'attrs': [], 'marks': []}
            reports[mr.report_id]['marks'].append(mr.mark.identifier)
            if mr.mark.identifier not in marks:
                marks[mr.mark.identifier] = {
                    'verdict': mr.mark.verdict, 'status': mr.mark.status,
                    'description': mr.mark.description, 'tags': []
                }

        for s_id, in ReportSafe.objects.filter(root=self.job.reportroot, verdict=SAFE_VERDICTS[4][0]).values_list('id'):
            reports[s_id] = {'attrs': [], 'marks': []}

        for r_id, aname, aval in ReportAttr.objects.filter(report_id__in=reports) \
                .order_by('attr__name__name').values_list('report_id', 'attr__name__name', 'attr__value'):
            reports[r_id]['attrs'].append([aname, aval])

        for identifier, tag in MarkSafeTag.objects\
                .filter(mark_version__mark__identifier__in=marks,
                        mark_version__version=F('mark_version__mark__version'))\
                .order_by('tag__tag').values_list('mark_version__mark__identifier', 'tag__tag'):
            marks[identifier]['tags'].append(tag)
        report_data = []
        for r_id in sorted(reports):
            report_data.append(reports[r_id])
        return {'reports': report_data, 'marks': marks}

    def __get_unsafes(self):
        marks = {}
        reports = {}

        for mr in MarkUnsafeReport.objects.filter(report__root=self.job.reportroot).select_related('mark'):
            if mr.report_id not in reports:
                reports[mr.report_id] = {'attrs': [], 'marks': {}}
            reports[mr.report_id]['marks'][mr.mark.identifier] = mr.result
            if mr.mark.identifier not in marks:
                marks[mr.mark.identifier] = {
                    'verdict': mr.mark.verdict, 'status': mr.mark.status,
                    'description': mr.mark.description, 'tags': []
                }

        for u_id, in ReportUnsafe.objects.filter(root=self.job.reportroot, verdict=UNSAFE_VERDICTS[5][0])\
                .values_list('id'):
            reports[u_id] = {'attrs': [], 'marks': {}}

        for r_id, aname, aval in ReportAttr.objects.filter(report_id__in=reports)\
                .order_by('attr__name__name').values_list('report_id', 'attr__name__name', 'attr__value'):
            reports[r_id]['attrs'].append([aname, aval])

        for identifier, tag in MarkUnsafeTag.objects\
                .filter(mark_version__mark__identifier__in=marks,
                        mark_version__version=F('mark_version__mark__version'))\
                .order_by('tag__tag').values_list('mark_version__mark__identifier', 'tag__tag'):
            marks[identifier]['tags'].append(tag)
        report_data = []
        for r_id in sorted(reports):
            report_data.append(reports[r_id])
        return {'reports': report_data, 'marks': marks}

    def __get_unknowns(self):
        marks = {}
        reports = {}

        for mr in MarkUnknownReport.objects.filter(report__root=self.job.reportroot).select_related('mark'):
            if mr.report_id not in reports:
                reports[mr.report_id] = {'attrs': [], 'marks': []}
            reports[mr.report_id]['marks'].append(mr.mark.identifier)
            if mr.mark.identifier not in marks:
                marks[mr.mark.identifier] = {
                    'component': mr.mark.component.name, 'function': mr.mark.function, 'is_regexp': mr.mark.is_regexp,
                    'status': mr.mark.status, 'description': mr.mark.description
                }

        for f_id, in ReportUnknown.objects.filter(root=self.job.reportroot).exclude(id__in=reports).values_list('id'):
            reports[f_id] = {'attrs': [], 'marks': []}

        for r_id, aname, aval in ReportAttr.objects.filter(report_id__in=reports) \
                .order_by('attr__name__name').values_list('report_id', 'attr__name__name', 'attr__value'):
            reports[r_id]['attrs'].append([aname, aval])

        report_data = []
        for r_id in sorted(reports):
            report_data.append(reports[r_id])
        return {'reports': report_data, 'marks': marks}


class ReadJobFile:
    def __init__(self, hash_sum):
        try:
            self._file = JobFile.objects.get(hash_sum=hash_sum)
        except ObjectDoesNotExist:
            raise BridgeException(_('The file was not found'))

    def read(self):
        return self._file.file.read()

    def lines(self):
        return self._file.file.read().decode('utf8').split('\n')


def get_key_by_val(dictionary: dict, val: str) -> str:
    for cur_key, cur_val in dictionary.items():
        if cur_val == val:
            return cur_key
    return ""


TAG_IGNORE_UNSAFES = "ignore_unsafes"
TAG_IGNORE_SAFES = "ignore_safes"
TAG_IGNORE_UNKNOWNS = "ignore_unknowns"


DEFAULT_RESOURCES = [RESOURCE_CPU_TIME, RESOURCE_WALL_TIME, RESOURCE_MEMORY_USAGE]


def get_quantile_plot(job_ids: list, args: dict) -> tuple:
    result = list()
    res_names = list(DEFAULT_RESOURCES)
    for job_id in job_ids:
        resources, attributes = __get_resources(job_id, args, res_names)
        tmp_result = dict()
        for res_name in res_names:
            tmp_result[res_name] = [
                (get_key_by_val(attributes, attrs), attrs, val) for attrs, val in sorted(
                    {attributes[r_id]: res.get(res_name, 0) for r_id, res in resources.items()}.items(),
                    key=operator.itemgetter(1)
                )
            ]
        result.extend([(job_id, res_name, data) for res_name, data in sorted(tmp_result.items())])
    return result, res_names


def __get_resources(job_id: int, args: dict, res_names: list) -> tuple:
    attributes = dict()
    resources = dict()

    reports = ReportComponent.objects.filter(root__job_id=job_id, verification=True)
    if args.get(TAG_IGNORE_UNKNOWNS):
        reports = reports.filter(leaves__unknown=None)
    if args.get(TAG_IGNORE_UNSAFES):
        reports = reports.filter(leaves__unsafe=None)
    if args.get(TAG_IGNORE_UNKNOWNS) and args.get(TAG_IGNORE_UNSAFES):
        reports = reports.filter(leaves__unsafe=None, leaves__unknown=None)
    if args.get(TAG_IGNORE_SAFES):
        reports = reports.filter(leaves__safe=None)
    for report_id, a_name, a_val, a_cmp, cpu_time, wall_time, memory in reports.values_list(
            'id', 'attrs__attr__name__name', 'attrs__attr__value', 'attrs__associate',
            'cpu_time', 'wall_time', 'memory'):
        if report_id not in attributes:
            attributes[report_id] = dict()
        if a_cmp:
            attributes[report_id][a_name] = a_val
        if report_id not in resources:
            resources[report_id] = {RESOURCE_CPU_TIME: cpu_time / 1000.0, RESOURCE_WALL_TIME: wall_time / 1000.0,
                                    RESOURCE_MEMORY_USAGE: memory / 1000000.0}
    for report_id, r_name, r_val in Resources.objects.filter(report__in=reports).\
            values_list('report__id', 'name', 'value'):
        resources[report_id][r_name] = r_val
        if r_name not in res_names:
            res_names.append(r_name)
    for report_id, attrs in attributes.items():
        attrs_str = "/".join([attrs[x] for x in sorted(attrs)])
        attributes[report_id] = attrs_str
    return resources, attributes


def get_scatter_plot(job1_id: int, job2_id: int, args: dict) -> tuple:
    result = dict()
    res_names = list(DEFAULT_RESOURCES)
    res1, attr1 = __get_resources(job1_id, args, res_names)
    res2, attr2 = __get_resources(job2_id, args, res_names)
    for res_name in res_names:
        result[res_name] = list()
        for common_attr in set(attr1.values()).intersection(set(attr2.values())):
            report_1 = get_key_by_val(attr1, common_attr)
            report_2 = get_key_by_val(attr2, common_attr)
            result[res_name].append((common_attr, report_1, report_2, res1[report_1].get(res_name, 0),
                                     res2[report_2].get(res_name, 0)))
    return result, res_names, len(set(attr1.values()).intersection(set(attr2.values())))
