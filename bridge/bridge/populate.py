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

import os

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.utils.translation import ungettext_lazy

import marks.SafeUtils as SafeUtils
import marks.UnknownUtils as UnknownUtils
import marks.UnsafeUtils as UnsafeUtils
from bridge.utils import file_get_or_create, unique_id, BridgeException
from bridge.vars import USER_ROLES, JOB_ROLES, ROOT_REPORT
from jobs.jobForm import JobForm
from jobs.models import Job, JobFile
from marks.tags import CreateTagsFromFile
from users.models import Extended

JOB_SETTINGS_FILE = 'settings.json'


def extend_user(user, role=USER_ROLES[1][0]):
    try:
        user.extended.role = role
        user.extended.save()
    except ObjectDoesNotExist:
        Extended.objects.create(role=role, user=user)
        user.first_name = 'Firstname'
        user.last_name = 'Lastname'
        user.save()


class PopulationError(Exception):
    pass


class Population:
    jobs_dir = os.path.join(settings.BASE_DIR, 'jobs', 'presets')

    def __init__(self, user=None, manager=None, service=None):
        self.changes = {'marks': {}}
        self.user = user
        if manager is None:
            self.manager = self.__get_manager(None, None)
            if service is not None:
                self.__add_service_user(service[0], service[1])
        else:
            self.manager = self.__get_manager(manager[0], manager[1])
            if service is not None and manager[0] != service[0]:
                self.__add_service_user(service[0], service[1])
        self.__population()

    def __population(self):
        if self.user is not None:
            try:
                Extended.objects.get(user=self.user)
            except ObjectDoesNotExist:
                extend_user(self.user)
        self.changes['jobs'] = self.__populate_jobs()

    def __correct_description(self, descr):
        self.__is_not_used()
        descr_strs = descr.split('\n')
        new_descr_strs = []
        for s in descr_strs:
            if len(s) > 0 and len(s.split()) > 0:
                new_descr_strs.append(s)
        return '\n'.join(new_descr_strs)

    def __get_manager(self, manager_username, manager_password):
        if manager_username is None:
            try:
                return Extended.objects.filter(role=USER_ROLES[2][0])[0].user
            except IndexError:
                raise BridgeException('There are no managers in the system')
        try:
            manager = User.objects.get(username=manager_username)
        except ObjectDoesNotExist:
            manager = User.objects.create(username=manager_username, first_name='Firstname', last_name='Lastname')
            self.changes['manager'] = {
                'username': manager.username,
                'password': self.__add_password(manager, manager_password)
            }
        extend_user(manager, USER_ROLES[2][0])
        return manager

    def __add_service_user(self, service_username, service_password):
        if service_username is None:
            return
        try:
            extend_user(User.objects.get(username=service_username), USER_ROLES[4][0])
        except ObjectDoesNotExist:
            service = User.objects.create(username=service_username, first_name='Firstname', last_name='Lastname')
            extend_user(service, USER_ROLES[4][0])
            self.changes['service'] = {
                'username': service.username,
                'password': self.__add_password(service, service_password)
            }

    def __add_password(self, user, password):
        self.__is_not_used()
        if isinstance(password, str):
            password = password.strip()
        if not isinstance(password, str) or len(password) == 0:
            password = unique_id()[:8]
        user.set_password(password)
        user.save()
        return password

    def __check_job_name(self, name):
        if not isinstance(name, str) or len(name) == 0:
            raise BridgeException('Default job name is required')
        job_name = name
        cnt = 1
        while True:
            try:
                Job.objects.get(name=job_name)
            except ObjectDoesNotExist:
                break
            cnt += 1
            job_name = "%s #%s" % (name, cnt)
        return job_name

    # Create a single empty root report.
    def __populate_jobs(self):
        root_job = JobForm(self.manager, None, 'copy').save({
            'identifier': None,
            'name': self.__check_job_name(ROOT_REPORT),
            'description': "<h3>{}</h3>".format(ROOT_REPORT),
            'global_role': JOB_ROLES[1][0]})
        return [[root_job.name, root_job.identifier]]

    def __get_file(self, path, fname):
        with open(path, mode='rb') as fp:
            hashsum = file_get_or_create(fp, fname, JobFile, True)[1]

        return {'type': 'file', 'text': fname, 'data': {'hashsum': hashsum}}

    def __get_dir(self, path, fname):
        return {'type': 'folder', 'text': fname, 'children': self.__get_children(path)}

    def __get_children(self, root):
        children = []
        for fname in os.listdir(root):
            if fname == JOB_SETTINGS_FILE:
                continue
            path = os.path.join(root, fname)
            if os.path.isfile(path):
                children.append(self.__get_file(path, fname))
            elif os.path.isdir(path):
                children.append(self.__get_dir(path, fname))
        return children

    def __populate_unknown_marks(self):
        res = UnknownUtils.PopulateMarks(self.manager)
        if res.created > 0:
            self.changes['marks']['unknown'] = (res.created, res.total)

    def __populate_safe_marks(self):
        res = SafeUtils.PopulateMarks(self.manager)
        new_num = len(res.created)
        if new_num > 0:
            self.changes['marks']['safe'] = (new_num, res.total)

    def __populate_unsafe_marks(self):
        res = UnsafeUtils.PopulateMarks(self.manager)
        new_num = len(res.created)
        if new_num > 0:
            self.changes['marks']['unsafe'] = (new_num, res.total)

    def __populate_tags(self):
        created_tags = []
        num_of_new = self.__create_tags('unsafe')
        if num_of_new > 0:
            created_tags.append(ungettext_lazy(
                '%(count)d new unsafe tag uploaded.', '%(count)d new unsafe tags uploaded.', num_of_new
            ) % {'count': num_of_new})
        return created_tags

    def __create_tags(self, tag_type):
        self.__is_not_used()
        preset_tags = os.path.join(settings.BASE_DIR, 'marks', 'tags_presets', "%s.json" % tag_type)
        if not os.path.isfile(preset_tags):
            return 0
        with open(preset_tags, mode='rb') as fp:
            try:
                res = CreateTagsFromFile(self.manager, fp, tag_type, True)
            except Exception as e:
                raise BridgeException("Error while creating tags: %s" % str(e))
            return res.number_of_created

    def __is_not_used(self):
        pass


# Example argument: {'username': 'myname', 'password': '12345', 'last_name': 'Mylastname', 'first_name': 'Myfirstname'}
# last_name and first_name are not required; username and password are required. email can be set for admin.
# Returns None if everything is OK, str (error text) in other cases.
def populate_users(admin=None, manager=None, service=None, exist_ok=False):

    def check_user_data(userdata):
        if not isinstance(userdata, dict):
            raise PopulationError('{0} data has wrong format')
        if 'username' not in userdata or not isinstance(userdata['username'], str) or len(userdata['username']) == 0:
            raise PopulationError('{0} username is required')
        if 'password' not in userdata or not isinstance(userdata['password'], str) or len(userdata['password']) == 0:
            raise PopulationError('{0} password is required')
        if 'last_name' not in userdata:
            userdata['last_name'] = 'Lastname'
        if 'first_name' not in userdata:
            userdata['first_name'] = 'Firstname'
        try:
            User.objects.get(username=userdata['username'])
            userdata['exists'] = True
            raise PopulationError('{0} with specified username already exists')
        except ObjectDoesNotExist:
            pass

    if admin is not None:
        try:
            check_user_data(admin)
        except PopulationError as e:
            if not admin.get('exists') or not exist_ok:
                return str(e).format('Administrator')
        else:
            user = User.objects.create_superuser(
                username=admin['username'], email=admin.get('email', ''), password=admin['password'],
                first_name=admin['first_name'], last_name=admin['last_name']
            )
            Extended.objects.create(user=user, role=USER_ROLES[1][0])

    if manager is not None:
        try:
            check_user_data(manager)
        except PopulationError as e:
            if not manager.get('exists') or not exist_ok:
                return str(e).format('Manager')
        else:
            user = User.objects.create_user(
                username=manager['username'], password=manager['password'],
                first_name=manager['first_name'], last_name=manager['last_name']
            )
            Extended.objects.create(user=user, role=USER_ROLES[2][0])

    if service is not None:
        try:
            check_user_data(service)
        except PopulationError as e:
            if not service.get('exists') or not exist_ok:
                return str(e).format('Service user')
        else:
            user = User.objects.create_user(
                username=service['username'], password=service['password'],
                first_name=service['first_name'], last_name=service['last_name']
            )
            Extended.objects.create(user=user, role=USER_ROLES[4][0])

    return None
