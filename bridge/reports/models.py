#
# Copyright (c) 2014-2016 ISPRAS (http://www.ispras.ru)
# Institute for System Programming of the Russian Academy of Sciences
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

from django.db import models
from django.contrib.auth.models import User
from bridge.vars import UNSAFE_VERDICTS, SAFE_VERDICTS, COMPARE_VERDICT
from jobs.models import File, Job

LOG_DIR = 'ReportLogs'


class AttrName(models.Model):
    name = models.CharField(max_length=63, unique=True)

    class Meta:
        db_table = 'attr_name'


class Attr(models.Model):
    name = models.ForeignKey(AttrName)
    value = models.CharField(max_length=255)

    class Meta:
        db_table = 'attr'


class ReportRoot(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    job = models.OneToOneField(Job)
    safes = models.PositiveIntegerField(default=0)
    tasks_total = models.PositiveIntegerField(default=0)
    average_time = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'report_root'


class Report(models.Model):
    root = models.ForeignKey(ReportRoot)
    parent = models.ForeignKey('self', null=True, related_name='+')
    identifier = models.CharField(max_length=255, unique=True)

    class Meta:
        db_table = 'report'


class ReportAttr(models.Model):
    attr = models.ForeignKey(Attr)
    report = models.ForeignKey(Report, related_name='attrs')

    class Meta:
        db_table = 'report_attrs'


class Computer(models.Model):
    description = models.TextField()

    class Meta:
        db_table = 'computer'


class Component(models.Model):
    name = models.CharField(max_length=15, unique=True)

    def __str__(self):
        return self.name

    class Meta:
        db_table = 'component'


class ReportComponent(Report):
    computer = models.ForeignKey(Computer)
    component = models.ForeignKey(Component, on_delete=models.PROTECT)
    cpu_time = models.BigIntegerField(null=True)
    wall_time = models.BigIntegerField(null=True)
    memory = models.BigIntegerField(null=True)
    start_date = models.DateTimeField()
    finish_date = models.DateTimeField(null=True)
    archive = models.ForeignKey(File, null=True, on_delete=models.SET_NULL, related_name='reports1')
    log = models.CharField(max_length=128, null=True)
    data = models.ForeignKey(File, null=True, related_name='reports2')

    class Meta:
        db_table = 'report_component'


class ReportUnsafe(Report):
    archive = models.ForeignKey(File)
    error_trace = models.CharField(max_length=128)
    verdict = models.CharField(max_length=1, choices=UNSAFE_VERDICTS, default='5')

    class Meta:
        db_table = 'report_unsafe'


class ReportSafe(Report):
    archive = models.ForeignKey(File, null=True)
    proof = models.CharField(max_length=128, null=True)
    verdict = models.CharField(max_length=1, choices=SAFE_VERDICTS, default='4')

    class Meta:
        db_table = 'report_safe'


class ReportUnknown(Report):
    component = models.ForeignKey(Component, on_delete=models.PROTECT)
    archive = models.ForeignKey(File)
    problem_description = models.CharField(max_length=128)

    class Meta:
        db_table = 'report_unknown'


class ReportComponentLeaf(models.Model):
    report = models.ForeignKey(ReportComponent, related_name='leaves')
    safe = models.ForeignKey(ReportSafe, null=True, related_name='leaves')
    unsafe = models.ForeignKey(ReportUnsafe, null=True, related_name='leaves')
    unknown = models.ForeignKey(ReportUnknown, null=True, related_name='leaves')

    class Meta:
        db_table = 'cache_report_component_leaf'


class AttrStatistic(models.Model):
    report = models.ForeignKey(ReportComponent)
    name = models.ForeignKey(AttrName)
    attr = models.ForeignKey(Attr, null=True)
    safes = models.PositiveIntegerField(default=0)
    unsafes = models.PositiveIntegerField(default=0)
    unknowns = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = 'cache_report_attr_statistic'


class Verdict(models.Model):
    report = models.OneToOneField(ReportComponent)
    unsafe = models.PositiveIntegerField(default=0)
    unsafe_bug = models.PositiveIntegerField(default=0)
    unsafe_target_bug = models.PositiveIntegerField(default=0)
    unsafe_false_positive = models.PositiveIntegerField(default=0)
    unsafe_unknown = models.PositiveIntegerField(default=0)
    unsafe_unassociated = models.PositiveIntegerField(default=0)
    unsafe_inconclusive = models.PositiveIntegerField(default=0)
    safe = models.PositiveIntegerField(default=0)
    safe_missed_bug = models.PositiveIntegerField(default=0)
    safe_incorrect_proof = models.PositiveIntegerField(default=0)
    safe_unknown = models.PositiveIntegerField(default=0)
    safe_unassociated = models.PositiveIntegerField(default=0)
    safe_inconclusive = models.PositiveIntegerField(default=0)
    unknown = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = "cache_report_verdict"


class ComponentResource(models.Model):
    report = models.ForeignKey(ReportComponent, related_name='resources_cache')
    component = models.ForeignKey(Component, null=True, on_delete=models.PROTECT)
    cpu_time = models.BigIntegerField()
    wall_time = models.BigIntegerField()
    memory = models.BigIntegerField()

    class Meta:
        db_table = 'cache_report_component_resource'


class LightResource(models.Model):
    report = models.ForeignKey(ReportRoot)
    component = models.ForeignKey(Component, null=True, on_delete=models.PROTECT)
    cpu_time = models.BigIntegerField()
    wall_time = models.BigIntegerField()
    memory = models.BigIntegerField()

    class Meta:
        db_table = 'cache_report_light_resource'


class ComponentUnknown(models.Model):
    report = models.ForeignKey(ReportComponent, related_name='unknowns_cache')
    component = models.ForeignKey(Component, on_delete=models.PROTECT)
    number = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = 'cache_report_component_unknown'


class CompareJobsInfo(models.Model):
    user = models.OneToOneField(User)
    root1 = models.ForeignKey(ReportRoot, related_name='+')
    root2 = models.ForeignKey(ReportRoot, related_name='+')
    files_diff = models.TextField()

    class Meta:
        db_table = 'cache_report_jobs_compare_info'


class CompareJobsCache(models.Model):
    info = models.ForeignKey(CompareJobsInfo)
    attr_values = models.TextField()
    verdict1 = models.CharField(max_length=1, choices=COMPARE_VERDICT)
    verdict2 = models.CharField(max_length=1, choices=COMPARE_VERDICT)
    reports1 = models.CharField(max_length=1000)
    reports2 = models.CharField(max_length=1000)

    class Meta:
        db_table = 'cache_report_jobs_compare'


class TasksNumbers(models.Model):
    root = models.OneToOneField(ReportRoot)
    bt_total = models.PositiveIntegerField(default=0)
    bt_num = models.PositiveIntegerField(default=0)
    avtg_total = models.PositiveIntegerField(default=0)
    avtg_fail = models.PositiveIntegerField(default=0)
    vtg_fail = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = 'report_tasks_numbers'


class TaskStatistic(models.Model):
    number_of_tasks = models.BigIntegerField(default=0)
    average_time = models.BigIntegerField(default=0)

    class Meta:
        db_table = 'cache_report_task_statistic'
