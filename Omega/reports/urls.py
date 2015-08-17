from django.conf.urls import url
from reports import views


urlpatterns = [
    url(r'^component/(?P<job_id>[0-9]+)/(?P<report_id>[0-9]+)/$',
        views.report_component, name='component'),
    url('^log/(?P<report_id>[0-9]+)/$', views.get_component_log, name='log'),
    url('^logcontent/(?P<report_id>[0-9]+)/$', views.get_log_content),
    url(r'^component/(?P<report_id>[0-9]+)/(?P<ltype>unsafes|safes|unknowns)/$',
        views.report_list, name='list'),

    url(r'^component/(?P<report_id>[0-9]+)/(?P<ltype>unsafes|safes)/'
        r'(?P<verdict>[0-9])/$', views.report_list, name='list_verdict'),

    url(r'^(?P<leaf_type>unsafe|safe|unknown)/(?P<report_id>[0-9]+)/$',
        views.report_leaf, name='leaf'),
    url(r'^component/(?P<report_id>[0-9]+)/unknowns/(?P<component_id>[0-9]+)/$',
        views.report_unknowns, name='unknowns'),
    url(r'^upload/$', views.upload_report),
    url(r'^clear_tables/$', views.clear_tables),
]
