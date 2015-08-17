from django.conf.urls import include, url
from django.contrib import admin
from django.conf import settings

urlpatterns = [
    url(r'^i18n/', include('django.conf.urls.i18n')),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^users/', include('users.urls', namespace='users')),
    url(r'^jobs/', include('jobs.urls', namespace='jobs')),
    url(r'^reports/', include('reports.urls', namespace='reports')),
    url(r'^marks/', include('marks.urls', namespace='marks')),
    url(r'^$', 'users.views.index_page'),
    url(r'^media/(?P<path>.*)$', 'django.views.static.serve',
        {'document_root': settings.MEDIA_ROOT, 'show_indexes': True})
]
