from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("user_logout", views.user_logout, name="user_logout"),
    path("dashboard", views.dashboard, name="dashboard"),
    path("template", views.template, name="template"),
    path("network/", views.network, name="network"),
    path("network_delete/", views.network_delete, name="network_delete"),
    path("flowspec/", views.flowspec, name="flowspec"),
    path("flowspec_toggle/", views.flowspec_toggle, name="flowspec_toggle"),
    path("flowspec_delete/", views.flowspec_delete, name="flowspec_delete"),
    path("flowspec_flush/", views.flowspec_flush, name="flowspec_flush"),
    path("flowspec_redeploy/", views.flowspec_redeploy, name="flowspec_redeploy"),
    path("help/", views.help, name="help"),
    path("hostgroup", views.hostgroup, name="hostgroup"),
    path('hostgroup_info/<str:hostgroup_name>/', views.hostgroup_info, name='hostgroup_info'),
    path("modify_hostgroup/<str:hostgroup>/", views.modify_hostgroup, name="modify_hostgroup"),
    path('delete_hostgroup/<str:name>/', views.delete_hostgroup, name='delete_hostgroup'),
    path('api_flowspec_delete/', views.api_flowspec_delete, name='api_flowspec_delete'),
    path('set_global_ban/', views.set_global_ban, name='set_global_ban'),
    path('set_global_unban/', views.set_global_unban, name='set_global_unban'),
    path('unban_ip_blackhole/<path:ip_to_unban>/', views.unban_ip_blackhole_view, name='unban_ip_blackhole_view'),
]
