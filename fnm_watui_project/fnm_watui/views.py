from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.template import loader

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import logout

from .forms import *
from .api_utils import *
from .models import Network, Flowspec

import requests
from django.http import JsonResponse
from django.db import IntegrityError

import os
import json
import ast
import ipaddress
import time

# Set the FastNetMon API endpoint and authentication details
DEFAULT_API_ENDPOINT = "http://127.0.0.1:10007"
DEFAULT_API_USER = "fnmadmin"
DEFAULT_API_PASSWORD = "fnmpassword"

FNM_API_ENDPOINT = os.environ.get('FNM_API_ENDPOINT',DEFAULT_API_ENDPOINT)
FNM_API_USER = os.environ.get('FNM_API_USER',DEFAULT_API_USER)
FNM_API_PASSWORD = os.environ.get('FNM_API_PASSWORD',DEFAULT_API_PASSWORD)

#########################
######### Views #########
#########################

def home(request):
	return render(request, 'home.html', {'current_view': 'home'})


# @login_required
# def template(request):
# 	return render(request, "template.html")


@login_required
def dashboard(request):
	total_traffic = get_total_traffic()
	global_ban_status = get_global_ban()
	global_unban_status = get_global_unban()
	host_traffic = get_hosts_traffic()
	flex_thresh = get_global_flexible_thresholds()
	# si l'API prend du temps à charger
	if host_traffic is None or total_traffic is None: 
		time.sleep(0.2)
		return redirect("dashboard")
	blackhole_info = get_blackhole()

	host_traffic_from_context = []
	# Pour tester l'affichage quand il n'y a pas de trafic, décommentez la suite

	# for i in range(3):
	# 	host_traffic_from_context.append({
	# 			'host': "10.0.0.1",
	# 			'incoming_packets': 0,
	# 			'incoming_bytes': 0,
	# 			'incoming_flows': 0,
	# 		})

	for host_data in host_traffic:
		host_traffic_from_context.append({
			'host': host_data['host'],
			'incoming_packets': host_data['incoming_packets'],
			'incoming_bytes': host_data['incoming_bytes'],
			'incoming_flows': host_data['incoming_flows'],
		})
	
	traffic_data = [
		("in_mbps", "fa-bar-chart", total_traffic["in_mbps"], total_traffic["in_mbps_suffix"], "INBOUND BYTES"),
		("in_pps", "fa-area-chart", total_traffic["in_pps"], total_traffic["in_pps_suffix"], "INBOUND PACKETS"),
		# On peut ajouter d'autres types
	]

	if request.method == 'POST':
		form = add_blackhole_form(request.POST)
		if form.is_valid():
			ban_response = set_blackhole(form.cleaned_data['blackholed_ip'])
			if not ban_response:
				messages.error(request, f"can't create this blackhole rule : {ban_response.text}")
				return render(request, "dashboard.html", {"traffic_data": traffic_data, "global_ban_status": global_ban_status, "global_unban_status": global_unban_status, "flex_thresh": flex_thresh, 'host_traffic': host_traffic_from_context, 'blackhole_info': blackhole_info, "form": form, 'current_view': 'dashboard',})
			else:
				return redirect('dashboard')

		# bool_anwser = api_commit()
		# if not bool_anwser:
		# 	messages.error(request, "commit didn't successed")

	else:
		form = add_blackhole_form()
		return render(request, "dashboard.html", {'current_view': 'dashboard', "traffic_data": traffic_data, "global_ban_status": global_ban_status, "global_unban_status": global_unban_status, "flex_thresh": flex_thresh, 'host_traffic': host_traffic_from_context, 'blackhole_info': blackhole_info, "form": form})


@login_required	
def unban_ip_blackhole_view(request, ip_to_unban):
	blackholes = get_blackhole()
	for i in blackholes:
		if i.get('ip', '') == f"{ip_to_unban}/32" or i.get('ip', '') == f"{ip_to_unban}":
			blackhole_uuid = i.get('uuid', '')
			break
	response = requests.delete(
		f"{FNM_API_ENDPOINT}/blackhole/{blackhole_uuid}",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	if response.status_code != 200:
		messages.error(request, f"can't delete this blackhole rule : {response.text}")
	# else:
		# bool_anwser = api_commit()
		# if not bool_anwser:
		# 	messages.error(request, "commit didn't successed")
	return redirect('dashboard') 


@login_required
def hostgroup(request):
	hostgroups = requests.get(
		f"{FNM_API_ENDPOINT}/hostgroup",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	form = HostgroupForm(request.POST or None)
	if request.method == 'POST':
		error_message = add_hostgroup(request)
		if error_message : 
			return render(request, "hostgroup.html", {'current_view': 'hostgroup', "hostgroups": hostgroups.json()["values"], "form": form, 'error_message': error_message})
		else:
			# bool_anwser = api_commit()
			# if not bool_anwser:
			# 	messages.error(request, "commit didn't successed")
			return redirect("hostgroup")
	else:
		form = HostgroupForm()
		return render(request, "hostgroup.html", {'current_view': 'hostgroup', "hostgroups": hostgroups.json()["values"], "form": form})


@login_required
def hostgroup_info(request, hostgroup_name):
	hostgroup_info = get_hostgroup_info(hostgroup_name)
	return render(request, "hostgroup_info.html", {'current_view': 'hostgroup', "hostgroup_info": hostgroup_info})


@login_required
def modify_hostgroup(request, hostgroup):
	if request.method == 'POST':
		form = ModifyHostgroupForm(request.POST)
		if form.is_valid():
			# Obtenez les données du formulaire valides
			name = form.cleaned_data['name']
			description = form.cleaned_data['description']
			mapped_networks = form.cleaned_data['mapped_networks']
			threshold_pps = form.cleaned_data['threshold_pps']
			threshold_mbps = form.cleaned_data['threshold_mbps']
			threshold_flows = form.cleaned_data['threshold_flows']
			enable_ban = form.cleaned_data['enable_ban']
			
			keys = ["name", "description", "networks", "threshold_pps", "threshold_mbps", "threshold_flows", "enable_ban"]
			values = [name, description, mapped_networks, threshold_pps, threshold_mbps, threshold_flows, enable_ban.lower()]
			for i in range(0,7):
				if keys[i] == "name":
					try:
						response = requests.put(
								f"{FNM_API_ENDPOINT}/hostgroup/{hostgroup}/{keys[i]}/{values[i]}",
								auth=(FNM_API_USER, FNM_API_PASSWORD),
							)
					except:
						messages.error(request, response.text)

				elif keys[i] == "networks":
					# supprimer les networks existants avant de les recréer si c'est une entrée valide
					if is_valid_cidr_list_or_wide(values[i]):
						delete_hostgroup_networks(values[0])
					else : 
						messages.error(request, "mapped networks not valid, please enter in the following format -> ['X.X.X.X/XX','X.X.X.X/XX',...]")
						return redirect("hostgroup")

					# si la liste est vide, il ne faut rien faire d'autre pour cete partie
					if values[i] != "":
						# Pour l'instant, c'est une string comme '[X.X.X.X/XX,...]' donc il faut caster en [X.X.X.X/XX,...]
						try:
							casted_list = ast.literal_eval(values[i])
						except:
							messages.error(request, response.text)
							return redirect("hostgroup")
						for element in casted_list:
							element = element.replace("/","%2F")
							try:
								response = requests.put(
										f"{FNM_API_ENDPOINT}/hostgroup/{hostgroup}/{keys[i]}/{element}",
										auth=(FNM_API_USER, FNM_API_PASSWORD),
									)
							except:
								messages.error(request, response.text)
				else:
					try:
						response = requests.put(
							f"{FNM_API_ENDPOINT}/hostgroup/{values[0]}/{keys[i]}/{values[i]}",
							auth=(FNM_API_USER, FNM_API_PASSWORD),
						)
					except:
						messages.error(request, response.text)

				if response.status_code != 200:
					messages.error(request, response.text)

			# bool_anwser = api_commit()
			# if not bool_anwser:
			# 	messages.error(request, "commit didn't successed")
			return redirect("hostgroup")
	else:
		# initial_data = {
		# 	'name': hostgroup.name,
		# 	'description': hostgroup.description,
		# 	'mapped_networks': hostgroup.networks,
		# 	'threshold_pps': hostgroup.threshold_pps,
		# 	'threshold_mbps': hostgroup.threshold_mbps,
		# 	'threshold_flows': hostgroup.threshold_flows,
		# 	'enable_ban': hostgroup.enable_ban,
		# }
		# form = ModifyHostgroupForm(initial=initial_data)

		# return render(request, 'modify_hostgroup.html', {'form': form, 'hostgroup': hostgroup})
		return redirect("hostgroup")


@login_required
def delete_hostgroup(request, name):
	if name == "global":
		messages.error(request, "you can't delete the global hostgroup, it's a native group")
		return redirect("hostgroup")
	else:
		# Supprimer l'hostgroup
		response = requests.delete(
			f"{FNM_API_ENDPOINT}/hostgroup/{name}",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)

		if response.status_code == 200:
			# bool_anwser = api_commit()
			# if not bool_anwser:
			# 	messages.error(request, "commit didn't successed")
			return redirect("hostgroup")
		else:
			messages.error(request, f"Hostgroup deletion error. Please try again. \n{response.text}")
			return redirect("hostgroup")


@login_required
def help(request):
	return render(request, "help.html", {'current_view': 'help'})


@login_required
def network(request):
	# A HTTP POST?
	if request.method == "POST":
		form = NetworkForm(request.POST)

		# Have we been provided with a valid form?
		if form.is_valid():
			# Save the new category to the database.
			# network = form.save(commit=False)
			network = form.cleaned_data['network']
			message = create_network(network) 
			if messages is not True:
				messages.error(request, message)

			# network.save()
			# messages.error(request, network)
			messages.success(request, "You have successfully assigned a network.")
			# Redirect to home (/)
			# bool_anwser = api_commit()
			# if not bool_anwser:
			# 	messages.error(request, "commit didn't successed")
			return redirect("/network/")
		else:
			# The supplied form contained errors - just print them to the terminal.
			messages.error(request, form.errors)
			return redirect("/network/")
	else:
		# If the request was not a POST, display the form to enter details.
		form = NetworkForm()
		# Also populate the table with existing networks
		networks = get_networks()
		# messages.error(request, networks)
	return render(request, "network.html", {"form": form, "networks": networks, 'current_view': 'network'})


@login_required
def network_delete(request):
	if request.method == "POST":
		# w = Network.objects.get(id=request.POST["network_id"])
		cidr = request.POST["cidr"]
		remove_network(cidr)
	return redirect("/network/")


@login_required
def flowspec(request):
	form = FlowspecForm()
	# Permet de recevoir les règles de l'API qui sont pas dans la DB
	api_only_flowspecs = check_other_fl_rules(request)
	#messages.error(request, api_only_flowspecs)

	if request.method == "POST":
		form = FlowspecForm(request.POST)
		# Have we been provided with a valid form?
		if form.is_valid():
			# Save the new category to the database.
			flowspec = form.save(commit=False)
			flowspec.save()
			print("Flowspec passes validation")
			messages.success(request, "You have sucessfully commited a Flowspec rule. congrats")
			# bool_anwser = api_commit()
			# if not bool_anwser:
			# 	messages.error(request, "commit didn't successed")
	flowspecs = Flowspec.objects.all()
	#print(flowspecs)
	#messages.error(request, flowspecs)
	return render(request, "flowspec.html", {"form": form, "flowspecs": flowspecs, "api_only_flowspecs": api_only_flowspecs, 'current_view': 'flowspec'})


@login_required
def flowspec_toggle(request):
	if request.method == "POST":
		w = Flowspec.objects.get(id=request.POST["flowspec_id"])
		if w.active == True:
			if remove_flowspec_route(w):
				w.active = False
				w.save()
		elif w.active == False:
			if insert_flowspec_route(w):
				w.active = True
				w.save()
		# bool_anwser = api_commit()
		# if not bool_anwser:
		# 	messages.error(request, "commit didn't successed")
	return redirect("/flowspec/")


@login_required
def flowspec_redeploy(request):
	if request.method == "POST":
		rules = Flowspec.objects.filter(net__user=request.user)
		for rule in rules:
			if insert_flowspec_route(rule):
				rule.active = True
				rule.save()
	
	# bool_anwser = api_commit()
	# if not bool_anwser:
	# 	messages.error(request, "commit didn't successed")
	return redirect("/flowspec/")


@login_required
def flowspec_flush(request):
	if request.method == "POST":
		#nets = Network.objects.all(id__=request.user)
		rules = Flowspec.objects.filter(net__user=request.user)
		for rule in rules: 
			if remove_flowspec_route(rule):
				rule.active = False
				rule.save()

	# bool_anwser = api_commit()
	# if not bool_anwser:
	# 	messages.error(request, "commit didn't successed")
	return redirect("/flowspec/")


@login_required	
def modify_flowspec_route(request, flowspec_id):
	w = Flowspec.objects.get(id=flowspec_id)
	if request.method == "POST":
		form = FlowspecForm(request.POST, instance=w)
		if form.is_valid():
			w.delete()
			messages.error(request, f"test : {w}")
			print(f"test : {w}")
			# Save the new category to the database.
			flowspec = form.save(commit=False)
			flowspec.save()
			print("Flowspec passes validation.")
			# messages.success(request, "You have sucessfully modified a Flowspec rule.")
			return redirect("flowspec")

		# bool_anwser = api_commit()
		# if not bool_anwser:
		# 	messages.error(request, "commit didn't successed")
	
	flowspecs = Flowspec.objects.all()
	form = FlowspecForm(instance=w)
	api_only_flowspecs = check_other_fl_rules(request)
	return render(request, "modify_flowspec_route.html", {"form": form, "flowspecs": flowspecs, "api_only_flowspecs": api_only_flowspecs, "flowspec_id": flowspec_id, 'current_view': 'flowspec'})


@login_required
def flowspec_delete(request):
	if request.method == "POST":
		w = Flowspec.objects.get(id=request.POST["flowspec_id"])
		if not w.active:
			w.delete()
		else:
			messages.warning(
				request,
				"You need to disable the Flowspec rule first.",
				extra_tags="flowspec_table",
			)
	return redirect("/flowspec/")


@login_required
def api_flowspec_delete(request):
	rule_uid = request.POST["api_flowspec_id"]
	messages.error(request, rule_uid)
	try:
		response = requests.delete(
			f"{FNM_API_ENDPOINT}/flowspec/{rule_uid}",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
		# bool_anwser = api_commit()
		# if not bool_anwser:
		# 	messages.error(request, "commit didn't successed")
	except:
		pass
	return redirect("/flowspec/")


@login_required
def user_logout(request):
	logout(request)
	return redirect("home")


def force_api_commit(request, current_tab="dashboard"):
	result = api_commit()
	time.sleep(3)
	if result:
		messages.success(request, "API Commit successful.")
	else:
		messages.error(request, "API Commit failed.")
	return redirect(f"{current_tab}")  # Redirigez après le traitement


