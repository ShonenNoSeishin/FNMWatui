from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.template import loader

from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import logout

from .forms import *
from .models import Network, Flowspec

import requests
from django.http import JsonResponse
from django.db import IntegrityError

import os
import json

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
	return render(request, "home.html")


@login_required
def template(request):
	return render(request, "template.html")


@login_required
def dashboard(request):
	total_traffic = get_total_traffic()
	global_ban_status = get_global_ban()
	global_unban_status = get_global_unban()
	host_traffic = get_hosts_traffic()
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
				return render(request, "dashboard.html", {"traffic_data": traffic_data, "global_ban_status": global_ban_status, "global_unban_status": global_unban_status, 'host_traffic': host_traffic_from_context, 'blackhole_info': blackhole_info, "form": form})
			else:
				return redirect('dashboard')
	else:
		form = add_blackhole_form()
		return render(request, "dashboard.html", {"traffic_data": traffic_data, "global_ban_status": global_ban_status, "global_unban_status": global_unban_status, 'host_traffic': host_traffic_from_context, 'blackhole_info': blackhole_info, "form": form})


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
    return redirect('dashboard')  # Remplacez 'your_redirect_url' par l'URL à laquelle vous souhaitez rediriger


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
			return render(request, "hostgroup.html", {"hostgroups": hostgroups.json()["values"], "form": form, 'error_message': error_message})
		else:
			return redirect("hostgroup")
	else:
		form = HostgroupForm()
		return render(request, "hostgroup.html", {"hostgroups": hostgroups.json()["values"], "form": form})


@login_required
def modify_hostgroup(request, hostgroup):
	if request.method == 'POST':
		form = ModifyHostgroupForm(request.POST)
		if form.is_valid():
			# Obtenez les données du formulaire valides
			name = form.cleaned_data['name']
			description = form.cleaned_data['description']
			threshold_pps = form.cleaned_data['threshold_pps']
			threshold_mbps = form.cleaned_data['threshold_mbps']
			threshold_flows = form.cleaned_data['threshold_flows']
			enable_ban = form.cleaned_data['enable_ban']

			if name == "global":
				messages.error(request, "you can't modify the global hostgroup, it's a native group")
				return redirect("hostgroup")
			
			keys = ["name", "description", "threshold_pps", "threshold_mbps", "threshold_flows", "enable_ban"]
			values = [name, description, threshold_pps, threshold_mbps, threshold_flows, enable_ban.lower()]
			for i in range(0,6):
				if keys[i] == "name":
					response = requests.put(
							f"{FNM_API_ENDPOINT}/hostgroup/{hostgroup}/{keys[i]}/{values[i]}",
							auth=(FNM_API_USER, FNM_API_PASSWORD),
						)
				else:
					response = requests.put(
						f"{FNM_API_ENDPOINT}/hostgroup/{values[0]}/{keys[i]}/{values[i]}",
						auth=(FNM_API_USER, FNM_API_PASSWORD),
					)

				if response.status_code != 200:
					messages.error(request, response.text)
			return redirect("hostgroup")
	else:
		initial_data = {
			'name': hostgroup.name,
			'description': hostgroup.description,
			'threshold_pps': hostgroup.threshold_pps,
			'threshold_mbps': hostgroup.threshold_mbps,
			'threshold_flows': hostgroup.threshold_flows,
			'enable_ban': hostgroup.enable_ban,
		}
		form = ModifyHostgroupForm(initial=initial_data)

		return render(request, 'modify_hostgroup.html', {'form': form, 'hostgroup': hostgroup})


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
			return redirect("hostgroup")
		else:
			messages.error(request, f"Hostgroup deletion error. Please try again. \n{response.text}")
			return redirect("hostgroup")


@login_required
def help(request):
	return render(request, "help.html")


@login_required
def network(request):
	# A HTTP POST?
	if request.method == "POST":
		form = NetworkForm(request.POST)

		# Have we been provided with a valid form?
		if form.is_valid():
			# Save the new category to the database.
			network = form.save(commit=False)
			network.save()
			messages.success(request, "You have successfully assigned a network.")
			# Redirect to home (/)
			return redirect("/network/")
		else:
			# The supplied form contained errors - just print them to the terminal.
			messages.error(request, form.errors)
			return redirect("/network/")
	else:
		# If the request was not a POST, display the form to enter details.
		form = NetworkForm()
		# Also populate the table with existing networks
		networks = Network.objects.all()
	return render(request, "network.html", {"form": form, "networks": networks})


@login_required
def network_delete(request):
	if request.method == "POST":
		w = Network.objects.get(id=request.POST["network_id"])
		w.delete()
	return redirect("/network/")


@login_required
def flowspec(request):
	form = FlowspecForm(user=request.user)
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
			messages.success(request, "You have sucessfully commited a Flowspec rule.")
	flowspecs = Flowspec.objects.filter(net__user=request.user)
	#print(flowspecs)
	#messages.error(request, flowspecs)
	return render(request, "flowspec.html", {"form": form, "flowspecs": flowspecs, "api_only_flowspecs": api_only_flowspecs})


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
	return redirect("/flowspec/")


@login_required
def flowspec_redeploy(request):
	if request.method == "POST":
	  rules = Flowspec.objects.filter(net__user=request.user)
	  for rule in rules:
		  if rule.active == True:
			  insert_flowspec_route(rule)
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
	return redirect("/flowspec/")


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
	except:
		pass
	return redirect("/flowspec/")


@login_required
def user_logout(request):
	logout(request)
	return redirect("home")


#####################################################
######### Fonctions utilisées par les views #########
#####################################################


#### DashBoard functions start ####
def get_total_traffic():
	response = requests.get(
			f"{FNM_API_ENDPOINT}/total_traffic_counters",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	json_data = response.json()
	if not json_data["success"]:
		totals = None
	else:
		totals = {
			"in_mbps": json_data["values"][7]["value"] + json_data["values"][11]["value"] + json_data["values"][13]["value"],
			"in_mbps_suffix": "mbps" if json_data["values"][7]["value"] <= 10240 else "gbps",
			"in_pps": json_data["values"][0]["value"] + json_data["values"][4]["value"] + json_data["values"][6]["value"],
			"in_pps_suffix": "pps" if json_data["values"][0]["value"] <= 10000 else "kpps",
			"out_mbps": json_data["values"][3]["value"],
			"out_mbps_suffix": "mbps" if json_data["values"][3]["value"] <= 10240 else "gbps",
			"out_pps": json_data["values"][2]["value"],
			"out_pps_suffix": "pps" if json_data["values"][2]["value"] <= 10000 else "kpps",
		}
	return totals


def get_global_ban():
	response = requests.get(
			f"{FNM_API_ENDPOINT}/main/enable_ban",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	json_data = response.json()
	if response.status_code == 200:
		return json_data["value"]
	return False


def get_global_unban():
	response = requests.get(
			f"{FNM_API_ENDPOINT}/main/unban_enabled",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	json_data = response.json()
	if response.status_code == 200:
		return json_data["value"]
	return False


@login_required	
def set_global_ban(request):
	if request.method == "POST":
		# voir le status actuel
		boolean = get_global_ban()
		if boolean:
			status = "false"
		else:
			status = "true"

		response = requests.put(
				f"{FNM_API_ENDPOINT}/main/enable_ban/{status}",
				auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
		if response.status_code != 200:
			messages.error(request, "set ban did'nt succeed")
		return redirect("/dashboard")


@login_required
def set_global_unban(request):
	if request.method == "POST":
		# voir le status actuel
		boolean = get_global_unban()
		if boolean:
			status = "false"
		else:
			status = "true"
		response = requests.put(
				f"{FNM_API_ENDPOINT}/main/unban_enabled/{status}",
				auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
		if response.status_code != 200:
			messages.error(request, "set unban did'nt succeed")
		return redirect("/dashboard")


def get_hosts_traffic():
	response = requests.get(
			f"{FNM_API_ENDPOINT}/host_counters",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	json_data = response.json()
	if not json_data["success"]:
		totals = None

	else:
		return json_data["values"]


def get_blackhole():
	response = requests.get(
			f"{FNM_API_ENDPOINT}/blackhole",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	if response.status_code == 200:
		json_data = response.json()
		return json_data["values"]
	return False


def set_blackhole(ip_to_blackhole):
	response = requests.put(
			f"{FNM_API_ENDPOINT}/blackhole/{ip_to_blackhole}",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	if response.status_code == 200:
		return True
	return response

	
#### DashBoard functions end ####


#### Hostgroup functions start ####

@login_required
def add_hostgroup(req):
	form = HostgroupForm(req.POST)
	if form.is_valid():
		name = form.cleaned_data['name']
		description = form.cleaned_data['description']
		print(f"name : {name}, description : {description}")
		error_message = f"name : {name}, description : {description}"
		
		# créer l'hostgroup
		response = requests.put(
			f"{FNM_API_ENDPOINT}/hostgroup/{name}",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)

		if response.status_code != 200:
			error_message = f"Hostgroup creation error. Please try again. \n{response.text}"
			return error_message

		# paramétrer la description
		response2 = requests.put(
			f"{FNM_API_ENDPOINT}/hostgroup/{name}/description/{description}",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)

		if response2.status_code != 200:
			error_message = f"Description setting error. Please try again. \n{response.text}"
			return error_message
	return False

#### Hostgroup functions end ####

#### Flowspec functions start ####

@login_required
def check_other_fl_rules(request):
	response = requests.get(
		f"{FNM_API_ENDPOINT}/flowspec",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	
	if response.status_code == 200:
		api_flowspecs = response.json()["values"]
		db_flowspecs = Flowspec.objects.all()
		db_list = []
		api_list = []
		rules_not_in_db = []
		for flowspec_data in api_flowspecs:
			uid = flowspec_data.get('uuid', '')
			announce_data = flowspec_data.get('announce', {})
			action_type = announce_data.get('action_type', '')
			destination_prefix = announce_data.get('destination_prefix', '')
			protocols = announce_data.get('protocols', ['']) if announce_data.get('protocols') else ''
			source_port = announce_data.get('source_ports', []) if announce_data.get('source_ports') else [-1] # -1 c'est "any"
			destination_port = announce_data.get('destination_ports', []) if announce_data.get('destination_ports') else [-1] # -1 c'est "any"
			source_prefix = announce_data.get('source_prefix', '')
			
			# s'il y a + d'une entrée en port ou protocoles, ça ne vient pas de l'application car ça ne le permet pas
			if len(source_port) > 1 or len(destination_port) > 1 or protocols == '' :
				rules_not_in_db.append([action_type, destination_prefix, source_port, source_prefix, destination_port, protocols, uid])
			else:
				api_list.append([action_type, destination_prefix, source_port[0], source_prefix, destination_port[0], protocols[0], uid])

		for element in db_flowspecs:
			db_list.append([element.action, element.dstip, element.srcprt, element.srcip, element.dstprt, element.protocol])

		for i in api_list[:6:]:
			if i not in db_list:
				rules_not_in_db.append(i)

		for i in rules_not_in_db:
			if i[2] == -1 or i[2] == [-1]:
				i[2] = "any"
			if i[4] == -1 or i[4] == [-1]:
				i[4] = "any"
			if i[5] == '':
				i[5] = "any"
		return rules_not_in_db

	else:
		return None


@login_required
def insert_flowspec_route(rule):

	# Set the flowspec mandatory route details
	route = {
		"destination_prefix": rule.dstip,
		"action_type": rule.action,
	}

	# add the flowspec optional route details
	if rule.srcip:
		route["source_prefix"] = rule.srcip
	if rule.srcprt > 0:
		route["source_ports"] = [rule.srcprt]
	if rule.dstprt > 0:
		route["destination_ports"] = [rule.dstprt]
	if rule.protocol:
		route["protocols"] = [rule.protocol]

	# Make the API call to insert the flowspec route
	response = requests.put(
		f"{FNM_API_ENDPOINT}/flowspec",
		json=route,
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	# Check if the API call was successful
	if response.status_code == 200:
		return True
	return False


@login_required
def remove_flowspec_route(rule):
	# Make the API call to insert the flowspec route
	response = requests.get(
		f"{FNM_API_ENDPOINT}/flowspec",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)

	# Set the flowspec mandatory route details
	route = {
		"destination_prefix": rule.dstip,
		"action_type": rule.action,
	}

	# add the flowspec optional route details
	if rule.srcip:
		route["source_prefix"] = rule.srcip
	if rule.srcprt > 0:
		route["source_ports"] = [rule.srcprt]
	if rule.dstprt > 0:
		route["destination_ports"] = [rule.dstprt]
	if rule.protocol:
		route["protocols"] = [rule.protocol]

	print(route)

	uuid = None
	for value in response.json()["values"]:
		if value["announce"] == route:
			uuid = value["uuid"]
			break
	else:
		# notfound
		return True

	print(uuid)

	response = requests.delete(
		f"{FNM_API_ENDPOINT}/flowspec/{uuid}",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)

	# Check if the API call was successful
	if response.status_code == 200:
		return True
	return False

#### Flowspec functions end ####





####### FONCTIONS PAS ENCORE UTILISEES #######




# def unban_ip_blackhole(ip_to_unban):
# 	blackholes = get_blackhole()
# 	for i in blackholes:
# 		if i.get('ip', '') == f"{ip_to_unban}/32":
# 			blackhole_uuid = i.get('uuid','')
# 			break
# 	response = requests.delete(
# 			f"{FNM_API_ENDPOINT}/blackhole/{blackhole_uuid}",
# 			auth=(FNM_API_USER, FNM_API_PASSWORD),
# 	)
# 	if response.status_code == 200:
# 		return True
# 	return False

def get_hostgroup_info(hostgroup_name):
	response = requests.get(
			f"{FNM_API_ENDPOINT}/hostgroup/{hostgroup_name}",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	if response.status_code == 200:
		json_data = response.json()
		return json_data["values"]
	return False

####### FONCTIONS PAS ENCORE UTILISEES (fin) #######

