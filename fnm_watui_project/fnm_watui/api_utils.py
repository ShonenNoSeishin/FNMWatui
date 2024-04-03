from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import logout

from django.db import IntegrityError

from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.template import loader
import requests

import os
import json
import ipaddress
import ast
import time

from .models import Network, Flowspec


# Set the FastNetMon API endpoint and authentication details
DEFAULT_API_ENDPOINT = "http://127.0.0.1:10007"
DEFAULT_API_USER = "fnmadmin"
DEFAULT_API_PASSWORD = "fnmpassword"

FNM_API_ENDPOINT = os.environ.get('FNM_API_ENDPOINT',DEFAULT_API_ENDPOINT)
FNM_API_USER = os.environ.get('FNM_API_USER',DEFAULT_API_USER)
FNM_API_PASSWORD = os.environ.get('FNM_API_PASSWORD',DEFAULT_API_PASSWORD)


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

def get_global_flexible_thresholds():
	response = requests.get(
			f"{FNM_API_ENDPOINT}/main/flexible_thresholds",
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

@login_required
def set_flex_thresh(request):
	if request.method == "POST":
		# voir le status actuel
		boolean = get_global_flexible_thresholds()
		if boolean:
			status = "false"
		else:
			status = "true"
		response = requests.put(
				f"{FNM_API_ENDPOINT}/main/flexible_thresholds/{status}",
				auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
		if response.status_code != 200:
			messages.error(request, "set flexible_thresholds did'nt succeed")
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


def get_hostgroup_info(hostgroup_name):
	response = requests.get(
			f"{FNM_API_ENDPOINT}/hostgroup/{hostgroup_name}",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	if response.status_code == 200:
		json_data = response.json()
		return json_data["values"]
	return False


def is_valid_cidr_list_or_wide(input_str):
	# si input_str est complètement vide, ça va aussi car c'est pour tout supprimer
	if input_str == "":
		return True 
	# définir une sous fonction qui vérifie si un CIDR est ok 
	def is_valid_cidr(cidr):
		try:
			ip_addr = ipaddress.ip_network(cidr, False)
			return True
		except ValueError:
			return False

	try:
		# Essayer de transformer la chaîne en une liste avec ast.literal_eval
		cidr_list = ast.literal_eval(input_str)

		# Vérifier que cidr_list est bien une liste
		if not isinstance(cidr_list, list):
			return False

		# Vérifier que tous les éléments de la liste sont des chaînes valides d'adresses IP CIDR
		for item in cidr_list:
			if not isinstance(item, str) or not is_valid_cidr(item):
				return False

		return True
	except (SyntaxError, ValueError):
		return False


def delete_hostgroup_networks(name):
	hostgroups_networks = requests.get(
		f"{FNM_API_ENDPOINT}/hostgroup/{name}/networks",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	casted_list = hostgroups_networks.json()["values"]
	if casted_list is not None:
		try:
			for element in casted_list:
				element = element.replace("/","%2F")
				response = requests.delete(
				f"{FNM_API_ENDPOINT}/hostgroup/{name}/networks/{element}",
				auth=(FNM_API_USER, FNM_API_PASSWORD),
			)
		except:
			messages.error(request, response.text)
		if response.status_code != 200:
			messages.error(request, response.text)

	if hostgroups_networks.status_code != 200:
		messages.error(request, response.text)

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
			protocols = announce_data.get('protocols', ['']) if announce_data.get('protocols') else [""] # c'est "any"
			source_port = announce_data.get('source_ports', []) if announce_data.get('source_ports') else [-1] # -1 c'est "any"
			destination_port = announce_data.get('destination_ports', []) if announce_data.get('destination_ports') else [-1] # -1 c'est "any"
			source_prefix = announce_data.get('source_prefix', '') if announce_data.get('source_prefix') else ""
			
			# s'il y a + d'une entrée en port ou protocoles, ça ne vient pas de l'application car ça ne le permet pas
			if len(source_port) > 1 or len(destination_port) > 1 or len(protocols) > 1 :
				rules_not_in_db.append([action_type, destination_prefix, source_port, source_prefix, destination_port, protocols[0], uid])
			else:
				api_list.append([action_type, destination_prefix, source_port[0], source_prefix, destination_port[0], protocols[0], uid])

		for element in db_flowspecs:
			db_list.append([element.action, element.dstip, element.srcprt, element.srcip, element.dstprt, element.protocol])

		# messages.error(request, f"{api_list[0][:6:]} |||| {db_list[0]}")
		for i in api_list:
			if i[:6:] not in db_list:
				rules_not_in_db.append(i)

		for i in rules_not_in_db:
			if i[2] == -1 or i[2] == [-1]:
				i[2] = "any"
			if i[3] == "":
				i[3] = "any"
			if i[4] == -1 or i[4] == [-1]:
				i[4] = "any"
			if i[5] == "":
				i[5] = "any"
		return rules_not_in_db

	else:
		return None


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

	# print(route)

	uuid = None
	for value in response.json()["values"]:
		if value["announce"] == route:
			uuid = value["uuid"]
			break
	else:
		# notfound
		return True

	# print(uuid)
	response = requests.delete(
		f"{FNM_API_ENDPOINT}/flowspec/{uuid}",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)

	# Check if the API call was successful
	if response.status_code == 200:
		return True
	return False

#### Flowspec functions end ####

#### Network functions start ####

def get_networks():
	response = requests.get(
			f"{FNM_API_ENDPOINT}/main/networks_list",
			auth=(FNM_API_USER, FNM_API_PASSWORD),
		)
	json_data = response.json()
	if not json_data["success"]:
		totals = None

	else:
		return json_data["values"]


def create_network(cidr):
	cidr = cidr.replace("/","%2F")
	response = requests.put(
		f"{FNM_API_ENDPOINT}/main/networks_list/{cidr}",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	# Check if the API call was successful
	if response.status_code == 200:
		return True
	return response.text


def remove_network(cidr):
	cidr = cidr.replace("/","%2F")
	response = requests.delete(
		f"{FNM_API_ENDPOINT}/main/networks_list/{cidr}",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)
	# Check if the API call was successful
	if response.status_code == 200:
		return True
	return response.text

#### Network functions end ####


def api_commit():
	response = requests.put(
		f"{FNM_API_ENDPOINT}/commit",
		auth=(FNM_API_USER, FNM_API_PASSWORD),
	)

	# Check if the API call was successful
	if response.status_code == 200:
		return True
	return False
