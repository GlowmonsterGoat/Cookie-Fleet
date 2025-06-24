import requests; import io; import json; import time; import re

_baseurl = "https://a2-station-api-prod-708695367983.us-central1.run.app"; _header_var = 'x-api-key'

def _MakeHeader(Key):
	return {f"{_header_var}" : f"{Key}"}

def _MakeURL(Ext):
	return _baseurl+Ext

def _CreateBase(Ext, Key):
	return _MakeURL(Ext), _MakeHeader(Key)

def _SendDelete(headers, url, payload=None, params=None):
	if payload and params:
		return requests.delete(headers=headers, url=url, params=params, json=payload)
	elif payload:
		return requests.delete(headers=headers, url=url, json=payload)
	elif params:
		return requests.delete(headers=headers, params=params, url=url)
	else:
		return requests.delete(headers=headers, url=url)

def _SendGet(headers, url, payload=None, params=None):
	if payload and params:
		return requests.get(headers=headers, url=url, params=params, json=payload)
	elif payload:
		return requests.get(headers=headers, url=url, json=payload)
	elif params:
		return requests.get(headers=headers, params=params, url=url)
	else:
		return requests.get(headers=headers, url=url)
	
def _SendPost(headers, url, payload=None, params=None):
	if payload and params:
		return requests.post(headers=headers, url=url, params=params, json=payload)
	elif payload:
		return requests.post(headers=headers, url=url, json=payload)
	elif params:
		return requests.post(headers=headers, params=params, url=url)
	else:
		return requests.post(headers=headers, url=url)
	
def _SendPatch(headers, url, payload=None, params=None):
	if payload and params:
		return requests.patch(headers=headers, url=url, params=params, json=payload)
	elif payload:
		return requests.patch(headers=headers, url=url, json=payload)
	elif params:
		return requests.patch(headers=headers, params=params, url=url)
	else:
		return requests.patch(headers=headers, url=url)

def CollectFleets(Key, IncludeConfig = False, IncludeStations = False, IncludeOfflineFleets = False):
	"""Function which will collect the fleets, and return in a json"""
	variables = [IncludeConfig, IncludeStations,IncludeOfflineFleets]
	if all(isinstance(v, bool) for v in variables):
		pass
	else:
		return "Config, Stations, Or fleets are not boolean values."
	url = _MakeURL(f"/v2/fleets")
	headers = _MakeHeader(Key)
	params = {
    'include_config': f'{IncludeConfig}',
    'include_stations': f'{IncludeStations}',
    'include_offline_fleets': f'{IncludeOfflineFleets}',
    'page_size': 16,
    'page': 1
	}

	return _SendGet(headers, url, params=params)

def CollectStations(Key, FleetID, IncludeConfig=False, IncludeStations=False, IncludeDisabled=False):
	"""Function which will collect the stations in a fleet, and return the json."""
	url = _MakeURL(f"/v1/fleets/{FleetID}")
	headers = _MakeHeader(Key)
	params = {
	'include_config': f'{IncludeConfig}',
	'include_stations': f'{IncludeStations}',
	'include_disabled': f'{IncludeDisabled}',
	}
	return _SendGet(headers, url, params=params)

def ConfigReadFleet(Key, FleetID):
	"""Read's a FLEETS config"""
	url = _MakeURL(f"/v1/fleets/{FleetID}/config")
	headers = _MakeHeader(Key)
	return _SendGet(headers, url)

def ConfigReadStation(Key, StationID, FleetConfig = False, EventConfig = False):
	"""Read's a stations specific config"""
	url = _MakeURL(f"/v2/stations/{StationID}/config")
	headers = _MakeHeader(Key)
	params = {
		"include_fleet_config" : f"{FleetConfig}",
		"include_event_config" : f"{EventConfig}"
	}
	return _SendGet(headers, url, params=params)

def ConfigSendFleet(Key, FleetID, config):
	"""Send's a config to a fleet, meaning will overide the whole fleet. Config does have a weird format, as it is a payload in format of a json. An example has been included ahead -> 

	{
  "BoardTextureUrl1": "URL",
  "ConfigStatement" : "VALUE"
	}
	"""
	# /v1/fleets/{fleet_id}/config
	headers = _MakeHeader(Key); url = _MakeURL(f'/v1/fleets/{FleetID}/config')
	payload = config
	response = _SendPost(headers, url, payload)
	return response

def ConfigSendStation(Key, StationID, config):
	"""Sends a config to a specific station within a fleet."""
	headers = _MakeHeader(Key)
	url = _MakeURL(f"/v2/stations/{StationID}/config")
	payload = config
	return _SendPost(headers, url, payload)
	
def ToggleScraprunFleet(Key, FleetID):
	"""Sends a config statement to open scraprun fleet wide.
	"""
	# /v1/fleets/{fleet_id}/config
	headers = _MakeHeader(Key)
	url = _MakeURL(f"/v1/fleets/{FleetID}/config")
	TempConf = ConfigReadFleet(Key, FleetID)
	try:
		CurVal = TempConf["loadedgamemodes.scraprunprime.modulestate.dashboardconfigoverrides.bscraprunopen"]
	except:
		CurVal = False
	if(CurVal):
		ToSend = "false"
	else:
		ToSend = "true"
	payload = {
		"loadedgamemodes.scraprunprime.modulestate.dashboardconfigoverrides.bscraprunopen" : f"{ToSend}"
	}
	return _SendPost(headers, url, payload)
	
def AlterArenaVar(Key, StationID, ArenaName, VarToChange, ValueOverride, IsFleet = False):
	ArenaName = ArenaName.lower()
	VarToChange = VarToChange.lower()
	PosArenas = [
		"tkb_plazafront",
		"tkb_plazaeast",
		"tkb_plazawest",
		"tkb_plazaeast",
		"tkb_complexeast",
		"tkb_complexwest",
		"tkb_basement",
		"tkb_upperannex_outersouthwest",
		"tkb_upperannex_outersoutheast",
		"tkb_upperannex_innersouthwest",
		"tkb_upperannex_innersoutheast",
		"tkb_upperannex_innernorthwest",
		"tkb_upperannex_innernortheast",
		"tkb_upperannex_outernorth"
	]
	PosVars = [
		"bkicklosingteam",
		"matchlengthseconds",
		"mercyscoredifference",
		"busewhitelist",
		"team0whitelist",
		"team1whitelist",
		"busebestof",
		"roundspermatch",
		"team0name",
		"team1name",
		"timebetweenrounds",
		"team0imageurl",
		"team1imageurl",
		"bshuffleteamsaftermatch",
		"ticketmanagersettings.maxteamsizes.0",
		"ticketmanagersettings.maxteamsizes.1",
	]
	ValidArena = False
	if ArenaName in PosArenas:
		ValidArena = True
	ValidVar = False
	if VarToChange in PosVars:
		ValidVar = True
	InvalidEntry = False
	if not ValidVar and not ValidArena:
		return "Invalid NetVar and Arena Name."
	elif not ValidVar:
		return "Invalid NetVar"
	elif not ValidArena:
		return "Invalid Arena Name"
		
	TorFVars = [
		"bkicklosingteam",
		"busewhitelist",
		"busebestof",
		"bshuffleteamsaftermatch"
	]
	NumVars = [
		"matchlengthseconds",
		"mercyscoredifference",
		"roundspermatch",
		"timebetweenrounds",
		"ticketmanagersettings.maxteamsizes.0",
		"ticketmanagersettings.maxteamsizes.1"
	]
	StringVars = [
		"team0whitelist",
		"team1whitelist",
		"team0imageurl",
		"team1imageurl",
		"team0name",
		"team1name"
	]

	ValueType = None
	OfCorrectOvveride = False
	if isinstance(ValueOverride, str):
		ValueType = "String"
		if VarToChange in StringVars:
			OfCorrectOvveride = True
	elif isinstance(ValueOverride, bool):
		ValueType = "Boolean"
		if VarToChange in TorFVars:
			OfCorrectOvveride = True
			if ValueOverride:
				ValueOverride = "true"
			else:
				ValueOverride = "false"
	elif isinstance(ValueOverride, int):
		ValueType = "Integer"
		if VarToChange in NumVars:
			OfCorrectOvveride = True
	if not OfCorrectOvveride:
		return "The netvar you inputted uses a different override value. Please ensure you get it right."
	if IsFleet:
		url = _MakeURL(f'/v1/fleets/{StationID}/config')
	else:
		url = _MakeURL(f'/v2/stations/{StationID}/config')
	headers = _MakeHeader(Key)
	payload = {
		f"loadedgamemodes.{ArenaName}.modulestate.dashboardconfigoverrides.{VarToChange}" : f"{ValueOverride}"
	}
	response = _SendPost(headers, url, payload)
	return response

def FetchRoles(Key, FleetID):
	url = _MakeURL(f"/v1/fleets/{FleetID}/roles")
	_SendGet(headers=_MakeHeader(Key), url=url)
	
def GetUsers(Key, FleetID, IncPerms = False, IncRoles = False):
	url = _MakeURL(f"/v2/fleets/{FleetID}/users"); headers = _MakeHeader(Key)
	params = {
		'include_permissions' : f'{IncPerms}',
		'include_roles' : f'{IncRoles}',
		'page_size' : '100000'
	}
	return _SendGet(headers, url, params=params)

def BanUserWID(Key, FleetID, UserID, Duration, Reason):
	headers = _MakeHeader(Key); url = _MakeURL(f"/v2/fleets/{FleetID}/users/{UserID}/ban");
	headers["Content-Type"] = "application/json"

	params = {
        "duration": {Duration}
    }
	
	payload = {
        "reason": f"{Reason}"
    }

	return _SendPost(headers, url, payload, params)

def GetFleetEvents(Key, FleetID, GetPast = False):
	url = _MakeURL(f"/v2/fleets/{FleetID}/events")
	params = {
		"get_past_events": str(GetPast)
	}
	headers = _MakeHeader(Key)
	return _SendGet(headers, url, params=params)
	
def CreateEvent(Key, FleetID, Title, Description, Duration, StartTime, EventType=None, EventLocation=None, StationID=None):
    """There is a lot here. Most of it is needed so make sure you have it.
    Timezones are based on UTC, E.g. 2025-03-06T10:43
    """
    
    iso8601_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$'
    
    if not re.match(iso8601_pattern, StartTime):
        return {"error": "Invalid StartTime format. Ensure it is in ISO 8601 format (YYYY-MM-DDTHH:MM) and in UTC."}, 400
    
    Public = True
    SignupsOpen = True
    
    url = _MakeURL(f"/v2/fleets/{FleetID}/events")
    headers = _MakeHeader(Key)
    
    payload = {
        "title": Title,
        "description": Description,
        "duration": Duration,
        "start_time": StartTime,
        "public": Public,
        "signups_open": SignupsOpen,
    }
    
    if EventType:
        payload["event_type"] = EventType
    if StationID:
        payload["station_id"] = StationID
    if EventLocation:
        payload["event_location"] = EventLocation
    
    return _SendPost(headers, url, payload)
    
def UpdateUserRole(Key, FleetID, UserID, RoleID, Give=True):
	"""Give a user a role, or take a user role.

	Args:
		Key (str): API Key
		FleetID (str): The fleet in which this should take place
		UserID (int): User ID to use
		RoleID (int): Role ID to use
		Give (int, optional): should we give or take the role. defaults to true.
	"""
	headers = _MakeHeader(Key)
	if Give:
		ext = f"/v1/fleets/{FleetID}/users/{UserID}/roles/{RoleID}"
		url = _MakeURL(ext)
		response = _SendPost(url=url, headers=headers)
	else:
		ext = f"/v1/fleets/{FleetID}/users/{UserID}/role/{RoleID}"
		url= _MakeURL(ext)
		response = _SendDelete(url=url, headers=headers)

	if response.status_code == 500:
		if Give:
			return "user already had the role"
		else:
			return "User already doesnt have role"
	else:
		return response

def DeleteFleetConfig(Key, FleetID):
	url =_MakeURL(f"/v1/fleets/{FleetID}/config") 
	return _SendDelete(headers=_MakeHeader(Key), url=url)
	
def DeleteStationConfig(Key, StationID):
	url = _MakeURL(f"/v2/stations/{StationID}/config")
	return _SendDelete(headers=_MakeHeader(Key),url=url)


def LastOnlineFleet(Key, FleetID):
	"""Collect when a fleet was last online

	Args:
		Key (str): Your API Key
		FleetID (str): Fleet ID To check

	Returns:
		response: Entire network object.
	"""
	url = _MakeURL(f"/v3/fleets/{FleetID}/online")
	headers = _MakeHeader(Key)
	return _SendGet(url=url, headers=headers)

def CreateRole(Key, FleetID, RoleName, RoleDescription):
	"""Create a role on a specific fleet

	Args:
		Key (str): Your API Key
		FleetID (str): The fleet to make the role on
		RoleName (str): What the role should be called
		RoleDescription (str): What the role description should be

	Returns:
		response: Entire network object.
	"""
	url = _MakeURL(f"/v1/fleets/{FleetID}/roles")
	headers = _MakeHeader(Key)
	payload = {
		"role_name" : f"{RoleName}",
		"role_description" : f"{RoleDescription}"
	}
	return _SendPost(headers, url, payload=payload)
	
def AddRolePerm(Key, FleetID, RoleID, Permission):

	url = _MakeURL(f"/v1/fleets/{FleetID}/roles/{RoleID}/permissions")
	headers = _MakeHeader(Key)
	payload = {
		"permissions" : f"{Permission}"
	}

	return _SendPost(headers, url, payload)

def GetUser(Key, UserID, IncRoles = False, IncPerms = False, IncBans = False):
	headers = _MakeHeader(Key)
	url = _MakeURL(f"/v2/users/{UserID}")
	params = {
		"include_roles" : f"{IncRoles}",
		"include_permissions" : f"{IncPerms}",
		"include_bans" : f"{IncBans}"}
	return _SendGet(headers, url, params=params)

def GetUserWRole(Key, FleetID, RoleID):
	url = _MakeURL(f"/v2/fleets/{FleetID}/roles/{RoleID}/users")
	headers = _MakeHeader(Key)
	return _SendGet(headers, url)

def UpdFleetName(Key, FleetID, NewName):
	url = _MakeURL(f"/v1/fleets/{FleetID}")
	payload = {"fleet_name":f"{NewName}"}
	headers = _MakeHeader(Key)
	return _SendPatch(headers, url, payload=payload)

def FetchBans(Key, FleetID, IncRevoked = False, IncExpired = False):
	url = _MakeURL(f"/v2/fleets/{FleetID}/bans")
	headers = _MakeHeader(Key)	
	params = {
		"include_revoked": f"{IncRevoked}".lower,
		"include_expired": f"{IncExpired}".lower
	}
	return _SendGet(headers, url, params=params)

def UnbanUser(Key, FleetID, UserID):
	url = _MakeURL(f"/v2/fleets/{FleetID}/users/{UserID}/unban")
	headers = _MakeHeader(Key)
	_SendPatch(headers, url)

def FetchStationEvents(Key, FleetID, Amount, Page =1, EventType = None):
	url, headers = _CreateBase(f"/v2/stations/{FleetID}/server_events", Key)
	params = {
		"page_size": {Amount},
		"page": {Page}
	}
	if EventType:
		params["event_type"] = f"{EventType}"
	return _SendGet(headers, url, params=params)

def GetEvent(Key, EventID):
	url, header = _CreateBase(f"/v2/events/{EventID}", Key)
	return _SendGet(header, url)

def DeleteEvent(Key, FleetID, EventID):
	url, headers = _CreateBase(f"/v2/fleets/{FleetID}/event/{EventID}")
	return _SendDelete(headers, url)

def UpdateEvent(Key, FleetID, EventID, Title=None,Description=None,StartTime=None,Duration=None,Public=None,Signups_Open=None,Event_Type=None,Event_Location=None, StationID = None):
	url, headers = _CreateBase(f"/v2/fleets/{FleetID}/event/{EventID}", Key)
	event = GetEvent(Key, EventID)
	if Title != None:
		event["title"] = Title
	if Description != None:
		event["description"] = Description
	if StartTime != None:
		iso8601_pattern = r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$'
		if not re.match(iso8601_pattern, StartTime):
			return "Start time invalid format"
		else:
			event["start_time"] = StartTime+"z"
	if Duration != None:
		event["duration"] = Duration
	if Public != None:
		event["public"] = f"{Public}".lower
	if Signups_Open != None:
		event["signups_open"] = f"{Signups_Open}".lower
	if StationID != None:
		event["station_id"] = StationID
	if Event_Type != None:
		event["event_type"] = Event_Type
	if Event_Location != None:
		event["event_location"] = Event_Location
	return _SendPatch(headers, url, payload=event)

def GetEventConfig(Key, FleetID, EventID):
	url, headers = _CreateBase(f"/v2/fleets/{FleetID}/event/{EventID}/config")
	return _SendGet(headers, url)

def SetEventConfig(Key, FleetID, EventID, Config):
	"""DOES NOT DELETE OLD CONFIG, ONLY UPDATES"""
	url, headers = _CreateBase(f"/v2/fleets/{FleetID}/event/{EventID}/config", Key)
	return _SendPost(headers, url, payload=Config)

def DeleteEventConfig(Key, FleetID, EventID):
	url, headers = _CreateBase(f"/v2/fleets/{FleetID}/event/{EventID}/config", Key)
	return _SendDelete(headers, url)

def AddServerEvent(Key, StationID, EventType, EventData):
	url, header = _CreateBase(f"/v1/stations/{StationID}/server_events", Key)
	json = {
		"event_type" : f"{EventType}",
		"event_data" : f"{EventData}"
	}
	return _SendPost(header, url, json)

def GetStationEvents(Key, StationID, Amount, Page, EventType=None):
	url, headers = _CreateBase(f"/v2/stations/{StationID}/server_events", Key)
	params = {
		"page_size": {Amount},
		"page": {Page}
	}
	if EventType:
		params["event_type"] = f"{EventType}"
	return _SendGet(headers, url, params=params)



def GetStation(Key, StationID, IncStationConfig = None, IncFleetConfig = None):
	"""Both configs default to true"""
	url, headers = _CreateBase(f"/v2/stations/{StationID}", Key)
	params = {
		"include_station_config" : IncStationConfig,
		"include_fleet_config" : IncFleetConfig
	}
	return _SendGet(headers, url, params=params)

def GiveRoleByUsername(APIKey, FleetID, RoleID, UserName):
	url, headers = _CreateBase(f"/v2/fleets/{FleetID}/user_roles", APIKey)
	payload = {
		"role_id" : f"{RoleID}",
		"username": f"{UserName}",
		"expires_hours": 0
	}
	return _SendPost(headers, url, payload)

def UnbanUser(APIKey, FleetID, UserID):
	url, headers = _CreateBase(f"/v2/fleets/{FleetID}/users/{UserID}/unban", APIKey)
	return _SendPatch(headers, url)

def DeleteStationConfig(Key, StationID, ConfigKey):
    """
    Deletes a config key from a station config.

    Args:
        Key (_type_): API Key
        StationID (_type_): Station ID to use
        ConfigKeys (list): config key to delete
    """
    url, headers = _CreateBase(f"/v2/stations/{StationID}/config", Key)
    
    payload = {
        "items": ConfigKey 
    }

    return _SendDelete(headers, url, payload=payload)