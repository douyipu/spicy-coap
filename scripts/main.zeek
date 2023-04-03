module CoAP;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;
	
	## Record type containing the column fields of the CoAP log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		
		## CoAP protocol version.
		version: count &optional &log;
		## CoAP protocol message type.
		message_type: MessageType &optional &log;
		## CoAP protocol code.
		code: Code &optional &log;
		## CoAP protocol message ID.
		message_id: count &optional &log;
		## CoAP protocol token.
		token: string &optional &log;
		## The number of CoAP option id, but not logged.
		option_num: count &optional;
		## The vector of CoAP protocol option ids.
		option_id: vector of OptionID &optional &log;
		## The vector of CoAP protocol option values.
		option_value: vector of string &optional &log;
		## CoAP messgae payload.
		payload: string &optional &log;
	};

	## Default hook into CoAP logging.
	global log_coap: event(rec: Info);
	global CoAP::fixed_header: event(c: connection, is_orig: bool, ver: count, message_type: MessageType, code: Code, message_id: count);
	global CoAP::token: event(c: connection, token: string);
	global CoAP::option_coap: event(c: connection, option_ID: OptionID, option_value: string);
	global CoAP::payload: event(c: connection, payload: string);
}

redef record connection += {
	coap: Info &optional;
};

const ports = {
	5683/udp # adapt port number in coap.evt accordingly
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(CoAP::LOG, [$columns=Info, $ev=log_coap, $path="coap", $policy=log_policy]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$coap )
		return;

	c$coap = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	}

function emit_log(c: connection)
	{
	if ( ! c?$coap )
		return;

	Log::write(CoAP::LOG, c$coap);
	delete c$coap;
	}

event CoAP::fixed_header(c: connection, is_orig: bool, ver: count, message_type: MessageType, code: Code, message_id: count)
	{
	hook set_session(c);
	
	local info = c$coap;
	info$version = ver;
	info$message_type = message_type;
	info$code = code;
	info$message_id = message_id;
	info$option_num = 0;
	}

event CoAP::token(c: connection, token: string)
	{
	c$coap$token = token;
	}

event CoAP::option_coap(c: connection, option_ID: OptionID, option_value: string)
	{
	local info = c$coap;
	if ( info$option_num == 0 )
		{
		info$option_num += 1;
		info$option_id = vector(option_ID);
		info$option_value = vector(option_value);
		}
	else
		{
		info$option_id += option_ID;
		info$option_value += option_value;
		}
	}
	
event CoAP::payload(c: connection, payload: string)
	{
	c$coap$payload = payload;
	}

event connection_state_remove(c: connection) &priority=-5
	{
	emit_log(c);
	}
