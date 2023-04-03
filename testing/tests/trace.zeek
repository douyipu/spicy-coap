# @TEST-DOC: Test Zeek parsing a trace file through the CoAP analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/Test.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff coap.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event CoAP::token(c: connection, token: string)
	{
	print fmt("Testing CoAP::token event -> c$id: %s, token: %s", c$id, token);
	}
