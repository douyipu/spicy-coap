spicy_add_analyzer(
    NAME CoAP
    PACKAGE_NAME spicy-coap
    SOURCES coap.spicy coap.evt zeek_coap.spicy
    SCRIPTS __load__.zeek main.zeek
)
