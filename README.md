# CoAP Protocol Analyzer with Spicy

## 1. Create the project directory with `spicy-protocol-analyzer` template.

```shell
root@zeek-ubuntu:~/# zkg create --features spicy-protocol-analyzer --packagedir spicy-coap
"package-template" requires a "name" value (the name of the package, e.g. "FooBar" or "spicy-http"): 
name: spicy-coap
"package-template" requires a "analyzer" value (name of the Spicy analyzer, which typically corresponds to the protocol/format being parsed (e.g. "HTTP", "PNG")): 
analyzer: CoAP
"package-template" requires a "protocol" value (transport protocol for the analyzer to use: TCP or UDP): 
protocol: UDP
"package-template" requires a "unit_orig" value (name of the top-level Spicy parsing unit for the originator side of the connection (e.g. "Request")): 
unit_orig: Message
"package-template" requires a "unit_resp" value (name of the top-level Spicy parsing unit for the responder side of the connection (e.g. "Reply"); may be the same as originator side): 
unit_resp: Message
```

## 2. Change these files and write your code.

```shell
├── analyzer
│   ├── coap.evt
│   ├── coap.spicy
│   └── zeek_coap.spicy
├── scripts
    ├── __load__.zeek
    ├── dpd.sig
    └── main.zeek
```

## 3. Build the Spicy analyzer.

```shell
root@zeek-ubuntu:~/spicy-coap# rm -rf build
root@zeek-ubuntu:~/spicy-coap# mkdir build
root@zeek-ubuntu:~/spicy-coap# cd build
root@zeek-ubuntu:~/spicy-coap/build# cmake ..
root@zeek-ubuntu:~/spicy-coap/build# cmake --build .
```

## 4. Test the Spicy analyzer.

1. Put your PCAP files under `spicy-coap/testing/Traces` directory.

2. Change `spicy-coap/testing/tests/standalone.spicy` and `spicy-coap/testing/tests/trace.zeek` testing commands.

3. Update `Baseline` directory files.

```shell
root@zeek-ubuntu:~/spicy-coap/testing# btest -U
```

4. Test.

```shell    
root@zeek-ubuntu:~/spicy-coap/testing# btest
```

## 5. Install the analyzer and verify it.

```shell
zkg install .
zeek -NN Zeek::Spicy
```

## 6. Run Zeek with CoAP analyzer.

Add `spicy-coap` if you want to generate `coap.log` file.

```shell
zeek -Cr Test.pcap spicy-coap
```

It's the format of `coap.log` in JSON.

```json
{
  "ts": 1618846973.710531,
  "uid": "CzQ5u56kn79ScgWC7",
  "id.orig_h": "10.0.0.2",
  "id.orig_p": 56955,
  "id.resp_h": "10.0.0.6",
  "id.resp_p": 5683,
  "version": 1,
  "message_type": "CoAP::MessageType_CONFIRMABLE",
  "code": "CoAP::Code_GET",
  "message_id": 53406,
  "token": "qp",
  "option_id": [
    "CoAP::OptionID_URI_PATH"
  ],
  "option_value": [
    "basic"
  ]
}
{
  "ts": 1618846973.732999,
  "uid": "CzQ5u56kn79ScgWC7",
  "id.orig_h": "10.0.0.2",
  "id.orig_p": 56955,
  "id.resp_h": "10.0.0.6",
  "id.resp_p": 5683,
  "version": 1,
  "message_type": "CoAP::MessageType_CONFIRMABLE",
  "code": "CoAP::Code_POST",
  "message_id": 53407,
  "token": "cK",
  "option_id": [
    "CoAP::OptionID_URI_PATH"
  ],
  "option_value": [
    "basic"
  ],
  "payload": "dummydata-9949"
}
```

If you want to load all your installed packages, add `@load packages` in `/opt/zeek/share/zeek/site/local.zeek` file. And add `local` or `local.zeek` when you use Zeek.

```shell
zeek -Cr Test.pcap local
```

## References

- [Zeek Documentation](https://docs.zeek.org/en/master/)
- [Spicy Documentation](https://docs.zeek.org/projects/spicy/en/latest/index.html)
- [Anatomy Of A Zeek Spicy Protocol Analyzer](https://www.youtube.com/watch?v=wmm-6ZggwNc&t=1086s) YouTube Video from Keith Jones
