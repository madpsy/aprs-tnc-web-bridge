# aprs-tnc-web-bridge

Thanks for checking out this attempt of a modern looking browser based APRS client (though is actually much more than that). It is very much a first attempt and MRs are very much welcomed! You can build your own frontends on top of its websocket server and APIs.

The idea is you run the Python application on a computer which has a connection to a KISS TNC, the built in web server is then available to any browser/client on the network.

More docs to come. See the INSTALL file to get going and then once running open http://127.0.0.1:5001/ for the main interface and http://127.0.0.1:5001/static/readme.html for documentation. Configuration is done by editing settings.yaml or the use the web frontend http://127.0.0.1:5001/static/settings.html

Currently designed for a good sized screen (PC/laptop etc) rather than a phone as there are already apps for that. Note: This is very much early stages and not all packets are decoded or utilised.

At a very basic level this sends raw and decoded APRS packets over websockets as JSON and receives raw packets and formatted location/message types over a JSON based API.

Essentially it is a KISS TNC (Serial/TCP) -> Web interface via websockets & JSON API. MQTT support for APRS analogue and digital telemetry channels as well as the usual mapping and messaging features are included.

TNCs which have been tested include CA2RXU's LoRa iGate and Tracker firmware, NinoTNC and the VGC VR-N76 HT.

It can also act as a proxy (i.e. transparent bridge) between a TCP network endpoint and the TNC, for example to allow a serial TNC to be accessible over a network. Tested with various software including APRSDroid.

The telemetry manager handles all 13 channels and takes care of sequence, unit and EQNS packets. Has been tested with Tasmota and Shelly switches over MQTT (digital channels) as well as reading various analouge values. This also has a JSON API endpoint to send updates to.

![map](images/map-messages.png)


![digi](images/digital-telemetry.png)

![analogue](images/analogue-telemetry.png)

![settings](images/settings.png)
