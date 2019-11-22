var pcap = require("../pcap"),
    pcap_session = pcap.createSession("lo", "");

console.log("Listening on " + pcap_session.device_name);

pcap_session.on('packet', function (raw_packet) {
    var packet = pcap.decode.packet(raw_packet);
    // console.log(packet.toString());
    // console.log(packet);
});
