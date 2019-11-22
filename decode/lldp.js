var EthernetAddr = require("./ethernet_addr");
var IPV4Addr = require("./ipv4_addr");
var IPV6Addr = require("./ipv6_addr");

LLDPConsts = Object.freeze({
    MAC: 1,
    IPV4: 2,
    IPV6: 3
});

LLDPSystemCapConsts =  Object.freeze({
    OTHER: "Other",
    REPEATER: "Repeater",
    BRIDGE: "Bridge",
    AP: "Ap",
    ROUTER: "Router",
    PHONE: "Phone",
    DOCSIS: "Docsis",
    STATION: "Station",
    CVLAN: "CvLan",
    SVLAN: "SvLan",
    TPRELAY: "TpRelay"
});

function LLDP(emitter) {
	this.emitter = emitter;
	this.chassisID = undefined;
    this.chassisIDType = undefined;
	this.portID = undefined;
    this.portIDType = undefined;
	this.ttl = undefined;
    this.portDescription = undefined;
    this.systemName = undefined;
    this.systemDescription = undefined;
    this.systemCapabilitiesSupported = undefined;
    this.systemCapabilitiesEnabled = undefined;
    this.managementAddr = undefined;
}

LLDP.prototype.decode = function (raw_packet, offset) {
    while (offset < raw_packet.length) {
        var tlvType = raw_packet[offset] >> 1;
        var tlvLength = (raw_packet.readUInt16BE(offset) & 0x1FF);
        offset += 2;
        switch (tlvType) {
            // Fim do pacote
            case 0: break;

            //Chassi
            case 1:
                this.chassisIDType = raw_packet[offset];

                var addrType;
                var incOffset = 2;

                switch(this.chassisIDType) {
                    case 4:
                        addrType = LLDPConsts.MAC;
                        incOffset = 1;
                        break;
                    case 5:
                        addrType = LLDPConsts.IPV4;
                        break;
                    case 6:
                        addrType = LLDPConsts.IPV6;
                        break;
                }

                this.chassisID = this.parseAddr(addrType, raw_packet, offset + incOffset, tlvLength);

                break;

            // ID da porta
            case 2:
                this.portIDType = raw_packet[offset];

                var addrType;

                switch(this.portIDType) {
                    case 3:
                        addrType = LLDPConsts.MAC;
                        break;
                }

                this.portID = this.parseAddr(addrType, raw_packet, offset + 1, tlvLength);

                break;

            // TTL (Time To Live)
            case 3:
                this.ttl = raw_packet.readUInt16BE(offset);

            // Descrição da porta
            case 4:
                this.portDescription = raw_packet.toString('utf8', offset, offset + tlvLength);
                break;
            // Nome do sistema
            case 5:
                this.systemName = raw_packet.toString('utf8', offset, offset + tlvLength);
                break;

            // Descrição do sistema
            case 6:
                this.systemDescription = raw_packet.toString('utf8', offset, offset + tlvLength);
                break;

            // Capacidades do sistema
            case 7:
                this.systemCapabilitiesSupported = this.parseSysCap(raw_packet.readUInt16BE(offset));
                offset += 2;
                this.systemCapabilitiesEnabled = this.parseSysCap(raw_packet.readUInt16BE(offset));
                break;

            // Endereço de gerenciamento
            case 8:
                this.managementAddr = undefined;
                break;
        }

        offset += tlvLength;
    }

    if (this.emitter) {
        this.emitter.emit("lldp", this);
    }

	return this;
}

LLDP.prototype.decoderName = "LLDP";
LLDP.prototype.eventsOnDecode = true;

LLDP.prototype.toString = function() {
    return 'LLDP from ' + this.chassisID;
};

LLDP.prototype.parseAddr = function(addrType, raw_packet, offset, tlvLength) {
    switch (addrType) {
        case LLDPConsts.MAC:
            return new EthernetAddr(raw_packet, offset);
        case LLDPConsts.IPV4:
            return new IPV4Addr().decode(raw_packet, offset);
        case LLDPConsts.IPV6:
            return new IPV6Addr().decode(raw_packet, offset);
        default:
            return raw_packet.slice(offset, offset + tlvLength - 1);
    }
};

LLDP.prototype.parseSysCap = function(sysCapType){
    switch(sysCapType){
        case 1:
            return LLDPSystemCapConsts.OTHER;
            break;
        case 2:
            return LLDPSystemCapConsts.REPEATER;
            break;
        case 4:
            return LLDPSystemCapConsts.BRIDGE;
            break;
        case 8:
            return LLDPSystemCapConsts.AP;
            break;
        case 16:
            return LLDPSystemCapConsts.ROUTER;
            break;
        case 32:
            return LLDPSystemCapConsts.PHONE;
            break;
        case 64:
            return LLDPSystemCapConsts.DOCSIS;
            break;
        case 128:
            return LLDPSystemCapConsts.STATION;
            break;
        case 256:
            return LLDPSystemCapConsts.CVLAN;
            break;
        case 512:
            return LLDPSystemCapConsts.SVLAN;
            break;
        case 1024:
            return LLDPSystemCapConsts.TPRELAY;
            break;
    }
}

module.exports = LLDP;