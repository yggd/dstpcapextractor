package org.yggd.pcap

import java.lang.IllegalArgumentException

data class TcpHost(val address: String, val host: String, val protocolValue: Byte, val protocolName: String) {

    companion object {

        fun deserialize(serialize: String) : TcpHost {
            val array = serialize.split(",")
            if (array.size != 4) {
                throw IllegalArgumentException("Wrong Serialize value:$serialize")
            }
            return TcpHost(array[0], array[1], array[2].toByte(), array[3])
        }

        fun serialize(tcpHost: TcpHost) : String =
            listOf(tcpHost.address, tcpHost.host, tcpHost.protocolValue, tcpHost.protocolName)
                .joinToString(separator = ",")
    }
}
