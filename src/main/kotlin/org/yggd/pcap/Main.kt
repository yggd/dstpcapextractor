package org.yggd.pcap

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import com.sun.org.apache.xpath.internal.Arg
import org.kohsuke.args4j.CmdLineParser
import org.kohsuke.args4j.Option
import org.mapdb.DBMaker
import org.mapdb.Serializer
import org.pcap4j.core.NotOpenException
import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNativeException
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.IpV4Packet
import org.yggd.kotlin.forSlf4j
import java.io.Closeable
import java.io.EOFException
import java.lang.IllegalArgumentException
import java.lang.IllegalStateException
import java.lang.System.err
import java.nio.file.Files
import java.nio.file.Path
import java.util.Spliterator.*
import java.util.Spliterators.spliteratorUnknownSize
import java.util.concurrent.ConcurrentMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.function.Consumer
import java.util.stream.Stream
import java.util.stream.StreamSupport
import kotlin.system.exitProcess

const val DB_HOST = "TcpHost"
val DB_PATH = "${System.getProperty("user.home")}/.pcapdb"

fun main(args: Array<String>) {

    val argModel = Args()

    val parser = CmdLineParser(argModel)

    try {
        parser.parseArgument(args.toList())
        validate(argModel)
    } catch (e : Exception) {
        parser.printUsage(err)
        exitProcess(1)
    }

    if (argModel.path.isNotBlank()) {
        HostParser().parse(argModel.path)
        return
    }

    if (argModel.show) {
        HostViewer().show()
        return
    }

    if (argModel.truncate) {
        Files.deleteIfExists(Path.of(DB_PATH))
        println("truncated.")
        return
    }

    if (argModel.count) {
        println("DB entries size:${HostCounter().count()}")
    }
}

class HostCounter {
    fun count() :Int = TcpRepository(DB_PATH, DB_HOST).use {
        return it.count()
    }
}

class HostViewer {
    fun show() = TcpRepository(DB_PATH, DB_HOST).use { tcpRepository ->
        println("address,host,protocolValue,protocolName")
        tcpRepository.findAll().forEach { th ->
            println("${th.address},${th.host}.${th.protocolValue},${th.protocolName}")
        }
    }

}

class HostParser {
    fun parse(path: String) {
        TcpRepository(DB_PATH, DB_HOST).use {
            PcapExtractor(path).extract {
                s: Stream<TcpHost> -> s.forEach { t: TcpHost -> it.register(t) }
            }
        }
    }
}

fun validate(args: Args) {
    require(args.path.isNotBlank() or args.show or args.count or args.truncate )
}

class Args {

    @Option(name = "-r", metaVar = "<path>", usage = "read and parse this pcap file path")
    var path: String = ""

    @Option(name = "-s", usage = "show the db record of dest packet")
    var show: Boolean = false

    @Option(name = "-c", usage = "count db record")
    var count: Boolean = false

    @Option(name = "-t", usage = "truncate db")
    var truncate: Boolean = false
}

class PcapExtractor(private val path: String) {

    val log = forSlf4j()

    fun extract(consumer: (Stream<TcpHost>) -> Unit) =
        try {
            consumer.invoke(
                StreamSupport.stream(
                    spliteratorUnknownSize(PcapIterator(Pcaps.openOffline(path)),
                        NONNULL or ORDERED or SIZED), false))
        } catch (e : PcapNativeException) {
            log.error("", e)
        }

    /**
     * CAUTION This class is NOT thread-safe.
     */
    private class PcapIterator(val pcapHandle: PcapHandle, val showLocalAddr: Boolean = false) : Iterator<TcpHost> {

        var log = forSlf4j()

        private val cache : Cache<String, String> = Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(5L, TimeUnit.MINUTES)
            .build()

        private var packet: IpV4Packet? = null

        override fun hasNext(): Boolean {
            // Can't use Result... because of mapDB depends Kotlin 1.2
            try {
                while (true) {
                    val p = pcapHandle.nextPacketEx ?: return false
                    val payload = p.payload as? IpV4Packet ?: continue
                    val dstAddr = payload.header.dstAddr
                    if (cache.getIfPresent(dstAddr.hostAddress) != null) {
                        continue
                    }
                    if (showLocalAddr || !dstAddr.isSiteLocalAddress) {
                        this.packet = payload
                        break
                    }
                }
            } catch (e : Exception) {
                when (e) {
                    is PcapNativeException, is TimeoutException, is NotOpenException -> {
                        log.error("", e)
                        return false
                    }
                    is EOFException -> {
                        return false
                    }
                }
            }
            return true
        }

        override fun next(): TcpHost {
            val header = packet?.header ?: throw IllegalStateException("packet lost...")
            val tcpHost = TcpHost(
                header.dstAddr.hostAddress,
                header.dstAddr.hostName,
                header.protocol.value(),
                header.protocol.name())
            cache.put(tcpHost.address, tcpHost.host)
            log.debug("parsing:{}", tcpHost.toString())
            return tcpHost
        }
    }
}

class TcpRepository(private val path: String, private val mapName: String) : Closeable {

    private val db = DBMaker.fileDB(path).make()

    private val map : ConcurrentMap<String, String> = db.hashMap(mapName, Serializer.STRING, Serializer.STRING).createOrOpen()

    private val dispose : () -> Unit = {
        if (!db.isClosed()) {
            db.close()
        }
    }

    init {
        shutdownHook { dispose() }
    }

    fun register(tcpHost: TcpHost) = map.putIfAbsent(tcpHost.address, TcpHost.serialize(tcpHost))

    fun findAll() = map.values.stream().map { v : String -> TcpHost.deserialize(v) }

    fun count() = map.size

    override fun close() {
        dispose()
    }

    private fun shutdownHook(hook: () -> Unit) {
        Runtime.getRuntime().addShutdownHook(Thread{hook()})
    }
}