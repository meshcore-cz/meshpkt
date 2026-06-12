package cz.meshcore.meshpkt

import cz.meshcore.meshpkt.mobile.Mobile
import org.json.JSONArray
import org.json.JSONObject

object Meshpkt {
    fun call(name: String, vararg args: Any?): JSONObject {
        val jsonArgs = JSONArray()
        args.forEach { arg ->
            jsonArgs.put(toJsonArg(arg))
        }

        val result = JSONObject(Mobile.call(name, jsonArgs.toString()))
        if (result.has("error")) {
            throw MeshpktException(result.getString("error"))
        }

        return result
    }

    fun encodeGroupText(
        channelName: String,
        sender: String,
        text: String,
    ): ByteArray {
        val result = call(
            "encodeGroupText",
            channelName,
            sender,
            text,
        )

        return result.getString("hex").hexToByteArray()
    }

    fun decodeEnvelope(packet: ByteArray): JSONObject =
        call("decodeEnvelope", packet)

    fun deriveChannelSecret(channelName: String): ByteArray {
        val result = call("deriveChannelSecret", channelName)
        return result.getString("hex").hexToByteArray()
    }
}

class MeshpktException(message: String) : RuntimeException(message)

private fun toJsonArg(arg: Any?): Any? =
    when (arg) {
        is ByteArray -> arg.toHexString()
        else -> arg
    }

private fun ByteArray.toHexString(): String =
    joinToString(separator = "") { byte ->
        "%02x".format(byte.toInt() and 0xff)
    }

private fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) {
        "Hex string must contain an even number of characters"
    }

    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
