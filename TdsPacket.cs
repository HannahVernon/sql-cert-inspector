namespace SqlCertInspector;

/// <summary>
/// Reads and writes TDS packet headers. A TDS packet has an 8-byte header:
///   [0]    Type (0x12 = PRELOGIN)
///   [1]    Status (0x01 = EOM)
///   [2-3]  Length (big-endian, includes header)
///   [4-5]  SPID
///   [6]    Packet ID
///   [7]    Window (unused, 0x00)
/// </summary>
public static class TdsPacket
{
    public const int HeaderSize = 8;
    public const byte TypePreLogin = 0x12;
    public const byte TypeTabularResult = 0x04;
    public const byte StatusEom = 0x01;
    public const byte StatusNormal = 0x00;

    /// <summary>
    /// Builds a complete TDS packet (header + payload).
    /// </summary>
    public static byte[] Build(byte type, byte status, byte[] payload, byte packetId = 1)
    {
        int totalLength = HeaderSize + payload.Length;
        byte[] packet = new byte[totalLength];
        packet[0] = type;
        packet[1] = status;
        packet[2] = (byte)(totalLength >> 8);
        packet[3] = (byte)(totalLength & 0xFF);
        packet[4] = 0x00; /* SPID high */
        packet[5] = 0x00; /* SPID low */
        packet[6] = packetId;
        packet[7] = 0x00; /* Window */
        Buffer.BlockCopy(payload, 0, packet, HeaderSize, payload.Length);
        return packet;
    }

    /// <summary>
    /// Reads a complete TDS packet from the stream (header + payload).
    /// Returns the packet type, status, and payload data.
    /// </summary>
    public static async Task<(byte type, byte status, byte[] payload)> ReadAsync(
        Stream stream, CancellationToken ct = default)
    {
        byte[] header = new byte[HeaderSize];
        await ReadExactAsync(stream, header, 0, HeaderSize, ct);

        byte type = header[0];
        byte status = header[1];
        int length = (header[2] << 8) | header[3];
        int payloadLength = length - HeaderSize;

        if (payloadLength < 0 || payloadLength > 65536)
        {
            throw new InvalidOperationException(
                $"Invalid TDS packet length: {length} (payload would be {payloadLength} bytes).");
        }

        byte[] payload = new byte[payloadLength];
        if (payloadLength > 0)
        {
            await ReadExactAsync(stream, payload, 0, payloadLength, ct);
        }

        return (type, status, payload);
    }

    private static async Task ReadExactAsync(
        Stream stream, byte[] buffer, int offset, int count, CancellationToken ct)
    {
        int totalRead = 0;
        while (totalRead < count)
        {
            int read = await stream.ReadAsync(
                buffer.AsMemory(offset + totalRead, count - totalRead), ct);
            if (read == 0)
            {
                throw new EndOfStreamException(
                    $"Connection closed while reading TDS packet. Expected {count} bytes, got {totalRead}.");
            }
            totalRead += read;
        }
    }
}
