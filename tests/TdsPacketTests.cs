using SqlCertInspector;

namespace SqlCertInspectorTests;

public class TdsPacketTests
{
    [Fact]
    public void Build_SetsTypeAndStatus()
    {
        byte[] payload = new byte[] { 0xAA, 0xBB };
        byte[] packet = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, payload);

        Assert.Equal(TdsPacket.TypePreLogin, packet[0]);
        Assert.Equal(TdsPacket.StatusEom, packet[1]);
    }

    [Fact]
    public void Build_SetsLengthBigEndian()
    {
        byte[] payload = new byte[100];
        byte[] packet = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, payload);

        int expectedLength = TdsPacket.HeaderSize + 100; /* 108 */
        Assert.Equal((byte)(expectedLength >> 8), packet[2]);
        Assert.Equal((byte)(expectedLength & 0xFF), packet[3]);
    }

    [Fact]
    public void Build_CopiesPayload()
    {
        byte[] payload = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        byte[] packet = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, payload);

        Assert.Equal(payload, packet[TdsPacket.HeaderSize..]);
    }

    [Fact]
    public void Build_SetsPacketId()
    {
        byte[] packet = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, Array.Empty<byte>(), packetId: 7);

        Assert.Equal(7, packet[6]);
    }

    [Fact]
    public void Build_EmptyPayload_HeaderOnly()
    {
        byte[] packet = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, Array.Empty<byte>());

        Assert.Equal(TdsPacket.HeaderSize, packet.Length);
    }

    [Fact]
    public async Task ReadAsync_ReadsCorrectPacket()
    {
        /* Build a valid TDS packet and feed it to ReadAsync */
        byte[] payload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        byte[] rawPacket = TdsPacket.Build(TdsPacket.TypeTabularResult, TdsPacket.StatusEom, payload);

        using var stream = new MemoryStream(rawPacket);
        var (type, status, readPayload) = await TdsPacket.ReadAsync(stream);

        Assert.Equal(TdsPacket.TypeTabularResult, type);
        Assert.Equal(TdsPacket.StatusEom, status);
        Assert.Equal(payload, readPayload);
    }

    [Fact]
    public async Task ReadAsync_ZeroPayload()
    {
        byte[] rawPacket = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, Array.Empty<byte>());

        using var stream = new MemoryStream(rawPacket);
        var (type, status, readPayload) = await TdsPacket.ReadAsync(stream);

        Assert.Empty(readPayload);
    }

    [Fact]
    public async Task ReadAsync_TruncatedHeader_Throws()
    {
        /* Only 4 bytes of header — ReadAsync should throw EndOfStreamException */
        byte[] truncated = new byte[] { 0x12, 0x01, 0x00, 0x0C };

        using var stream = new MemoryStream(truncated);
        await Assert.ThrowsAsync<EndOfStreamException>(
            () => TdsPacket.ReadAsync(stream));
    }

    [Fact]
    public async Task ReadAsync_TruncatedPayload_Throws()
    {
        /* Header says 12 bytes total (4 payload), but only 2 payload bytes present */
        byte[] raw = new byte[]
        {
            0x12, 0x01, 0x00, 0x0C, /* type, status, length=12 */
            0x00, 0x00, 0x01, 0x00, /* SPID, packetId, window */
            0xAA, 0xBB              /* only 2 of 4 expected payload bytes */
        };

        using var stream = new MemoryStream(raw);
        await Assert.ThrowsAsync<EndOfStreamException>(
            () => TdsPacket.ReadAsync(stream));
    }

    [Fact]
    public async Task ReadAsync_InvalidLength_Throws()
    {
        /* Header with impossibly large length */
        byte[] raw = new byte[]
        {
            0x12, 0x01, 0xFF, 0xFF, /* length = 65535 → payload = 65527 */
            0x00, 0x00, 0x01, 0x00
            /* No payload data — will fail reading */
        };

        using var stream = new MemoryStream(raw);
        await Assert.ThrowsAsync<EndOfStreamException>(
            () => TdsPacket.ReadAsync(stream));
    }
}
