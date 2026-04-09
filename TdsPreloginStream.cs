namespace SqlCertInspector;

/// <summary>
/// A custom Stream that wraps TLS handshake data inside TDS PRELOGIN packets.
/// 
/// During SQL Server's TDS PRELOGIN phase, the TLS handshake records are wrapped
/// inside TDS type 0x12 packets. After the handshake completes, subsequent data
/// flows as raw TLS (no TDS wrapping). This stream handles that framing so
/// <see cref="System.Net.Security.SslStream"/> can perform a standard TLS handshake
/// through TDS-wrapped transport.
/// </summary>
public sealed class TdsPreloginStream : Stream
{
    private readonly Stream _innerStream;
    private byte[] _readBuffer = Array.Empty<byte>();
    private int _readOffset;
    private int _readCount;

    public TdsPreloginStream(Stream innerStream)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
    }

    public override bool CanRead => true;
    public override bool CanWrite => true;
    public override bool CanSeek => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        if (_readCount > 0)
        {
            int toCopy = Math.Min(count, _readCount);
            Buffer.BlockCopy(_readBuffer, _readOffset, buffer, offset, toCopy);
            _readOffset += toCopy;
            _readCount -= toCopy;
            return toCopy;
        }

        /* Read the next TDS packet and unwrap its payload */
        var (type, status, payload) = await TdsPacket.ReadAsync(_innerStream, ct);

        if (payload.Length == 0)
        {
            return 0;
        }

        int copyNow = Math.Min(count, payload.Length);
        Buffer.BlockCopy(payload, 0, buffer, offset, copyNow);

        if (copyNow < payload.Length)
        {
            _readBuffer = payload;
            _readOffset = copyNow;
            _readCount = payload.Length - copyNow;
        }

        return copyNow;
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        /* Wrap the TLS record data in a TDS PRELOGIN packet */
        byte[] payload = new byte[count];
        Buffer.BlockCopy(buffer, offset, payload, 0, count);

        byte[] packet = TdsPacket.Build(TdsPacket.TypePreLogin, TdsPacket.StatusEom, payload);
        await _innerStream.WriteAsync(packet, ct);
        await _innerStream.FlushAsync(ct);
    }

    public override void Flush()
    {
        _innerStream.Flush();
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
