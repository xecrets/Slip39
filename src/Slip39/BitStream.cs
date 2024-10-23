using System;

namespace Slip39;

public class BitStream
{
    private byte[] _buffer;
    private int _writePos;
    private int _readPos;
    private int _lengthInBits;

    public BitStream(byte[] buffer)
    {
        byte[] newBuffer = new byte[buffer.Length];
        Buffer.BlockCopy(buffer, 0, newBuffer, 0, buffer.Length);
        _buffer = newBuffer;
        _readPos = 0;
        _writePos = 0;
        _lengthInBits = buffer.Length * 8;
    }

    private void WriteBit(bool bit)
    {
        EnsureCapacity();
        if (bit)
        {
            _buffer[_writePos / 8] |= (byte)(1 << (8 - (_writePos % 8) - 1));
        }
        _writePos++;
        _lengthInBits++;
    }

    public void WriteBits(long value, int n)
    {
        if (n is < 1 or > 63)
        {
            throw new ArgumentOutOfRangeException(nameof(n), "n must be between 1 and 63");
        }
        if (value < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(value), "value must be positive.");
        }

        int fullBytes = n / 8;
        int fullByteBits = fullBytes * 8;

        int bitShift = n;
        while (bitShift > fullByteBits)
        {
            bool bit = ((value >> --bitShift) & 1) == 1;
            WriteBit(bit);
        }

        while ((bitShift -= 8) >= 0)
        {
            byte currentByte = (byte)(value >> bitShift);
            WriteByte(currentByte);
        }
    }

    public void WriteByte(byte b)
    {
        EnsureCapacity();

        int remainCount = _writePos % 8;
        int i = _writePos / 8;
        _buffer[i] |= (byte)(b >> remainCount);

        int written = 8 - remainCount;
        _writePos += written;
        _lengthInBits += written;

        if (remainCount > 0)
        {
            EnsureCapacity();

            _buffer[i + 1] = (byte)(b << (8 - remainCount));
            _writePos += remainCount;
            _lengthInBits += remainCount;
        }
    }

    private bool TryReadBit(out bool bit)
    {
        bit = false;
        if (_readPos == _lengthInBits)
        {
            return false;
        }

        int mask = 1 << (8 - (_readPos % 8) - 1);

        bit = (_buffer[_readPos / 8] & mask) == mask;
        _readPos++;
        return true;
    }

    public bool TryReadBits(int count, out int bits)
    {
        int val = 0;
        while (count >= 8)
        {
            val <<= 8;
            if (!TryReadByte(out byte readByte))
            {
                bits = 0;
                return false;
            }
            val |= readByte;
            count -= 8;
        }

        while (count > 0)
        {
            val <<= 1;
            if (TryReadBit(out bool bit))
            {
                val |= bit ? 1 : 0;
                count--;
            }
            else
            {
                bits = 0;
                return false;
            }
        }
        bits = val;
        return true;
    }

    private bool TryReadByte(out byte b)
    {
        b = 0;
        if (_readPos == _lengthInBits)
        {
            return false;
        }

        int i = _readPos / 8;
        int remainCount = _readPos % 8;
        b = (byte)(_buffer[i] << remainCount);

        if (remainCount > 0)
        {
            if (i + 1 == _buffer.Length)
            {
                b = 0;
                return false;
            }
            b |= (byte)(_buffer[i + 1] >> (8 - remainCount));
        }
        _readPos += 8;
        return true;
    }

    public byte[] ToByteArray()
    {
        int arraySize = (_writePos + 7) / 8;
        byte[] byteArray = new byte[arraySize];
        Array.Copy(_buffer, byteArray, arraySize);
        return byteArray;
    }

    public int Available => _lengthInBits - _readPos;

    private void EnsureCapacity()
    {
        if (_writePos / 8 == _buffer.Length)
        {
            Array.Resize(ref _buffer, _buffer.Length + (4 * 1024));
        }
    }
}