namespace Slip39;

public interface IRandom
{
    void GetBytes(byte[] buffer);

    byte[] GetBytes(int count);
}
