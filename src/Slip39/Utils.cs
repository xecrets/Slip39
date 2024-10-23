using System;

namespace Slip39;

public static class Utils
{
    public static T[] Concat<T>(this T[] first, T[] second)
    {
        T[] result = new T[first.Length + second.Length];
        Array.Copy(first, 0, result, 0, first.Length);
        Array.Copy(second, 0, result, first.Length, second.Length);
        return result;
    }

    public static T[] Concat<T>(this T first, T[] second) => new T[] { first }.Concat(second);
}
