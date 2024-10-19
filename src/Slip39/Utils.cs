using System.Linq;

namespace Slip39;

public static class Utils
{
    public static T[] Concat<T>(params T[][] arrays) =>
        arrays.SelectMany(x => x).ToArray();
}
