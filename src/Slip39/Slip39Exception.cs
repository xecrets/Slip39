using System;

namespace Slip39;

public class Slip39Exception(string message, Exception innerException) : Exception(message, innerException)
{
}
