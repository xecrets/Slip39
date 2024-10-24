using System;

namespace Slip39;

public class MnemonicException(string message, Exception innerException) : Exception(message, innerException)
{
}
