namespace Slip39;

/// <summary>
/// Defines the main parameter of a group.
/// </summary>
/// <param name="MemberThreshold">Member threshold for group i, a positive integer, 1 ≤ Ti ≤ Ni.</param>
/// <param name="Count">Total number of members in group i, a positive integer, 1 ≤ Ni ≤ 16.</param>
public record Group(int MemberThreshold, int Count);
