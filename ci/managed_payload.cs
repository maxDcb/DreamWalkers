using System;

public static class ManagedPayload
{
    public static int Main(string[] args)
    {
        Console.WriteLine("managed_payload_go");
        if (args.Length > 0)
        {
            Console.WriteLine("managed_payload_arg:" + args[0]);
        }

        return 0;
    }
}
