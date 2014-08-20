using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.Linq;

namespace Battlefield_RCON_Server_Manager
{
    class Program
    {
        static IPAddress address;
        static int port;
        static int sequence = 0;

        static void Main(string[] args)
        {
            Console.Title = "Battlefield RCON Server Manager";
            Console.WriteLine("***** Battlefield RCON Server Manager - by Leotichidas *****");
            Console.WriteLine();

            String ipArg = args.Length == 2 ? args[0] : "";
            String portArg = args.Length == 2 ? args[1] : "";

            if (!(IPAddress.TryParse(ipArg, out address) & Int32.TryParse(portArg, out port)))
            {
                Console.Write("Enter IP Address: ");
                if (!IPAddress.TryParse(Console.ReadLine(), out address))
                {
                    Console.WriteLine("#ERROR: The ip entered is invalid!");
                    Console.WriteLine();
                    Console.WriteLine("Press a key to exit...");
                    Console.ReadKey();
                    return;
                }

                Console.Write("Enter Port Numbert: ");
                if (!Int32.TryParse(Console.ReadLine(), out port))
                {
                    Console.WriteLine("#ERROR: The port entered is invalid!");
                    Console.WriteLine();
                    Console.WriteLine("Press a key to exit...");
                    Console.ReadKey();
                    return;
                }
            }

            Console.WriteLine("OK Contacting server {0}:{1}...", address.ToString(), port);
            Thread.Sleep(1000);

            try
            {
                using (TcpClient client = new TcpClient("62.104.17.147", 47200))
                using (NetworkStream stream = client.GetStream())
                {
                    Console.WriteLine("OK Established connection! Type login for authentication.");
                    String[] commands = new String[0];

                    while (true)
                    {
                        if (commands.Length == 0)
                        {
                            Console.WriteLine();
                            Console.Write(">> ");
                            commands = Console.ReadLine().Split(' ');
                        }

                        if (commands[0] == "login")
                            commands = new String[] { "login.hashed" };

                        switch (commands[0])
                        {
                            case ("login"):
                                commands = new String[] { "login.hashed" };
                                break;
                            case ("clear"):
                                Console.Clear();
                                Console.WriteLine("***** Battlefield RCON Server Manager - by Leotichidas *****");
                                commands = new String[0];
                                continue;
                        }

                        byte[] request = encodePacket(commands);
                        stream.Write(request, 0, request.Length);
                        byte[] response = new byte[65356];
                        stream.Read(response, 0, 65356);
                        String[] decResponse = decodePacket(response);
                        Console.WriteLine(String.Join(" ", decResponse));

                        switch (commands[0])
                        {
                            case ("quit"):
                                return;
                            case ("login.hashed"):
                                if (commands.Length > 1)
                                {
                                    commands = new String[0];
                                    continue;
                                }
                                Console.Write("Enter RCON Password: ");
                                String password = Console.ReadLine();
                                commands = new String[] { "login.hashed", GenerateHash(password, decResponse[1]) };
                                break;
                            default:
                                commands = new String[0];
                                break;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("#ERROR: " + ex.Message);
            }

            Console.WriteLine();
            Console.WriteLine("Press a key to exit...");
            Console.ReadKey();
        }

        static byte[] encodePacket(params String[] commands)
        {
            int commandsLenght = 0;
            foreach (String command in commands)
                commandsLenght += command.Length;

            int commandsCount = commands.Length;
            int size = 4 + 4 + 4 + 4 * commandsCount + commandsLenght + 1 * commandsCount;
            byte[] packet = new byte[size];
            packet[0] = 1;
            packet[2] = (byte)sequence++;

            byte[] tmpSize = BitConverter.GetBytes(size);
            for (int i = 0; i < tmpSize.Length; i++)
                packet[4 + i] = tmpSize[i];

            byte[] tmpLenght = BitConverter.GetBytes(commandsCount);
            for (int i = 0; i < tmpLenght.Length; i++)
                packet[8 + i] = tmpLenght[i];

            int position = 12;

            foreach (String command in commands)
            {
                byte[] tmpCommandLenght = BitConverter.GetBytes(command.Length);
                for (int i = 0; i < tmpCommandLenght.Length; i++)
                    packet[position + i] = tmpCommandLenght[i];

                byte[] tmpCommand = Encoding.Default.GetBytes(command);
                for (int i = 0; i < tmpCommand.Length; i++)
                    packet[position + 4 + i] = tmpCommand[i];

                position += (4 + command.Length + 1);
            }

            return packet;
        }

        static String[] decodePacket(byte[] packet)
        {
            if (packet.Length == 0)
                return new String[] { "Generic Error" };

            List<String> ls = new List<String>();
            int arguments = BitConverter.ToInt32(packet, 8);
            int position = 12;

            while (arguments-- != 0)
            {
                int argLen = BitConverter.ToInt32(packet, position);
                ls.Add(Encoding.Default.GetString(packet, position + 4, argLen));

                // size + lenght + endChar
                position += (4 + argLen + 1);
            }

            return ls.ToArray();
        }

        private static string GenerateHash(string pValue, string pSalt)
        {
            byte[] salt = Enumerable.Range(0, pSalt.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(pSalt.Substring(x, 2), 16)).ToArray();
            byte[] value = System.Text.Encoding.Default.GetBytes(pValue);
            byte[] data = new byte[salt.Length + value.Length];
            salt.CopyTo(data, 0);
            value.CopyTo(data, salt.Length);
            data = System.Security.Cryptography.MD5.Create().ComputeHash(data);
            return String.Concat(data.Select(b => b.ToString("X2")).ToArray());
        }
    }
}
