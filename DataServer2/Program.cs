using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DataServer2
{
    class Program
    {
        const int PORT = 9002;
        const string DATA = "Server2_Data: [Pressure=1013hPa, Wind=15km/h]";

        static void Main(string[] args)
        {
            Console.WriteLine($"[SERVER 2] Starting on port {PORT}");
            Console.WriteLine($"[SERVER 2] Will return: {DATA}");

            TcpListener listener = new TcpListener(IPAddress.Loopback, PORT);
            listener.Start();
            Console.WriteLine($"[SERVER 2] Listening on 127.0.0.1:{PORT}");

            while (true)
            {
                try
                {
                    TcpClient client = listener.AcceptTcpClient();
                    Console.WriteLine($"[SERVER 2] Client connected from {client.Client.RemoteEndPoint}");

                    using (NetworkStream stream = client.GetStream())
                    {
                        // Read request (though we ignore it)
                        byte[] buffer = new byte[1024];
                        int bytesRead = stream.Read(buffer, 0, buffer.Length);
                        string request = Encoding.UTF8.GetString(buffer, 0, bytesRead).Trim();
                        Console.WriteLine($"[SERVER 2] Request: {request}");

                        // Send response
                        byte[] response = Encoding.UTF8.GetBytes(DATA);
                        stream.Write(response, 0, response.Length);
                        Console.WriteLine($"[SERVER 2] Sent {response.Length} bytes");
                    }

                    client.Close();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SERVER 2] Error: {ex.Message}");
                }
            }
        }
    }
}
