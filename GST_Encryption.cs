using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Configuration;

namespace ApnaPay
{
    /// <summary>
    /// 
    /// </summary>
    public class GST_Encryption
    {
        public string generateAppKey()
        {
            string publicKeyUrl1 = "~/GST_Certificate/GSTN_G2A_SANDBOX_UAT_public.cer";
            X509Certificate2 cert = new X509Certificate2(System.Web.Hosting.HostingEnvironment.MapPath(publicKeyUrl1));
            RSACryptoServiceProvider rsaservice = (RSACryptoServiceProvider)cert.PublicKey.Key;
            byte[] plaintext = Encoding.UTF8.GetBytes(ConfigurationManager.AppSettings["OcpApimSubscriptionKey"].ToString());
            byte[] ciphertext = rsaservice.Encrypt(plaintext, false);
            return Convert.ToBase64String(ciphertext);
        }

        public string HMAC_Encrypt(string message, byte[] keyByte)
        {
            var encoding = new System.Text.ASCIIEncoding();
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hashmessage);
            }
        }


        public string Encrypt(string jsonPayload, byte[] DecyptesSekkeyBytes)
        {
            byte[] dataToEncrypt = UTF8Encoding.UTF8.GetBytes(jsonPayload);

            AesManaged tdes = new AesManaged();

            tdes.KeySize = 256;
            tdes.BlockSize = 128;
            tdes.Key = DecyptesSekkeyBytes;// Encoding.ASCII.GetBytes(key);
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform crypt = tdes.CreateEncryptor();
            byte[] cipher = crypt.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
            tdes.Clear();
            return Convert.ToBase64String(cipher, 0, cipher.Length);
        }



        public string Encrypt(string otp, string appkey)
        {
            byte[] dataToEncrypt = UTF8Encoding.UTF8.GetBytes(otp);

            AesManaged tdes = new AesManaged();

            tdes.KeySize = 256;
            tdes.BlockSize = 128;
            tdes.Key = Encoding.UTF8.GetBytes(appkey);
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform crypt = tdes.CreateEncryptor();
            byte[] cipher = crypt.TransformFinalBlock(dataToEncrypt, 0, dataToEncrypt.Length);
            tdes.Clear();
            return Convert.ToBase64String(cipher, 0, cipher.Length);

        }        

        public byte[] decrypt(string SekText, string AppKey)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(SekText);

            AesManaged tdes = new AesManaged();
            tdes.KeySize = 256;
            tdes.BlockSize = 128;
            tdes.Key = Encoding.UTF8.GetBytes(AppKey);
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform decrypt = tdes.CreateDecryptor();
            byte[] deCipher = decrypt.TransformFinalBlock(dataToDecrypt, 0, dataToDecrypt.Length);
            tdes.Clear();

            return deCipher;
        }

        public byte[] Decrypt(string encryptedText, byte[] keys)
        {
            byte[] dataToDecrypt = Convert.FromBase64String(encryptedText);
            AesManaged tdes = new AesManaged();
            tdes.KeySize = 256;
            tdes.BlockSize = 128;
            tdes.Key = keys;
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.PKCS7;

            ICryptoTransform decrypt = tdes.CreateDecryptor();
            byte[] deCipher = decrypt.TransformFinalBlock(dataToDecrypt, 0, dataToDecrypt.Length);
            tdes.Clear();

            return deCipher;
        }
    }
}
