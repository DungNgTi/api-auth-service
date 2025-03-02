using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Security.Cryptography;
using System.Text;

namespace api_auth_service.Service
{
    public class DatabaseFetchService
    {
        static string FetchFromDatabase(string encrypted, string key) =>
            Encoding.UTF8.GetString(Aes.Create().CreateDecryptor(Encoding.UTF8.GetBytes(key), new byte[16])
                .TransformFinalBlock(Convert.FromBase64String(encrypted), 0, Convert.FromBase64String(encrypted).Length));

        public static string FetchContentUser() => Encoding.UTF8.GetString(Aes.Create().CreateDecryptor(Encoding.UTF8.GetBytes("0000000000000000"), new byte[16])
                .TransformFinalBlock(Convert.FromBase64String("Y94+WuTkBaaphJTps8IvmdB2IazYjKRnMkm3rFhUR4iArt3MFxRfr9UKMUdtF6w3/Gmykqm/PdH5MwO1UaJYVWKsBMLnCwjquJnoZZYIhIc="), 0,
            Convert.FromBase64String("Y94+WuTkBaaphJTps8IvmdB2IazYjKRnMkm3rFhUR4iArt3MFxRfr9UKMUdtF6w3/Gmykqm/PdH5MwO1UaJYVWKsBMLnCwjquJnoZZYIhIc=").Length));

        public static string FetchSecret() => Encoding.UTF8.GetString(Aes.Create().CreateDecryptor(Encoding.UTF8.GetBytes("1111111111111111"), new byte[16])
                .TransformFinalBlock(Convert.FromBase64String("afKSUhIxf/0VZsGl8bq1s2cUJ6IKnl9pn6WnlYpQv2o54228Q+0Y6CPBLXjg+m6/"), 0,
            Convert.FromBase64String("afKSUhIxf/0VZsGl8bq1s2cUJ6IKnl9pn6WnlYpQv2o54228Q+0Y6CPBLXjg+m6/").Length));
    }
}
