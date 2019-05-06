using System;

namespace Token
{
    public static class TokenValidator
    {
        private static string _alg => "HmacSHA512";
        private static string _salt => "rz8LuOtFBXphj9WQfvFh";

        public static bool IsTokenValid(string token, long expirationMinutes, string identifier, string password)
        {
            bool result = false;

            try
            {
                //split key into multiple parts for validation
                string[] key_parts = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(token)).Split(new char[] { ':' });

                //key should always result in 3 parameters after split
                if (key_parts.Length == 3)
                {
                    //get hash parts
                    string param_hash = key_parts[0];

                    //convert ticks value into datetime
                    DateTime timeStamp = new DateTime(long.Parse(key_parts[2]));

                    //ensure timestamp in request is still valid
                    bool expired = Math.Abs((DateTime.Now - timeStamp).TotalMinutes) > expirationMinutes;
                    if (!expired)
                    {
                        if (string.Compare(key_parts[1], identifier) == 0)
                        {
                            //compare the computed hash with hash passed by application
                            result = (token == GenerateToken(identifier, password, long.Parse(key_parts[2])));
                        }
                    }
                }
            }
            catch (Exception)
            {
                //
            }

            return result;
        }

        public static string GenerateToken(string identifier, string password, long ticks)
        {
            //create placeholder parameters to complete the hash string
            string hashLeft, hashRight = string.Empty;

            //using hash-based message authentication, generate hash key
            using (System.Security.Cryptography.HMAC hmac = System.Security.Cryptography.HMAC.Create(_alg))
            {
                //create key to use in hash algorithm
                hmac.Key = System.Text.Encoding.UTF8.GetBytes(GetHashedPassword(password));
                //compute hash value for byte array
                hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(string.Join(":", new string[] { identifier, ticks.ToString() })));
                //convert left hash parameter to base64 string
                hashLeft = Convert.ToBase64String(hmac.Hash);
                //create right hash parameter from identifier and datetime tick value
                hashRight = string.Join(":", new string[] { identifier, ticks.ToString() });
            }

            //return base64 string based on hash parameters created in previous stemp
            return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(string.Join(":", new string[] { hashLeft, hashRight })));
        }

        public static string GetHashedPassword(string password)
        {
            //using hash-based message authentication, generate hash value
            using (System.Security.Cryptography.HMAC hmac = System.Security.Cryptography.HMAC.Create(_alg))
            {
                //generate key to be used in hash algorithm
                hmac.Key = System.Text.Encoding.UTF8.GetBytes(_salt);
                //compute hash value for byte array
                hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(string.Join(":", new string[] { password, _salt })));
                //return base64 string from HMAC hash value
                return Convert.ToBase64String(hmac.Hash);
            }
        }
    }
}