using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Newtonsoft.Json;
using System.Diagnostics;

public class vauth : IDisposable
{
    private HttpClient _httpClient = new HttpClient();
    private string _apiBaseUrl = "https://velvetauth.com/api/1.1/";
    private string _appId;
    private string _secret;
    private string _version;
    public string _sessionId { get; private set; }

    public string Username { get; private set; }
    public string Email { get; private set; }
    public int user_level { get; private set; }
    public DateTime? ExpiryDate { get; private set; }
    public string _hwid = WindowsIdentity.GetCurrent().User.Value;

    public vauth(string appId, string secret, string version)
    {
        _appId = EncryptString(secret, appId);
        _secret = secret;
        _version = EncryptString(secret, version);
    }

    public HttpResponseMessage Post(string endpoint, object data)
    {
        var jsonData = JsonConvert.SerializeObject(data);
        var content = new StringContent(jsonData, Encoding.UTF8, "application/json");

        Console.WriteLine($"Request URL: {_apiBaseUrl + endpoint}");
        Console.WriteLine($"Request Data: {jsonData}");

        HttpResponseMessage response = _httpClient.PostAsync(_apiBaseUrl + endpoint, content).Result;
        Console.WriteLine($"Response Status Code: {response.StatusCode}");

        if (response != null && response.IsSuccessStatusCode)
        {
            return response;
        }
        else
        {
            return null;
        }
    }

    public bool Initialize()
    {
        var requestData = new
        {
            type = "init",
            app_id = _appId,
            secret = _secret,
            version = _version
        };

        var response = Post("index.php", requestData);
        if (response != null && response.IsSuccessStatusCode)
        {
            var responseContent = response.Content.ReadAsStringAsync().Result;
            Console.WriteLine($"Raw Response Content for Initialization: {responseContent}");

            try
            {
                dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);

                if (jsonResponse.status == "true")
                {
                    _sessionId = jsonResponse.session_id;
                    Console.WriteLine("Initialization Successful.");
                    Console.WriteLine(jsonResponse);
                    return true;
                }
                else if (jsonResponse.error != null)
                {
                    Console.WriteLine("Initialization failed: " + jsonResponse.error);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("JSON Parsing error during initialization: " + ex.Message);
            }
        }
        else
        {
            Console.WriteLine("Initialization failed: HTTP " + (response?.StatusCode.ToString() ?? "No response"));
        }
        return false;
    }

    private void DownloadNewVersion(string url)
    {
        try
        {
            Console.WriteLine("Attempting to download new version from: " + url);
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
            Console.WriteLine("Download process started successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error starting download process: " + ex.Message);
        }
    }

    public bool keyless_register(string username, string password, string email)
    {
        var encryptedUsername = EncryptString(_secret, username);
        var encryptedPassword = EncryptString(_secret, password);
        var encryptedEmail = EncryptString(_secret, email);
        var encryptedHwid = EncryptString(_secret, _hwid);

        var requestData = new
        {
            type = "keyless",
            username = encryptedUsername,
            app_id = _appId,
            password = encryptedPassword,
            secret = _secret,
            email = encryptedEmail,
            hwid = encryptedHwid
        };

        var response = Post("index.php", requestData);
        var responseContent = response.Content.ReadAsStringAsync().Result;
        Console.WriteLine($"Raw Response Content for Registration: {responseContent}");

        try
        {
            dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
            if (jsonResponse != null)
            {
                if (jsonResponse.message == "Registration successful")
                {
                    Console.WriteLine("Registration successful.");
                    return true;
                }
                else if (jsonResponse.message == "Username is already used")
                {
                    Console.WriteLine("Registration failed: Username is already used.");
                }
                else if (jsonResponse.message == "Email is already used")
                {
                    Console.WriteLine("Registration failed: Email is already used.");
                }
                else
                {
                    Console.WriteLine("Registration failed: " + (jsonResponse.message ?? "Unknown error"));
                }
            }
            else
            {
                Console.WriteLine("No valid response received from API.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("JSON Parsing error during registration: " + ex.Message);
        }
        return false;
    }
    public bool RegisterLicense(string username, string password, string licenseKey, string email)
    {
        var encryptedUsername = EncryptString(_secret, username);
        var encryptedPassword = EncryptString(_secret, password);
        var encryptedLicenseKey = EncryptString(_secret, licenseKey);
        var encryptedEmail = EncryptString(_secret, email);
        var encryptedHwid = EncryptString(_secret, _hwid);
        var encryptedSID = EncryptString(_secret, _sessionId);

        var requestData = new
        {
            type = "register",
            username = encryptedUsername,
            app_id = _appId,
            password = encryptedPassword,
            secret = _secret,
            license_key = encryptedLicenseKey,
            email = encryptedEmail,
            hwid = encryptedHwid,
            session_id = encryptedSID
        };

        var response = Post("index.php", requestData);
        var responseContent = response.Content.ReadAsStringAsync().Result;
        Console.WriteLine($"Raw Response Content for Registration: {responseContent}");


        try
        {
            dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
            if (jsonResponse != null)
            {
                if (jsonResponse.message == "Registration successful")
                {
                    Username = username;
                    Email = jsonResponse.data.email;
                    ExpiryDate = jsonResponse.data.expiry_date != null ? jsonResponse.data.expiry_date : (DateTime?)null;
                    user_level = jsonResponse.data.user_level;
                    Console.WriteLine("Registration successful.");
                    return true;
                }
                else
                {
                    Console.WriteLine("Registration failed: " + jsonResponse.message);
                }
            }
            else
            {
                Console.WriteLine("No valid response received from API.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("JSON Parsing error during registration: " + ex.Message);
        }
        return false;
    }


    public bool Logout()
    {
        var encryptedSessionId = EncryptString(_secret, _sessionId);
        var encryptedAppId = _appId;
        var encryptedUsername = EncryptString(_secret, Username);

        var requestData = new
        {
            type = "logout",
            session_id = encryptedSessionId,
            app_id = encryptedAppId,
            secret = _secret,
            username = encryptedUsername
        };

        var response = Post("index.php", requestData);
        var responseContent = response.Content.ReadAsStringAsync().Result;
        Console.WriteLine($"Raw Response Content for Logout: {responseContent}");

        if (response.StatusCode == System.Net.HttpStatusCode.BadRequest)
        {
            Console.WriteLine("BadRequest Error: Check if all fields are correctly encrypted and match server expectations.");
            return false;
        }

        try
        {
            dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
            if (jsonResponse != null && jsonResponse.message == "Logout successful")
            {
                Console.WriteLine("Logout successful.");
                return true;
            }
            else
            {
                Console.WriteLine("Logout failed: " + (jsonResponse?.message ?? "Unknown error"));
                return false;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("JSON Parsing error during logout: " + ex.Message);
            return false;
        }
    }

    public bool LoginUser(string username, string password)
    {
        var encryptedUsername = EncryptString(_secret, username);
        var encryptedPassword = EncryptString(_secret, password);
        var encryptedHwid = EncryptString(_secret, _hwid);
        //var encryptedAppId = _appId;
        var encryptedSessionId = EncryptString(_secret, _sessionId);

        var requestData = new
        {
            type = "login",
            username = encryptedUsername,
            password = encryptedPassword,
            hwid = encryptedHwid,
            app_id = _appId,
            secret = _secret,
            session_id = encryptedSessionId // Include session ID here
        };

        var response = Post("index.php", requestData);
        var responseContent = response.Content.ReadAsStringAsync().Result;
        Console.WriteLine($"Raw Response Content for Login: {responseContent}");

        try
        {
            dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
            if (jsonResponse != null)
            {
                if (jsonResponse.message == "Login successful")
                {
                    Username = username;
                    Email = jsonResponse.data.email;
                    ExpiryDate = jsonResponse.data.expiry_date != null ? jsonResponse.data.expiry_date : (DateTime?)null;
                    user_level = jsonResponse.data.user_level;
                    Console.WriteLine("Login successful.");
                    return true;
                }
                else
                {
                    Console.WriteLine("Login failed: " + jsonResponse.error);
                }
            }
            else
            {
                Console.WriteLine("No valid response received from API.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("JSON Parsing error during login: " + ex.Message);
        }
        return false;
    }

    public bool ExtendLicenseExpiry(string username, string licenseKey)
    {
        var encryptedUsername = EncryptString(_secret, username);
        var encryptedLicenseKey = EncryptString(_secret, licenseKey);
        var encryptedAppId = _appId;

        var requestData = new
        {
            type = "extend_expiry",
            username = encryptedUsername,
            license_key = encryptedLicenseKey,
            app_id = encryptedAppId,
            secret = _secret
        };

        var response = Post("index.php", requestData);
        var responseContent = response.Content.ReadAsStringAsync().Result;
        Console.WriteLine($"Raw Response Content for License Extension: {responseContent}");

        try
        {
            dynamic jsonResponse = JsonConvert.DeserializeObject(responseContent);
            if (jsonResponse != null)
            {
                if (jsonResponse.message == "License expiry extended successfully")
                {
                    ExpiryDate = jsonResponse.data.new_expiry_date;
                    Console.WriteLine("License expiry extended successfully.");
                    return true;
                }
                else
                {
                    Console.WriteLine("License extension failed: " + jsonResponse.message);
                }
            }
            else
            {
                Console.WriteLine("No valid response received from API.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("JSON Parsing error during license extension: " + ex.Message);
        }
        return false;
    }



    public static string EncryptString(string keyHex, string plainText)
    {
        byte[] key = StringToByteArray(keyHex);
        byte[] iv;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.GenerateIV();
            iv = aesAlg.IV;
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }
                byte[] encryptedContent = msEncrypt.ToArray();
                byte[] result = new byte[iv.Length + encryptedContent.Length];
                Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length);
                return Convert.ToBase64String(result);
            }
        }
    }

    public static byte[] StringToByteArray(string hex)
    {
        int NumberChars = hex.Length;
        byte[] bytes = new byte[NumberChars / 2];
        for (int i = 0; i < NumberChars; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }

    public static string DecryptString(string keyHex, string cipherText)
    {
        byte[] key = StringToByteArray(keyHex);
        byte[] fullCipher = Convert.FromBase64String(cipherText);
        byte[] iv = new byte[16]; // AES block size is 16 bytes
        byte[] cipher = new byte[fullCipher.Length - iv.Length];

        Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
        Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.IV = iv; // Extracted IV from the encrypted content
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipher))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }
}
