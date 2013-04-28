#region License
// KeyMaster: Program.cs
//
// Author:
//   Kelvin Miles (kelvinm1@aol.com)
//
// Copyright (C) 2013 Kelvin Miles
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion License
#region Using Directives
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
#endregion Using Directives

namespace KeyMaster
{
    /// <summary>
    /// This program is used to generate keys and encrypt/decrypt text using AES encryption.
    /// </summary>
    class Program
    {
        #region Microsoft VC++ Runtime
        /// <summary>
        /// P/Invoke built-in file renaming function from Microsoft NT CRT library
        /// </summary>
        /// <param name="oldPath"></param>
        /// <param name="newPath"></param>
        /// <returns></returns>
        [DllImport("msvcrt", CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
        internal static extern int rename(
                [MarshalAs(UnmanagedType.LPStr)]
            string oldPath,
                [MarshalAs(UnmanagedType.LPStr)]
            string newPath);
        #endregion Microsoft VC++ Runtime

        #region Constants & Static Members
        /// <summary>
        /// Key size (in bytes)
        /// </summary>
        const int FIXED_KEY_SIZE = 256;

        /// <summary>
        /// Use 128 bit encryption
        /// </summary>
        const int FIXED_BLOCK_SIZE = 128;

        /// <summary>
        /// Use buffer size of 16 bytes for 128 bit encryption
        /// </summary>
        const int BUFFER_SIZE = FIXED_BLOCK_SIZE / 8;

        /// <summary>
        /// Usage text for help screen.
        /// </summary>
        static readonly string UsageText = string.Format(
            "keymaster.exe [option]\nOptions:\n\t{0}\n\t{1}\n\t{2}\n\t{3}\n\t{4}\n",
            "/v                        Displays the current version of KeyMaster",
            "/c                        Creates a new AES encrypted key",
            "/d  <cipher> <key>        Decrypts the cipher with specified key",
            "/e  <text> <key>          Encrypts the plain text with specified key",
            "/df <file>                Decrypts the specified file",
            "/ef <file>                Encrypts the specified file");

        /// <summary>
        /// Random set of bytes used as additional input to hash the password for encrypting/decrypting file
        /// </summary>
        static readonly byte[] Salt = new byte[] { 
            0xC4, 0x57, 0xF6, 0xAC, 0x53, 0x77, 0xB5, 0xCF, 0xE6, 
            0xC1, 0x4A, 0x56, 0x69, 0x11, 0xB7, 0xA1, 0x61, 0x39,
            0x4E, 0xEA, 0xF0, 0x2B, 0x64, 0x8D, 0x47, 0x83, 0x53, 
            0xB7, 0x63, 0xDA, 0x6B, 0x59
        };
        #endregion Constants & Static Members

        #region Main Entry Point
        /// <summary>
        /// Main application entry point
        /// </summary>
        /// <param name="args">Command line arguments</param>
        static void Main(string[] args)
        {
            // Exit code: default is 0 (successful)
            int retCode = 0;

            try
            {
                #region Parse command line arguments
                if (args.Length == 1 && args[0].Equals("?"))
                {
                    // Print Help
                    Console.Error.WriteLine("Usage: \n\t{0}", UsageText);
                }
                else if (args.Length == 1 && args[0].Equals("/v"))
                {
                    // Print version info
                    string version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version.ToString();
                    Console.WriteLine(version);
                }
                else if (args.Length == 1 && args[0].ToLower().Equals("/c"))
                {
                    // Generates a random AES key.
                    // Print hexadecimal string without dashes.
                    byte[] key = CreateKey();
                    string hexidecimal = BitConverter.ToString(key).Replace("-", "");
                    Console.WriteLine(hexidecimal);
                }
                else if (args.Length == 3 && args[0].ToLower().Equals("/e") &&
                    !string.IsNullOrEmpty(args[1]) && !string.IsNullOrEmpty(args[2]))
                {
                    // Encrypt text with specified AES key.
                    string encodedText = Encrypt(args[1], StringToBytes(args[2]));
                    Console.WriteLine(encodedText);
                }
                else if (args.Length == 2 && args[0].ToLower().Equals("/ef") && !string.IsNullOrEmpty(args[1]))
                {
                    // Encrypt file...
                    if (!File.Exists(args[1]))
                        throw new FileNotFoundException("file not found.");

                    string tmpFile = args[1] + ".tmp";

                    Console.WriteLine("Please enter a password:");
                    string pwd = ReadMaskInput();
                    EncryptFile(args[1], tmpFile, pwd);
                    File.Delete(args[1]);
                    rename(tmpFile, args[1]);

                }
                else if (args.Length == 3 && args[0].ToLower().Equals("/d") &&
                    !string.IsNullOrEmpty(args[1]) && !string.IsNullOrEmpty(args[2]))
                {
                    // Decrypts cipher with AES key provided.
                    string decodedText = Decrypt(args[1], StringToBytes(args[2]));
                    Console.WriteLine(decodedText);
                }
                else if (args.Length == 2 && args[0].ToLower().Equals("/df") && !string.IsNullOrEmpty(args[1]))
                {
                    // Decrypt file...
                    if (!File.Exists(args[1]))
                        throw new FileNotFoundException("file not found.");

                    string tmpFile = args[1] + ".tmp";

                    Console.WriteLine("Please enter a password:");
                    string pwd = ReadMaskInput();
                    DecryptFile(args[1], tmpFile, pwd);
                    File.Delete(args[1]);
                    rename(tmpFile, args[1]);
                }
                else
                {
                    // Invalid command line arguments.
                    Console.Error.WriteLine("Invalid or missing command line arguments. Please try again.");
                    Console.Error.WriteLine("Usage: \n\t{0}", UsageText);
                    retCode = 1;
                }
                #endregion Parse command line arguments
            }
            catch (Exception ex)
            {
                // Print exception message to error output stream.
                Console.Error.WriteLine(ex.Message);
#if DEBUG
                // Print call stack if in DEBUG only.
                Console.Error.WriteLine("Call Stack: {0}", ex.StackTrace);
#endif
                retCode = 1;
            }

            Environment.Exit(retCode); // Exit program
        }
        #endregion Main Entry Point

        #region Extension Methods
        /// <summary>
        /// Converts hexadecimal string to an array of bytes.
        /// </summary>
        /// <param name="hexadecimal">encryption key in base 16 format</param>
        /// <returns>byte array representing the encryption key</returns>
        static byte[] StringToBytes(string hexadecimal)
        {
            // Remove dashes ('-') from hexadecimal string.
            // Used for cases where the string passed contains dashes to separate each hexadecimal value. 
            hexadecimal = hexadecimal.Replace("-", "");

            int numberChars = hexadecimal.Length / 2;
            byte[] bytes = new byte[numberChars];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hexadecimal.Substring(i, 2), 16);
            return bytes;
        }

        /// <summary>
        /// Generates a new AES Encrypted key
        /// </summary>
        /// <returns>byte array representing the encryption key</returns>
        static byte[] CreateKey()
        {
            byte[] key = null;
            // Declare the Aes object 
            // used to encrypt the data.
            Aes aesAlg = null;
            try
            {
                aesAlg = Aes.Create();
                key = aesAlg.Key;
            }
            finally
            {
                // Clear the Aes object. 
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            //return ASCIIEncoding.ASCII.GetString(key);
            return key;
        }

        /// <summary>
        /// Encrypts the supplied text using the encryption key specified
        /// </summary>
        /// <param name="plainText">text data</param>
        /// <param name="key">encryption key</param>
        /// <returns>encrypted data</returns>
        static string Encrypt(string plainText, byte[] key)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            string result = string.Empty;
            try
            {
                // encrypt the data into a string using the AES encryption level.
                result = EncryptToBase64String(plainText, GetKey(key), GetIV(key));
            }
            catch (Exception ex)
            {
                throw new System.IO.InvalidDataException("Unable to encrypt data", ex);
            }

            return result;

        }

        /// <summary>
        /// Decrypts the supplied cipher data using the encryption key specified
        /// </summary>
        /// <param name="cipherText">cipher data</param>
        /// <param name="key">encryption key</param>
        /// <returns>original (decrypted) data</returns>
        static string Decrypt(string cipherText, byte[] key)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            string result = string.Empty;

            try
            {
                // decrypt the data into a string using the AES encryption level.
                result = DecryptFromBase64String(cipherText, GetKey(key), GetIV(key));
            }
            catch (System.Exception ex)
            {
                throw new System.IO.InvalidDataException("Unable to decrypt data", ex);
            }

            return result;
        }

        /// <summary>
        /// Encrypt text value to Base 64 using key and iv
        /// </summary>
        /// <param name="value">data to encrypt</param>
        /// <param name="key">encryption key</param>
        /// <param name="iv">initialization vector</param>
        /// <returns>encrypted data in base 64 format</returns>
        static string EncryptToBase64String(string value, byte[] key, byte[] iv)
        {
            AesManaged cryptoProvider = new AesManaged() { KeySize = FIXED_KEY_SIZE, BlockSize = FIXED_BLOCK_SIZE };

            // Note: we are using BASE64 encoding so that the encrypted data is still string-based
            // and can be stored in a text file
            byte[] toEncryptArray = UTF8Encoding.UTF8.GetBytes(value);

            //cryptoProvider.BlockSize = FIXED_BLOCK_SIZE;
            cryptoProvider.IV = iv;
            cryptoProvider.Key = key;
            // use a cipher mode that uses a prior block's data as part of the cipher next block's encryption.
            // this causes substantially similar strings to look different when encoded.
            cryptoProvider.Mode = CipherMode.CBC;
            cryptoProvider.Padding = PaddingMode.ISO10126;
            ICryptoTransform cryptoTransform = cryptoProvider.CreateEncryptor();

            byte[] resultArray = cryptoTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);
        }

        /// <summary>
        /// Decrypt cipher value from Base 64 using key and iv
        /// </summary>
        /// <param name="value">base 64 encrypted data to decrypt</param>
        /// <param name="key">encryption key</param>
        /// <param name="iv">initialization vector</param>
        /// <returns>original (decrypted) data</returns>
        static string DecryptFromBase64String(string value, byte[] key, byte[] iv)
        {
            AesManaged cryptoProvider = new AesManaged() { KeySize = FIXED_KEY_SIZE, BlockSize = FIXED_BLOCK_SIZE };

            // Note: we are using BASE64 encoding so that the encrypted data is still string-based
            // and can be stored in a text file
            byte[] toDecryptArray = Convert.FromBase64String(value);

            //cryptoProvider.BlockSize = FIXED_BLOCK_SIZE;
            cryptoProvider.IV = iv;
            cryptoProvider.Key = key;
            // use a cipher mode that uses a prior block's data as part of the cipher next block's encryption.
            // this causes substantially similar strings to look different when encoded.
            cryptoProvider.Mode = CipherMode.CBC;
            cryptoProvider.Padding = PaddingMode.ISO10126;
            ICryptoTransform cryptoTransform = cryptoProvider.CreateDecryptor();

            byte[] resultDecryptArray = cryptoTransform.TransformFinalBlock(toDecryptArray, 0, toDecryptArray.Length);

            return UTF8Encoding.UTF8.GetString(resultDecryptArray);
        }

        /// <summary>
        /// The key that will be used to encrypt the data
        /// <param name="key">32-bit master key used to decrypt/encrypt cipher</param>
        /// <returns>byte array representing key</returns>
        /// </summary>
        static byte[] GetKey(byte[] key)
        {
            SHA256Managed hash = new SHA256Managed();
            byte[] retVal = hash.ComputeHash(key);
            return retVal;
        }

        /// <summary>
        /// The key that will be used to encode the CBC blocks
        /// <param name="key">16-bit master key used to decrypt/encrypt cipher</param>
        /// <returns>byte array representing iv</returns>
        /// </summary>
        static byte[] GetIV(byte[] key)
        {
            SHA256Managed hash = new SHA256Managed();
            byte[] retVal = hash.ComputeHash(key, 0, BUFFER_SIZE);
            Array.Resize(ref retVal, BUFFER_SIZE);
            return retVal;
        }
        
        /// <summary>
        /// Encrypts data in specified file using a password provided by user
        /// </summary>
        /// <param name="inputPath">original file</param>
        /// <param name="outputPath">encrypted file</param>
        /// <param name="password">user password</param>
        static void EncryptFile(string inputPath, string outputPath, string password)
        {
            try
            {
                AesManaged algorithm = new AesManaged() { KeySize = FIXED_KEY_SIZE, BlockSize = FIXED_BLOCK_SIZE };
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, Salt);

                algorithm.Key = key.GetBytes(algorithm.KeySize / 8);
                algorithm.IV = key.GetBytes(algorithm.BlockSize / 8);

                using (FileStream input = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
                {
                    using (FileStream output = new FileStream(outputPath, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        using (CryptoStream encryptedStream = new CryptoStream(output, algorithm.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            CopyStream(input, encryptedStream);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        /// <summary>
        /// Decrypts data in specified file with the password provided by user
        /// </summary>
        /// <param name="inputPath">encrypted file</param>
        /// <param name="outputPath">decrypted file</param>
        /// <param name="password">user password</param>
        static void DecryptFile(string inputPath, string outputPath, string password)
        {
            try
            {
                AesManaged algorithm = new AesManaged() { KeySize = FIXED_KEY_SIZE, BlockSize = FIXED_BLOCK_SIZE };
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, Salt);

                algorithm.Key = key.GetBytes(algorithm.KeySize / 8);
                algorithm.IV = key.GetBytes(algorithm.BlockSize / 8);

                using (FileStream input = new FileStream(inputPath, FileMode.Open, FileAccess.Read))
                {
                    using (FileStream output = new FileStream(outputPath, FileMode.OpenOrCreate, FileAccess.Write))
                    {
                        using (CryptoStream decryptedStream = new CryptoStream(output, algorithm.CreateDecryptor(), CryptoStreamMode.Write))
                        {
                            CopyStream(input, decryptedStream);
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                throw new InvalidDataException("Please supply a valid password");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        /// <summary>
        /// Copies data from source file to destination file
        /// </summary>
        /// <param name="input">source file</param>
        /// <param name="output">destination file</param>
        static void CopyStream(Stream input, Stream output)
        {
            using (output)
            {
                using (input)
                {
                    byte[] buffer = new byte[BUFFER_SIZE];
                    int read;
                    while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        output.Write(buffer, 0, read);
                    }
                }
            }
        }
        
        /// <summary>
        /// Masks the console input
        /// </summary>
        /// <returns>the masked text</returns>
        static string ReadMaskInput()
        {
            string password = "";
            ConsoleKeyInfo info = Console.ReadKey(true);
            while (info.Key != ConsoleKey.Enter)
            {
                if (info.Key != ConsoleKey.Backspace)
                {
                    Console.Write("*");
                    password += info.KeyChar;
                }
                else if (info.Key == ConsoleKey.Backspace)
                {
                    if (!string.IsNullOrEmpty(password))
                    {
                        // remove one character from the list of password characters
                        password = password.Substring(0, password.Length - 1);
                        // get the location of the cursor
                        int pos = Console.CursorLeft;
                        // move the cursor to the left by one character
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                        // replace it with space
                        Console.Write(" ");
                        // move the cursor to the left by one character again
                        Console.SetCursorPosition(pos - 1, Console.CursorTop);
                    }
                }
                info = Console.ReadKey(true);
            }

            // add a new line because user pressed enter at the end of their password
            Console.WriteLine();
            return password;
        }
        #endregion Extension Methods
    }
}
