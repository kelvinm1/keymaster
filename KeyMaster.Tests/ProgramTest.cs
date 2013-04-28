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
using KeyMaster;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
#endregion Using Directives

namespace KeyMaster.Tests
{
    
    
    /// <summary>
    ///This is a test class for ProgramTest and is intended
    ///to contain all ProgramTest Unit Tests
    ///</summary>
    [TestClass()]
    public class ProgramTest
    {


        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        // 
        //You can use the following additional attributes as you write your tests:
        //
        //Use ClassInitialize to run code before running the first test in the class
        //[ClassInitialize()]
        //public static void MyClassInitialize(TestContext testContext)
        //{
        //}
        //
        //Use ClassCleanup to run code after all tests in a class have run
        //[ClassCleanup()]
        //public static void MyClassCleanup()
        //{
        //}
        //
        //Use TestInitialize to run code before running each test
        //[TestInitialize()]
        //public void MyTestInitialize()
        //{
        //}
        //
        //Use TestCleanup to run code after each test has run
        //[TestCleanup()]
        //public void MyTestCleanup()
        //{
        //}
        //
        #endregion


        /// <summary>
        ///A test for CreateKey
        ///</summary>
        [TestMethod()]
        [DeploymentItem("KeyMaster.exe")]
        public void CreateKeyTest()
        {
            byte[] notExpected = null; // TODO: Initialize to an appropriate value
            byte[] actual = Program_Accessor.CreateKey();
            Assert.AreNotEqual(notExpected, actual);
        }

        /// <summary>
        ///A test for Decrypt
        ///</summary>
        [TestMethod()]
        [DeploymentItem("KeyMaster.exe")]
        public void DecryptTest()
        {
            string cipherText = "Y2cJ7NCoRMtrVsNXE+4o5g==";
            byte[] key = Program_Accessor.StringToBytes("AE6D75E17DB657D0851BCDFC9065BABF8205AC59CF50E174D6B5B8E468ADB2E8");
            string expected = "Hello World";
            string actual = Program_Accessor.Decrypt(cipherText, key);
            Assert.AreEqual(expected, actual);
            //Assert.Inconclusive("Verify the correctness of this test method.");
        }

        /// <summary>
        ///A test for Encrypt
        ///</summary>
        [TestMethod()]
        [DeploymentItem("KeyMaster.exe")]
        public void EncryptTest()
        {
            string plainText = "Hello World";
            byte[] key = Program_Accessor.StringToBytes("AE6D75E17DB657D0851BCDFC9065BABF8205AC59CF50E174D6B5B8E468ADB2E8");
            string expected;
            string actual;
            actual = Program_Accessor.Encrypt(plainText, key);
            expected = Program_Accessor.Decrypt(actual, key);
            Assert.AreEqual(expected, plainText);
            //Assert.Inconclusive("Verify the correctness of this test method.");
        }

        /// <summary>
        ///A test for EncryptFile
        ///</summary>
        [TestMethod()]
        [DeploymentItem("KeyMaster.exe")]
        public void EncryptAndDecryptFileTest()
        {
            string inputPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString() + ".txt"); ;
            string outputPath = inputPath + ".tmp";
            string expected = "This is a test of encrypt file.";
            string password = "password123";

            // Write some text to file...
            using (StreamWriter outfile = new StreamWriter(inputPath))
            {
                outfile.Write(expected);
            }

            // Encrypt file...
            Program_Accessor.EncryptFile(inputPath, outputPath, password);
            File.Delete(inputPath);
            Program_Accessor.rename(outputPath, inputPath);
            //Assert.Inconclusive("A method that does not return a value cannot be verified.");

            // Now, lets decrypt the file we just encrypted.
            Program_Accessor.DecryptFile(inputPath, outputPath, password);
            File.Delete(inputPath);
            Program_Accessor.rename(outputPath, inputPath);

            string actual = string.Empty;
            using (StreamReader sr = new StreamReader(inputPath))
            {
                actual = sr.ReadToEnd();
            }
            File.Delete(inputPath);

            // Compare actual vs. expected value...
            Assert.AreEqual(expected, actual);
        }

        /// <summary>
        ///A test for EncryptToBase64String
        ///</summary>
        [TestMethod()]
        [DeploymentItem("KeyMaster.exe")]
        public void EncryptToBase64StringTest()
        {
            string value = "Hello World";
            byte[] masterKey = Program_Accessor.StringToBytes("AE6D75E17DB657D0851BCDFC9065BABF8205AC59CF50E174D6B5B8E468ADB2E8");
            byte[] key = Program_Accessor.GetKey(masterKey);
            byte[] iv = Program_Accessor.GetIV(masterKey);
            string actual = Program_Accessor.EncryptToBase64String(value, key, iv);
            string expected = Program_Accessor.DecryptFromBase64String(actual, key, iv);
            Assert.AreEqual(expected, value);
            //Assert.Inconclusive("Verify the correctness of this test method.");
        }

        /// <summary>
        ///A test for DecryptFromBase64String
        ///</summary>
        [TestMethod()]
        [DeploymentItem("KeyMaster.exe")]
        public void DecryptFromBase64StringTest()
        {
            string value = "Y2cJ7NCoRMtrVsNXE+4o5g==";
            byte[] masterKey = Program_Accessor.StringToBytes("AE6D75E17DB657D0851BCDFC9065BABF8205AC59CF50E174D6B5B8E468ADB2E8");
            byte[] key = Program_Accessor.GetKey(masterKey);
            byte[] iv = Program_Accessor.GetIV(masterKey);
            string expected = "Hello World";
            string actual = Program_Accessor.DecryptFromBase64String(value, key, iv);
            Assert.AreEqual(expected, actual);
            //Assert.Inconclusive("Verify the correctness of this test method.");
        }

    }
}
