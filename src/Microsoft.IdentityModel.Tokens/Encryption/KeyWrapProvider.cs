//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    public class KeyWrapResult
    {
        public byte[] Ciphertext { get; set; }

        public byte[] iv { get; set; }

        public byte[] AuthenticationTag { get; set; }
    }

    public class KeyWrapProvider
    {
        private readonly static byte[] defaultIV = new byte[] { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };

        public KeyWrapProvider(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if(!IsSupportedAlgorithm(key, algorithm))
                throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(algorithm), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));

            Algorithm = algorithm;
            Key = key;
        }

        public string Algorithm { get; private set; }

        public string Context { get; set; }

        public SecurityKey Key { get; private set; }

        public virtual byte[] DecryptKey(byte[] key)
        {
            return new byte[0];
        }

        public virtual KeyWrapResult EncryptKey(byte[] key)
        {
            if (key == null || key.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(key));

            KeyWrapResult result = new KeyWrapResult();

            if (SecurityAlgorithms.Aes128KW.Equals(Algorithm, StringComparison.Ordinal))
            {
                SymmetricSecurityKey symmetricKey = Key as SymmetricSecurityKey;
                if (symmetricKey == null)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10655, key.GetType())));

                Aes aes = Aes.Create();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.Key = symmetricKey.Key;
                aes.IV = defaultIV;
                result.Ciphertext = Utility.Transform(aes.CreateEncryptor(), key, 0, key.Length);
            }
            else if (SecurityAlgorithms.Aes256KW.Equals(Algorithm, StringComparison.Ordinal))
            { }
            else if (SecurityAlgorithms.RsaPKCS1.Equals(Algorithm, StringComparison.Ordinal))
            { }
            else if (SecurityAlgorithms.RsaOAEP.Equals(Algorithm, StringComparison.Ordinal))
            { }
            else
            {

            }
        }

        public virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128KW:
                case SecurityAlgorithms.Aes256KW:
                    {
                        SymmetricSecurityKey symmetricKey = key as SymmetricSecurityKey;
                        if (symmetricKey == null)
                            throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10655, key.GetType())));

                        ValidateKeySize(symmetricKey, algorithm);
                        return true;
                    }

                case SecurityAlgorithms.RsaPKCS1:
                case SecurityAlgorithms.RsaOAEP:
                    return true;

                default:
                    return false;
            }
        }

        private void ValidateKeySize(SymmetricSecurityKey key, string algorithm)
        {
            if (SecurityAlgorithms.Aes128KW.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.Key.Length < 16)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10653, SecurityAlgorithms.Aes128KW, 128, key.KeyId, key.Key.Length << 3)));

                return;
            }

            if (SecurityAlgorithms.Aes256KW.Equals(algorithm, StringComparison.Ordinal))
            {
                if (key.Key.Length < 32)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10653, SecurityAlgorithms.Aes256KW, 256, key.KeyId, key.Key.Length << 3)));

                return;
            }

            throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(algorithm), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));
        }
    }
}
