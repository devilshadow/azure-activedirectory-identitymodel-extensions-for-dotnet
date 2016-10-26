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
    /// <summary>
    /// Provides Wrap key and UnWrap key services.
    /// </summary>
    public class KeyWrapProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyWrapProvider"/> class used for wrap key and unwrap key.
        /// <param name="key">The <see cref="SecurityKey"/> that will be used for crypto operations.</param>
        /// <param name="algorithm">The KeyWrap algorithm to apply.</param>
        /// <exception cref="ArgumentNullException">'key' is null.</exception>
        /// <exception cref="ArgumentNullException">'algorithm' is null or whitespace.</exception>
        /// <exception cref="ArgumentOutOfRangeException">If <see cref="SecurityKey"/> and algorithm pair are not supported.</exception>
        /// </summary>
        public KeyWrapProvider(SecurityKey key, string algorithm)
        {
            if (key == null)
                throw LogHelper.LogArgumentNullException(nameof(key));

            if (string.IsNullOrWhiteSpace(algorithm))
                throw LogHelper.LogArgumentNullException(nameof(algorithm));

            if (!IsSupportedAlgorithm(key, algorithm))
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(algorithm), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, algorithm)));

            Algorithm = algorithm;
            Key = key;
        }

        /// <summary>
        /// Gets the KeyWrap algorithm that is being used.
        /// </summary>
        public string Algorithm { get; private set; }

        /// <summary>
        /// Gets or sets a user context for a <see cref="KeyWrapProvider"/>.
        /// </summary>
        /// <remarks>This is null by default. This can be used by runtimes or for extensibility scenarios.</remarks>
        public string Context { get; set; }

        /// <summary>
        /// Gets the <see cref="SecurityKey"/> that is being used.
        /// </summary>
        public SecurityKey Key { get; private set; }

        /// <summary>
        /// UnWrap the wrappedKey
        /// </summary>
        /// <param name="wrappedKey">the wrapped key to unwrap.</param>
        /// <returns>Unwrap wrappted key</returns>
        /// <exception cref="ArgumentNullException">'wrappedKey' is null or empty.</exception>
        /// <exception cref="ArgumentException">'Key' is not a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <exception cref="KeyWrapUnwrapException">Failed to unwrap the wrapptedKey.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The algorithm is not supported.</exception>
        public virtual byte[] UnWrapKey(byte[] wrappedKey)
        {
            if (wrappedKey == null || wrappedKey.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(wrappedKey));

            if (IsSymmetricAlgorithmSupported(Algorithm))
            {
                SymmetricSecurityKey symmetricKey = Key as SymmetricSecurityKey;
                if (symmetricKey == null)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10655, wrappedKey.GetType())));

                ValidateKeySize(symmetricKey, Algorithm);
                if (SecurityAlgorithms.Aes128KW.Equals(Algorithm, StringComparison.Ordinal))
                {
                    try
                    {
                        AesKw128 aesKw128 = new AesKw128();
                        return aesKw128.CreateDecryptor(symmetricKey.Key).TransformFinalBlock(wrappedKey, 0, wrappedKey.Length);
                    }
                    catch (Exception ex)
                    {
                        throw LogHelper.LogExceptionMessage(new KeyWrapUnwrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10657, ex)));
                    }
                }
                else if (SecurityAlgorithms.Aes256KW.Equals(Algorithm, StringComparison.Ordinal))
                {
                    try
                    {
                        AesKw256 aesKw256 = new AesKw256();
                        return aesKw256.CreateDecryptor(symmetricKey.Key).TransformFinalBlock(wrappedKey, 0, wrappedKey.Length);
                    }
                    catch (Exception ex)
                    {
                        throw LogHelper.LogExceptionMessage(new KeyWrapUnwrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10657, ex)));
                    }
                }
                else
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(Algorithm), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, Algorithm)));
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(Algorithm), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, Algorithm)));
        }

        /// <summary>
        /// Wrap the 'keyToWrap'
        /// </summary>
        /// <param name="keyToWrap">the key to be wrappted.</param>
        /// <returns>The wrappted key</returns>
        /// <exception cref="ArgumentNullException">'keyToWrap' is null or empty.</exception>
        /// <exception cref="ArgumentException">'Key' is not a <see cref="SymmetricSecurityKey"/>.</exception>
        /// <exception cref="KeyWrapWrapException">Failed to wrap the keyToWrap.</exception>
        /// <exception cref="ArgumentOutOfRangeException">The algorithm is not supported.</exception>
        public virtual byte[] WrapKey(byte[] keyToWrap)
        {
            if (keyToWrap == null || keyToWrap.Length == 0)
                throw LogHelper.LogArgumentNullException(nameof(keyToWrap));

            if (IsSymmetricAlgorithmSupported(Algorithm))
            {
                SymmetricSecurityKey symmetricKey = Key as SymmetricSecurityKey;
                if (symmetricKey == null)
                    throw LogHelper.LogExceptionMessage(new ArgumentException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10655, keyToWrap.GetType())));

                ValidateKeySize(symmetricKey, Algorithm);
                if (SecurityAlgorithms.Aes128KW.Equals(Algorithm, StringComparison.Ordinal))
                {
                    try
                    {
                        AesKw128 aesKw128 = new AesKw128();
                        return aesKw128.CreateEncryptor(symmetricKey.Key).TransformFinalBlock(keyToWrap, 0, keyToWrap.Length);
                    }
                    catch (Exception ex)
                    {
                        throw LogHelper.LogExceptionMessage(new KeyWrapWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10656, ex)));
                    }
                }
                else if (SecurityAlgorithms.Aes256KW.Equals(Algorithm, StringComparison.Ordinal))
                {
                    try
                    {
                        AesKw256 aesKw256 = new AesKw256();
                        return aesKw256.CreateEncryptor(symmetricKey.Key).TransformFinalBlock(keyToWrap, 0, keyToWrap.Length);
                    }
                    catch (Exception ex)
                    {
                        throw LogHelper.LogExceptionMessage(new KeyWrapWrapException(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10656, ex)));
                    }
                }
                else
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(Algorithm), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, Algorithm)));
            }

            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(Algorithm), string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10652, Algorithm)));
        }

        /// <summary>
        /// Answers if an algorithm is supported
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/></param>
        /// <param name="algorithm">the algorithm to use</param>
        /// <returns>true if the algorithm is supported; otherwise, false.</returns>
        protected virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            if (key as SymmetricSecurityKey != null)
                return IsSymmetricAlgorithmSupported(algorithm);

            return false;
        }

        private bool IsSymmetricAlgorithmSupported(string algorithm)
        {
            switch (algorithm)
            {
                case SecurityAlgorithms.Aes128KW:
                case SecurityAlgorithms.Aes256KW:
                    return true;
            }

            return false;
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
