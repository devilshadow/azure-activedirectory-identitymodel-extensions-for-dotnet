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
using System.Collections.Generic;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Tests for KeyWrapProvider
    /// Constructors
    ///     - validate parameters (null, empty)
    ///     - algorithms supported
    ///     - properties are set correctly (Algorithm, Context, Key)
    /// WrapKey/UnWrapKey
    ///     - positive tests for keys (128, 256) X Algorithms supported.
    ///     - parameter validation for WrapKey
    /// Decrypt
    ///     - parameter validataion for UnWrapKey
    /// DecryptMismatch
    ///     - negative tests for switching (keys, algorithms)
    /// EncryptVirtual
    ///     - tests virtual method was called
    /// DecryptVirtual
    ///     - tests virtual method was called
    /// </summary>
    public class KeyWrapProviderTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("KeyWrapConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void Constructors(string testId, SecurityKey key, string algorithm, ExpectedException ee)
        {
            try
            {
                var context = Guid.NewGuid().ToString();
                var provider = new KeyWrapProvider(key, algorithm) { Context = context };

                ee.ProcessNoException();

                Assert.Equal(provider.Algorithm, algorithm);
                Assert.Equal(provider.Context, context);
                Assert.True(ReferenceEquals(provider.Key, key));
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, SecurityKey, string, ExpectedException> KeyWrapConstructorTheoryData()
        {
            var theoryData = new TheoryData<string, SecurityKey, string, ExpectedException>();

            theoryData.Add("Test1", null, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test2", Default.SymmetricEncryptionKey128, null, ExpectedException.ArgumentNullException());
            theoryData.Add("Test3", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128Encryption, ExpectedException.ArgumentException("IDX10661:"));
            theoryData.Add("Test4", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes128KW, ExpectedException.NoExceptionExpected);
            theoryData.Add("Test5", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256KW, ExpectedException.NoExceptionExpected);

            JsonWebKey key = new JsonWebKey();
            key.Kty = JsonWebAlgorithmsKeyTypes.Octet;
            theoryData.Add("Test6", key, SecurityAlgorithms.Aes256KW, ExpectedException.ArgumentException("IDX10657:"));
            theoryData.Add("Test7", Default.SymmetricEncryptionKey128, SecurityAlgorithms.Aes256KW, ExpectedException.ArgumentOutOfRangeException("IDX10662:"));
            theoryData.Add("Test8", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128KW, ExpectedException.ArgumentOutOfRangeException("IDX10662:"));
            theoryData.Add("Test9", Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes256CbcHmacSha512, ExpectedException.ArgumentOutOfRangeException("IDX10652:"));

            return theoryData;
        }

//#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
//        [Theory, MemberData("DecryptTheoryData")]
//#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
//        public void UnWrapKey()
//        { }


    }
}
