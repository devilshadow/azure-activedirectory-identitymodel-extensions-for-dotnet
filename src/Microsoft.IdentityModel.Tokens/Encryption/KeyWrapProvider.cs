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
        protected KeyWrapProvider(SecurityKey key, string algorithm)
        {
            IsSupportedAlgorithm(key, algorithm);
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
            return new KeyWrapResult();
        }

        public virtual bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            return true;
        }
    }
}
