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
    /// EncryptKey/DecryptKey
    ///     - positive tests for keys (128, 256) X Algorithms or RSA key supported.
    ///     - parameter validation for Encrypt
    /// Decrypt
    ///     - parameter validataion for Decrypt
    /// DecryptMismatch
    ///     - negative tests for switching (keys, algorithms)
    /// EncryptVirtual
    ///     - tests virtual method was called
    /// DecryptVirtual
    ///     - tests virtual method was called
    /// </summary>
    public class AuthenticatedKeyWrapProviderTests
    {
    }
}
