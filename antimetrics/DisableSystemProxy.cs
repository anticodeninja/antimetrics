// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

namespace Antimetrics
{
    using System;
    using System.Net;

    class DisableSystemProxy : IWebProxy
    {
        public Uri GetProxy(Uri destination) => throw new InvalidOperationException();
        public bool IsBypassed(Uri host) => true;
        public ICredentials Credentials { get; set; }
    }
}
