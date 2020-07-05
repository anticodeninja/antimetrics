// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright 2020 Artem Yamshanov, me [at] anticode.ninja

﻿namespace antidbg64
{
    using antidbg;

    static class Program
    {
        static void Main(string[] args) => new DbgEngine(args).Run();
    }
}
