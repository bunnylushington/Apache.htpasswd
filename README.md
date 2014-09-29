# Apache.Htpasswd

Provides basic htpasswd(1) functions as a library.  The hashing
methods available are :md5 (the default), :sha, :crypt, and
:plaintext.


## Examples
    iex> Apache.Htpasswd.check "user:pass", "test/htfile"
    false
  
    iex> Apache.Htpasswd.check "plaintext:plaintext", "test/htfile"
    true
  
    iex> Apache.Htpasswd.encode "user", "pass"
    "user:$apr1$O5f9TZT.$IBzxX8byvgfsLYp/dkIzC/"
  
    iex> Apache.Htpasswd.encode "user", "pass", :sha
    "user:{SHA}nU4eI71bcnBGqeO0t9tXvY1u5oQ="
  
    iex> Apache.Htpasswd.check "user:pass",
    ...>   Apache.Htpasswd.encode("user", "pass")
    true
  
    iex> Apache.Htpasswd.add("user", "pass", "/tmp/htpasswd")
    {:ok, "user:$apr1$on6He14N$3AeecTsC32uTadbYK1Ij4/"}
  
    iex> Apache.Htpasswd.rm("user", "/tmp/htpasswd")
    :ok


## Requirements

Apache.Htpasswd depends on the Elixir package `apache_passwd_md5` and,
optionally, the Erlang crypt library (if crypt style passwords are
going to be read or written).  I've tried to ensure that the code
works just fine in default (:md5) mode if the crypt library isn't
present.  If you run into trouble, please drop me a line and I'll take
a look.


--------

The MIT License (MIT)

Copyright (c) 2014 Kevin Montuori & BAPI Consulting.

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
