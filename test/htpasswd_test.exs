defmodule HtpasswdTest do
  use ExUnit.Case
  alias Htpasswd, as: H

  @htfile "test/htfile"

  test "check/2" do
    assert H.check("plaintext:plaintext", @htfile) == true
    assert H.check("plaintext:xxx", @htfile) == false
    assert H.check("plaintext:", @htfile) == false

    assert H.check("crypt:crypt", @htfile) == true
    assert H.check("crypt:xxx", @htfile) == false
    assert H.check("crypt:", @htfile) == false

    assert H.check("md5:md5", @htfile) == true
    assert H.check("md5:xxx", @htfile) == false
    assert H.check("md5:", @htfile) == false

  end

  test "get_enc_passwd/2" do
    assert "plaintext" == H.get_enc_passwd("plaintext", @htfile)
    assert nil == H.get_enc_passwd("xyzzy", @htfile)
  end

end
