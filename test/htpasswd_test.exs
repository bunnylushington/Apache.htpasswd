defmodule HtpasswdTest do
  use ExUnit.Case
  alias Apache.Htpasswd, as: H

  @htfile "test/htfile"

  test "check/2" do
    assert H.check(nil, @htfile) == false

    assert H.check("plaintext:plaintext", @htfile) == true
    assert H.check("plaintext:xxx", @htfile) == false
    assert H.check("plaintext:", @htfile) == false
      
    assert H.check("md5:md5", @htfile) == true
    assert H.check("md5:xxx", @htfile) == false
    assert H.check("md5:", @htfile) == false
    
    assert H.check("default:default", @htfile) == true
    assert H.check("default:xxx", @htfile) == false
    assert H.check("default:", @htfile) == false
    
    assert H.check("sha:sha", @htfile) == true
    assert H.check("sha:xxx", @htfile) == false
    assert H.check("sha:", @htfile) == false

    if Code.ensure_loaded(:crypt) do
      assert H.check("crypt:crypt", @htfile) == true
    else
      assert H.check("crypt:crypt", @htfile) == false
    end

    assert H.check("crypt:xxx", @htfile) == false
    assert H.check("crypt:", @htfile) == false
    
    assert H.check("ghost:ghost", @htfile) == false
    assert H.check("ghost:", @htfile) == false
  end
    

  test "encode/3" do
    plaintext = H.encode!("plaintext", "plaintext", :plaintext)
    assert H.check("plaintext:plaintext", plaintext)

    if Code.ensure_loaded?(:crypt) do
      crypt = H.encode!("crypt", "crypt", :crypt)
      assert H.check("crypt:crypt", crypt)
    else
      assert_raise RuntimeError, fn -> H.encode!("x", "y", :crypt) end
    end

    md5 = H.encode!("md5", "md5", :md5)
    assert H.check("md5:md5", md5)

    sha = H.encode!("sha", "sha", :sha)
    assert H.check("sha:sha", sha)

    default = H.encode!("default", "default")
    assert H.check("default:default", default)
  end
  
  test "add/4" do
    tmp_file = Path.join System.tmp_dir!, "htpasswd_test"
    assert {:ok, _str} = H.add("user", "pass", tmp_file, :md5)
    assert H.check("user:pass", tmp_file) == true
  end

  test "rm/3" do
    tmp_file = Path.join System.tmp_dir!, "htpasswd_test"
    assert {:ok, _str} = H.add("newuser", "newpass", tmp_file)
    assert :ok = H.rm("newuser", tmp_file)
  end
    


end
