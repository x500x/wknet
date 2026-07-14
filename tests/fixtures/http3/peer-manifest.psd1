@{
    Aioquic = @{
        Version = '1.2.0'
        Requirements = 'aioquic-requirements.txt'
        PackageUri = 'https://files.pythonhosted.org/packages/dd/aa/e8a8a75c93dee0ab229df3c2d17f63cd44d0ad5ee8540e2ec42779ce3a39/aioquic-1.2.0-cp38-abi3-win_amd64.whl'
        Sha256 = 'e3dcfb941004333d477225a6689b55fc7f905af5ee6a556eb5083be0354e653a'
    }
    MsQuic = @{
        Version = '2.5.8'
        Commit = 'bf10e4a60dd03c471343623eccd35b4ea671937f'
        SourceUri = 'https://github.com/microsoft/msquic/archive/refs/tags/v2.5.8.zip'
        Sha256 = '5bcbb8f3fc788b07fd296186138ac0624c12ee7a838e49ddcd879047afc07b80'
        Xdp = @{
            Commit = 'f23b1fb4d492d9c20bcd7767bba2278f94355df8'
            SourceUri = 'https://github.com/microsoft/xdp-for-windows/archive/f23b1fb4d492d9c20bcd7767bba2278f94355df8.zip'
            Sha256 = 'a026a52b643246e3292a7bfd3c1af222f885510d55d391b2dbef8fa38780b769'
        }
    }
}
