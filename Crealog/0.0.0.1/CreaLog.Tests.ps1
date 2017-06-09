$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($env:PSModulePath -notmatch ($(($here -split "\\Crealog")[0] -replace "\\","\\"))) {
    $env:PSModulePath += ";$(($here -split "\\Crealog")[0])"
}

InModuleScope Crealog {
    Describe "Get-mCRUser" {
        It "does something useful" {
            $true | Should Be $true
        }
    }

    Describe "Test" {
        context '2017' {
            mock -CommandName get-date -MockWith {"2017"}
            it 'should return "today"' {
                get-date|Should be "today"
            }

            it 'should be true' {
                crealog|should be $true
            }

            it 'Should return 213.185.165.52' {
                (Resolve-DnsName jerry.bgt.ag).IPAddress| should be "213.185.165.52"
            }
        }
        context '2018' {
            mock -CommandName get-date -MockWith {"2018"}
            it 'should be false' {
                crealog|should be $false
            }
        }
    }
}