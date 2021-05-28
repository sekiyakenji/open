
[String] $BASEDIR = "C:\tmp\"
[String] $LOGDIR = $BASEDIR  + "log\"
[String] $LOGDATE = Get-Date -Format "yyyy-MMdd"
[String] $CSVDIR = $BASEDIR + "csv\"
[String] $script_name = $myInvocation.MyCommand.name
[String] $LOGFILE = $LOGDIR + $script_name + "_" + $LOGDATE  + ".log" 
[String] $BACKUPFILE = $BASEDIR + "backup\backuplist_" + $LOGDATE  + ".csv"
[String] $FAILFILE =  $LOGDIR + "FAILED"+ "_" + $LOGDATE  + ".log"
[String] $ALCSVFILE = $CSVDIR + "read.csv.post"
[Datetime] $EXPIREDATE = [Datetime](Get-Date).AddMonths(6)
[int] $OK=0
[int] $NG=1

Add-type -AssemblyName System.Web;

function Write-Log() {    
    [CmdletBinding()]
    param(
        [String] $Message,
        [String] $Severity = 'Inf',
        [String] $logfiles 
    )

    $myObject = [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $Message
        Severity = $Severity
        logfiles = $logfiles
        }  

    [String] $mes =  $myObject.Time + " " +  $myObject.Severity + " " +  $myObject.Message
    Write-host $mes
    Out-File -InputObject $mes -FilePath $myObject.logfiles -Append  
}

function SendEmail($Server, $Port, $Sender, $Recipient, $Subject, $Body) {
    #$Credentials = [Net.NetworkCredential](Get-Credential)

    $SMTPClient = New-Object Net.Mail.SmtpClient($Server, $Port)
    $SMTPClient.EnableSsl = $true
    $SMTPClient.Credentials = New-Object System.Net.NetworkCredential("XXXXXXXXXXXX", "XXXXXXXXXXXXXXX");
    
    
    try {
        Write-Host "Sending message..."
        $SMTPClient.Send($Sender, $Recipient, $Subject, $Body)
        Write-Host "Message successfully sent to $($Recipient)"
    } catch [System.Exception] {
        Write-Output "An error occurred:"
        Write-Error $_
    }
}

function SendNotficationEmail($mail, [String] $bodya){
   Write-Host "An"
try{
    $Server = "email-smtp.us-east-1.amazonaws.com"
    $Port = 587
       Write-Host $bodya
     
    $Subject = "CRAS ACCOUNT NOTIFICATION"
    #$Body = "This message was sent from Amazon SES using PowerShell (explicit SSL, port 587)."

    $Sender = "XXXXX@i.softbank.jp"
    $Recipient = $mail

    SendEmail $Server $Port $Sender $Recipient $Subject $bodya
    }catch{
       Write-Host "en"
     
    throw }
}


function addaccount([array] $user){
    try{
        $mes = "addacount start " + $user.account
        Write-Log -Message $mes -logfiles $LOGFILE -Severity Inf
        $ou =  "OU=" + $user.Department + ",OU=ou01,DC=pi,DC=local"  
        $pass  = [System.Web.Security.Membership]::GeneratePassword(10,3)
        $adduser = @{
            SamAccountName = $user.account  # ログオン名
            Name = $user.account
            Surname = $user.SurName  # 姓
            GivenName = $user.GivenName  # 名
            DisplayName = "CRAS USER " + $user.SurName  + " "  +$user.GivenName    # 表示名    
            Path = $ou  # OU
            Description = "CRAS ACCOUNT"  # 説明欄
            UserPrincipalName = $user.mail  # ユーザプリンシパル名
            AccountPassword = (ConvertTo-SecureString -AsPlainText $pass -force)  # 暗号化したパスワード
            ChangePasswordAtLogon = $True  # 次回ログオン時にパスワード変更が必要
            AccountExpirationDate = $EXPIREDATE # アカウントの有効期限
            Enabled = $True  # ユーザを有効にする
        }
        New-ADUser @adduser  # アカウント追加
        [String] $mes = "Account added sucessfully:" + $user.account 
        Write-Log -Message $mes -logfiles $LOGFILE -Severity Infy
    }catch [System.ServiceModel.FaultException]{
       $mes = "account is already :" + $user.account
        Write-Log -Message $mes -logfiles $LOGFILE -Severity Err
    }catch{ 
        $mes = "add acount failed:" + $user.account
        Write-Log -Message  $error[0]       -logfiles $LOGFILE -Severity Err
        Write-Log -Message  $PSItem.Exception       -logfiles $LOGFILE -Severity Err        
        Write-Log -Message  $mes  -logfiles $FAILFILE -Severity Err
        throw 
    }
}

function deleteaccount([array] $user){

    try{
        [String]  $mes =  "disable " + $user.account  + " start"
        Write-Log -Message $mes  -logfiles $LOGFILE -Severity Inf
      
        $adduser = @{
            Enabled = $False  # ユーザを無効にする
        }

        Set-ADUser  -Identity  $user.account  @adduser  # アカウント追加
        [String] $mes = "Account disable sucessfully:" + $user.account 
        Write-Log -Message $mes -logfiles $LOGFILE -Severity Inf
    }catch{ 
        Write-Log -Message  $error[0]  -logfiles $LOGFILE -Severity Err
        Write-Log -Message  $user.account  -logfiles $LOGFILE -Severity Err
        throw
    }

}

function modifyaccount([array] $user){
    try{
        [String]  $mes =  "modify " + $user.account  + " start"
        Write-Log -Message $mes  -logfiles $LOGFILE -Severity Inf
      
        $adduser = @{
            Surname = $user.SurName  # 姓
            GivenName = $user.GivenName  # 名
            DisplayName = "CRAS USER " + $user.SurName  + " "  +$user.GivenName    # 表示名    
            Description = "CRAS ACCOUNT"  # 説明欄
            UserPrincipalName = $user.mail  # ユーザプリンシパル名
            AccountExpirationDate = $EXPIREDATE # アカウントの有効期限
            Enabled = $True  # ユーザを有効にする
        }
        Set-ADUser  -Identity  $user.account  @adduser  # アカウント追加
        [String] $mes = "Account mod sucessfully:" + $user.account 
        Write-Log -Message $mes -logfiles $LOGFILE -Severity Inf
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException]{
        Write-Log -Message  "no account"  -logfiles $LOGFILE -Severity Err
    }catch{ 
        Write-Log -Message  $error[0]  -logfiles $LOGFILE -Severity Err
        Write-Log -Message  $user.account  -logfiles $FAILFILE -Severity Err
        Write-Log -Message  $PSItem.Exception       -logfiles $LOGFILE -Severity Err        
        
        throw 
    }

}

function resetpassword([array] $user){
    try{
        [String]  $mes =  "reset password " + $user.account  + " start1"
        Write-Log -Message $mes  -logfiles $LOGFILE -Severity Inf
        [String]   $pass  = [System.Web.Security.Membership]::GeneratePassword(10,3)
        Set-ADAccountPassword -Identity $user.account -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $pass -Force)
        [String] $mes = "reset password sucessfully:" + $user.account 
        $body = $user.account + " your new password is " + $pass
        SendNotficationEmail $user.mail $body 
        Write-Log -Message $mes -logfiles $LOGFILE -Severity Inf
     
    }catch{ 
        Write-Log -Message  $error[0]  -logfiles $LOGFILE -Severity Err
        Write-Log -Message  $user.account  -logfiles $FAILFILE -Severity Err
        throw 
    }

}

function checkaccount([array] $user){
    if ($user.kubun -eq "Del"){
        #throw "the accoun already exists:" + $user.account
    }elseif(($user.kubun -eq "Add")  -or ($user.kubun -eq "Mod")) {
        #throw "the accoun dose exists:" + $user.account
    }
}

function mergecsvfile(){
    try{
       Write-Log -Message "meagecsvfile() start" -logfiles $LOGFILE -Severity Inf
        
       [int] $filecount = (Get-ChildItem $CSVDIR*.csv | ? { ! $_.PsIsContainer }).Count
       [array] $filenames = Get-ChildItem $CSVDIR*.csv
       [int] $counter = 1
       [String] $file =""
       foreach($file in $filenames) {
           $mes = [string]$counter + " CSVFILE:" + $file
           Write-Log -Message $mes -logfiles $LOGFILE -Severity Inf
           $counter = $counter + 1
       }
       if ($filecount-eq 0) {
           Write-Log -Message "NO CSV FILE" -logfiles $LOGFILE -Severity Err
           throw 
       }
       $csv = Get-Content $CSVDIR*.csv 
       Out-File -InputObject $csv -FilePath $ALCSVFILE
    }catch{
            throw 
    }finally{
       Write-Log -Message "meagecsvfile() end" -logfiles $LOGFILE -Severity Inf
    }
}

function outADList(){
 try {
    Get-ADUser `
     -Filter * `
     -Properties `
      Passwordlastset, `
      Passwordneverexpires,  `
      msDS-UserPasswordExpiryTimeComputed | `
    Format-Table `
     Name, `
     Enabled, `
     SamAccountName, `
     Surname, `
     GivenName, `
     UserPrincipalName, `
     DistinguishedName, `
     @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}, `
     Passwordlastset, `
     Passwordneverexpires `
     -Wrap -Auto  | Out-File  -FilePath $BACKUPFILE
  } catch {
    throw
  }
}

function init(){ 
    try{
        Write-Log -Message "init() start" -logfiles $LOGFILE -Severity Inf
        if (Test-Path $ALCSVFILE) {
            Remove-Item $ALCSVFILE
        }
    }catch{
        throw
    } finally{
        Write-Log -Message "init() end"   -logfiles $LOGFILE -Severity Inf
    }        

}

function register([String] $csvfile){
    Write-Log -Message "register() start" -logfiles $LOGFILE -Severity Inf

    [int] $error_flag = $OK
    [array] $userlist = Import-Csv $csvfile -Encoding UTF8
    foreach($user in $userlist){
        try{
            checkaccount($user)
            if ($user.kubun -eq "Add"){
                    addaccount($user)
            }elseif ($user.kubun -eq "Mod"){
                    modifyaccount($user)
            }elseif ($user.kubun -eq "Del"){
                    deleteaccount($user)
            }elseif ($user.kubun -eq "Res"){
                    resetpassword($user)
            }else{
            }
       }catch{
            #Write-Log  $PSItem.Exception.Message  -logfiles $LOGFILE -Severity Error
            #Write-Log -Message $PSItem.Exception.Message -logfiles $LOGFILE -Severity Err
            Write-Log  $PSItem.Exception.StackTrace  -logfiles $LOGFILE -Severity Err
            #Write-Log -Message $error[0] -logfiles $LOGFILE -Severity Err
            $error_flag  = $NG
        }
   }
   Write-Log -Message "register() end" -logfiles $LOGFILE -Severity Inf 
   return $error_flag
}

function main(){
    try{
        outADList
        init 
        mergecsvfile
    }catch {
        Write-Log -Message $error[0] -logfiles $LOGFILE -Severity Err   
        exit $NG
    }    
    $return = register($ALCSVFILE)
    exit $return
}

main
