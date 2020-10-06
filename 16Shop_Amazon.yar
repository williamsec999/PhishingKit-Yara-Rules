rule PhishKit_16Shop_Amazon
{
    meta:
        description = "Rule for 16Shop kits targeting Amazon, including cracked versions."
        author = "@sysgoblin"
        date = "2020-07-18"

    strings:
        $zip = { 50 4b 03 04 }
        $dir1 = "security"
        $dir2 = "admin"
        $dir3 = "result"
        $server_ini = "server.ini"
        $setting_ini = "setting.ini"
        $file1 = "onetime.php"
        $file2 = "main.php"
        $am_dir = "ap"
        $am_file1 = "additional.php"
        $am_file2 = "upload-cc.php"

    condition:
        uint32(0) == 0x04034b50 and
        $zip and 
        ($server_ini or $setting_ini) and
        all of ($file*) and
        all of ($dir*) and
        $am_dir and
        all of ($am_file*)
}
