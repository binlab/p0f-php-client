<?php
/*
    p0f-client.php - simple p0f v3 API client function

    Can be used to query p0f API sockets from PHP Script
    
    Version: 0.1 - 18-Mar-2013
    
    Distributed under the terms and conditions of MIT.
    --------------------------------------------------------

	Demo:

	https://www.browserleaks.com/whois

    --------------------------------------------------------

    Usage Example:

    <?php
        include 'p0f_client.php';
        $array = p0f_client($_SERVER['REMOTE_ADDR'], '/var/run/p0f.sock');
        print_r($array);
    ?>

    Returns:

    Array
    (
        [magic_number] => 1345340930
        [status] => 16
        [first_seen] => 1363094107
        [last_seen] => 1363096712
        [total_conn] => 26
        [uptime_min] => 0
        [up_mod_days] => 0
        [last_nat] => 0
        [last_chg] => 0
        [distance] => 0
        [bad_sw] => 0
        [os_match_q] => 0
        [os_name] => Windows
        [os_flavor] => 7 or 8
        [http_name] => Firefox
        [http_flavor] => 10.x or newer
        [link_type] => Ethernet or modem
        [language] => English
    )


*/

function p0f_client($ip, $socket)
{
    if ($socket = @fsockopen('unix://'.$socket))
    {
        $query = pack('Lha*@24',0x50304601, 4, inet_pton($ip));

        fwrite($socket, $query);
        $resp = fread($socket, 233);
        fclose($socket);

        $resp = unpack( 'Lmagic_number/Lstatus/Lfirst_seen/Llast_seen'.
                        '/Ltotal_conn/Luptime_min/Lup_mod_days/Llast_nat'.
                        '/Llast_chg/cdistance/Cbad_sw/Cos_match_q'.
                        '/a32os_name/a32os_flavor/a32http_name/a32http_flavor'.
                        '/a32link_type/a32language', $resp);

        if (!is_array($resp)) {
            return false;
        }

        return $resp;
    }

    return false;
}
