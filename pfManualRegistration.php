<?php
/*
* PHP script to manually change users to a "registered" state
* within PacketFence (http://www.packetfence.org/)
*
* Uses LDAP for authentication
*
* Copyright Andrew Niemantsverdriet 2010
* Released under the GPL: http://www.gnu.org/licenses/gpl-3.0.txt
*
*/

//LDAP Authenticate Function
//takes username and clear text password returns true on success else returns false
function authenticateUser($username,$password) {
  $ldapServer = 'your.ldap.server';
  $ldapDCRoot = 'dc=base,dc=name';

  //Sanitize LDAP Username
  //Only allow letters and number and the . charater
  $username = preg_replace("/[^a-zA-Z0-9.]/", "", $username);

  $ldap_connection = ldap_connect($ldapServer);

  if($ldap_connection) {
    //Load from data
    $isBound = ldap_bind($ldap_connection);
    if(!$isBound) {
      //echo 'Failed to Anonymously Bind to LDAP'; //DEBUG
      return false;
    }

    $usernameFilter = "uid=$username";
    $search = ldap_search($ldap_connection, $ldapDCRoot, $usernameFilter);

    if(ldap_count_entries($ldap_connection,$search) == 1) {
      $info = ldap_get_entries($ldap_connection,$search);

      //Attempt to Rebind with the user's password
      $bind = @ldap_bind($ldap_connection,$info[0]['dn'],$password);
      if(!$bind || !isset($bind)) {
        //echo 'LDAP Password mismatch'; //DEBUG
        return false;
      } else {
        //echo 'LDAP Success'; //DEBUG
        return true;
      }
    } else {
     //echo 'Invalid number of Users Returned (Too many or None)'; //DEBUG
     return false;
    }
  } else {
    //echo 'Failed to Connect to LDAP'; //DEBUG
    return false;
  }
}

//MAC Address Validate function
//takes MAC address returns MAC address on valid MAC else returns null
function validateMAC($macAddress) {
  //Make sure MAC only contain letters A-F and numbers 0-9 and the colon
  if (preg_match('/^[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}:[a-f0-9]{2}$/i',$macAddress)) {
    return $macAddress;
  } else {
    return null;
  }
}

//Execute pfcmd on remote system
function pfcmdExecute($username,$macAddress) {
  exec('/usr/local/pf/bin/pfcmd person edit '.$username); //ensure user exists
  exec('/usr/local/pf/bin/pfcmd node edit '.$macAddress.' status="reg",pid="'.$username.'"');
}

  //Get Posted Variables
  $username = $_POST['username'];
  //Sanitize Username
  $username = preg_replace("/[^a-zA-Z0-9.]/", "", $username);
  $password = $_POST['password'];
  $macAddress = $_POST['macAddress'];

  //Check LDAP for valid password / username combo
  if (authenticateUser($username,$password)) {
    //Check for valid MAC
    $santizedMac = validateMAC($macAddress);
    if (!is_null($santizedMac)) {
      //Use PFCMD to add system
      pfcmdExecute($username,$santizedMac);
      //Redirect to Success Page
      header('Location: http://www.example.com/success.html');
      //DEBUG echo "<br/>You did it";
    } else {
      echo "Invalid MAC Address";
    }
  } else {
    echo "Invalid Username or Password";
  }
?>
