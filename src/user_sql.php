<?php

/**
 * ownCloud - user_sql
 *
 * @author Andreas Böhler and contributors
 * @copyright 2012/2013 Andreas Böhler <andreas (at) aboehler (dot) at>
 *
 * credits go to Ed W for several SQL injection fixes and caching support
 * credits go to Frédéric France for providing Joomla support
 * credits go to
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\EventDispatcher\Event;
use Postfixadmin\Md5crypt;

class OC_USER_SQL extends OC_User_Backend implements OC_User_Interface {

    // cached settings
    protected $sql_host;
    protected $sql_username;
    protected $sql_database;
    protected $sql_password;
    protected $sql_table;
    protected $sql_column_username;
    protected $sql_column_password;
    protected $sql_column_active;
    protected $sql_column_displayname;
    protected $sql_type;
    protected $db_conn;
    protected $db;
    protected $default_domain;
    protected $strip_domain;
    protected $crypt_type;
    protected static $eventDispatcher;

    public function __construct()
    {
        $this->init();
    }

    protected function init () {
        $this->db_conn = false;
        $this->loadAppValues();

        try
        {
            $this->connectToDatabase();
            $this->db_conn = true;

            $eventDispatcher = $this->getEventDispatcher();
            $eventDispatcher->addListener('valid_user', array($this,'validUserByActiveFlag'));

            $this->loadPlugins();
        }
        catch (PDOException $e)
        {
            OC_Log::write('OC_USER_SQL', 'Failed to connect to the database: ' . $e->getMessage(), OC_Log::ERROR);
        }
    }

    public function getAppValueWrapper($appName,$valueName,$default)
    {
        return OCP\Config::getAppValue($appName, $valueName, $default);
    }

    public function loadAppValues()
    {
        $this->sql_host = $this->getAppValueWrapper('user_sql', 'sql_host', '');
        $this->sql_username = $this->getAppValueWrapper('user_sql', 'sql_user', '');
        $this->sql_database = $this->getAppValueWrapper('user_sql', 'sql_database', '');
        $this->sql_password = $this->getAppValueWrapper('user_sql', 'sql_password', '');
        $this->sql_table = $this->getAppValueWrapper('user_sql', 'sql_table', '');
        $this->sql_column_username = $this->getAppValueWrapper('user_sql', 'sql_column_username', '');
        $this->sql_column_password = $this->getAppValueWrapper('user_sql', 'sql_column_password', '');
        $this->sql_column_displayname = $this->getAppValueWrapper('user_sql', 'sql_column_displayname', '');
        $this->sql_column_active = $this->getAppValueWrapper('user_sql', 'sql_column_active', '');
        $this->sql_type = $this->getAppValueWrapper('user_sql', 'sql_type', '');
        $this->default_domain = $this->getAppValueWrapper('user_sql', 'default_domain', '');
        $this->strip_domain = $this->getAppValueWrapper('user_sql', 'strip_domain', 0);
        $this->crypt_type = $this->getAppValueWrapper('user_sql', 'crypt_type', 'md5crypt');
    }

    public function loadPlugins()
    {
        OC_App::loadApps('user_sql_addon');
    }

    public function connectToDatabase()
    {
        $dsn = $this->sql_type.":host=".$this->sql_host.";dbname=".$this->sql_database;

        $this->db = new PDO($dsn, $this->sql_username, $this->sql_password);
    }

    /**
     * @return \Symfony\Component\EventDispatcher\EventDispatcher
     */
    public static function getEventDispatcher()
    {
        if ( static::$eventDispatcher === null ) {
            static::$eventDispatcher = new EventDispatcher();
        }

        return static::$eventDispatcher;
    }

    public function implementsAction($actions)
    {
        return (bool)((OC_USER_BACKEND_CHECK_PASSWORD | OC_USER_BAKCNED_GET_DISPLAYNAME) & $actions);
    }

    public function hasUserListings() {
        return true;
    }

    public function createUser() {
        // Can't create user
        OC_Log::write('OC_USER_SQL', 'Not possible to create local users from web frontend using SQL user backend', OC_Log::ERROR);
        return false;
    }

    public function deleteUser( $uid )
    {
        // Can't delete user
        OC_Log::write('OC_USER_SQL', 'Not possible to delete local users from web frontend using SQL user backend', OC_Log::ERROR);
        return false;
    }


    public function canonicalizeUid($uid) {
        $uid = trim($uid);
        $uid = addDomainUid($uid);
        return strtolower($uid);
    }

    public function stripDomainUid($uid) {
        if($this->strip_domain) {
            $uid = explode("@", $uid);
            $uid = $uid[0];
        }
        return strtolower($uid);
    }

    public function addDomainUid($uid) {
        if(!is_string($this->default_domain) ||
           strpos($uid, '@') === false
        ) {
            return $uid;
        }

        return $uid . "@" . $this->default_domain;
    }

    public function setPassword ( $uid, $password ) {
        // Update the user's password - this might affect other services, that user the same database, as well
        OC_Log::write('OC_USER_SQL', "Entering setPassword for UID: $uid", OC_Log::DEBUG);
        if(!$this->db_conn)
        {
            return false;
        }
        $uid = $this->canonicalizeUid($uid);

        /**
         * @todo pacrypt return a bool if it faild we need here ExceptionHandle
         */
        $old_password = $this->getPassword($uid);
        $enc_password = $this->pacrypt($password, $old_password);

        $query = "UPDATE $this->sql_table SET $this->sql_column_password = :enc_password WHERE $this->sql_column_username = :uid";
        OC_Log::write('OC_USER_SQL', "Preapring query: $query", OC_Log::DEBUG);
        $result = $this->db->prepare($query);

        $result->bindParam(":enc_password", $enc_password);
        $result->bindParam(":uid", $uid);

        OC_Log::write('OC_USER_SQL', "Executing query...", OC_Log::DEBUG);
        if(!$result->execute()) {
            $err = $result->errorInfo();
            OC_Log::write('OC_USER_SQL', "Query failed: ".$err[2], OC_Log::DEBUG);
            OC_Log::write('OC_USER_SQL', "Could not update password!", OC_Log::ERROR);
            return false;
        }

        OC_Log::write('OC_USER_SQL', "Updated password successfully, return true", OC_Log::DEBUG);
        return true;
    }

    /**
    *
    * @param string $uid The username
    * @return string $password The password
    */
    protected function getPassword($uid)
    {
        OC_Log::write('OC_USER_SQL', "Entering getPassword() for UID: $uid", OC_Log::DEBUG);
        if (!$this->db_conn) {
            return false;
        }

        $uid = $this->canonicalizeUid($uid);

        $query = "SELECT $this->sql_column_password FROM $this->sql_table WHERE $this->sql_column_username = :uid";
        OC_Log::write('OC_USER_SQL', "Preparing query: $query", OC_Log::DEBUG);
        $result = $this->db->prepare($query);
        $result->bindParam(":uid", $uid);

        OC_Log::write('OC_USER_SQL', "Executing query...", OC_Log::DEBUG);
        if(!$result->execute()) {
            return false;
        }

        OC_Log::write('OC_USER_SQL', "Fetching result...", OC_Log::DEBUG);
        if ( $result->rowCount() === 0 ) {
            return false;
        }

        $row = $result->fetch();
        return $row[ $this->sql_column_password ];
    }

    /**
    * @brief Check if the password is correct
    * @param string $uid The username
    * @param string $password The password
    * @returns true/false
    *
    * Check if the password is correct without logging in the user
    */
    public function checkPassword($uid, $password)
    {
        OC_Log::write('OC_USER_SQL', "Entering checkPassword() for UID: $uid", OC_Log::DEBUG);
        if (!$this->db_conn) {
            return false;
        }

        $uid = $this->canonicalizeUid($uid);


        $column = array($this->sql_column_username,$this->sql_column_password);
        if ($this->sql_column_active != '') {
            $column[]=$this->sql_column_active;
        }

        $query = sprintf("SELECT %s FROM %s WHERE %s",
            implode(",", $column),
            $this->sql_table,
            "$this->sql_column_username = :uid");

        OC_Log::write('OC_USER_SQL', "Preparing query: $query", OC_Log::DEBUG);
        $result = $this->db->prepare($query);
        $result->bindParam(":uid", $uid);
        OC_Log::write('OC_USER_SQL', "Executing query...", OC_Log::DEBUG);
        if (!$result->execute()) {
            $err = $result->errorInfo();
            OC_Log::write('OC_USER_SQL', "Query failed: ".$err[2], OC_Log::DEBUG);
            return false;
        }
        OC_Log::write('OC_USER_SQL', "Fetching row...", OC_Log::DEBUG);
        $row = $result->fetch();
        if (!$row) {
            OC_Log::write('OC_USER_SQL', "Got no row, return false", OC_Log::DEBUG);
            return false;
        }

        if (!$this->validUser($row)) {
            return false;
        }

        /**
         * @todo we need here exception handle if pacrypt faild
         */
        OC_Log::write('OC_USER_SQL', "Encrypting and checking password", OC_Log::DEBUG);
        if ($row[$this->sql_column_password] !== $this->pacrypt($password, $row[$this->sql_column_password]) ) {
            OC_Log::write('OC_USER_SQL', "Passwords do not match, return false", OC_Log::DEBUG);
            return false;
        }


        OC_Log::write('OC_USER_SQL', "Passwords matching, return true", OC_Log::DEBUG);
        return $this->stripDomainUid($uid);
    }

    /**
    * @brief Get a list of all users
    * @returns array with all uids
    *
    * Get a list of all users.
    */

    public function getUsers($search = '', $limit = null, $offset = null)
    {
       OC_Log::write('OC_USER_SQL', "Entering getUsers() with Search: $search, Limit: $limit, Offset: $offset", OC_Log::DEBUG);
       $users = array();
       if(!$this->db_conn)
       {
        return false;
       }



       $column = array($this->sql_column_username);
       if ($this->sql_column_active != '') {
           $column[]=$this->sql_column_active;
       }

       $query = "SELECT " . implode(',', $column) ." FROM $this->sql_table";
       if($search != '') {
          $query .= " WHERE $this->sql_column_username LIKE :search";
       }
       $query .= " ORDER BY $this->sql_column_username";
       if($limit != null)
       {
          $limit = intval($limit);
          $query .= " LIMIT $limit";
       }
       if($offset != null)
       {
          $offset = intval($offset);
          $query .= " OFFSET $offset";
       }
       OC_Log::write('OC_USER_SQL', "Preparing query: $query", OC_Log::DEBUG);
       $result = $this->db->prepare($query);
       if($search != '')
       {
          $search = "%$search%";
          $result->bindParam(":search", $search);
       }
       OC_Log::write('OC_USER_SQL', "Executing query...", OC_Log::DEBUG);
       if(!$result->execute())
       {
        $err = $result->errorInfo();
        OC_Log::write('OC_USER_SQL', "Query failed: ".$err[2], OC_Log::DEBUG);
        return array();
       }
       OC_Log::write('OC_USER_SQL', "Fetching results...", OC_Log::DEBUG);
       while($row = $result->fetch())
       {
           if ( !$this->validUser($row) ) {
               continue;
           }
           $users[] =  $this->stripDomainUid( $row[$this->sql_column_username] );
       }
       OC_Log::write('OC_USER_SQL', "Return list of results", OC_Log::DEBUG);
       return $users;
    }


    /**
     *
     * @param array|object $user
     * @return unknown
     */
    public function validUser(&$user)
    {
        $uid = $user[$this->sql_column_username];

        OC_Log::write('OC_USER_SQL', sprintf('Valid user "%s" has permission to connect',$uid), OC_Log::DEBUG);

        $event = new Event();
        $event->userId= $uid;
        $event->userData= $user;
        $event->validStatus= true;
        $event->db=array(
            'sql_table'=>$this->sql_table,
            'sql_column_username'=>$this->sql_column_username,
            'handle'=>$this->db
        );

        $dispacher = static::getEventDispatcher();

        // all hight level valid functions
        $dispacher->dispatch('valid_user.pre',$event);

        if ( $event->validStatus !== false ) {
            // all valid functions
            $dispacher->dispatch('valid_user',$event);
        }

        if ( $event->validStatus !== false ) {
            // all low level valid functions
            $dispacher->dispatch('valid_user.post',$event);
        }

        if ($event->validStatus) {
            OC_Log::write('OC_USER_SQL', sprintf('Valid user "%s" has been true',$uid), OC_Log::DEBUG);
        } else {
            OC_Log::write('OC_USER_SQL', sprintf('Valid user "%s" has been false',$uid), OC_Log::DEBUG);
        }

        return $event->validStatus;
    }

    public function validUserByActiveFlag(Event $event)
    {
        $user = $event->userData;

        OC_Log::write('OC_USER_SQL', sprintf('Valid user "%s" has active flag',$event->userId), OC_Log::DEBUG);
        if($this->sql_column_active == '' || !isset($user[$this->sql_column_active])) {
            goto RETURN_TRUE;
        }

        if ( (int) $user[$this->sql_column_active] === 1 ) {
            goto RETURN_TRUE;
        }

        RETURN_FALSE:
            $event->validStatus = false;
            $event->stopPropagation();
            return false;

        RETURN_TRUE:
            $event->validStatus = true;
            return true;
    }

    /**
    * @brief check if a user exists
    * @param string $uid the username
    * @return boolean
    */

    public function userExists($uid)
    {
    	static $cached_exists;
        OC_Log::write('OC_USER_SQL', "Entering userExists() for UID: $uid", OC_Log::DEBUG);
        if(!$this->db_conn)
        {
            return false;
        }

        $uid = $this->canonicalizeUid($uid);

        if ($uid === $cached_exists) {
            OC_Log::write('OC_USER_SQL', "User exists (using cache), return true", OC_Log::DEBUG);
            return true;
        }


        $column = array($this->sql_column_username);
        if ($this->sql_column_active != '') {
            $column[]=$this->sql_column_active;
        }

        $query = sprintf("SELECT %s FROM %s WHERE %s",
                implode(",", $column),
                $this->sql_table,
                "$this->sql_column_username = :uid");

        OC_Log::write('OC_USER_SQL', "Preparing query: $query", OC_Log::DEBUG);
        $result = $this->db->prepare($query);
        $result->bindParam(":uid", $uid);
        OC_Log::write('OC_USER_SQL', "Executing query...", OC_Log::DEBUG);
        if(!$result->execute())
        {
            $err = $result->errorInfo();
            OC_Log::write('OC_USER_SQL', "Query failed: ".$err[2], OC_Log::DEBUG);
            return false;
        }
        OC_Log::write('OC_USER_SQL', "Fetching results...", OC_Log::DEBUG);
        $row = $result->fetch();
        if(!$row)
        {
            OC_Log::write('OC_USER_SQL', "Empty row, user does not exists, return false", OC_Log::DEBUG);
            return false;
        }

        if ( $this->validUser($row) ) {
            OC_Log::write('OC_USER_SQL', "User exists, return true", OC_Log::DEBUG);
            $cached_exists = $uid;
            return true;
        }
        return false;
    }

    public function getDisplayName($uid)
    {
        OC_Log::write('OC_USER_SQL', "Entering getDisplayName() for UID: $uid", OC_Log::DEBUG);
        if(!$this->db_conn)
        {
            return false;
        }

        $uid = $this->canonicalizeUid($uid);

        if(!$this->userExists($uid))
        {
            return false;
        }

        // we don't need check active because user exists do this too...
        $query = "SELECT $this->sql_column_displayname FROM $this->sql_table WHERE $this->sql_column_username = :uid";

        OC_Log::write('OC_USER_SQL', "Preparing query: $query", OC_Log::DEBUG);
        $result = $this->db->prepare($query);
        $result->bindParam(":uid", $uid);
        OC_Log::write('OC_USER_SQL', "Executing query...", OC_Log::DEBUG);
        if(!$result->execute())
        {
            $err = $result->errorInfo();
            OC_Log::write('OC_USER_SQL', "Query failed: ".$err[2], OC_Log::DEBUG);
            return false;
        }
        OC_Log::write('OC_USER_SQL', "Fetching results...", OC_Log::DEBUG);
        $row = $result->fetch();
        if(!$row)
        {
            OC_Log::write('OC_USER_SQL', "Empty row, user has no display name or does not exist, return false", OC_Log::DEBUG);
            return false;
        }

        OC_Log::write('OC_USER_SQL', "User exists, return true", OC_Log::DEBUG);
        $displayName = utf8_encode($row[$this->sql_column_displayname]);
        return $displayName;
    }

    public function getDisplayNames($search = '', $limit = null, $offset = null)
    {
        $uids = $this->getUsers($search, $limit, $offset);
        $displayNames = array();
        foreach($uids as $uid)
        {
            $displayNames[$uid] = $this->getDisplayName($uid);
        }
        return $displayNames;
    }

     /**
     * The following functions were directly taken from PostfixAdmin and just slightly modified
     * to suit our needs.
     * Encrypt a password, using the apparopriate hashing mechanism as defined in
     * config.inc.php ($this->crypt_type).
     * When wanting to compare one pw to another, it's necessary to provide the salt used - hence
     * the second parameter ($pw_db), which is the existing hash from the DB.
     *
     * @todo here we need a Exception and ExceptionHandling string or bool is a bad idea...
     * @todo this if stack cost performence, refactor it to a faster logic
     * @todo allow app to add here a own password crypt (security-problem)
     * @param string $pw
     * @param string $encrypted password
     * @return string encrypted password.
     */
    private function pacrypt ($pw, $pw_db="")
    {
        OC_Log::write('OC_USER_SQL', "Entering private pacrypt()", OC_Log::DEBUG);
        $pw = stripslashes($pw);
        $password = "";
        $salt = "";

        if ($this->crypt_type == 'md5crypt') {
            $split_salt = preg_split ('/\$/', $pw_db);
            if (isset ($split_salt[2])) {
                $salt = $split_salt[2];
            }
            $password = Md5crypt::md5crypt($pw, $salt);
        }

        elseif ($this->crypt_type == 'md5') {
            $password = md5($pw);
        }

        elseif ($this->crypt_type == 'system') { // We never generate salts, as user creation is not allowed here
            $password = crypt ($pw, $pw_db);
        }

        elseif ($this->crypt_type == 'cleartext') {
            $password = $pw;
        }

        // See https://sourceforge.net/tracker/?func=detail&atid=937966&aid=1793352&group_id=191583
        // this is apparently useful for pam_mysql etc.
        elseif ($this->crypt_type == 'mysql_encrypt') {
            if(!$this->db_conn) {
                return false;
            }
            if ($pw_db!="") {
                $salt=substr($pw_db,0,2);
                $query = "SELECT ENCRYPT(:pw, :salt);";
            } else {
                $query = "SELECT ENCRYPT(:pw);";
            }

            $result = $this->db->prepare($query);
            $result->bindParam(":pw", $pw);
            if($pw_db != "") {
                $result->bindParam(":salt", $salt);
            }

            if(!$result->execute() ||
               $result->rowCount() !== 1) {
                return false;
            }

            $row = $result->fetch();
            $password = $row[0];
        }

        elseif($this->crypt_type == 'mysql_password') {
            if(!$this->db_conn)
            {
                return false;
            }
            $query = "SELECT PASSWORD(:pw);";

            $result = $this->db->prepare($query);
            $result->bindParam(":pw", $pw);

            if(!$result->execute() ||
               $result->rowCount() !== 1) {
                return false;
            }
            $row = $result->fetch();
            $password = $row[0];
        }

        // The following is by Frédéric France
        elseif($this->crypt_type == 'joomla') {
            $split_salt = preg_split ('/:/', $pw_db);
            if(isset($split_salt[1])) {
                $salt = $split_salt[1];
            }
            $password = ($salt) ? md5($pw.$salt) : md5($pw);
            $password.= ':'.$salt;
        }

        else {
            OC_Log::write('OC_USER_SQL', "unknown/invalid crypt_type settings: $this->crypt_type", OC_Log::ERROR);
            die ('unknown/invalid Encryption type setting: ' . $this->crypt_type);
        }
        OC_Log::write('OC_USER_SQL', "pacrypt() done, return", OC_Log::DEBUG);
        return $password;
    }
}
